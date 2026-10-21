"""Add-on Lock core: lock, verify and diff an AI agent's add-on configuration. Standard library only, offline.
Never launches a server, never makes a network call, never reads anything outside the project folder except a file the
user names with --config (paths.py),
does not record env or header values unless pinned, and redacts credentials it recognises in every other recorded
string (redact.py; best effort, see SPEC.md).

Vocabulary (shared with Model Lock):
  UNCHANGED      the configuration matches the lockfile
  CHANGED        at least one server, field, instruction file or launched local file differs, appeared or disappeared
  CANT_VERIFY    the check could not be completed (no or invalid lockfile, unreadable config, unsafe link, error)

r3: one scrubbing pass; lexical inside-the-project path resolution; linked watched folders; nested fields.
r4 (adversarial review 2 and held-out set 3): verify never takes --pin-env/--pin-header/--config from the lockfile
and never prints pinned values (H1); commands recorded as original text with in-place redaction (H3); header and
settings-env values pinnable, unpinned values listed as not covered (M4, M5); more launch forms resolved and a gap
when a launch's code cannot be found (M6); hard-linked files and secrets files by long name never read (M8, L5);
exact-version pins only (L6); names and keys scrubbed (L1); an empty project can be locked (set 3, case 19).
"""
import hashlib, json, math, os, re, shlex, tempfile

from . import paths
from .redact import REDACTED, SECRET_NAME, scrub, scrub_args, scrub_command, program_of

SCHEMA = "addonlock/5"  # r5: text_sha256 for text files (line-ending-normalised digest)
LOCKFILE = "addonlock.json"
CONFIGS = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json")
INSTRUCTION_DIRS = (".claude/skills", ".claude/agents", ".claude/commands", ".claude/hooks")
SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
COMMAND_KEYS = {"command"}
HELPER_KEYS = {"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"}  # commands that emit credentials
VALUE_KEYS = {"default", "value", "defaultValue", "initialValue"}  # input/prompt values (VS Code inputs may hold passwords)
PATH_VARS = ("${workspaceFolder}", "${workspaceRoot}", "${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR")
SENSITIVE_FILE = re.compile(r"(^\.env|\.env$|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.kdbx$|^id_(rsa|dsa|ecdsa|ed25519)|^credentials|^secrets?\.|^\.npmrc$|^\.netrc$|^\.pypirc$|^\.pgpass$|^\.dev\.vars$|^\.git-credentials$|^\.boto$|^\.s3cfg$)", re.I)
RUNNERS = {"npx", "bunx", "uvx", "pnpx"}
INTERPRETERS = {"node", "nodejs", "python", "python3", "py", "deno", "bun", "sh", "bash", "zsh", "pwsh", "powershell", "ruby",
                "php", "java", "dotnet", "go", "uv", "tsx", "ts-node", "npm", "pnpm", "yarn", "cmd"}
SCRIPT_RUNNERS = {"npm", "pnpm", "yarn", "bun"}
MAX_LINK_DEPTH = 2
MAX_LOCKFILE = 64 << 20
ADS = re.compile(r"(::?\$[A-Za-z_]+$|^[^:\\/]+\.[A-Za-z0-9]{1,10}:[^\\/:]*$|^\.[A-Za-z0-9_.\-]+:[^\\/:]*$)")
HOME_PREFIX = re.compile(r"^(~|\$HOME\b|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\$env:USERPROFILE)", re.I)
CODE_FILE = re.compile(r"\.(js|mjs|cjs|ts|mts|cts|jsx|tsx|py|ps1|psm1|sh|bash|zsh|rb|php|pl|lua)$", re.I)

PROVES = [
    "Whether the add-on configuration matches the lockfile: servers, launch commands, arguments, package pins, "
    "env and header names, pinned env and header values and other config and settings fields (as recorded after redaction)",
    "Whether instruction files (skills, agents, commands, hooks) and local files a server or hook launches are "
    "byte-identical (except that a documentation file (.md, .txt, .json, .yaml, .toml) whose only difference is line "
    "endings is reported as a notice, not a change), and whether links among them point where they did",
]
DOES_NOT_PROVE = [
    "That an add-on is safe, or that it is malicious",
    "Which tools a server exposes at run time (it is never launched; use AgentGate for the tool surface)",
    "Changes inside packages fetched at launch time (floating pins are flagged at lock for this reason)",
    "Changes inside redacted values, unpinned env or header values, or anything listed under 'Not covered'",
    "That every secret was recognised: redaction is best effort; read a lockfile before committing it",
    "Anything in user-level configuration not passed with --config",
]


class CantVerify(Exception):
    """Raised for conditions that make a verdict impossible; reported as CANT_VERIFY."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def _rel(root, p): return os.path.relpath(p, root).replace(os.sep, "/")


# ---------------------------------------------------------------- JSON

def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas outside strings (the JSON-with-comments that VS Code accepts).
    Returns strict-JSON text. r2; r3: a line comment also ends at a lone CR."""
    out, i, n, in_str = [], 0, len(text), False

    def eol(k):  # r5 (review 3, L5): the CR search is bounded by the next LF, so the whole pass stays linear
        nl = text.find("\n", k)
        cr = text.find("\r", k, nl if nl != -1 else n)
        cands = [x for x in (nl, cr) if x != -1]
        return min(cands) if cands else n

    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n: out.append(text[i + 1]); i += 2; continue
            if c == '"': in_str = False
            i += 1; continue
        if c == '"': in_str = True; out.append(c); i += 1; continue
        if text.startswith("//", i): i = eol(i); continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j == -1: raise ValueError("unterminated block comment")
            i = j + 2; out.append(" "); continue
        if c == ",":
            j = i + 1
            while True:  # look past whitespace and comments for a closing bracket
                while j < n and text[j] in " \t\r\n": j += 1
                if text.startswith("//", j): j = eol(j); continue
                if text.startswith("/*", j):
                    k = text.find("*/", j + 2); j = n if k == -1 else k + 2; continue
                break
            if j < n and text[j] in "}]": i += 1; continue
        out.append(c); i += 1
    return "".join(out)


def _bad_constant(c): raise ValueError(f"non-standard JSON constant {c}")


def _parse(text, label, notices):
    """Strict JSON (NaN/Infinity refused), falling back to JSON with comments with a notice. Raises only CantVerify."""
    try:
        try: return json.loads(text, parse_constant=_bad_constant)
        except ValueError as first:
            if "non-standard JSON constant" in str(first): raise CantVerify(f"{label}: {first}")
            try: doc = json.loads(strip_jsonc(text), parse_constant=_bad_constant)
            except ValueError as e: raise CantVerify(f"{label} is not valid JSON or JSON with comments: {e}")
            notices.append(f"{label}: comments or trailing commas were ignored when reading")
            return doc
    except RecursionError: raise CantVerify(f"{label} is nested too deeply to read")


def _read_text(real, label):
    try:
        with open(real, "rb") as f: return f.read().decode("utf-8-sig")
    except OSError as e: raise CantVerify(f"cannot read {label}: {e.strerror or e}")
    except UnicodeDecodeError as e: raise CantVerify(f"{label} is not UTF-8: {e}")


def _resolve_no_links(root, rel, label):
    """Real path of a config or settings file; None if absent. Refuses links anywhere on the way."""
    links = []
    try: real = paths.resolve(root, rel, links)
    except paths.Outside as e: raise CantVerify(f"{label}: {e}")
    if links: raise CantVerify(f"symbolic link or junction is not supported: {links[0][0]}")
    if not os.path.lexists(real): return None
    if not os.path.isfile(real): raise CantVerify(f"{label} is not a regular file")
    return real


# ---------------------------------------------------------------- recording values

def split_words(cmd):
    """Shell-like split: quotes respected, backslashes kept literally (Windows paths in commands stay intact)."""
    lx = shlex.shlex(str(cmd), posix=True, punctuation_chars=False)
    lx.whitespace_split, lx.escape, lx.commenters = True, "", ""
    try: return list(lx)
    except ValueError: return str(cmd).split()


def record_command(cmd, gaps, where, helper=False):
    """A command string as its ORIGINAL text (quoting and spacing kept), secrets redacted in place (r4, H3). For a
    credential helper only the program is kept."""
    words = split_words(cmd)
    if helper:
        if len(words) > 1: gaps.append(f"{where}: arguments of a credential helper are not recorded")
        return scrub_args(words[:1], gaps, where)[0] if words else ""
    return scrub_command(cmd, words, gaps, where)


def _put(d, key, value, gaps, where):
    """Insert without ever overwriting (r5, review 3 H1): two different names that redact to the same text get distinct
    keys ('name', 'name #2', ...), so a redaction can never make an entry disappear."""
    k, n = key, 1
    while k in d:
        n += 1; k = f"{key} #{n}"
    if n > 1: gaps.append(f"{where}: two names redact to the same text; the second is recorded as {k!r}")
    d[k] = value
    return k


def _names(d, gaps, where):
    out = {}
    for x in sorted(d, key=str): _put(out, scrub(str(x), gaps, where), True, gaps, where)
    return sorted(out)


def _pinned(d, kind, pins, gaps, where):
    """Names-only record of an env or headers object, plus plain-text values for pinned names, plus a gap naming the
    values that are not recorded (r4, M4/M5)."""
    rec = {"names": _names(d, gaps, where)}
    vals = {str(k): str(v) for k, v in sorted(d.items(), key=lambda kv: str(kv[0])) if str(k) in pins}
    if vals: rec["pinned_values"] = vals
    if any(str(k) not in pins for k in d):
        gaps.append(f"{where}: {kind} values are not recorded; changes to them are not detected (pin with --pin-{'env' if kind == 'env' else 'header'})")
    return rec


def record_value(v, gaps, where, key=None, secret=False, pins=None):
    """Recursive record of a config or settings value: env/headers objects keep names (and pinned values); values
    under a secret-like key are redacted; command strings keep their original text with secrets redacted; args lists
    get argument rules; every other string, and every key, is scrubbed. Numbers, booleans and null are kept."""
    pins = pins or {"env": set(), "header": set()}
    k = str(key) if key is not None else ""
    secret = secret or bool(k and SECRET_NAME.search(k)) or k in VALUE_KEYS
    if k == "env" and isinstance(v, dict): return _pinned(v, "env", pins["env"], gaps, where)
    if re.search(r"headers$", k, re.I) and isinstance(v, dict): return _pinned(v, "header", pins["header"], gaps, where)  # customHeaders etc.
    if re.fullmatch(r"(?i)environment|env_?vars", k) and isinstance(v, dict): return _pinned(v, "env", pins["env"], gaps, where)
    if isinstance(v, dict):  # a secret-like name on an object does not blank its children; each is judged by its own key
        inherited = secret and k in VALUE_KEYS
        out = {}
        for x, y in sorted(v.items(), key=lambda kv: str(kv[0])):
            _put(out, scrub(str(x), gaps, where), record_value(y, gaps, f"{where}.{x}", x, inherited, pins), gaps, where)
        return out
    if isinstance(v, list):
        if k == "args" and not secret and all(isinstance(x, str) for x in v): return scrub_args(v, gaps, where)
        return [record_value(x, gaps, f"{where}[{i}]", key, secret, pins) for i, x in enumerate(v)]
    if isinstance(v, str):
        if k in HELPER_KEYS: return record_command(v, gaps, where, helper=True)
        if secret: gaps.append(f"{where}: value redacted (secret-like name)"); return REDACTED
        if k in COMMAND_KEYS: return record_command(v, gaps, where)
        return scrub(v, gaps, where)
    if secret and v not in (None, True, False): gaps.append(f"{where}: value redacted (secret-like name)"); return REDACTED
    if isinstance(v, float) and not math.isfinite(v): raise CantVerify(f"{where}: non-finite number")
    return v


_EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_EXACT_PEP440 = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")


def package_pins(command, args):
    """(spec, status) pairs for packages a runner fetches at launch, read from the RECORDED (scrubbed) command and
    args. status: pinned (exact version or image digest) | floating (tag, range, partial version) | unpinned |
    redacted. r4 (review 2, L6): dist-tags and partial versions are floating."""
    cmd = program_of(str(command).split(" ")[0])
    args = [str(a) for a in args]
    # r5 (review 3, M5): unwrap cmd /c, sh -c / bash -c, and the package-runner subcommands of pnpm/yarn/npm/bun
    if cmd == "cmd" and args[:1] and args[0].lower() in ("/c", "/k", "/s"):
        inner = args[1:]
        if len(inner) == 1: inner = split_words(inner[0])
        return package_pins(inner[0], inner[1:]) if inner else []
    if cmd in ("sh", "bash", "zsh") and args[:1] == ["-c"] and len(args) > 1:
        inner = split_words(args[1])
        return package_pins(inner[0], inner[1:]) if inner else []
    if (cmd in ("pnpm", "yarn") and args[:1] == ["dlx"]) or (cmd == "npm" and args[:1] in (["exec"], ["x"])) or (cmd == "bun" and args[:1] == ["x"]):
        cmd, args = "npx", [a for a in args[1:] if a != "--"]
    pkg, rest = None, None
    if cmd in RUNNERS: rest = args
    elif cmd == "pipx" and args[:1] == ["run"]: rest = args[1:]
    elif cmd == "uv" and args[:2] == ["tool", "run"]: rest = args[2:]
    if rest is not None:
        js = cmd in ("npx", "bunx", "pnpx")
        names_pkg = {"-p", "--package"} if js else {"--from", "--spec"}
        skip_value = names_pkg | ({"--registry", "--cache"} if js else {"--with", "--python", "-p", "--index-url", "--index"})
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("-y", "--yes", "-q", "--quiet"): i += 1; continue
            if a in skip_value and i + 1 < len(rest):
                if a in names_pkg: pkg = rest[i + 1]; break
                i += 2; continue
            if a.startswith("-"): i += 1; continue
            pkg = a; break
        if pkg is None: return []
        if REDACTED in pkg: return [(pkg, "redacted")]
        if pkg.startswith("@"): name, _, ver = pkg[1:].partition("@"); name = "@" + name; exact = _EXACT_SEMVER
        else:
            m = re.match(r"^([^=<>@\s]+)(==|@)(.+)$", pkg)
            name, ver = (m.group(1), m.group(3)) if m else (pkg, "")
            exact = _EXACT_PEP440 if (m and m.group(2) == "==") else _EXACT_SEMVER
        if not ver: return [(pkg, "unpinned")]
        return [(pkg, "pinned" if exact.match(ver) else "floating")]
    if cmd in ("docker", "podman") and args[:1] == ["run"]:
        i, rest = 0, args[1:]
        valued = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--env-file", "-w", "--workdir",
                  "--user", "-u", "--entrypoint", "--mount", "--platform", "-l", "--label"}
        while i < len(rest):
            a = rest[i]
            if a in valued: i += 2; continue
            if a.startswith("-"): i += 1; continue
            if REDACTED in a: return [(a, "redacted")]
            if "@sha256:" in a: return [(a, "pinned")]
            tag = a.rsplit("/", 1)[-1].partition(":")[2]
            return [(a, "floating" if tag else "unpinned")]
    return []


def record_server(name, entry, pins, gaps, notices):
    where = f"server {name}"
    if not isinstance(entry, dict): raise CantVerify(f"{where}: entry is not an object")
    rec = {}
    prog = entry.get("command") if isinstance(entry.get("command"), str) else None
    for key in sorted(entry, key=str):
        v = entry[key]
        if key == "args":
            if not isinstance(v, list): raise CantVerify(f"{where}: args is not a list")
            rec["args"] = scrub_args(v, gaps, where, program=split_words(prog)[0] if prog and split_words(prog) else None)
        elif key == "command":
            if not isinstance(v, str): raise CantVerify(f"{where}: command is not a string")
            rec["command"] = record_command(v, gaps, f"{where} command")
        elif key in ("env", "headers"):
            if not isinstance(v, dict): raise CantVerify(f"{where}: {key} is not an object")
            rec[key] = _pinned(v, "env" if key == "env" else "header", pins["env" if key == "env" else "header"], gaps, where)
        else:
            _put(rec, scrub(str(key), gaps, where), record_value(v, gaps, f"{where}.{key}", key, pins=pins), gaps, where)
    for spec, status in package_pins(rec.get("command", ""), rec.get("args", []) or []):
        rec.setdefault("packages", []).append({"spec": spec, "status": status})
        if status in ("floating", "unpinned"): notices.append(f"{where}: package {spec!r} is {status}; code fetched at launch can change without any config change")
        if status == "redacted": notices.append(f"{where}: package spec contains a redacted part; its pin cannot be judged")
    return rec


# ---------------------------------------------------------------- launched files

def _expand(s, root):
    for v in PATH_VARS: s = s.replace(v, root)
    return s


def _candidate_paths(words, base_rel, depth=0):
    """(path string, base folder, kind) for paths a launch command may read: plain words, --flag=path, -m modules
    (also under src/), --directory/--prefix/--cwd (also as --x=dir), cd DIR, nested -c / /c command strings, and the
    package.json of npm/pnpm/yarn/bun script runs. r4 (review 2, M6)."""
    out, base, i = [], base_rel, 0
    words = [w.strip("();&|`") if w not in ("&&", "||", ";", "|") else w for w in words]
    prog = program_of(words[0]) if words else ""
    if prog in SCRIPT_RUNNERS and len(words) > 1 and words[1] in ("run", "start", "test", "run-script"):
        script = words[2] if words[1] in ("run", "run-script") and len(words) > 2 else words[1]
        out.append(("package.json", base, "manifest:" + script))
    while i < len(words):
        w, nxt = words[i], words[i + 1] if i + 1 < len(words) else None
        if not w: i += 1; continue
        if w in ("--directory", "--project", "--prefix", "--cwd", "-C") and nxt:
            base = os.path.join(base, nxt); out.append((nxt, base_rel, "dir")); i += 2; continue
        m = re.match(r"^--(directory|project|prefix|cwd)=(.+)$", w)
        if m: base = os.path.join(base, m.group(2)); out.append((m.group(2), base_rel, "dir")); i += 1; continue
        if w == "cd" and nxt: base = os.path.join(base, nxt); i += 2; continue
        if w == "--env-file" and nxt: out.append((nxt, base, "secret")); i += 2; continue
        if w in ("-c", "/c", "/C", "/k", "/K", "-Command", "-command") and nxt and depth < 2:
            out += _candidate_paths(split_words(nxt), base, depth + 1); i += 2; continue
        if w == "-m" and nxt and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", nxt):
            mod = nxt.replace(".", "/")
            for pre in ("", "src/"):
                for c in (mod + ".py", mod + "/__main__.py", mod + "/__init__.py"): out.append((pre + c, base, "module"))
            i += 2; continue
        m = re.match(r"^--?[A-Za-z0-9_.\-]{1,64}=(.+)$", w)
        if m: out.append((m.group(1), base, "word")); i += 1; continue
        if not w.startswith("-") and REDACTED not in w and "://" not in w and w not in ("&&", "||", ";", "|"): out.append((w, base, "word"))
        i += 1
    return out


def _long_name(real):
    """The long file name on Windows (an 8.3 alias such as ENV~1.PRO is expanded); the basename elsewhere (L5)."""
    if os.name != "nt": return os.path.basename(real)
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(32768)
        n = ctypes.windll.kernel32.GetLongPathNameW(str(real), buf, 32768)
        return os.path.basename(buf.value) if 0 < n < 32768 else os.path.basename(real)
    except Exception: return os.path.basename(real)


def _readable_file(real, rel, gaps, where):
    """Digest of a regular file, or None (with a gap) if it must not be read: secrets-file names (by long name) and
    files with other hard links (their content may live outside the project; review 2, M8)."""
    if SENSITIVE_FILE.search(_long_name(real)) or SENSITIVE_FILE.search(os.path.basename(rel)):
        gaps.append(f"{where}: {rel} looks like a secrets file; it is not read"); return None
    try: st = os.stat(real)
    except (OSError, ValueError) as e: raise CantVerify(f"cannot read {rel}: {getattr(e, 'strerror', None) or e}")
    if st.st_nlink > 1:
        gaps.append(f"{where}: {rel} has other hard links; it is not read"); return None
    return _digest(real, rel)


def _script_words(real_manifest, script):
    """Words of a package.json script (the file is inside the project and already resolved); None if absent."""
    try:
        with open(real_manifest, "rb") as f: doc = json.loads(f.read().decode("utf-8-sig"))
        cmd = doc.get("scripts", {}).get(script) if isinstance(doc, dict) and isinstance(doc.get("scripts"), dict) else None
    except (OSError, ValueError, UnicodeDecodeError, RecursionError): return None
    return split_words(cmd) if isinstance(cmd, str) else None


def _launched(root, words, cwd, gaps, where, found, depth=0):
    """Digest regular files inside the project that the words name. Never touches network paths or anything outside
    the project. If the launch uses an interpreter and no file is found, says so (r4, M6)."""
    base = "."
    if cwd is not None:
        c = _expand(str(cwd), root)
        if paths.network_like(c) or not paths.lexically_inside(c if os.path.isabs(c) else os.path.join(root, c), root):
            gaps.append(f"{where}: cwd is outside the project; relative launch paths are not resolved"); return
        base = os.path.relpath(os.path.abspath(c if os.path.isabs(c) else os.path.join(root, c)), root)
    words = [_expand(x, root) for x in words if isinstance(x, str)]
    n_before, g_before, hit = len(found), len(gaps), False
    for w, b, kind in _candidate_paths(words, base):
        if paths.network_like(w):
            gaps.append(f"{where}: a network path is not read"); hit = True; continue
        if paths.WINDOWS and ":" in os.path.splitdrive(w)[1]:  # r5 (review 3, L3): not a path, or NTFS stream syntax
            if ADS.search(w): gaps.append(f"{where}: NTFS stream syntax is not read"); hit = True
            continue
        if HOME_PREFIX.match(w):  # r5 (review 3, L4)
            gaps.append(f"{where}: a launch path in the home folder is outside the project and not pinned: {scrub(w, [], where)}"); hit = True; continue
        try:
            raw = w if os.path.isabs(w) else os.path.join(root, b, w)  # r5 (review 3, L1): '..' is resolved by paths.resolve
            full = os.path.abspath(raw)
        except (ValueError, OSError): continue
        if not paths.lexically_inside(full, root):
            if os.path.isabs(w) or "/" in w or "\\" in w: gaps.append(f"{where}: a launched path outside the project is not read: {scrub(w, [], where)}"); hit = True
            continue
        links = []
        try: real = paths.resolve(root, raw, links)
        except paths.Outside: gaps.append(f"{where}: a launch path was refused (it leaves the project through a link, or uses stream or device syntax)"); hit = True; continue
        except (ValueError, OSError): continue
        if not os.path.exists(real): continue
        rel = scrub(_rel(root, real), gaps, where)  # r5: the file actually read
        if kind == "secret": gaps.append(f"{where}: {rel} is an env file; it is not read"); hit = True; continue
        if os.path.isdir(real):
            if kind != "dir": gaps.append(f"{where}: launch target {rel} is a folder; its contents are not pinned"); hit = True
            continue
        if not os.path.isfile(real): continue
        entry = _readable_file(real, rel, gaps, where)
        hit = True
        if entry is None: continue
        if links: entry["links"] = [scrub(f"{a} -> {t}", gaps, where) for a, t in links]
        if rel in found and found[rel] != entry: rel = _put(found, rel, entry, gaps, where)
        else: found[rel] = entry
        if CODE_FILE.search(rel):  # r5 (held-out set 4, cases 17 and 20; Codex review): say it, never miss silently
            gaps.append(f"{where}: files that {rel} itself imports, sources or loads are not pinned")
        if kind.startswith("manifest:"):  # r4 (review 2, M6): follow the npm/pnpm/yarn/bun script one level
            sw = _script_words(real, kind.split(":", 1)[1])
            if sw and depth < 2:
                _launched(root, sw, os.path.relpath(os.path.dirname(real), root), gaps, f"{where} (script {kind.split(':', 1)[1]})", found, depth + 1)
            else: gaps.append(f"{where}: the {kind.split(':', 1)[1]!r} script in {rel} was not resolved; the code it runs is not pinned")
    if words and program_of(words[0]) in INTERPRETERS and not hit and len(found) == n_before and len(gaps) == g_before:
        gaps.append(f"{where}: no local file named by this launch was found; the code it runs is not pinned")


# ---------------------------------------------------------------- instruction folders

def _digest(p, label):
    """sha256 and size of the bytes; for a text file (no NUL byte) also text_sha256, the digest with CRLF turned into
    LF, so a checkout with different line endings is not reported as Changed (r5, review 3 M3)."""
    try:
        raw, txt, size, text, carry = hashlib.sha256(), hashlib.sha256(), 0, True, b""
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                raw.update(b); size += len(b)
                if text:
                    if b"\x00" in b: text = False; continue
                    b = carry + b; carry = b""
                    if b.endswith(b"\r"): carry, b = b"\r", b[:-1]
                    txt.update(b.replace(b"\r\n", b"\n"))
        if text and carry: txt.update(carry)
        out = {"sha256": raw.hexdigest(), "size": size}
        if text: out["text_sha256"] = txt.hexdigest()
        return out
    except (OSError, ValueError) as e: raise CantVerify(f"cannot read {label}: {getattr(e, 'strerror', None) or e}")


def _walk(root, label, real, entries, gaps, depth, seen):
    key = os.path.normcase(os.path.abspath(real))
    if key in seen: gaps.append(f"{label}: folder reached again through a link; not walked twice"); return
    seen.add(key)
    try: names = sorted(os.listdir(real))
    except OSError as e: raise CantVerify(f"cannot read folder {label}: {e.strerror or e}")
    for n in names:
        p, lab = os.path.join(real, n), scrub(f"{label}/{n}", gaps, label)
        if lab in entries: lab = _put(entries, lab, None, gaps, label); del entries[lab]  # reserve a distinct key (H1)
        if paths.is_link(p): _link(root, lab, p, entries, gaps, depth, seen)
        elif os.path.isdir(p): _walk(root, lab, p, entries, gaps, depth, seen)
        elif os.path.isfile(p):
            e = _readable_file(p, lab, gaps, lab)
            entries[lab] = e if e is not None else {"not_read": "secrets-file name or hard link"}


def _link(root, lab, p, entries, gaps, depth, seen):
    """A link or junction: record its text; follow it only if it stays inside the project and the link depth allows."""
    try: text = paths.read_link(p)
    except paths.Outside: entries[lab] = {"symlink": "<network path>"}; gaps.append(f"{lab}: link to a network location; not followed"); return
    except OSError as e: raise CantVerify(f"cannot read link {lab}: {e.strerror or e}")
    entry = {"symlink": scrub(text.replace(os.sep, "/"), gaps, lab)}
    target = os.path.abspath(text if os.path.isabs(text) else os.path.join(os.path.dirname(p), text))
    entries[lab] = entry
    if not paths.lexically_inside(target, root):
        gaps.append(f"{lab}: link target is outside the project; its contents are not pinned"); return
    if depth >= MAX_LINK_DEPTH:
        gaps.append(f"{lab}: link nested too deep; recorded, not followed"); return
    try: real = paths.resolve(root, target)
    except paths.Outside as e: gaps.append(f"{lab}: {scrub(str(e), [], lab)}; contents not pinned"); return
    if not os.path.exists(real): gaps.append(f"{lab}: link target is missing"); return
    if os.path.isfile(real):
        d = _readable_file(real, lab, gaps, lab)
        if d is not None: entry.update(d)
    elif os.path.isdir(real): _walk(root, lab, real, entries, gaps, depth + 1, seen)


def _instruction_files(root, gaps):
    entries, seen = {}, set()
    for d in INSTRUCTION_DIRS:
        parent, name = os.path.split(d)
        try: real_parent = paths.resolve(root, parent)
        except paths.Outside as e: raise CantVerify(f"{parent}: {e}")
        if not os.path.isdir(real_parent): continue
        p = os.path.join(real_parent, name)
        if paths.is_link(p): _link(root, d, p, entries, gaps, 0, seen)
        elif os.path.isdir(p): _walk(root, d, p, entries, gaps, 0, seen)
    return entries


# ---------------------------------------------------------------- snapshot

def _servers_of(doc, label, notices):
    if not isinstance(doc, dict): raise CantVerify(f"{label} is not a JSON object")
    present = [k for k in ("mcpServers", "servers") if k in doc]
    if len(present) == 2: raise CantVerify(f"{label} has both mcpServers and servers; which one an agent reads is ambiguous")
    if not present:
        notices.append(f"{label}: no mcpServers or servers key; no servers recorded from this file")
        return {}, None
    servers = doc[present[0]]
    if not isinstance(servers, dict): raise CantVerify(f"{label}: {present[0]} is not an object")
    return servers, present[0]


def _launch_words(root, raw_cmd, raw_args):
    """Words of a server launch from the RAW config (not the recorded, redacted text): a command that is itself an
    existing in-project path with spaces stays one word (review 2, L4)."""
    words = []
    if isinstance(raw_cmd, str) and raw_cmd.strip():
        c = _expand(raw_cmd.strip(), root)
        whole = c if os.path.isabs(c) else os.path.join(root, c)
        is_file = False
        if re.search(r"\s", c) and paths.lexically_inside(whole, root):
            try: is_file = os.path.isfile(paths.resolve(root, whole))  # r5 (review 3, L2): never stat through a link first
            except (paths.Outside, ValueError, OSError): is_file = False
        words = [c] if is_file else split_words(raw_cmd)
    return words + [a for a in (raw_args or []) if isinstance(a, str)]


def _settings_commands(v, key=None):
    if isinstance(v, dict):
        for k, x in v.items(): yield from _settings_commands(x, str(k))
    elif isinstance(v, list):
        for x in v: yield from _settings_commands(x, key)
    elif isinstance(v, str) and (key in COMMAND_KEYS or key in HELPER_KEYS): yield v


LOCAL_MARK = "<local file: value not recorded>"
LOCAL_SETTINGS = {".claude/settings.local.json"}  # Claude Code keeps this file out of version control


def _structure_only(v, key=None):
    """r7 redaction policy for the PUBLIC tool (founder: decide per product): a lockfile must never make a value more
    public than the file it came from. Files normally kept out of version control (settings.local.json, user-level
    --config files outside the project) are recorded as structure only: keys, booleans, numbers and null are kept,
    every string becomes LOCAL_MARK. Env/header names and values the user explicitly pinned are kept."""
    if key in ("names", "pinned_values"): return v
    if isinstance(v, dict): return {k: _structure_only(x, k) for k, x in v.items()}
    if isinstance(v, list): return [_structure_only(x, key) for x in v]
    if isinstance(v, str): return LOCAL_MARK
    return v


def snapshot(root, extra_configs=(), pin_env=(), pin_header=(), missing_ok=False):
    """Everything the lock records, computed from disk. Never launches anything."""
    if paths.network_like(root): raise CantVerify("the project folder is a network path")
    if not os.path.isdir(root): raise CantVerify(f"not a folder: {root}")
    if paths.is_link(root): raise CantVerify("the project folder itself is a symbolic link or junction")
    root = os.path.abspath(root)
    pins = {"env": set(pin_env), "header": set(pin_header)}
    gaps, notices, configs, launched, meta, settings = [], [], {}, {}, {}, {}
    sources = [(rel, "rel", rel, False) for rel in sorted(CONFIGS)]
    for c in extra_configs:
        if paths.network_like(c): raise CantVerify("--config is a network path")
        if paths.lexically_inside(c, root): sources.append((_rel(root, os.path.abspath(c)), "rel", os.path.abspath(c), True))
        else: sources.append((os.path.abspath(c).replace(os.sep, "/"), "abs", os.path.abspath(c), True))
    for label, kind, where, explicit in sources:
        if kind == "abs":  # an explicit user-level file outside the project: that one file only, no links
            if paths.is_link(where): raise CantVerify(f"--config is a symbolic link or junction: {where}")
            real = where if os.path.isfile(where) else None
        else:
            real = _resolve_no_links(root, where, label)
        if real is None:
            if explicit and not missing_ok: raise CantVerify(f"--config file not found: {label}")
            continue  # a missing --config at verify time is reported as config-removed
        doc = _parse(_read_text(real, label), label, notices)
        servers, used_key = _servers_of(doc, label, notices)
        other = {k: v for k, v in doc.items() if k not in ("mcpServers", "servers")}
        local = kind == "abs"
        if local: gaps.append(f"{label}: a user-level file outside the project; only its structure is recorded, not its values (changes to values are not detected)")
        shape = _structure_only if local else (lambda x: x)
        meta[label] = {"key": used_key, "other": shape(record_value(other, gaps, f"{label}", pins=pins))}
        recs = {}
        for name in sorted(servers, key=str):
            sname = scrub(str(name), gaps, label)
            entry = servers[name]
            rec = shape(record_server(sname, entry, pins, gaps, [] if local else notices))
            sname = _put(recs, sname, rec, gaps, label)
            raw_cwd = entry.get("cwd") if isinstance(entry, dict) and isinstance(entry.get("cwd"), str) else None
            _launched(root, _launch_words(root, entry.get("command"), entry.get("args")), raw_cwd, gaps, f"{label} > {sname}", launched)
        configs[label] = recs
    for rel in SETTINGS:
        real = _resolve_no_links(root, rel, rel)
        if real is None: continue
        doc = _parse(_read_text(real, rel), rel, notices)
        if not isinstance(doc, dict): raise CantVerify(f"{rel} is not a JSON object")
        settings[rel] = record_value(doc, gaps, rel, pins=pins)
        if rel in LOCAL_SETTINGS:  # r7: kept out of version control, so its values never enter a lockfile
            settings[rel] = _structure_only(settings[rel])
            gaps.append(f"{rel}: a local file kept out of version control; only its structure is recorded, not its values (changes to values are not detected)")
        for cmd in _settings_commands(doc):
            _launched(root, split_words(cmd), None, gaps, rel, launched)
    instr = _instruction_files(root, gaps)
    seen_names = {n for c in configs.values() for r in c.values() for f in ("env", "headers") for n in r.get(f, {}).get("names", [])}
    seen_names |= {n for s in settings.values() for n in (s.get("env", {}) or {}).get("names", [])} if all(isinstance(s, dict) for s in settings.values()) else set()
    for n in sorted((pins["env"] | pins["header"]) - seen_names): notices.append(f"pinned name {n}: no server or settings file sets it")
    if not configs and not settings and not instr:
        notices.append("nothing found to lock: no add-on configuration or instruction files; anything added later will be reported")
    return {"configs": configs, "config_meta": meta, "settings": settings, "instruction_files": instr, "launched_files": launched,
            "coverage_gaps": sorted(set(scrub(g, [], "gap") for g in gaps)), "notices": sorted(set(scrub(n, [], "notice") for n in notices))}


# ---------------------------------------------------------------- lock / verify / diff

def _label(root, c):
    return _rel(root, os.path.abspath(c)) if paths.lexically_inside(c, root) else os.path.abspath(c).replace(os.sep, "/")


def lock(root, extra_configs=(), pin_env=(), source=None, pin_header=()):
    """r4: an empty project can be locked ("nothing approved"), so the first add-on added later is reported."""
    snap = snapshot(root, extra_configs, pin_env, pin_header)
    doc = {"schema": SCHEMA, "pin_env": sorted(set(pin_env)), "pin_header": sorted(set(pin_header)),
           "extra_configs": sorted(_label(os.path.abspath(root), c) for c in extra_configs), **snap}
    if source: doc["source"] = scrub(source, [], "source")
    return doc


def write_lock(root, doc, out=None):
    """Default <root>/addonlock.json. r5 (Codex AL-O01: --out could overwrite an MCP config or a launched script with
    success): --out must be outside the project folder, or be exactly <root>/addonlock.json, as in Model Lock. A link
    destination is refused; atomic replace so a failed write leaves an earlier lockfile intact."""
    if out is not None and paths.network_like(out): raise CantVerify("lockfile destination is a network path")
    default = os.path.abspath(os.path.join(root, LOCKFILE))
    path = os.path.abspath(out or default)
    if paths.network_like(path): raise CantVerify("lockfile destination is a network path")
    if os.path.normcase(path) != os.path.normcase(default) and paths.lexically_inside(path, root):
        raise CantVerify("--out must be outside the project folder (or be <folder>/addonlock.json)")
    if paths.is_link(path): raise CantVerify(f"lockfile destination is a symbolic link or junction: {path}")
    folder = os.path.dirname(path)
    try: fd, tmp = tempfile.mkstemp(prefix=".addonlock-", suffix=".tmp", dir=folder)
    except OSError as e: raise CantVerify(f"cannot write lockfile in {folder}: {e.strerror or e}")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        try: os.remove(tmp)
        except OSError: pass
        raise CantVerify(f"cannot write lockfile {path}: {e.strerror or e}")
    return path


def _entry_ok(e, group):
    if not isinstance(e, dict): return False
    if "text_sha256" in e and not (isinstance(e["text_sha256"], str) and len(e["text_sha256"]) == 64): return False
    digest_ok = isinstance(e.get("sha256"), str) and len(e["sha256"]) == 64 and isinstance(e.get("size"), int)
    if group == "launched_files": return digest_ok and all(isinstance(x, str) for x in e.get("links", []))
    if "not_read" in e: return isinstance(e["not_read"], str)
    return digest_ok or (isinstance(e.get("symlink"), str) and ("sha256" not in e or digest_ok))


def _check_lock_path(path, root=None):
    """r5 (review 3, M2): the lockfile is never read through a link (inside the project: no link on the way), must be
    a regular file, and at most MAX_LOCKFILE bytes."""
    if paths.network_like(path): raise CantVerify("the lockfile path is a network path")
    if root is not None and paths.lexically_inside(path, root):
        links = []
        try: paths.resolve(root, path, links)
        except paths.Outside as e: raise CantVerify(f"lockfile: {e}")
        if links: raise CantVerify("the lockfile is reached through a symbolic link or junction; refused")
    if paths.is_link(path): raise CantVerify("the lockfile is a symbolic link or junction; refused")
    if os.path.lexists(path):
        if not os.path.isfile(path): raise CantVerify("the lockfile is not a regular file")
        if os.path.getsize(path) > MAX_LOCKFILE: raise CantVerify("the lockfile is too large")


def read_lock(path, root=None):
    _check_lock_path(path, root)
    try:
        with open(path, "rb") as f: doc = json.loads(f.read().decode("utf-8-sig"), parse_constant=_bad_constant)  # r4: BOM accepted
    except FileNotFoundError: raise CantVerify(f"no lockfile at {path}")
    except OSError as e: raise CantVerify(f"cannot read lockfile {path}: {e.strerror or e}")
    except (ValueError, UnicodeDecodeError, RecursionError) as e: raise CantVerify(f"lockfile is not valid JSON: {e}")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA: raise CantVerify(f"lockfile is not a {SCHEMA} document (re-lock)")
    for k, t in (("configs", dict), ("config_meta", dict), ("settings", dict), ("instruction_files", dict), ("launched_files", dict),
                 ("pin_env", list), ("pin_header", list), ("extra_configs", list)):
        if not isinstance(doc.get(k), t): raise CantVerify(f"lockfile field {k} is missing or malformed")
    for label, servers in doc["configs"].items():
        if not isinstance(servers, dict) or not all(isinstance(s, dict) for s in servers.values()): raise CantVerify("malformed lockfile config")
    for label, m in doc["config_meta"].items():
        if not (isinstance(m, dict) and "key" in m and "other" in m): raise CantVerify("malformed lockfile config meta")
    if not all(isinstance(x, str) for x in doc["pin_env"] + doc["pin_header"] + doc["extra_configs"]): raise CantVerify("malformed lockfile lists")
    for group in ("instruction_files", "launched_files"):
        for rel, e in doc[group].items():
            if not _entry_ok(e, group): raise CantVerify("malformed lockfile entry")
    return doc


_MISSING = "<absent>"


def _entry_label(e):
    if "symlink" in e: return f"symlink -> {e['symlink']}" + (f" ({e['sha256']})" if "sha256" in e else "")
    if "not_read" in e: return f"not read ({e['not_read']})"
    return e["sha256"] + (f" via {', '.join(e['links'])}" if e.get("links") else "")


def _deep_diff(x, y, path):
    """Leaf-level differences between two recorded JSON values: (path, before, after); lists compare as whole values."""
    if isinstance(x, dict) and isinstance(y, dict):
        for k in sorted(set(x) | set(y)):
            p = f"{path}.{k}" if path else k
            if k not in x: yield p, _MISSING, y[k]
            elif k not in y: yield p, x[k], _MISSING
            else: yield from _deep_diff(x[k], y[k], p)
    elif x != y:
        yield path, x, y


def _strip_pinned(v):
    """Recorded value with pinned plain-text values removed, for output (r4, H1: verify never prints them)."""
    if isinstance(v, dict): return {k: _strip_pinned(x) for k, x in v.items() if k != "pinned_values"}
    if isinstance(v, list): return [_strip_pinned(x) for x in v]
    return v


def _names_and_pins(out, kind, w, fx, fy):
    nx, ny = set((fx or {}).get("names", [])), set((fy or {}).get("names", []))
    for n in sorted(ny - nx): out.append({"kind": f"{kind}-name-added", "where": w, "name": n})
    for n in sorted(nx - ny): out.append({"kind": f"{kind}-name-removed", "where": w, "name": n})
    px, py = (fx or {}).get("pinned_values", {}), (fy or {}).get("pinned_values", {})
    for n in sorted(set(px) | set(py)):
        if px.get(n) != py.get(n): out.append({"kind": f"pinned-{kind}-changed", "where": w, "name": n})  # values never printed


def compare(a, b):
    """Changes from snapshot/lock a (approved) to b (current). Each change: kind, where, and before/after (recorded,
    already redacted values; pinned plain-text values are never included)."""
    out = []
    for label in sorted(set(a["configs"]) | set(b["configs"])):
        x, y = a["configs"].get(label), b["configs"].get(label)
        if x is None: out.append({"kind": "config-added", "where": label, "servers": sorted(y)}); continue
        if y is None: out.append({"kind": "config-removed", "where": label, "servers": sorted(x)}); continue
        for name in sorted(set(x) | set(y)):
            sx, sy = x.get(name), y.get(name)
            w = f"{label} > {name}"
            if sx is None: out.append({"kind": "server-added", "where": w, "after": _strip_pinned(sy)}); continue
            if sy is None: out.append({"kind": "server-removed", "where": w, "before": _strip_pinned(sx)}); continue
            for field in sorted(set(sx) | set(sy)):
                fx, fy = sx.get(field), sy.get(field)
                if fx == fy: continue
                if field in ("env", "headers"): _names_and_pins(out, "env" if field == "env" else "header", w, fx, fy)
                elif isinstance(fx, dict) and isinstance(fy, dict):
                    for p, bx, by in _deep_diff(_strip_pinned(fx), _strip_pinned(fy), field):
                        out.append({"kind": f"{field}-changed", "where": f"{w} > {p}", "before": bx, "after": by})
                    if _strip_pinned(fx) == _strip_pinned(fy): out.append({"kind": f"{field}-changed", "where": f"{w} > {field}"})
                else:
                    out.append({"kind": f"{field}-changed", "where": w, "before": _strip_pinned(fx), "after": _strip_pinned(fy)})
    for label in sorted(set(a["config_meta"]) & set(b["config_meta"])):
        ma, mb = a["config_meta"][label], b["config_meta"][label]
        if ma["key"] != mb["key"]: out.append({"kind": "config-key-changed", "where": label, "before": ma["key"], "after": mb["key"]})
        for p, bx, by in _deep_diff(_strip_pinned(ma["other"]), _strip_pinned(mb["other"]), ""):
            out.append({"kind": "config-field-changed", "where": f"{label} > {p or '(root)'}", "before": bx, "after": by})
    for label in sorted(set(a["settings"]) | set(b["settings"])):
        x, y = a["settings"].get(label), b["settings"].get(label)
        if x is None: out.append({"kind": "settings-added", "where": label}); continue
        if y is None: out.append({"kind": "settings-removed", "where": label}); continue
        ex, ey = (x.get("env") if isinstance(x, dict) else None), (y.get("env") if isinstance(y, dict) else None)
        if isinstance(ex, dict) and isinstance(ey, dict) and ex.get("pinned_values") != ey.get("pinned_values"):
            _names_and_pins(out, "env", f"{label} > env", {"pinned_values": ex.get("pinned_values", {})}, {"pinned_values": ey.get("pinned_values", {})})
        for p, before, after in _deep_diff(_strip_pinned(x), _strip_pinned(y), ""):
            out.append({"kind": "settings-changed", "where": f"{label} > {p or '(root)'}", "before": before, "after": after})
    for group, kind in (("instruction_files", "instruction-file"), ("launched_files", "launched-file")):
        x, y = a[group], b[group]
        for rel in sorted(set(x) | set(y)):
            if rel not in y: out.append({"kind": f"{kind}-removed", "where": rel})
            elif rel not in x: out.append({"kind": f"{kind}-added", "where": rel})
            elif x[rel] != y[rel] and not (eol_tolerant(group, rel) and same_text(x[rel], y[rel])):
                out.append({"kind": f"{kind}-changed", "where": rel, "before": _entry_label(x[rel]), "after": _entry_label(y[rel])})
    return out


DOC_TEXT = re.compile(r"\.(md|markdown|mdc|txt|json|jsonc|ya?ml|toml)$", re.I)


def eol_tolerant(group, rel):
    """r6 (Codex AL-R5-EOL-01): only documentation-type instruction files may differ in line endings alone without
    being reported. Launched files and scripts stay byte-exact: a CRLF shell script does not run on Linux."""
    return group == "instruction_files" and bool(DOC_TEXT.search(rel)) and not CODE_FILE.search(rel)


def same_text(a, b):
    """True if two file entries differ only in line endings (both text, same CRLF-normalised digest, same links)."""
    strip = lambda e: {k: v for k, v in e.items() if k not in ("sha256", "size")}
    return "text_sha256" in a and "text_sha256" in b and strip(a) == strip(b)


def eol_only(a, b):
    return [rel for g in ("instruction_files", "launched_files") for rel in sorted(set(a[g]) & set(b[g]))
            if a[g][rel] != b[g][rel] and eol_tolerant(g, rel) and same_text(a[g][rel], b[g][rel])]


def _card(): return {"proves": PROVES, "does_not_prove": DOES_NOT_PROVE}


def _cant(reason):
    return {"verdict": "CANT_VERIFY", "reason": scrub(str(reason), [], "reason"), "changes": [], "coverage_gaps": [], "notices": [], "card": _card()}


def verify(root, lock_path=None, extra_configs=(), pin_env=(), pin_header=()):
    """r4 (review 2, H1): the --config, --pin-env and --pin-header options are taken from the caller, never from the
    lockfile; they must match what the lockfile was made with, or the result is Can't verify. A lockfile can therefore
    not make verify read another file or reveal a value."""
    lock_path = lock_path or os.path.join(root, LOCKFILE)
    try:
        doc = read_lock(lock_path, os.path.abspath(root))
        given = {"pin_env": sorted(set(pin_env)), "pin_header": sorted(set(pin_header)),
                 "extra_configs": sorted(_label(os.path.abspath(root), c) for c in extra_configs)}
        for k, v in given.items():
            if sorted(doc[k]) != v:
                raise CantVerify(f"the lockfile was made with different --{k.replace('_', '-').replace('extra-configs', 'config')} options; "
                                 "pass the same options to verify (verify never takes them from the lockfile)")
        cur = snapshot(root, extra_configs, pin_env, pin_header, missing_ok=True)
        changes = compare(doc, cur)
        notices = cur["notices"] + [f"{r}: only line endings differ (not reported as a change)" for r in eol_only(doc, cur)]
        return {"verdict": "CHANGED" if changes else "UNCHANGED", "changes": changes,
                "coverage_gaps": cur["coverage_gaps"], "notices": notices, "card": _card()}
    except CantVerify as e:
        return _cant(e)
    except (RecursionError, MemoryError, OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        return _cant(f"internal error: {type(e).__name__}")


def diff(lock_a, lock_b):
    a, b = read_lock(lock_a), read_lock(lock_b)
    changes = compare(a, b)
    return {"verdict": "CHANGED" if changes else "UNCHANGED", "changes": changes}
