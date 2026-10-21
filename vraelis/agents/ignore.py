"""r8 (Codex AL-PUB-02), r9 (Codex AL-011-IGNORE-01): is a project file excluded from version control by the
project's OWN ignore rules?

A lockfile must never make a value more public than the file it came from. A file name alone does not establish that
(a gitignored .mcp.json is just as private as settings.local.json), so a config file's visibility is judged from the
ignore rules inside the project: .git/info/exclude (when the project folder is the repository root) and every
.gitignore on the way from the project folder to the file. git is never run (nothing is launched), and nothing outside
the project is read, so ignore rules in folders above the project and git's global excludes file are not consulted;
the card says so.

Conservative by construction (the answer only ever errs towards "private"):
- A rules file that cannot be read safely, or that holds a pattern this module does not fully support, makes the answer
  UNKNOWN, which callers treat as private.
- git matches case-insensitively when core.ignorecase is true (the default for repositories created on Windows and
  macOS). The repository's setting is not read, so a file counts as ignored if EITHER case-sensitive or
  case-insensitive matching ignores it.

Pattern semantics follow gitignore(5) and git's wildmatch (r9 ports its bracket rules: '!'/'^' negation, ']' first
is literal, ranges, backslash escapes, the twelve POSIX classes such as [:punct:] and [:alpha:]; an unknown class or an
unterminated bracket is unsupported). Lines are split on '\\n' with one trailing '\\r' dropped; blank lines and '#'
comments are skipped; trailing spaces are dropped unless escaped; '!' negates; a trailing '/' matches folders only; a
pattern with a '/' before its end is anchored to its .gitignore's folder, otherwise it matches a name at any depth;
'*', '?' and brackets never match '/'; a run of two or more '*' spans folders only when it is bounded by the start or a
'/' on the left and the end or a '/' on the right ('**/', '/**/', '/**', '**'), otherwise it is a single '*'; the last
matching rule wins, deeper .gitignore files win over shallower ones; a file inside an ignored folder is ignored whatever
later rules say."""
import re

UNKNOWN = object()


# Case-insensitive matching as git's wildmatch does it under core.ignorecase: the path and the pattern's ordinary
# characters are lowercased (ASCII only), but characters inside a bracket and backslash-escaped characters are
# compared as written (so .[M]cp.json matches neither .mcp.json nor .MCP.json), and a range also matches a letter
# whose upper case falls inside it.
_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_LOWER = "abcdefghijklmnopqrstuvwxyz"


class Unsupported(ValueError):
    pass


# git's sane_ctype classes are ASCII-only
POSIX = {"alnum": "a-zA-Z0-9", "alpha": "a-zA-Z", "blank": " \\t", "cntrl": "\\x00-\\x1f\\x7f", "digit": "0-9",
         "graph": "!-~", "lower": "a-z", "print": " -~", "punct": "!-/:-@\\[-`{-~", "space": " \\t\\n\\r\\f\\v",
         "upper": "A-Z", "xdigit": "0-9A-Fa-f"}


def _bracket(p, i, ci):
    """Translate the bracket expression starting at p[i] == '['. Returns (regex, index after ']')."""
    n, j = len(p), i + 1
    if j >= n: raise Unsupported("unterminated bracket")
    neg = p[j] in "!^"
    if neg: j += 1
    parts, prev, first = [], None, True
    while True:
        if j >= n: raise Unsupported("unterminated bracket")
        c = p[j]
        if c == "]" and not first: j += 1; break
        first = False
        if c == "\\":
            j += 1
            if j >= n: raise Unsupported("trailing backslash in bracket")
            c = p[j]; parts.append(re.escape(c)); prev = c; j += 1; continue
        if c == "-" and prev is not None and j + 1 < n and p[j + 1] != "]":
            j += 1; hi = p[j]
            if hi == "\\":
                j += 1
                if j >= n: raise Unsupported("trailing backslash in bracket")
                hi = p[j]
            lo = parts.pop()  # the escaped previous character
            if prev <= hi:
                parts.append(f"{re.escape(prev)}-{re.escape(hi)}")
                if ci: parts.extend(c for c in _LOWER if prev <= c.upper() <= hi)  # wildmatch also tries toupper(text)
            else: parts.append(lo)  # git: an empty range matches nothing, but prev itself was already matched
            prev = None; j += 1; continue
        if c == "[" and j + 1 < n and p[j + 1] == ":":
            k = p.find("]", j + 2)
            if k < 0: raise Unsupported("unterminated bracket")
            body = p[j + 2:k]
            if body.endswith(":") and len(body) >= 1:
                name = body[:-1]
                if name not in POSIX: raise Unsupported(f"unknown character class [:{name}:]")
                parts.append("a-zA-Z" if ci and name == "upper" else POSIX[name]); prev = None; j = k + 1; continue  # wildmatch: [:upper:] also takes a lower-case letter when folding
            parts.append(re.escape("[")); prev = "["; j += 1; continue  # git: no ':]' found, '[' is an ordinary member
        parts.append(re.escape(c)); prev = c; j += 1
    cls = "".join(parts)
    if not cls: return ("[^/]" if neg else "(?!)"), j
    return "(?!/)[" + ("^" if neg else "") + cls + "]", j


def _translate(p, ci):
    out, i, n = [], 0, len(p)
    while i < n:
        c = p[i]
        if c == "*":
            k = i
            while k < n and p[k] == "*": k += 1
            run = k - i
            left = i == 0 or p[i - 1] == "/"
            if run >= 2 and left and k < n and p[k] == "\\": raise Unsupported("escaped character after '**'")
            if run >= 2 and left and (k == n or p[k] == "/"):
                if k == n: out.append(".*")
                else: out.append("(?:.*/)?"); k += 1
            else: out.append("[^/]*")
            i = k; continue
        if c == "?": out.append("[^/]"); i += 1; continue
        if c == "\\":
            if i + 1 >= n: raise Unsupported("trailing backslash")
            out.append(re.escape(p[i + 1])); i += 2; continue
        if c == "[":
            rx, i = _bracket(p, i, ci); out.append(rx); continue
        out.append(re.escape(c.translate(_FOLD) if ci else c)); i += 1
    return "".join(out)


def parse(text):
    """Rules as (neg, dir_only, anchored, case-sensitive regex, case-insensitive regex). Raises Unsupported."""
    rules = []
    for line in text.split("\n"):
        s = line[:-1] if line.endswith("\r") else line
        if not s or s.startswith("#"): continue
        while s.endswith(" ") and not s.endswith("\\ "): s = s[:-1]
        if not s: continue
        neg = s.startswith("!")
        if neg: s = s[1:]  # a leading backslash (\! or \#) is a literal escape, handled by _translate
        dir_only = s.endswith("/")
        s = s.rstrip("/")
        if not s: continue
        anchored = "/" in s
        if s.startswith("/"): s = s[1:]
        try: rules.append((neg, dir_only, anchored, re.compile("(?s)" + _translate(s, False)), re.compile("(?s)" + _translate(s, True))))
        except re.error as e: raise Unsupported(f"pattern not compilable: {e}")
    return rules


def _match(rules, rel, is_dir, ci):
    state = None
    base = rel.rsplit("/", 1)[-1]
    for neg, dir_only, anchored, rx_cs, rx_ci in rules:
        if dir_only and not is_dir: continue
        target = rel if anchored else base
        if (rx_ci.fullmatch(target.translate(_FOLD)) if ci else rx_cs.fullmatch(target)): state = not neg
    return state


def _ignored_one(parts, sources, ci):
    for i in range(len(parts)):
        is_dir = i < len(parts) - 1
        state = None
        for k, rules in sources:
            if k > i: continue
            r = _match(rules, "/".join(parts[k:i + 1]), is_dir, ci)
            if r is not None: state = r
        if state: return True
    return False


def ignored(rel, read, repo_root):
    """True if `rel` (a project-relative file path with '/' separators) is excluded by the project's own ignore rules
    under case-sensitive OR case-insensitive matching, False if not, UNKNOWN if a rules file could not be read safely
    or holds a pattern this module does not support. read(path) returns the text of a project-relative file, "" if it
    is absent, or UNKNOWN."""
    parts = rel.split("/")
    texts = []  # (folder depth, text), lowest priority first
    if repo_root: texts.append((0, read(".git/info/exclude")))
    for k in range(len(parts)): texts.append((k, read("/".join(parts[:k] + [".gitignore"]))))
    if any(t is UNKNOWN for _, t in texts): return UNKNOWN
    try: sources = [(k, parse(t)) for k, t in texts]
    except Unsupported: return UNKNOWN
    return _ignored_one(parts, sources, False) or _ignored_one(parts, sources, True)
