"""Secret scrubbing for every string Add-on Lock records (r3, rewritten in r4 after adversarial review 2).

One pass, `scrub(text, gaps, where)`, runs over every recorded string: args, commands, URLs, settings strings
(permissions included), names and keys, package specs, notices and gap texts. It replaces credential-shaped
substrings with <redacted> and adds a coverage gap for each. It is BEST EFFORT: a secret in a shape no rule
recognises (for example a short password passed with no telling flag, key name, URL position or known prefix) can
still be recorded. Hashing is never used. All rules are linear-time (bounded repetition, no nested quantifiers), and
strings longer than MAX_LEN are not recorded at all (review 2, M7: a crafted argument could stall verify).
"""
import re
from urllib.parse import urlsplit, urlunsplit, unquote

REDACTED = "<redacted>"
MAX_LEN = 8192
# Names whose value is a secret. Over-matching is safe (the value is redacted and listed as not covered).
SECRET_NAME = re.compile(r"key|token|secret|(?<!by)pass|pwd|(?:^|[^a-z])pw(?:$|[^a-z])|auth|credential|bearer|cookie|session|private|signature|(?:^|[^a-z])pat(?:$|[^a-z])|cert|basic", re.I)
# Flags whose NEXT argument carries a credential or a header (which may carry one). Not -u/-b/-a/-P/-p generically:
# they mean other things in many programs; those are handled per program below.
VALUE_FLAGS = re.compile(r"^(-H|--header|--user|--basic-auth|--proxy-user|--oauth2-bearer|--cookie)$")
TWO_VALUE_FLAGS = {"--headers"}  # mcp-proxy: --headers NAME VALUE
PROGRAM_VALUE_FLAGS = {  # program basename -> flags whose next argument is a password (review 2, M2)
    "sqlcmd": {"-P"}, "redis-cli": {"-a"}, "curl": {"-b", "-u"}, "wget": {"--password", "--http-password"},
    "mongosh": {"-p"}, "mongo": {"-p"},
}
GENERIC_PW_FLAGS = {"-P", "-a", "-p"}  # password in mysql/sqlcmd/redis/mongo style; redacted unless the value is plainly not one


def _plain_value(a):
    """A value after -p/-P/-a that is plainly not a password: a number (port), a path, a package spec or a flag."""
    return bool(re.fullmatch(r"\d{1,6}", a)) or a.startswith(("-", "@", ".", "/", "~", "$")) or "/" in a or "\\" in a or bool(re.search(r"@\d", a))


ATTACHED_P = {"mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump"}  # -pPASSWORD
TOKEN_PREFIX = r"(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|sk-|sk_live_|sk_test_|rk_live_|xox[abprs]-|AKIA|ASIA|AIza|hf_|npm_|pypi-|shpat_|SG\.)"
HOST = r"(?:localhost|(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z][A-Za-z0-9-]{0,62}|\[[0-9A-Fa-f:.]{2,45}\])"
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,30}://[^\s\"'<>`]{1,4096}")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{0,20000}?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)")
_NAMEVAL = re.compile(r"(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]{1,64})(\s{0,4}[=:]\s{0,4})(\"[^\"\n]{0,1024}\"|'[^'\n]{0,1024}'|\{[^}\n]{0,1024}\}|[^\s;&\"',)]{1,1024})")
_CONNSEG = re.compile(r"(^|;)(\s{0,4})([^=;\n]{1,64})=([^;\n]{0,1024})")
_RULES = [
    # Authorization-style headers: keep the header name, drop the value (to end of line or quote).
    (re.compile(r"(?i)\b((?:proxy-)?authorization|x-[a-z0-9-]{0,40}(?:key|token|auth|secret)[a-z0-9-]{0,40}|api[-_]?key|cookie)(\s{0,4}[:=]\s{0,4})([^\"'\n]{1,1024})"), r"\1\2" + REDACTED),
    (re.compile(r"(?i)\b(bearer|basic|token)\s{1,4}[^\s\"']{1,1024}"), r"\1 " + REDACTED),
    # user:password@host and :password@host (no scheme), also after "/" (review 2, M1).
    (re.compile(r"(?<![A-Za-z0-9+.\-])([A-Za-z0-9_.\-]{0,64}):([^\s@/:\"']{1,256})@(" + HOST + ")"), r"\1:" + REDACTED + r"@\3"),
    # user:password@host where the host has no dot (a container or service name); password 6+ characters; not a
    # docker image digest (name:tag@sha256:...).
    (re.compile(r"(?<![A-Za-z0-9+.\-])([A-Za-z0-9_.\-]{1,64}):([^\s@/:\"']{6,256})@(?!sha\d)([A-Za-z][A-Za-z0-9_\-]{0,62})(?=[:/\s\"']|$)"), r"\1:" + REDACTED + r"@\3"),
    # Oracle / EZConnect user/password@host (review 2, M1). The host must look like a host name.
    (re.compile(r"(?<![A-Za-z0-9_@/.\-])([A-Za-z][A-Za-z0-9_.$\-]{0,63})/([^\s@/\"']{1,256})@(" + HOST + r")(?=[:/\s\"']|$)"), r"\1/" + REDACTED + r"@\3"),
    # -u user:password inside command strings.
    (re.compile(r"(\s-u\s{1,4}|\s--user\s{1,4})([^\s:\"']{1,256}):([^\s\"']{1,256})"), r"\1\2:" + REDACTED),
    (re.compile(r"(?<![A-Za-z0-9_\-])" + TOKEN_PREFIX + r"[A-Za-z0-9_\-.=]{1,1024}"), REDACTED),  # r5: left boundary (review 3, H1)
    (re.compile(r"eyJ[A-Za-z0-9_\-]{5,4096}\.[A-Za-z0-9_\-]{5,4096}\.[A-Za-z0-9_\-]{0,4096}"), REDACTED),  # JWT
]
_OPAQUE = re.compile(r"(?<![A-Za-z0-9_\-+/=])([A-Za-z0-9_\-+=]{32,4096})(?![A-Za-z0-9_\-+/=])")  # tokens containing "/" are a known limit
_HEX_DIGEST = re.compile(r"sha(?:256|512):[0-9a-f]{64,128}")


def _mixed(s, n):
    return len(s) >= n and re.search(r"[A-Za-z]", s) and re.search(r"\d", s)


def _opaque_segment(seg):
    """A URL path segment or a bare argument that looks like a key: letters and digits mixed, 12+ characters, no
    punctuation that names usually have (dot, @, slash)."""
    return len(seg) <= 4096 and bool(re.fullmatch(r"[A-Za-z0-9_\-]{12,}", seg)) and bool(_mixed(seg, 12)) and len(re.findall(r"\d", seg)) >= 2


def _mixed_case_segment(seg):
    """r5 (review 3, L6): a 20+ character letters-and-digits URL path segment with both cases looks like a key even
    with fewer than 2 digits (Slack webhook secrets)."""
    return len(seg) <= 4096 and bool(re.fullmatch(r"[A-Za-z0-9]{20,}", seg)) and bool(re.search(r"[a-z]", seg)) and bool(re.search(r"[A-Z]", seg))


def _redact_pairs(s):
    """name=value&... with values redacted; a part without '=' is redacted whole."""
    return "&".join((p.split("=", 1)[0] + "=" + REDACTED) if "=" in p else REDACTED for p in s.split("&")) if s else s


def _scrub_url(u, gaps, where):
    try:
        s = urlsplit(u)
        s.hostname  # raises on a malformed IPv6 literal
    except ValueError:
        gaps.append(f"{where}: unparseable URL redacted"); return REDACTED
    changed = False
    netloc = s.netloc
    if "@" in netloc: netloc = netloc.rsplit("@", 1)[1]; changed = True
    segs = s.path.split("/")
    for i, seg in enumerate(segs):
        if _opaque_segment(seg) or re.match(TOKEN_PREFIX, seg) or _mixed_case_segment(seg): segs[i] = REDACTED; changed = True
    query, frag = s.query, s.fragment
    if query: query = _redact_pairs(query); changed = True
    if frag and "=" in frag: frag = _redact_pairs(frag); changed = True  # r4: fragments kept (review 2, M6), values redacted
    if changed: gaps.append(f"{where}: parts of a URL redacted (user info, query or fragment values, key-like path segments)")
    return urlunsplit((s.scheme, netloc, "/".join(segs), query, frag))


def _nameval(m, gaps, where):
    name, sep, val = m.group(1), m.group(2), m.group(3)
    if SECRET_NAME.search(name) and val not in ("*", "") and REDACTED not in val:
        gaps.append(f"{where}: {name} value redacted"); return name + sep + REDACTED
    return m.group(0)


def _connseg(m, gaps, where):
    lead, sp, name, val = m.group(1), m.group(2), m.group(3), m.group(4)
    if SECRET_NAME.search(name) and val.strip() and val.strip() != REDACTED:
        gaps.append(f"{where}: connection-string {name.strip()} redacted"); return f"{lead}{sp}{name}={REDACTED}"
    return m.group(0)


def _sub(rx, rep, out, gaps, where, msg):
    new = rx.sub(rep, out)
    if new != out: gaps.append(f"{where}: {msg}")
    return new


def scrub(text, gaps, where):
    """Return text with credential-shaped substrings replaced by <redacted>; each replacement adds a gap."""
    if not isinstance(text, str) or not text: return text
    if len(text) > MAX_LEN:
        gaps.append(f"{where}: a value of {len(text)} characters was not recorded (too long)"); return f"<value not recorded: {len(text)} characters>"
    if "%" in text:  # r4: percent-encoded credentials; r5 (review 3, M1): decoded at most 3 times, scrubbed once
        dec = text
        for _ in range(3):
            u = unquote(dec)
            if u == dec: break
            dec = u
        if dec != text:
            probe = _scrub_once(dec, [], where)
            if probe != dec:
                gaps.append(f"{where}: percent-encoded text decoded and redacted"); return _scrub_once(dec, gaps, where)
    return _scrub_once(text, gaps, where)


def _scrub_once(text, gaps, where):
    """One non-recursive scrubbing pass (r5)."""
    keep = {}
    def hold(m):  # protect content digests (docker image pins) from the opaque-string rule
        k = f"\x00{len(keep)}\x00"; keep[k] = m.group(0); return k
    out = _sub(_PEM, REDACTED, text, gaps, where, "private key redacted")
    out = _HEX_DIGEST.sub(hold, out)
    out = _URL.sub(lambda m: _scrub_url(m.group(0), gaps, where), out)
    out = _sub(re.compile(r"//([^\s/:@\"']{0,64}):([^\s/@\"']{1,256})@"), r"//\1:" + REDACTED + "@", out, gaps, where, "credentials redacted")
    out = _NAMEVAL.sub(lambda m: _nameval(m, gaps, where), out)
    if ";" in out and "=" in out: out = _CONNSEG.sub(lambda m: _connseg(m, gaps, where), out)
    for rx, rep in _RULES: out = _sub(rx, rep, out, gaps, where, "credential-shaped text redacted")
    new = _OPAQUE.sub(lambda m: REDACTED if _mixed(m.group(0), 1) else m.group(0), out)
    if new != out: gaps.append(f"{where}: long opaque string redacted"); out = new
    for k, v in keep.items(): out = out.replace(k, v)
    return out


def program_of(word):
    """Lower-case basename of a program word, without .exe/.cmd/.bat."""
    b = re.split(r"[\\/]", str(word))[-1].lower()
    for ext in (".exe", ".cmd", ".bat"):
        if b.endswith(ext): b = b[: -len(ext)]
    return b


def scrub_args(args, gaps, where, program=None):
    """Argument lists: context rules first (the value after a secret-like or header flag is dropped whole, two values
    after --headers, program-specific password flags, mysql -pPASSWORD, a bare key-like argument), then scrub()."""
    prog = program_of(program) if program else None
    pflags = PROGRAM_VALUE_FLAGS.get(prog, set())
    out, hide = [], 0
    for i, a in enumerate(args):
        w, prev = f"{where} arg {i}", args[i - 1] if i else None
        if not isinstance(a, str):
            out.append(REDACTED); gaps.append(f"{w}: non-string argument not recorded"); hide = 0; continue
        if hide:
            out.append(REDACTED); gaps.append(f"{w}: value after a secret-like or header flag redacted"); hide -= 1; continue
        if a in TWO_VALUE_FLAGS: out.append(a); hide = 2; continue
        if a in pflags: out.append(a); hide = 1; continue
        if (prog in ATTACHED_P and re.match(r"^-p.", a) and not a.startswith("--")) or re.fullmatch(r"-p(?=[^\s]*[A-Za-z])[^\s/@=]{6,}", a):
            out.append("-p" + REDACTED); gaps.append(f"{w}: attached password redacted"); continue
        if prev in GENERIC_PW_FLAGS and not _plain_value(a):
            out.append(REDACTED); gaps.append(f"{w}: value after {prev} redacted (may be a password)"); continue
        m = re.match(r"^(-{1,2})([A-Za-z0-9_.\-]{1,64})$", a)
        if m and (SECRET_NAME.search(m.group(2)) or VALUE_FLAGS.match(a)):
            out.append(a); hide = 1; continue
        m = re.match(r"^(-{0,2})([A-Za-z0-9_.\-]{1,64})=(.*)$", a, re.S)
        if m and (SECRET_NAME.search(m.group(2)) or VALUE_FLAGS.match(m.group(1) + m.group(2))):
            out.append(f"{m.group(1)}{m.group(2)}={REDACTED}"); gaps.append(f"{w}: {m.group(2)} value redacted"); continue
        if prev in ("-u", "--user") and ":" in a:
            out.append(a.split(":", 1)[0] + ":" + REDACTED); gaps.append(f"{w}: password after -u redacted"); continue
        if _opaque_segment(a):
            out.append(REDACTED); gaps.append(f"{w}: key-like argument redacted"); continue
        out.append(scrub(a, gaps, w))
    return out


def scrub_command(cmd, words, gaps, where):
    """r4 (review 2, H3): a command string is recorded as the ORIGINAL text, quoting and spacing kept, with secrets
    redacted in place. Argument-context redactions found on the split words are applied to their text in the string,
    then scrub() runs on the whole string."""
    text = str(cmd)
    red = scrub_args(words, gaps, where, program=words[0] if words else None)
    for w, r in zip(words, red):
        if w != r and w: text = text.replace(w, r)
    return scrub(text, gaps, where)
