"""r8 (Codex AL-PUB-02): is a project file excluded from version control by the project's OWN ignore rules?

A lockfile must never make a value more public than the file it came from. A file name alone does not establish that
(a gitignored .mcp.json is just as private as settings.local.json), so a config file's visibility is judged from the
ignore rules inside the project: .git/info/exclude (when the project folder is the repository root) and every
.gitignore on the way from the project folder to the file. git is never run (nothing is launched), and nothing outside
the project is read, so ignore rules in folders above the project and git's global excludes file are not consulted;
the card says so. A rules file that cannot be read safely makes the answer UNKNOWN, which callers treat as private.

Pattern semantics follow gitignore(5): blank lines and '#' comments skipped; trailing spaces dropped unless escaped;
'!' negates; a trailing '/' matches folders only; a pattern with a '/' before its end is anchored to its .gitignore's
folder, otherwise it matches a name at any depth; '*', '?' and '[...]' never match '/'; '**/', '/**/' and '/**' span
folders; the last matching rule wins, deeper .gitignore files win over shallower ones; a file inside an ignored folder
is ignored whatever later rules say."""
import re

UNKNOWN = object()


def _translate(p):
    out, i, n = [], 0, len(p)
    while i < n:
        if i == 0 and p.startswith("**/"): out.append("(?:.*/)?"); i += 3; continue
        if p.startswith("/**/", i): out.append("/(?:.*/)?"); i += 4; continue
        if p[i:] == "/**": out.append("/.*"); break
        if p.startswith("**", i): out.append(".*"); i += 2; continue
        c = p[i]
        if c == "*": out.append("[^/]*")
        elif c == "?": out.append("[^/]")
        elif c == "\\" and i + 1 < n: out.append(re.escape(p[i + 1])); i += 1
        elif c == "[":
            j = i + 1
            if j < n and p[j] in "!^": j += 1
            if j < n and p[j] == "]": j += 1
            while j < n and p[j] != "]": j += 1
            if j >= n: out.append(re.escape(c))
            else:
                body = p[i + 1:j]
                if body[:1] in ("!", "^"): body = "^" + body[1:]
                out.append("(?!/)[" + body.replace("\\", "\\\\") + "]"); i = j
        else: out.append(re.escape(c))
        i += 1
    return re.compile("(?s)" + "".join(out))


def parse(text):
    rules = []
    for line in text.splitlines():
        s = line
        while s.endswith(" ") and not s.endswith("\\ "): s = s[:-1]
        if not s or s.startswith("#"): continue
        neg = s.startswith("!")
        if neg: s = s[1:]  # a leading backslash (\! or \#) is a literal escape, handled by _translate
        dir_only = s.endswith("/")
        s = s.rstrip("/")
        if not s: continue
        anchored = "/" in s
        if s.startswith("/"): s = s[1:]
        try: rx = _translate(s)
        except re.error: continue  # git ignores a pattern it cannot use; so do we
        rules.append((neg, dir_only, anchored, rx))
    return rules


def _match(rules, rel, is_dir):
    state = None
    base = rel.rsplit("/", 1)[-1]
    for neg, dir_only, anchored, rx in rules:
        if dir_only and not is_dir: continue
        if rx.fullmatch(rel if anchored else base): state = not neg
    return state


def ignored(rel, read, repo_root):
    """True if `rel` (a project-relative file path with '/' separators) is excluded by the project's own ignore rules,
    False if not, UNKNOWN if a rules file could not be read safely. read(path) returns the text of a project-relative
    file, "" if it is absent, or UNKNOWN."""
    parts = rel.split("/")
    sources = []  # (folder depth, rules), lowest priority first
    if repo_root:
        t = read(".git/info/exclude")
        if t is UNKNOWN: return UNKNOWN
        sources.append((0, parse(t)))
    for k in range(len(parts)):
        t = read("/".join(parts[:k] + [".gitignore"]))
        if t is UNKNOWN: return UNKNOWN
        sources.append((k, parse(t)))
    for i in range(len(parts)):
        is_dir = i < len(parts) - 1
        state = None
        for k, rules in sources:
            if k > i: continue
            r = _match(rules, "/".join(parts[k:i + 1]), is_dir)
            if r is not None: state = r
        if state: return True
    return False
