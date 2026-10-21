"""Safe path resolution inside the project (r3, after adversarial review 1: P1 UNC paths, P2 linked parent folders
and Windows junctions; r4, after review 2: H2 mixed-separator UNC paths, L3 `..` after a link, NUL bytes).

Rules:
- A path string that names a network or device location is never passed to the filesystem. It is judged after
  normalising separators and after os.path.abspath (pure string work), so `/\\host\\share` and `\\/host/share` count.
- A path is resolved component by component from the project root, in order: a link or junction is read as link
  text (os.readlink) and followed only while it stays inside the root; `..` steps back from the RESOLVED location (as
  the operating system does), not lexically. Each component is checked to lie inside the root before it is lstat-ed.
  Nothing outside the root is ever opened, stat-ed or listed.
- This is a precheck, not a sandbox: a filesystem changed by another process during the run can still race it.
"""
import os, re, stat

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
MAX_HOPS = 40
WINDOWS = os.name == "nt"


class Outside(Exception):
    """The path leaves the project, names a network/device location, or cannot be resolved safely."""


def _prefix_network(s, windows=WINDOWS):
    """Layer 1: a UNC or device prefix, after normalising '/' to '\\' on Windows (so /\\host and \\/host count)."""
    t = s.replace("/", "\\") if windows else s
    return t.startswith("\\\\") or s.startswith("//") or t.startswith("\\??\\")


def _abspath_network(s):
    """Layer 2 (Windows): what the OS itself would make of the string (os.path.abspath is pure string work)."""
    try: a = os.path.abspath(s)
    except (ValueError, OSError): return True
    return a.startswith("\\\\") or os.path.splitdrive(a)[0].startswith("\\\\")


def network_like(s):
    """Network or device location (or a NUL byte): never handed to the filesystem. Two independent layers on
    Windows, each tested on its own."""
    s = str(s)
    if "\0" in s: return True  # refuse outright; never handed to the OS
    if _prefix_network(s): return True
    return WINDOWS and _abspath_network(s)


def _norm(p): return os.path.normcase(os.path.abspath(p))


def lexically_inside(path, root):
    if network_like(path): return False
    path, root = _norm(path), _norm(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def is_link(p):
    """Symbolic link or Windows junction (any reparse point that os.readlink can read)."""
    try: st = os.lstat(p)
    except (OSError, ValueError): return False
    if stat.S_ISLNK(st.st_mode): return True
    if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        try: os.readlink(p); return True
        except (OSError, ValueError): return False
    return False


def read_link(p):
    t = os.readlink(p)
    if t.startswith("\\\\?\\UNC\\"): raise Outside(f"link to a network location: {t}")
    if t.startswith("\\\\?\\"): t = t[4:]
    if network_like(t): raise Outside(f"link to a network location: {t}")
    return t


def _components(path, root):
    """Raw components of path relative to root, WITHOUT collapsing '..' (so it can be applied after links)."""
    if os.path.isabs(path):
        a, r = os.path.normcase(path), os.path.normcase(os.path.abspath(root))
        if not (a == r or a.startswith(r.rstrip(os.sep) + os.sep)):
            raise Outside(f"outside the project: {path}")
        path = path[len(os.path.abspath(root).rstrip(os.sep)) + 1:] if a != r else ""
    parts = [c for c in re.split(r"[\\/]+" if WINDOWS else r"/+", path) if c not in ("", ".")]
    if WINDOWS and any(":" in c for c in parts): raise Outside("stream or device syntax is not read")  # r5 (review 3, L3); no path echoed
    return parts


def resolve(root, path, links=None):
    """Resolve path (absolute, or relative to root) to a real path inside root without touching anything outside it.
    links, if given, collects (logical path, link text) for every link crossed. Raises Outside."""
    if network_like(path): raise Outside(f"network or device path: {path}")
    root = os.path.abspath(root)
    parts, cur, hops = _components(path, root), root, 0
    while parts:
        c = parts.pop(0)
        if c == "..":
            cur = os.path.dirname(cur)
            if not lexically_inside(cur, root): raise Outside(f"outside the project: {path}")
            continue
        nxt = os.path.join(cur, c)
        if not lexically_inside(nxt, root): raise Outside(f"outside the project: {path}")
        if is_link(nxt):
            hops += 1
            if hops > MAX_HOPS: raise Outside(f"too many links: {path}")
            text = read_link(nxt)
            if links is not None: links.append((os.path.relpath(nxt, root).replace(os.sep, "/"), text.replace(os.sep, "/")))
            if os.path.isabs(text):
                if not lexically_inside(text, root): raise Outside(f"link leaves the project: {os.path.relpath(nxt, root)} -> {text}")
                parts = _components(text, root) + parts; cur = root
            else:
                target = os.path.abspath(os.path.join(cur, text))
                if not lexically_inside(target, root): raise Outside(f"link leaves the project: {os.path.relpath(nxt, root)} -> {text}")
                parts = _components(text, root) + parts  # relative to cur, applied component by component
            continue
        cur = nxt
    return cur
