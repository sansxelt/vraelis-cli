"""Model Lock core: lock, verify and diff a folder of model files. Standard library only, offline.

Vocabulary (fixed):
  UNCHANGED      every locked file is present with the locked bytes, and no file was added
  CHANGED        at least one locked file differs, is missing, or a new file appeared
  CANT_VERIFY    the check could not be completed (no or invalid lockfile, unreadable file, unsafe path)
Format findings from the bundled checker are reported alongside but never turn CHANGED into UNCHANGED or the reverse.
"""
import hashlib, json, os, re, tempfile

from . import modelcheck  # vendored checker (revision in modelcheck.REVISION; see VENDORED.md)

SCHEMA = "modellock/0"
LOCKFILE = "modellock.json"
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__"}
SIG_SUFFIXES = (".sigstore.json", ".sigstore", ".sig", ".bundle", ".intoto.jsonl")

PROVES = [
    "Whether the files in this folder are byte-identical to the files recorded in the lockfile",
    "Which files changed, went missing or were added since the lock",
    "What the bundled structural checks found (safetensors, GGUF, shard indexes, JSON, LFS pointers)",
]
DOES_NOT_PROVE = [
    "That the model is safe, correct, or behaves as intended",
    "Which model a server or device actually loads or runs",
    "Who published the files: signature files are detected by name but not verified (use model_signing for that)",
    "That files the checker reports UNSUPPORTED are structurally sound",
]


class CantVerify(Exception):
    """Raised for conditions that make a verdict impossible; reported as CANT_VERIFY."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def _safe_rel(rel):
    """Reject absolute paths, drive letters, backslashes, '..' components, the lockfile itself, and any path inside
    an ignored namespace (.git, .hg, .svn, __pycache__), which lock never records (r1, ML-P02)."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel or ":" in rel or rel == LOCKFILE:
        return False
    return all(part not in ("", ".", "..") and part not in SKIP_DIRS for part in rel.split("/"))


def _check_no_symlink_ancestors(root, rel):
    """Refuse if the root or any component of root/rel is a symbolic link (r1, ML-P02). Not a race-free guarantee."""
    path = root
    if os.path.islink(path): raise CantVerify("the model folder itself is a symbolic link")
    for part in rel.split("/"):
        path = os.path.join(path, part)
        if os.path.islink(path): raise CantVerify(f"symbolic link in path: {rel}")


def list_files(root):
    """Sorted relative POSIX paths of regular files under root. Symlinks are refused, not followed."""
    out = []
    if os.path.islink(root): raise CantVerify("the model folder itself is a symbolic link")

    def onerror(err):  # r1, ML-E01: a partial inventory cannot establish "nothing added"
        where = os.path.relpath(err.filename, root) if err.filename else root
        raise CantVerify(f"cannot read folder {where}: {err.strerror or err}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        for d in dirnames:  # r1, ML-P02: every folder, including ignored ones, is checked before pruning
            if os.path.islink(os.path.join(dirpath, d)):
                raise CantVerify(f"symbolic link to a folder is not supported: {os.path.relpath(os.path.join(dirpath, d), root)}")
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if os.path.islink(p): raise CantVerify(f"symbolic link is not supported: {rel}")  # r1: before the lockfile skip (ML-P01)
            if rel == LOCKFILE: continue
            if not os.path.isfile(p): continue
            out.append(rel)
    return sorted(out)


def structural(root, files):
    """Run the bundled checker folder by folder. Returns (findings, notices) with paths relative to root."""
    findings, notices = [], []
    for d in sorted({os.path.dirname(f) for f in files}):
        folder = os.path.join(root, *d.split("/")) if d else root
        rep = modelcheck.check_report(folder, strict_json=True)
        prefix = f"{d}/" if d else ""
        for x in rep["findings"]:
            name = x["file"]
            findings.append({"file": name if name.startswith(("(", folder)) else prefix + name, "state": x["state"], "detail": x["detail"]})
        for n in rep["notices"]:
            notices.append({"file": prefix + n["file"], "detail": n["detail"]})
    key = lambda x: (x["file"], x.get("state", ""), x["detail"])
    return sorted(findings, key=key), sorted(notices, key=key)


# r8 redaction policy for this PUBLIC tool (founder delegated the policy per product): Model Lock records only names,
# sizes and digests, so no value leaves a file. The exception: a digest (or size) of a small secret file can be
# brute-forced, so a file whose name looks like a secrets file is inventoried as present, never digested or measured.
SECRET_FILE = re.compile(r"(^\.env|\.env$|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.kdbx$|^id_(rsa|dsa|ecdsa|ed25519)|^credentials|^secrets?\.|^\.npmrc$|^\.netrc$|^\.pypirc$|^\.pgpass$|^\.git-credentials$)", re.I)
NOT_DIGESTED = {"not_digested": "secrets-file name"}


def _secret_name(rel): return bool(SECRET_FILE.search(rel.rsplit("/", 1)[-1]))


def lock(root, source=None):
    """Build a lockfile dict for root. Deterministic: no timestamps or host paths."""
    if not os.path.isdir(root): raise CantVerify(f"not a folder: {root}")
    files = list_files(root)
    if not files: raise CantVerify("no files to lock")
    entries = {}
    for rel in files:
        p = os.path.join(root, *rel.split("/"))
        if _secret_name(rel): entries[rel] = dict(NOT_DIGESTED); continue  # r8
        try: entries[rel] = {"sha256": sha256_file(p), "size": os.path.getsize(p)}
        except OSError as e: raise CantVerify(f"cannot read {rel}: {e.strerror or e}")  # r2, ML-E03 (OSError only)
    findings, notices = structural(root, files)
    doc = {"schema": SCHEMA, "files": entries, "findings_at_lock": findings, "notices_at_lock": notices,
           "signature_candidates": [f for f in files if f.endswith(SIG_SUFFIXES)],
           "checker": {"modelcheck_revision": modelcheck.REVISION}}
    if source: doc["source"] = source
    return doc


def _inside(path, folder):
    path, folder = os.path.realpath(path), os.path.realpath(folder)
    try: return os.path.commonpath([path, folder]) == folder
    except ValueError: return False  # different drives


def write_lock(root, doc, out=None):
    """Write the lockfile. r1 policy (ML-P01, ML-O01, ML-E02): the default is <root>/modellock.json; --out must be
    outside the model folder; a symlink destination is refused; the write goes to a temporary file in the same folder
    and then replaces the destination, so a failed write leaves any earlier lockfile intact. Not a hostile-filesystem
    race guarantee."""
    default = os.path.join(root, LOCKFILE)
    path = out or default
    if out and os.path.abspath(out) != os.path.abspath(default) and _inside(out, root):
        raise CantVerify("--out must be outside the model folder (or be <folder>/modellock.json)")
    if os.path.islink(path): raise CantVerify(f"lockfile destination is a symbolic link: {path}")
    folder = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp = tempfile.mkstemp(prefix=".modellock-", suffix=".tmp", dir=folder)
    except OSError as e:
        raise CantVerify(f"cannot write lockfile in {folder}: {e.strerror or e}")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        try: os.remove(tmp)
        except OSError: pass
        raise CantVerify(f"cannot write lockfile {path}: {e.strerror or e}")
    return path


def read_lock(path):
    try:
        with open(path, "rb") as f: doc = json.loads(f.read().decode("utf-8"))
    except FileNotFoundError: raise CantVerify(f"no lockfile at {path}")
    except OSError as e: raise CantVerify(f"cannot read lockfile {path}: {e.strerror or e}")
    except (ValueError, UnicodeDecodeError) as e: raise CantVerify(f"lockfile is not valid JSON: {e}")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("files"), dict):
        raise CantVerify(f"lockfile is not a {SCHEMA} document")
    for rel, e in doc["files"].items():
        if not _safe_rel(rel): raise CantVerify(f"unsafe path in lockfile: {rel!r}")
        if e == NOT_DIGESTED: continue  # r8
        if not (isinstance(e, dict) and isinstance(e.get("sha256"), str) and len(e["sha256"]) == 64 and isinstance(e.get("size"), int)):
            raise CantVerify(f"malformed lockfile entry: {rel!r}")
    return doc


def verify(root, lock_path=None):
    """Compare root against its lockfile. Returns a result dict with verdict UNCHANGED / CHANGED / CANT_VERIFY."""
    lock_path = lock_path or os.path.join(root, LOCKFILE)
    try:
        doc = read_lock(lock_path)
        if not os.path.isdir(root): raise CantVerify(f"not a folder: {root}")
        current = list_files(root)
        changes, gaps = [], []
        for rel, e in sorted(doc["files"].items()):
            _check_no_symlink_ancestors(root, rel)  # r1, ML-P02
            p = os.path.join(root, *rel.split("/"))
            if not os.path.isfile(p): changes.append({"file": rel, "change": "missing"}); continue
            if e == NOT_DIGESTED or _secret_name(rel):  # r8: presence only
                if e != NOT_DIGESTED: changes.append({"file": rel, "change": "changed"})
                else: gaps.append(f"{rel}: looks like a secrets file; only its presence is checked, not its content")
                continue
            try: digest, size = sha256_file(p), os.path.getsize(p)
            except OSError as err: raise CantVerify(f"cannot read {rel}: {err}")
            if digest != e["sha256"] or size != e["size"]:
                changes.append({"file": rel, "change": "changed", "locked_sha256": e["sha256"], "current_sha256": digest})
        for rel in current:
            if rel not in doc["files"]: changes.append({"file": rel, "change": "added"})
        findings, notices = structural(root, current)
        verdict = "CHANGED" if changes else "UNCHANGED"
        return {"verdict": verdict, "changes": changes, "coverage_gaps": gaps, "findings": findings, "notices": notices,
                "signature_candidates": [f for f in current if f.endswith(SIG_SUFFIXES)],
                "card": {"proves": PROVES, "does_not_prove": DOES_NOT_PROVE}}
    except CantVerify as e:
        return {"verdict": "CANT_VERIFY", "reason": str(e), "changes": [], "findings": [], "notices": [],
                "card": {"proves": PROVES, "does_not_prove": DOES_NOT_PROVE}}


def diff(lock_a, lock_b):
    """Compare two lockfiles (e.g. the approved release and a new upload under the same name)."""
    a, b = read_lock(lock_a), read_lock(lock_b)
    out = []
    for rel in sorted(set(a["files"]) | set(b["files"])):
        x, y = a["files"].get(rel), b["files"].get(rel)
        if x is None: out.append({"file": rel, "change": "added"})
        elif y is None: out.append({"file": rel, "change": "removed"})
        elif x == NOT_DIGESTED or y == NOT_DIGESTED:
            if x != y: out.append({"file": rel, "change": "changed"})
        elif x["sha256"] != y["sha256"] or x["size"] != y["size"]:
            out.append({"file": rel, "change": "changed", "a_sha256": x["sha256"], "b_sha256": y["sha256"]})
    return {"verdict": "CHANGED" if out else "UNCHANGED", "changes": out}
