"""Shared serialization inspection for .bin/.pt/.pth/.ckpt files. Standard library only.
Never unpickles, never loads, never executes. It looks only at a raw pickle protocol prefix or at ZIP member names,
so a positive result is a cautious heuristic: it does not prove valid pickle contents, executable behaviour or
malice, and a negative result does not prove the file is safe (protocol 0/1 pickles have no prefix)."""
import io, zipfile

VERSION = "serialization-1.1"

def inspect(data):
    """Return {"kind", "risk", "detail"} for the bytes of one file."""
    if len(data) >= 2 and data[0] == 0x80 and 2 <= data[1] <= 5:
        return {"kind": "pickle-protocol-prefix", "risk": True,
                "detail": f"recognized pickle protocol prefix (protocol {data[1]}): potential executable serialization; not loaded or validated"}
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z: names = z.namelist()
        except (zipfile.BadZipFile, ValueError, EOFError):
            return {"kind": "zip-unreadable", "risk": False, "detail": "starts like a ZIP archive but is not a readable ZIP"}
        pkl = sorted(n for n in names if n.endswith(".pkl"))
        if pkl:
            return {"kind": "zip-pickle-named-member", "risk": True,
                    "detail": f"ZIP archive with pickle-named member(s) {', '.join(pkl[:3])}: potential executable serialization; not loaded or validated"}
        return {"kind": "zip-no-pickle-named-member", "risk": False,
                "detail": "ZIP archive with no pickle-named member; weights format not recognised by this check"}
    return {"kind": "unrecognised", "risk": False, "detail": "weights format not recognised by this check"}


def inspect_zipfile(fileobj):
    """ZIP branch of inspect() for a seekable file object (serialization-1 logic, no full read). Caller has checked
    that the file starts with b"PK"."""
    try:
        with zipfile.ZipFile(fileobj) as z: names = z.namelist()
    except (zipfile.BadZipFile, ValueError, EOFError):
        return {"kind": "zip-unreadable", "risk": False, "detail": "starts like a ZIP archive but is not a readable ZIP"}
    pkl = sorted(n for n in names if n.endswith(".pkl"))
    if pkl:
        return {"kind": "zip-pickle-named-member", "risk": True,
                "detail": f"ZIP archive with pickle-named member(s) {', '.join(pkl[:3])}: potential executable serialization; not loaded or validated"}
    return {"kind": "zip-no-pickle-named-member", "risk": False,
            "detail": "ZIP archive with no pickle-named member; weights format not recognised by this check"}
