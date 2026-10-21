"""Command line: addonlock lock | verify | diff. Exit codes: 0 unchanged, 1 changed, 2 can't verify, 3 lock refused."""
import argparse, json, sys

from . import core
from .redact import scrub

EXIT = {"UNCHANGED": 0, "CHANGED": 1, "CANT_VERIFY": 2}
LABEL = {"UNCHANGED": "Unchanged", "CHANGED": "Changed", "CANT_VERIFY": "Can't verify"}


import re as _re
_UNSAFE = _re.compile("[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _s(x):
    """r5 (review 3, M4): escape control, C1 and bidi characters in any text taken from config, the filesystem or a
    lockfile, so a name cannot move the cursor, clear lines or reorder what the terminal shows."""
    return _UNSAFE.sub(lambda m: "\\x%02x" % ord(m.group(0)) if ord(m.group(0)) < 0x100 else "\\u%04x" % ord(m.group(0)), str(x))


def _short(v):
    s = json.dumps(v, sort_keys=True)
    return s if len(s) <= 120 else s[:117] + "..."


def _print_change(c):
    line = f"  {_s(c['kind']):<26} {_s(c['where'])}"
    if "name" in c: line += f" [{_s(c['name'])}]"
    print(line)
    if c["kind"].endswith("-changed") and not c["kind"].endswith("file-changed") and ("before" in c or "after" in c):
        print(f"      before: {_short(c.get('before'))}\n      after:  {_short(c.get('after'))}")


def _print_lists(res):
    if res.get("notices"):
        print("\nNotices (not changes):")
        for n in res["notices"]: print(f"  - {_s(n)}")
    if res.get("coverage_gaps"):
        print("\nNot covered (changes here cannot be detected):")
        for g in res["coverage_gaps"]: print(f"  - {_s(g)}")


def _safe_streams():
    """r4 (review 2, M9): never crash on text the console encoding cannot show (a Windows pipe is often cp1252)."""
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError): pass


def _pins(sp):
    sp.add_argument("--config", action="append", default=[], help="extra MCP config file (repeatable)")
    sp.add_argument("--pin-env", action="append", default=[], metavar="NAME", help="also record this env variable's value, in plain text (repeatable)")
    sp.add_argument("--pin-header", action="append", default=[], metavar="NAME", help="also record this header's value, in plain text (repeatable)")


def main(argv=None):
    _safe_streams()
    ap = argparse.ArgumentParser(prog="vraelis agents", description="Pin and verify an AI agent's add-on configuration (offline; never launches servers).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lock", help="record MCP server configuration, instruction files and launched local files")
    p.add_argument("folder"); _pins(p)
    p.add_argument("--source", help="free-text note"); p.add_argument("--out", help="write the lockfile here instead of <folder>/addonlock.json")
    p.add_argument("--strict", action="store_true", help="refuse to lock if any package is unpinned or floating")
    p.add_argument("--json", action="store_true")
    v = sub.add_parser("verify", help="compare the current configuration with the lockfile")
    v.add_argument("folder"); v.add_argument("--lockfile"); v.add_argument("--json", action="store_true"); _pins(v)
    d = sub.add_parser("diff", help="compare two lockfiles")
    d.add_argument("lock_a"); d.add_argument("lock_b"); d.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    def refuse(reason, code=2, extra=None):
        reason = scrub(str(reason), [], "reason")
        if a.json: print(json.dumps({"locked": False, "reason": reason, **(extra or {})}, indent=1))
        else: print(f"Can't lock: {_s(reason)}", file=sys.stderr)
        return code

    if a.cmd == "lock":
        try: doc = core.lock(a.folder, a.config, a.pin_env, a.source, a.pin_header)
        except core.CantVerify as e: return refuse(str(e))
        loose = [x for c in doc["configs"].values() for s in c.values() for x in s.get("packages", []) if x["status"] != "pinned"]
        if a.strict and loose: return refuse("unpinned or floating packages (--strict)", 3, {"packages": loose})
        try: path = core.write_lock(a.folder, doc, a.out)
        except core.CantVerify as e: return refuse(str(e))
        n_srv = sum(len(c) for c in doc["configs"].values())
        if a.json:
            print(json.dumps({"locked": True, "lockfile": path, "servers": n_srv, "instruction_files": len(doc["instruction_files"]),
                              "launched_files": len(doc["launched_files"]), "notices": doc["notices"], "coverage_gaps": doc["coverage_gaps"]}, indent=1))
        else:
            print(f"Locked {n_srv} servers in {len(doc['configs'])} config files, {len(doc['instruction_files'])} instruction files, "
                  f"{len(doc['launched_files'])} launched local files -> {_s(path)}")
            _print_lists(doc)
        return 0

    if a.cmd == "verify":
        res = core.verify(a.folder, a.lockfile, a.config, a.pin_env, a.pin_header)
        if a.json: print(json.dumps(res, indent=1, sort_keys=True))
        else:
            print(LABEL[res["verdict"]])
            if res["verdict"] == "CANT_VERIFY": print(f"  {_s(res['reason'])}")
            for c in res["changes"]: _print_change(c)
            _print_lists(res)
            print("\nThis result shows:"); [print(f"  - {x}") for x in res["card"]["proves"]]
            print("It does not show:"); [print(f"  - {x}") for x in res["card"]["does_not_prove"]]
        return EXIT[res["verdict"]]

    try: res = core.diff(a.lock_a, a.lock_b)
    except core.CantVerify as e:
        print(f"Can't verify: {scrub(str(e), [], 'reason')}", file=sys.stderr); return 2
    if a.json: print(json.dumps(res, indent=1, sort_keys=True))
    else:
        print(LABEL[res["verdict"]])
        for c in res["changes"]: _print_change(c)
    return EXIT[res["verdict"]]


def run(argv=None):
    """Entry point: any unexpected error exits 2 (Can't verify), never 1 (Changed) (r3, R1)."""
    try: return main(argv)
    except SystemExit: raise
    except BaseException as e:  # noqa: BLE001 - the exit code must never claim a verdict after a crash
        if isinstance(e, KeyboardInterrupt): raise
        print(f"Can't verify: internal error: {type(e).__name__}", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(run())
