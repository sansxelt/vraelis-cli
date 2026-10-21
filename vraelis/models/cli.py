"""Command line: modellock lock | verify | diff. Exit codes: 0 unchanged, 1 changed, 2 can't verify, 3 lock refused."""
import argparse, json, sys

from . import core, signature

EXIT = {"UNCHANGED": 0, "CHANGED": 1, "CANT_VERIFY": 2}
LABEL = {"UNCHANGED": "Unchanged", "CHANGED": "Changed", "CANT_VERIFY": "Can't verify"}


def _print_card(card):
    print("\nThis result shows:")
    for x in card["proves"]: print(f"  - {x}")
    print("It does not show:")
    for x in card["does_not_prove"]: print(f"  - {x}")


def _print_not_checked(gaps):
    """r9 (Codex ML-PUB-01): files compared for presence only are listed in normal output, not only in --json."""
    if gaps:
        print("\nNot checked (presence only):")
        for g in gaps: print(f"  {g}")


def _print_findings(res):
    if res.get("findings"):
        print("\nFormat findings:")
        for x in res["findings"]: print(f"  {x['state']:<11} {x['file']}: {x['detail']}")
    if res.get("notices"):
        print("\nRisk notices (not defects):")
        for x in res["notices"]: print(f"  {x['file']}: {x['detail']}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vraelis models", description="Pin and verify local model files (offline).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lock", help="record the exact bytes of every file in a model folder")
    p.add_argument("folder"); p.add_argument("--source", help="free-text note, e.g. repo@revision")
    p.add_argument("--out", help="write the lockfile here instead of <folder>/modellock.json (leaves the folder untouched)")
    p.add_argument("--strict", action="store_true", help="refuse to lock if the checker reports PROBLEM or ERROR")
    p.add_argument("--json", action="store_true")
    v = sub.add_parser("verify", help="compare a model folder with its lockfile")
    v.add_argument("folder"); v.add_argument("--lockfile"); v.add_argument("--json", action="store_true")
    g = sub.add_parser("signature", help="NETWORKED, optional: check the publisher's Sigstore signature with model_signing")
    g.add_argument("folder"); g.add_argument("--identity", required=True, help="expected signer identity (e.g. an email or workflow URL)")
    g.add_argument("--issuer", required=True, help="expected OIDC issuer URL"); g.add_argument("--signature", help="signature file (default: model.sig in the folder)")
    g.add_argument("--json", action="store_true")
    d = sub.add_parser("diff", help="compare two lockfiles")
    d.add_argument("lock_a"); d.add_argument("lock_b"); d.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "lock":
        try: doc = core.lock(a.folder, source=a.source)
        except core.CantVerify as e:
            if a.json: print(json.dumps({"locked": False, "reason": str(e)}, indent=1))
            else: print(f"Can't lock: {e}", file=sys.stderr)
            return 2
        bad = [x for x in doc["findings_at_lock"] if x["state"] in ("PROBLEM", "ERROR")]
        if a.strict and bad:
            if a.json: print(json.dumps({"locked": False, "findings": bad}, indent=1))
            else:
                print("Lock refused (--strict): the checker reported problems:")
                for x in bad: print(f"  {x['state']:<11} {x['file']}: {x['detail']}")
            return 3
        try: path = core.write_lock(a.folder, doc, a.out)
        except core.CantVerify as e:  # r1, ML-E02: structured refusal, exit 2
            if a.json: print(json.dumps({"locked": False, "reason": str(e)}, indent=1))
            else: print(f"Can't lock: {e}", file=sys.stderr)
            return 2
        if a.json: print(json.dumps({"locked": True, "lockfile": path, "files": len(doc["files"]), "findings": doc["findings_at_lock"]}, indent=1))
        else:
            print(f"Locked {len(doc['files'])} files -> {path}")
            _print_not_checked([f"{rel}: looks like a secrets file; recorded as present only, never digested" for rel, e in sorted(doc["files"].items()) if e == core.NOT_DIGESTED])
            _print_findings({"findings": doc["findings_at_lock"], "notices": doc["notices_at_lock"]})
            if doc["signature_candidates"]:
                print(f"\nSignature files present (not verified): {', '.join(doc['signature_candidates'])}")
        return 0

    if a.cmd == "verify":
        res = core.verify(a.folder, a.lockfile)
        if a.json: print(json.dumps(res, indent=1, sort_keys=True))
        else:
            print(LABEL[res["verdict"]])
            if res["verdict"] == "CANT_VERIFY": print(f"  {res['reason']}")
            for c in res["changes"]: print(f"  {c['change']:<8} {c['file']}")
            _print_not_checked(res.get("coverage_gaps", []))
            _print_findings(res)
            _print_card(res["card"])
        return EXIT[res["verdict"]]

    if a.cmd == "signature":
        res = signature.check(a.folder, a.identity, a.issuer, a.signature)
        if a.json: print(json.dumps(res, indent=1, sort_keys=True))
        else:
            print({"SIGNED_BY_EXPECTED": "Signed by the expected signer", "NOT_VERIFIED": "Not verified", "CANT_VERIFY": "Can't verify"}[res["verdict"]])
            if res.get("reason"): print(f"  {res['reason']}")
            if res.get("verifier_output") and res["verdict"] != "SIGNED_BY_EXPECTED": print(f"  verifier: {res['verifier_output']}")
            _print_card(res["card"])
        return {"SIGNED_BY_EXPECTED": 0, "NOT_VERIFIED": 1, "CANT_VERIFY": 2}[res["verdict"]]

    try: res = core.diff(a.lock_a, a.lock_b)
    except core.CantVerify as e:
        print(f"Can't verify: {e}", file=sys.stderr); return 2
    if a.json: print(json.dumps(res, indent=1, sort_keys=True))
    else:
        print(LABEL[res["verdict"]])
        for c in res["changes"]: print(f"  {c['change']:<8} {c['file']}")
        _print_not_checked(res.get("coverage_gaps", []))
    return EXIT[res["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
