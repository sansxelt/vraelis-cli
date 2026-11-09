"""Exercise the installed CLI, preserving verification and reporting outcomes.

Prepare is offline. Submit explicitly writes three clearly named acceptance reports
using VRAELIS_REPORT_TOKEN; no retries. Output never includes credentials.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

CASES = {"unchanged": (0, "UNCHANGED"), "changed": (1, "CHANGED"), "cant-verify": (2, "CANT_VERIFY")}


def command(*args, env=None):
    return subprocess.run(["vraelis", *args], capture_output=True, text=True,
                          env=env, timeout=45, check=False)


def prepare(root):
    root.mkdir(parents=True, exist_ok=False)
    model = root / "model"
    model.mkdir()
    weights = model / "weights.bin"
    weights.write_bytes(b"acceptance baseline")
    assert command("models", "lock", str(model)).returncode == 0, "Lock failed"
    outcomes = {}
    for name, (code, verdict) in CASES.items():
        if name == "changed":
            weights.write_bytes(b"acceptance changed")
        target = root / "missing-model" if name == "cant-verify" else model
        result = command("models", "verify", str(target), "--json")
        document = json.loads(result.stdout)
        assert result.returncode == code and document["verdict"] == verdict, "Wrong verification outcome"
        (root / (name + ".json")).write_text(result.stdout, encoding="utf-8")
        outcomes[name] = {"exit": result.returncode, "verdict": document["verdict"]}
    (root / "verification.json").write_text(json.dumps(outcomes, indent=2), encoding="utf-8")
    print("Installed CLI: UNCHANGED=0, CHANGED=1, CANT_VERIFY=2 confirmed.")


def submit(root, run_id):
    token = os.environ.get("VRAELIS_REPORT_TOKEN", "")
    if not token:
        raise RuntimeError("VRAELIS_REPORT_TOKEN is missing; real-account acceptance is blocked.")
    outcomes = json.loads((root / "verification.json").read_text(encoding="utf-8"))
    accepted = []
    for name in CASES:
        result = command("report", "--file", str(root / (name + ".json")),
                         "--name", f"cli-acceptance-{run_id}-{name}", "--json")
        if result.returncode != 0:
            raise RuntimeError(f"{name}: account report was not confirmed. No automatic retry; earlier reports may exist.")
        response = json.loads(result.stdout)
        assert response == {"ok": True, "source": "client-reported", "compared": False}
        accepted.append(name)
        print(f"{name}: report accepted; client-reported, not server-compared.")
    # A syntactically valid but deliberately invalid token exercises actual 401 handling.
    environment = dict(os.environ, VRAELIS_REPORT_TOKEN="vrc_" + "0" * 64)
    rejected = command("report", "--file", str(root / "changed.json"),
                       "--name", f"cli-acceptance-{run_id}-rejected", env=environment)
    assert rejected.returncode == 2, "Rejected upload must exit 2"
    assert outcomes["changed"]["exit"] == 1
    assert json.loads((root / "verification.json").read_text(encoding="utf-8")) == outcomes
    (root / "reporting.json").write_text(json.dumps({"accepted": accepted,
        "rejected_upload_exit": 2, "changed_verification_exit": 1}, indent=2), encoding="utf-8")
    print("Rejected upload=2; stored changed verification remains 1.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "submit"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--run-id", default="local")
    args = parser.parse_args()
    if not args.run_id.isascii() or not args.run_id.replace("-", "").isalnum() or len(args.run_id) > 40:
        parser.error("run-id must contain 1–40 ASCII letters, numbers or hyphens")
    try:
        if args.action == "prepare":
            prepare(args.directory)
        else:
            submit(args.directory, args.run_id)
    except Exception as exc:
        # Do not echo subprocess output, bearer tokens or arbitrary transport exceptions.
        print("Acceptance failed: " + (str(exc) if isinstance(exc, (AssertionError, RuntimeError)) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
