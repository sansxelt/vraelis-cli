"""Explicit, minimized upload of model verification results. Never used by verify."""
import argparse
import json
import os
import re
import queue
import threading
import sys
import urllib.request

ENDPOINT = "https://data.vraelis.com/api/prompto/report"
MAX_INPUT = 4 * 1024 * 1024
MAX_RESPONSE = 64 * 1024


def clean_text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def payload(document, name):
    if not clean_text(name, 120) or name != name.strip():
        raise ValueError("Name must be 1–120 characters without surrounding whitespace or controls.")
    if not isinstance(document, dict):
        raise ValueError("Expected a model verify JSON object.")
    verdict, changes = document.get("verdict"), document.get("changes")
    if verdict not in ("UNCHANGED", "CHANGED", "CANT_VERIFY") or not isinstance(changes, list):
        raise ValueError("Expected a model verify verdict and changes list.")
    if (verdict == "CHANGED") != bool(changes):
        raise ValueError("Verdict and changes disagree.")
    if len(changes) > 10000:
        raise ValueError("Too many changes.")
    projected, seen = [], set()
    for change in changes:
        if not isinstance(change, dict):
            raise ValueError("Unsupported change entry; only model verify results are supported.")
        path, kind = change.get("file"), change.get("change")
        if (not clean_text(path, 4096) or "\\" in path or ":" in path
                or any(p in ("", ".", "..") for p in path.split("/"))):
            raise ValueError("Changes must contain safe relative file paths.")
        if kind not in ("added", "missing", "changed") or path in seen:
            raise ValueError("Unsupported or duplicate model change.")
        seen.add(path)
        projected.append({"file": path, "change": kind})
    return {"name": name, "result": {"verdict": verdict, "changes": projected}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _send(body, token):
    request = urllib.request.Request(ENDPOINT, data=body, method="POST", headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "vraelis-cli-report"})
    # Explicitly disable ambient proxies: this credential has one fixed destination.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError("Report was not accepted.")
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("Report response exceeded the size limit.")
    result = json.loads(raw)
    if not isinstance(result, dict) or result.get("ok") is not True or result.get("compared") is not False:
        raise ValueError("Unexpected report response.")
    return result


def send(body, token):
    """Bound the CLI wait, including DNS and slow responses, to 30 seconds."""
    completed = queue.Queue(maxsize=1)

    def attempt():
        try:
            completed.put((True, _send(body, token)))
        except Exception:
            completed.put((False, None))

    threading.Thread(target=attempt, daemon=True).start()
    try:
        ok, result = completed.get(timeout=30)
    except queue.Empty:
        raise ValueError("Reporting deadline exceeded.") from None
    if not ok:
        raise ValueError("Report request failed.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Submit model verify JSON (explicit network operation). Relative filenames leave this machine.")
    parser.add_argument("--file", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        token = os.environ.get("VRAELIS_REPORT_TOKEN", "")
        if not re.fullmatch(r"vrc_[A-Za-z0-9_-]{16,256}", token):
            raise ValueError("Set VRAELIS_REPORT_TOKEN to an account report token.")
        with open(args.file, "rb") as source:
            raw = source.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("Result file exceeds 4 MiB.")
        body = json.dumps(payload(json.loads(raw), args.name), ensure_ascii=True).encode("utf-8")
        if len(body) > MAX_INPUT:
            raise ValueError("Report exceeds 4 MiB.")
        send(body, token)
    except (OSError, ValueError, RecursionError):
        # Neither server bodies, filenames, exception strings nor credentials are logged.
        print("Report not submitted: check the result file, report token, plan and network. Verification results are unchanged.", file=sys.stderr)
        return 2
    result = {"ok": True, "source": "client-reported", "compared": False}
    print(json.dumps(result) if args.json else "Report accepted (client-reported; not server-compared).")
    return 0
