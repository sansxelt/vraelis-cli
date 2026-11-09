"""Read-only sequential verification for explicitly selected model folders."""
import json

from . import core

EXIT = {"UNCHANGED": 0, "CHANGED": 1, "CANT_VERIFY": 2}
MAX_FOLDERS = 256


def verify_many(folders):
    if not 1 <= len(folders) <= MAX_FOLDERS:
        raise ValueError("Choose between 1 and 256 model folders.")
    counts = {verdict: 0 for verdict in EXIT}
    items = []
    for folder in folders:
        try:
            result = core.verify(folder)
        except Exception:
            # One inaccessible/corrupt folder must not conceal results for others.
            # Do not echo unexpected exception text (which can contain local secrets).
            result = {"verdict": "CANT_VERIFY", "changes": [],
                      "reason": "An internal verification error prevented this folder from being checked.",
                      "coverage_gaps": [], "findings": [], "notices": [],
                      "card": {"proves": core.PROVES, "does_not_prove": core.DOES_NOT_PROVE}}
        counts[result["verdict"]] += 1
        items.append({"folder": folder, "result": result})
    verdict = "CANT_VERIFY" if counts["CANT_VERIFY"] else "CHANGED" if counts["CHANGED"] else "UNCHANGED"
    return {"schema": "vraelis.model-batch.v1", "verdict": verdict,
            "summary": {"total": len(items), **counts}, "results": items}


def display(document):
    for item in document["results"]:
        result = item["result"]
        print(f"{result['verdict']}: {json.dumps(item['folder'], ensure_ascii=True)}")
        if result.get("reason"):
            print("  Reason: " + json.dumps(result["reason"], ensure_ascii=True))
        for change in result["changes"]:
            print(f"  {change['change']}: {json.dumps(change['file'], ensure_ascii=True)}")
        for gap in result.get("coverage_gaps", []):
            print("  Not checked: " + json.dumps(gap, ensure_ascii=True))
        for finding in result.get("findings", []):
            print("  Format finding: " + json.dumps(finding, ensure_ascii=True))
        for notice in result.get("notices", []):
            print("  Notice: " + json.dumps(notice, ensure_ascii=True))
    summary = document["summary"]
    print(f"\n{summary['total']} folders: {summary['UNCHANGED']} unchanged, {summary['CHANGED']} changed, {summary['CANT_VERIFY']} could not be verified.")
    print("These results compare local files with each folder's lockfile; they are not a security assessment or signature verification.")
