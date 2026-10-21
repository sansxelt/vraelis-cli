"""Optional publisher-signature check. A separate, NETWORKED step: it runs the OpenSSF `model_signing` tool, which
fetches Sigstore trust material. `lock`, `verify` and `diff` stay offline and never call this.

The expected signer identity and OIDC issuer must be named by the user. They are never read from the signature
bundle, because the bundle's own claim proves only that someone with that identity signed it, not that it is the
publisher you meant.

r5 (after review ML-R4-01..05): the verifier is run as `<this Python> -I -m model_signing`, never looked up on PATH,
so a model folder (or the current folder) cannot supply its own fake verifier, and no batch file or shell is involved.
Isolated mode (-I) keeps the current folder off the module path.

Results: SIGNED_BY_EXPECTED (exit 0); NOT_VERIFIED (exit 1: the verifier ran and did not accept it: wrong signer,
changed or extra files, bad bundle, or it could not reach Sigstore; its output says which); CANT_VERIFY (exit 2: no
signature file, no signer named, folder missing, model_signing not installed for this Python, the verifier rejected
its own arguments, or it timed out)."""
import os, subprocess, sys

SIG_NAMES = ("model.sig", "model.sigstore.json", "model.sigstore")
TIMEOUT_S = 300

PROVES = ["The verifier accepted the signature over the files it covers, for the signer identity and issuer you named"]
DOES_NOT_PROVE = [
    "That the named identity is the publisher you intend (you chose it; check it against the publisher's own statement)",
    "Anything about files the verifier skips by default: .git/, .github/, .gitattributes, .gitignore",
    "That the model is safe, or which model a device actually runs",
    "Anything offline: this step contacts Sigstore services",
]


def _run(cmd, runner):
    return runner(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_S)


def installed(python=None, runner=subprocess.run):
    """True if model_signing is importable by this Python in isolated mode (the current folder is not consulted)."""
    py = python or sys.executable
    try:
        p = _run([py, "-I", "-c", "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('model_signing') else 3)"], runner)
    except (OSError, subprocess.SubprocessError): return False
    return p.returncode == 0


def check(folder, identity, issuer, signature=None, runner=subprocess.run, python=None, is_installed=None):
    card = {"proves": PROVES, "does_not_prove": DOES_NOT_PROVE}
    def cant(reason): return {"verdict": "CANT_VERIFY", "reason": reason, "card": card}
    if not identity or not issuer: return cant("name the expected signer: --identity and --issuer are required")
    if not os.path.isdir(folder): return cant(f"not a folder: {folder}")
    if signature is None:
        found = [os.path.join(folder, n) for n in SIG_NAMES if os.path.isfile(os.path.join(folder, n))]
        if not found: return cant(f"no signature file ({', '.join(SIG_NAMES)}) in {folder}")
        signature = found[0]
    if not os.path.isfile(signature): return cant(f"signature file not found: {signature}")
    py = python or sys.executable
    if not (is_installed if is_installed is not None else installed(py, runner)):
        return cant("model_signing is not installed for this Python (pip install model-signing)")
    folder_abs = os.path.abspath(folder)
    cmd = [py, "-I", "-m", "model_signing", "verify", "sigstore", folder_abs, "--signature", os.path.abspath(signature),
           "--identity", identity, "--identity_provider", issuer, "--ignore-paths", os.path.abspath(signature)]
    lock = os.path.join(folder_abs, "modellock.json")
    if os.path.exists(lock): cmd += ["--ignore-paths", lock]
    try: p = _run(cmd, runner)
    except subprocess.TimeoutExpired: return cant(f"the verifier did not finish within {TIMEOUT_S} s")
    except (OSError, subprocess.SubprocessError) as e: return cant(f"could not run model_signing: {e}")
    tail = ((p.stdout or "") + (p.stderr or "")).strip()[-800:]
    if p.returncode == 0: return {"verdict": "SIGNED_BY_EXPECTED", "identity": identity, "issuer": issuer, "verifier_output": tail, "card": card}
    if p.returncode == 2:  # click usage error: the verifier rejected its own arguments (version mismatch, odd path)
        r = cant("the verifier rejected its arguments (unsupported model_signing version?)"); r["verifier_output"] = tail; return r
    return {"verdict": "NOT_VERIFIED", "identity": identity, "issuer": issuer, "verifier_exit": p.returncode, "verifier_output": tail, "card": card}
