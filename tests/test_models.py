"""Model Lock prototype tests. Run: python -m unittest discover -s tests (from the modellock folder)."""
import io, json, os, pickle, shutil, struct, sys, tempfile, unittest, zipfile
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis.models import core, cli  # noqa: E402


def safetensors(n=2):
    h = json.dumps({"w": {"dtype": "F16", "shape": [n], "data_offsets": [0, 2 * n]}}).encode()
    return struct.pack("<Q", len(h)) + h + b"\0" * (2 * n)


def gguf_header_only():
    # GGUF v3, 0 tensors, 0 metadata entries: a minimal valid header.
    return b"GGUF" + struct.pack("<IQQ", 3, 0, 0)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err): code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.m = os.path.join(self.tmp, "model"); os.makedirs(os.path.join(self.m, "sub"))
        self.write("model.safetensors", safetensors()); self.write("config.json", b'{"a": 1}')
        self.write("sub/tokenizer_config.json", b'{"chat_template": "x"}'); self.write("model.gguf", gguf_header_only())
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)
    def write(self, rel, data):
        p = os.path.join(self.m, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f: f.write(data)


class Verdicts(Base):
    def test_unchanged(self):
        self.assertEqual(run("lock", self.m)[0], 0)
        code, out, _ = run("verify", self.m)
        self.assertEqual(code, 0); self.assertTrue(out.startswith("Unchanged"))

    def test_byte_change_same_size(self):
        run("lock", self.m); self.write("config.json", b'{"a": 2}')
        code, out, _ = run("verify", self.m)
        self.assertEqual(code, 1); self.assertIn("changed  config.json", out)

    def test_missing_and_added(self):
        run("lock", self.m); os.remove(os.path.join(self.m, "model.gguf")); self.write("extra.bin", b"x")
        res = core.verify(self.m)
        self.assertEqual(res["verdict"], "CHANGED")
        self.assertEqual({(c["file"], c["change"]) for c in res["changes"]}, {("model.gguf", "missing"), ("extra.bin", "added")})

    def test_nested_file_change(self):
        run("lock", self.m); self.write("sub/tokenizer_config.json", b'{"chat_template": "y"}')
        self.assertEqual(core.verify(self.m)["changes"][0]["file"], "sub/tokenizer_config.json")

    def test_lockfile_itself_and_git_ignored(self):
        os.makedirs(os.path.join(self.m, ".git")); self.write(".git/HEAD", b"ref")
        run("lock", self.m)
        doc = json.load(open(os.path.join(self.m, core.LOCKFILE)))
        self.assertNotIn(core.LOCKFILE, doc["files"]); self.assertFalse(any(f.startswith(".git/") for f in doc["files"]))
        self.write(".git/HEAD", b"changed")
        self.assertEqual(core.verify(self.m)["verdict"], "UNCHANGED")


class CantVerify(Base):
    def test_no_lockfile(self):
        code, out, _ = run("verify", self.m)
        self.assertEqual(code, 2); self.assertIn("Can't verify", out)

    def test_corrupt_lockfile(self):
        open(os.path.join(self.m, core.LOCKFILE), "w").write("{not json")
        self.assertEqual(core.verify(self.m)["verdict"], "CANT_VERIFY")

    def test_wrong_schema(self):
        open(os.path.join(self.m, core.LOCKFILE), "w").write(json.dumps({"schema": "other", "files": {}}))
        self.assertEqual(core.verify(self.m)["verdict"], "CANT_VERIFY")

    def test_unsafe_paths_rejected(self):
        for bad in ("../outside.txt", "/etc/passwd", "C:/x", "a\\b", "a/../b", "./a"):
            open(os.path.join(self.m, core.LOCKFILE), "w").write(json.dumps(
                {"schema": core.SCHEMA, "files": {bad: {"sha256": "0" * 64, "size": 1}}}))
            res = core.verify(self.m)
            self.assertEqual(res["verdict"], "CANT_VERIFY", bad); self.assertIn("unsafe path", res["reason"])

    def test_malformed_entry(self):
        open(os.path.join(self.m, core.LOCKFILE), "w").write(json.dumps({"schema": core.SCHEMA, "files": {"a": {"sha256": "x"}}}))
        self.assertEqual(core.verify(self.m)["verdict"], "CANT_VERIFY")

    @unittest.skipIf(os.name == "nt" and not hasattr(os, "symlink"), "no symlink support")
    def test_symlink_refused(self):
        try: os.symlink(os.path.join(self.m, "config.json"), os.path.join(self.m, "link.json"))
        except (OSError, NotImplementedError): self.skipTest("symlinks not permitted here")
        self.assertEqual(run("lock", self.m)[0], 2)

    def test_empty_folder(self):
        e = os.path.join(self.tmp, "empty"); os.makedirs(e)
        self.assertEqual(run("lock", e)[0], 2)


class Lockfile(Base):
    def test_deterministic(self):
        run("lock", self.m); a = open(os.path.join(self.m, core.LOCKFILE), "rb").read()
        run("lock", self.m); b = open(os.path.join(self.m, core.LOCKFILE), "rb").read()
        self.assertEqual(a, b)

    def test_strict_refuses_problem(self):
        self.write("bad.json", b'{"a": 1,}')
        code, out, _ = run("lock", self.m, "--strict")
        self.assertEqual(code, 3); self.assertIn("invalid JSON", out)
        self.assertFalse(os.path.exists(os.path.join(self.m, core.LOCKFILE)))

    def test_non_strict_records_findings(self):
        self.write("weights.safetensors", b"version https://git-lfs.github.com/spec/v1\noid sha256:x\n")
        run("lock", self.m)
        doc = json.load(open(os.path.join(self.m, core.LOCKFILE)))
        self.assertTrue(any("Git LFS pointer" in x["detail"] for x in doc["findings_at_lock"]))

    def test_serialization_notice_not_defect(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z: z.writestr("archive/data.pkl", pickle.dumps({"x": 1}))
        self.write("pytorch_model.bin", b.getvalue())
        code, _, _ = run("lock", self.m, "--strict")
        self.assertEqual(code, 0, "a risk notice must not block a strict lock")
        doc = json.load(open(os.path.join(self.m, core.LOCKFILE)))
        self.assertEqual([n["file"] for n in doc["notices_at_lock"]], ["pytorch_model.bin"])

    def test_signature_candidate_reported(self):
        self.write("model.sig", b'{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}')
        run("lock", self.m)
        self.assertEqual(json.load(open(os.path.join(self.m, core.LOCKFILE)))["signature_candidates"], ["model.sig"])

    def test_nested_finding_path(self):
        self.write("sub/broken.json", b"{")
        run("lock", self.m)
        files = [x["file"] for x in json.load(open(os.path.join(self.m, core.LOCKFILE)))["findings_at_lock"]]
        self.assertIn("sub/broken.json", files)


class OutOption(Base):
    def test_out_leaves_folder_untouched(self):
        before = sorted(os.listdir(self.m)); out = os.path.join(self.tmp, "elsewhere.json")
        self.assertEqual(run("lock", self.m, "--out", out)[0], 0)
        self.assertEqual(sorted(os.listdir(self.m)), before)
        self.assertEqual(run("verify", self.m, "--lockfile", out)[0], 0)


def can_symlink():
    d = tempfile.mkdtemp()
    try: os.symlink(d, os.path.join(d, "probe")); return True
    except (OSError, NotImplementedError): return False
    finally: shutil.rmtree(d, ignore_errors=True)


SYMLINKS = can_symlink()


class R1Regressions(Base):
    """Codex review 41de6b4 findings ML-P01, ML-P02, ML-E01, ML-O01, ML-E02."""

    def outside(self, name, data=b"sentinel"):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f: f.write(data)
        return p

    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_p01_lockfile_symlink_refused_and_target_untouched(self):
        target = self.outside("target.json", b'{"keep": true}')
        os.symlink(target, os.path.join(self.m, core.LOCKFILE))
        code, out, _ = run("lock", self.m, "--json")
        self.assertEqual(code, 2); self.assertFalse(json.loads(out)["locked"])
        with open(target, "rb") as f: self.assertEqual(f.read(), b'{"keep": true}')

    def test_p02_lockfile_entries_in_ignored_namespaces_rejected(self):
        for bad in (".git/payload.bin", "sub/.git/x", "__pycache__/a.pyc", core.LOCKFILE):
            with open(os.path.join(self.m, core.LOCKFILE), "w") as f:
                f.write(json.dumps({"schema": core.SCHEMA, "files": {bad: {"sha256": "0" * 64, "size": 1}}}))
            res = core.verify(self.m)
            self.assertEqual(res["verdict"], "CANT_VERIFY", bad); self.assertIn("unsafe path", res["reason"])

    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_p02_symlinked_ignored_folder_refused(self):
        ext = os.path.join(self.tmp, "ext"); os.makedirs(ext)
        os.symlink(ext, os.path.join(self.m, ".git"))
        self.assertEqual(run("lock", self.m)[0], 2)

    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_p02_symlinked_ancestor_of_locked_entry_refused(self):
        run("lock", self.m)
        ext = os.path.join(self.tmp, "ext"); os.makedirs(ext)
        shutil.copy(os.path.join(self.m, "sub", "tokenizer_config.json"), ext)
        shutil.rmtree(os.path.join(self.m, "sub")); os.symlink(ext, os.path.join(self.m, "sub"))
        res = core.verify(self.m)
        self.assertEqual(res["verdict"], "CANT_VERIFY"); self.assertIn("symbolic link", res["reason"])

    def _scandir_fails_for(self, fragment):
        real = os.scandir
        def fake(path="."):
            if fragment in str(path): raise PermissionError(13, "Permission denied", str(path))
            return real(path)
        return fake

    def test_e01_unreadable_nested_folder_is_cant_verify(self):
        run("lock", self.m)
        self.write("unreadable/new.bin", b"x")
        orig = os.scandir; os.scandir = self._scandir_fails_for("unreadable")
        try: res = core.verify(self.m)
        finally: os.scandir = orig
        self.assertEqual(res["verdict"], "CANT_VERIFY"); self.assertIn("cannot read folder", res["reason"])

    def test_e01_unreadable_root_is_cant_verify(self):
        run("lock", self.m)
        orig = os.scandir; os.scandir = self._scandir_fails_for(os.path.basename(self.m))
        try: res = core.verify(self.m)
        finally: os.scandir = orig
        self.assertEqual(res["verdict"], "CANT_VERIFY")

    def test_o01_out_inside_model_folder_refused(self):
        with open(os.path.join(self.m, "config.json"), "rb") as f: before = f.read()
        for name in ("approved.json", "config.json", "sub/lock.json"):
            code, out, _ = run("lock", self.m, "--out", os.path.join(self.m, *name.split("/")), "--json")
            self.assertEqual(code, 2, name); self.assertIn("outside the model folder", json.loads(out)["reason"])
        with open(os.path.join(self.m, "config.json"), "rb") as f: self.assertEqual(f.read(), before)

    def test_o01_out_equal_to_default_allowed(self):
        self.assertEqual(run("lock", self.m, "--out", os.path.join(self.m, core.LOCKFILE))[0], 0)
        self.assertEqual(core.verify(self.m)["verdict"], "UNCHANGED")

    def test_o01_relative_out_inside_refused(self):
        cwd = os.getcwd(); os.chdir(self.tmp)
        try: code = run("lock", "model", "--out", os.path.join("model", "x.json"))[0]
        finally: os.chdir(cwd)
        self.assertEqual(code, 2)

    def test_e02_missing_output_folder_is_exit_2_with_json(self):
        code, out, _ = run("lock", self.m, "--out", os.path.join(self.tmp, "missing", "lock.json"), "--json")
        self.assertEqual(code, 2); self.assertFalse(json.loads(out)["locked"])

    def test_e02_failed_write_preserves_previous_lockfile(self):
        out = os.path.join(self.tmp, "approved.json")
        self.assertEqual(run("lock", self.m, "--out", out)[0], 0)
        with open(out, "rb") as f: before = f.read()
        self.write("config.json", b'{"a": 9}')
        orig = os.replace
        def boom(a, b): raise OSError(28, "No space left on device")
        os.replace = boom
        try: code = run("lock", self.m, "--out", out)[0]
        finally: os.replace = orig
        self.assertEqual(code, 2)
        with open(out, "rb") as f: self.assertEqual(f.read(), before)
        self.assertEqual([n for n in os.listdir(self.tmp) if n.startswith(".modellock-")], [])

    # Direct tests for guards that overlap: the end-to-end paths above are also stopped by list_files, so each
    # layer is tested on its own (found by mutation checks: without these, removing one layer went unnoticed).
    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_layer_list_files_refuses_symlinked_lockfile(self):
        os.symlink(self.outside("t.json"), os.path.join(self.m, core.LOCKFILE))
        with self.assertRaises(core.CantVerify): core.list_files(self.m)

    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_layer_write_lock_refuses_symlink_destination(self):
        target = self.outside("t.json", b"keep"); link = os.path.join(self.tmp, "out.json"); os.symlink(target, link)
        with self.assertRaises(core.CantVerify): core.write_lock(self.m, {"schema": core.SCHEMA, "files": {}}, link)
        with open(target, "rb") as f: self.assertEqual(f.read(), b"keep")

    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_layer_ancestor_check(self):
        ext = os.path.join(self.tmp, "ext"); os.makedirs(ext); os.symlink(ext, os.path.join(self.m, "linked"))
        with self.assertRaises(core.CantVerify): core._check_no_symlink_ancestors(self.m, "linked/file.bin")
        core._check_no_symlink_ancestors(self.m, "sub/tokenizer_config.json")  # no link: no exception

    @unittest.skipUnless(SYMLINKS, "symlinks not permitted here")
    def test_layer_verify_uses_ancestor_check_when_inventory_misses_link(self):
        run("lock", self.m)
        ext = os.path.join(self.tmp, "ext"); os.makedirs(ext)
        shutil.copy(os.path.join(self.m, "sub", "tokenizer_config.json"), ext)
        shutil.rmtree(os.path.join(self.m, "sub")); os.symlink(ext, os.path.join(self.m, "sub"))
        orig = core.list_files
        core.list_files = lambda root: sorted(json.load(open(os.path.join(root, core.LOCKFILE)))["files"])
        try: res = core.verify(self.m)
        finally: core.list_files = orig
        self.assertEqual(res["verdict"], "CANT_VERIFY"); self.assertIn("symbolic link in path", res["reason"])

    def test_e03_unreadable_model_file_lock_json_exit_2(self):
        """r2, ML-E03: the read fails after an earlier file was hashed; baseline and model bytes are preserved."""
        out = os.path.join(self.tmp, "approved.json")
        self.assertEqual(run("lock", self.m, "--out", out)[0], 0)
        with open(out, "rb") as f: baseline = f.read()
        model_bytes = {n: open(os.path.join(self.m, n), "rb").read() for n in ("config.json", "model.safetensors")}
        orig, calls = core.sha256_file, {"n": 0}
        def flaky(p):
            calls["n"] += 1
            if calls["n"] == 2: raise PermissionError(13, "Permission denied", p)
            return orig(p)
        core.sha256_file = flaky
        try: code, stdout, _ = run("lock", self.m, "--out", out, "--json")
        finally: core.sha256_file = orig
        self.assertEqual(code, 2); res = json.loads(stdout)
        self.assertFalse(res["locked"]); self.assertIn("cannot read", res["reason"])
        self.assertEqual(calls["n"], 2, "failure should come after one successful file")
        with open(out, "rb") as f: self.assertEqual(f.read(), baseline)
        for n, b in model_bytes.items():
            with open(os.path.join(self.m, n), "rb") as f: self.assertEqual(f.read(), b)

    def test_e03_programming_errors_not_swallowed(self):
        orig = core.sha256_file
        core.sha256_file = lambda p: (_ for _ in ()).throw(TypeError("bug"))
        try:
            with self.assertRaises(TypeError): core.lock(self.m)
        finally: core.sha256_file = orig

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0, "needs a non-root POSIX user")
    def test_e03_real_permission_denied(self):
        p = os.path.join(self.m, "config.json"); os.chmod(p, 0)
        try:
            code, stdout, _ = run("lock", self.m, "--out", os.path.join(self.tmp, "x.json"), "--json")
        finally: os.chmod(p, 0o644)
        self.assertEqual(code, 2); self.assertFalse(json.loads(stdout)["locked"])

    def test_unreadable_lockfile_is_cant_verify(self):
        os.makedirs(os.path.join(self.tmp, "dir.json"))
        res = core.verify(self.m, os.path.join(self.tmp, "dir.json"))
        self.assertEqual(res["verdict"], "CANT_VERIFY")


class Diff(Base):
    def test_diff_same_name_replacement(self):
        run("lock", self.m); a = os.path.join(self.tmp, "a.json"); shutil.copy(os.path.join(self.m, core.LOCKFILE), a)
        self.write("model.safetensors", safetensors(3)); run("lock", self.m)
        code, out, _ = run("diff", a, os.path.join(self.m, core.LOCKFILE))
        self.assertEqual(code, 1); self.assertIn("changed  model.safetensors", out)

    def test_diff_identical(self):
        run("lock", self.m); p = os.path.join(self.m, core.LOCKFILE)
        self.assertEqual(run("diff", p, p)[0], 0)




class SignatureR5(unittest.TestCase):
    """r4/r5: the networked signature step with the verifier replaced by a recorder (no network in unit tests)."""
    def setUp(self):
        import tempfile as _t
        self.d = _t.mkdtemp(); open(os.path.join(self.d, "model.safetensors"), "wb").write(b"x")
        self.calls = []

    def tearDown(self):
        import shutil as _s; _s.rmtree(self.d, ignore_errors=True)

    def run_sig(self, rc, out="out", **kw):
        from vraelis.models import signature
        import subprocess as sp
        def fake(cmd, **k): self.calls.append((cmd, k)); return sp.CompletedProcess(cmd, rc, out, "")
        return signature.check(kw.get("folder", self.d), kw.get("identity", "rel@example.com"), kw.get("issuer", "https://issuer.example"),
                               kw.get("sig"), runner=fake, python="PY", is_installed=kw.get("inst", True))

    def sig(self): open(os.path.join(self.d, "model.sig"), "w").write("{}")

    def test_no_signature_file(self):
        self.assertEqual(self.run_sig(0)["verdict"], "CANT_VERIFY"); self.assertEqual(self.calls, [])

    def test_identity_required(self):
        self.sig(); self.assertEqual(self.run_sig(0, identity="")["verdict"], "CANT_VERIFY"); self.assertEqual(self.calls, [])

    def test_missing_folder(self):
        self.assertEqual(self.run_sig(0, folder=os.path.join(self.d, "nope"), sig=os.path.join(self.d, "x"))["verdict"], "CANT_VERIFY")

    def test_accepted_and_rejected(self):
        self.sig()
        self.assertEqual(self.run_sig(0)["verdict"], "SIGNED_BY_EXPECTED")
        self.assertEqual(self.run_sig(1)["verdict"], "NOT_VERIFIED")
        cmd = self.calls[0][0]
        self.assertEqual(cmd[cmd.index("--identity") + 1], "rel@example.com")
        self.assertEqual(cmd[cmd.index("--identity_provider") + 1], "https://issuer.example")

    def test_verifier_is_isolated_python_module_not_path_lookup(self):  # review ML-R4-01/02
        self.sig(); self.run_sig(0)
        cmd, kw = self.calls[0]
        self.assertEqual(cmd[:4], ["PY", "-I", "-m", "model_signing"])
        self.assertNotIn("shell", kw)

    def test_planted_verifier_in_folder_is_ignored(self):  # end to end with the real Python: a folder-local fake is never run
        import subprocess as sp
        from vraelis.models import signature
        self.sig()
        for n in ("model_signing.bat", "model_signing.cmd", "model_signing.py", "model_signing.exe"):
            open(os.path.join(self.d, n), "w").write("print('FAKE')\n")
        os.makedirs(os.path.join(self.d, "model_signing")); open(os.path.join(self.d, "model_signing", "__main__.py"), "w").write("print('FAKE')\n")
        cwd = os.getcwd(); os.chdir(self.d)
        try: r = signature.check(".", "a@example.com", "https://i.example", is_installed=signature.installed())
        finally: os.chdir(cwd)
        self.assertNotEqual(r["verdict"], "SIGNED_BY_EXPECTED")
        self.assertNotIn("FAKE", r.get("verifier_output", ""))

    def test_usage_error_is_cant_verify(self):  # review ML-R4-03
        self.sig(); self.assertEqual(self.run_sig(2)["verdict"], "CANT_VERIFY")

    def test_timeout_is_cant_verify(self):
        from vraelis.models import signature
        import subprocess as sp
        self.sig()
        def slow(cmd, **k): raise sp.TimeoutExpired(cmd, 1)
        self.assertEqual(signature.check(self.d, "a", "b", runner=slow, python="PY", is_installed=True)["verdict"], "CANT_VERIFY")

    def test_output_decoded_safely(self):  # review ML-R4-04
        self.sig(); self.run_sig(0)
        self.assertEqual(self.calls[0][1].get("errors"), "replace"); self.assertEqual(self.calls[0][1].get("encoding"), "utf-8")

    def test_lockfile_excluded_from_signed_set(self):
        self.sig(); open(os.path.join(self.d, "modellock.json"), "w").write("{}")
        self.run_sig(0)
        self.assertIn(os.path.join(os.path.abspath(self.d), "modellock.json"), self.calls[0][0])

    def test_not_installed(self):
        self.sig(); r = self.run_sig(0, inst=False)
        self.assertEqual(r["verdict"], "CANT_VERIFY"); self.assertIn("not installed", r["reason"]); self.assertEqual(self.calls, [])


class ViewR5(unittest.TestCase):
    """Checker 5.4 View: bytes-like behaviour and closing (review ML-D01: no View tests existed)."""
    def setUp(self):
        import tempfile as _t
        self.d = _t.mkdtemp(); self.p = os.path.join(self.d, "f.bin"); open(self.p, "wb").write(b"PKabcdef")

    def tearDown(self):
        import shutil as _s; _s.rmtree(self.d, ignore_errors=True)

    def test_bytes_like(self):
        from vraelis.models.modelcheck import View
        v = View(self.p)
        self.assertEqual(len(v), 8); self.assertEqual(v[0], ord("P")); self.assertEqual(v[-1], ord("f"))
        self.assertEqual(v[2:5], b"abc"); self.assertEqual(v[6:100], b"ef"); self.assertTrue(v.startswith(b"PK"))
        self.assertIn(b"cde", v); self.assertTrue(bool(v)); v.close()
        self.assertEqual(v[0:2], b"PK"); v.close()  # reopens after close

    def test_empty_file(self):
        from vraelis.models.modelcheck import View
        open(self.p, "wb").close(); v = View(self.p)
        self.assertEqual(len(v), 0); self.assertFalse(v); self.assertEqual(v[0:4], b""); self.assertNotIn(b"x", v)
        with self.assertRaises(IndexError): v[0]

    def test_closed_after_check_file_replaceable(self):
        from vraelis.models import modelcheck
        modelcheck.check_report(self.d)
        os.replace(self.p, self.p + ".moved")  # fails on Windows if a map or handle were still open

    def test_size_change_is_error(self):
        from vraelis.models.modelcheck import View
        v = View(self.p); open(self.p, "ab").write(b"more")
        with self.assertRaises(OSError): v[0:1]




class ProjectCodeNeverRunsR6(unittest.TestCase):
    """r6: a model folder's json.py / hashlib.py must not run when the tool is started from inside the folder."""
    def test_shadowing_modules_not_imported(self):
        import subprocess, tempfile as _t, shutil as _s
        d = _t.mkdtemp(); self.addCleanup(_s.rmtree, d, True)
        marker = os.path.join(d, "MARKER")
        for n in ("json.py", "hashlib.py", "tempfile.py"):
            open(os.path.join(d, n), "w").write("open(%r, 'w').write('ran')\nraise SystemExit(0)\n" % marker)
        open(os.path.join(d, "model.safetensors"), "wb").write(b"x")
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = os.path.join(_t.gettempdir(), "ml-r6-%d.json" % os.getpid())
        # PYTHONPATH naming "." puts the model folder back on the path under -P: only the package's own guard keeps
        # json.py/hashlib.py/tempfile.py out (so this exercises that guard, not just -P).
        p = subprocess.run([sys.executable, "-P", "-m", "vraelis", "models", "lock", ".", "--out", out, "--json"],
                           cwd=d, env=dict(os.environ, PYTHONPATH=here + os.pathsep + "."), capture_output=True, text=True, timeout=120)
        self.assertFalse(os.path.exists(marker), p.stdout + p.stderr); self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        os.makedirs(os.path.join(d, "vraelis")); open(os.path.join(d, "vraelis", "__init__.py"), "w").write("open(%r, 'w').write('ran')\n" % marker)
        p = subprocess.run([sys.executable, "-P", "-m", "vraelis", "models", "lock", ".", "--out", out], cwd=d, env=dict(os.environ, PYTHONPATH=here), capture_output=True, text=True, timeout=120)
        self.assertFalse(os.path.exists(marker), p.stdout + p.stderr)

    def test_plain_python_m_refused(self):  # r7 (Codex AL/ML-BOOT-01)
        import subprocess
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = subprocess.run([sys.executable, "-m", "vraelis", "models", "verify", "."], env=dict(os.environ, PYTHONPATH=here), capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 2); self.assertIn("isolated mode", p.stderr)

class SecretsFilesR8(unittest.TestCase):
    """r8 policy: a file named like a secrets file is inventoried as present, never digested or measured."""
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
        open(os.path.join(self.d, "model.safetensors"), "wb").write(b"x")
        for n, body in ((".env", b"HF_TOKEN=abc\n"), ("id_rsa", b"k")): open(os.path.join(self.d, n), "wb").write(body)
        self.lp = os.path.join(self.d, "..", os.path.basename(self.d) + "-lock.json")
        self.addCleanup(lambda: os.path.exists(self.lp) and os.remove(self.lp))
        core.write_lock(self.d, core.lock(self.d), self.lp)

    def test_no_digest_or_size_recorded(self):
        doc = json.load(open(self.lp))
        self.assertEqual(doc["files"][".env"], {"not_digested": "secrets-file name"})
        self.assertEqual(doc["files"]["id_rsa"], {"not_digested": "secrets-file name"})
        self.assertIn("sha256", doc["files"]["model.safetensors"])

    def test_content_change_is_a_listed_gap_and_removal_is_detected(self):
        open(os.path.join(self.d, ".env"), "wb").write(b"HF_TOKEN=other\n")
        r = core.verify(self.d, self.lp); self.assertEqual(r["verdict"], "UNCHANGED")
        self.assertTrue(any(".env" in g for g in r["coverage_gaps"]))
        os.remove(os.path.join(self.d, ".env"))
        r = core.verify(self.d, self.lp); self.assertEqual([c["change"] for c in r["changes"]], ["missing"])


class NotCheckedShownR9(SecretsFilesR8):
    """r9 (Codex ML-PUB-01): presence-only files appear in normal output, and the byte-identity claim is qualified."""
    def test_verify_human_output_lists_presence_only_files(self):
        open(os.path.join(self.d, ".env"), "wb").write(b"HF_TOKEN=changed")
        code, out, _ = run("verify", self.d, "--lockfile", self.lp)
        self.assertEqual(code, 0); self.assertIn("Not checked (presence only):", out)
        self.assertIn(".env", out.split("Not checked")[1]); self.assertIn("id_rsa", out.split("Not checked")[1])
        self.assertNotIn("Whether the files in this folder are byte-identical", out)
        self.assertIn("Whether every digested file in this folder is byte-identical", out)

    def test_lock_human_output_lists_presence_only_files(self):
        out_lp = self.lp + ".2"; self.addCleanup(lambda: os.path.exists(out_lp) and os.remove(out_lp))
        code, out, _ = run("lock", self.d, "--out", out_lp)
        self.assertEqual(code, 0); self.assertIn("Not checked (presence only):", out); self.assertIn(".env", out)

    def test_diff_reports_presence_only_gap(self):
        r = core.diff(self.lp, self.lp); self.assertEqual(r["verdict"], "UNCHANGED")
        self.assertEqual(sorted(g.split(":")[0] for g in r["coverage_gaps"]), [".env", "id_rsa"])
        code, out, _ = run("diff", self.lp, self.lp); self.assertEqual(code, 0); self.assertIn("Not checked (presence only):", out)

    def test_no_gap_section_without_secret_files(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        open(os.path.join(d, "model.safetensors"), "wb").write(b"x"); run("lock", d)
        code, out, _ = run("verify", d); self.assertEqual(code, 0); self.assertNotIn("Not checked (presence only):", out)


if __name__ == "__main__":
    unittest.main()
