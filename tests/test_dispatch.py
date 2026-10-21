"""The top-level `vraelis` dispatcher: routing, usage, exit codes, isolation refusal."""
import io, os, shutil, subprocess, sys, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from vraelis import cli, __version__


def run(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e): code = cli.run(list(argv))
    return code, o.getvalue(), e.getvalue()


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)

    def test_usage_and_version(self):
        self.assertEqual(run()[0], 2); self.assertEqual(run("--help")[0], 0)
        code, out, _ = run("--version"); self.assertEqual(code, 0); self.assertIn(__version__, out)

    def test_unknown_tool(self):
        code, _, err = run("lock", "."); self.assertEqual(code, 2); self.assertIn("unknown tool", err)

    def test_models_routes(self):
        open(os.path.join(self.d, "model.safetensors"), "wb").write(b"x")
        out = os.path.join(tempfile.gettempdir(), "vr-dispatch-%d.json" % os.getpid()); self.addCleanup(lambda: os.path.exists(out) and os.remove(out))
        self.assertEqual(run("models", "lock", self.d, "--out", out)[0], 0)
        self.assertEqual(run("models", "verify", self.d, "--lockfile", out)[0], 0)
        open(os.path.join(self.d, "model.safetensors"), "wb").write(b"y")
        self.assertEqual(run("models", "verify", self.d, "--lockfile", out)[0], 1)

    def test_agents_routes(self):
        open(os.path.join(self.d, ".mcp.json"), "w").write('{"mcpServers": {"s": {"command": "x"}}}')
        self.assertEqual(run("agents", "lock", self.d)[0], 0); self.assertEqual(run("agents", "verify", self.d)[0], 0)
        open(os.path.join(self.d, ".mcp.json"), "w").write('{"mcpServers": {"s": {"command": "y"}}}')
        self.assertEqual(run("agents", "verify", self.d)[0], 1)

    def test_help_names_vraelis(self):
        for tool in ("models", "agents"):
            with self.subTest(tool):
                o = io.StringIO()
                with redirect_stdout(o), self.assertRaises(SystemExit): cli.run([tool, "-h"])
                self.assertIn(f"vraelis {tool}", o.getvalue())

    def test_crash_exits_2(self):
        with mock.patch.object(cli, "main", side_effect=RuntimeError("boom")): self.assertEqual(run("models")[0], 2)

    def test_plain_python_m_refused_and_safe_path_runs(self):
        env = dict(os.environ, PYTHONPATH=HERE)
        p = subprocess.run([sys.executable, "-m", "vraelis", "--version"], cwd=self.d, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 2); self.assertIn("isolated mode", p.stderr)
        p = subprocess.run([sys.executable, "-P", "-m", "vraelis", "--version"], cwd=self.d, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr); self.assertIn(__version__, p.stdout)


if __name__ == "__main__":
    unittest.main()
