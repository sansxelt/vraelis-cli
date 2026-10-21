"""r3 regressions for adversarial review 1 (28 findings) and held-out set 2 (symlinked watched folder)."""
import io, json, os, shutil, sys, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vraelis.agents import core, cli, paths
import review1_cases as R

WINDOWS = os.name == "nt"


def can_symlink():
    d = tempfile.mkdtemp()
    try: os.symlink(os.path.join(d, "x"), os.path.join(d, "y")); return True
    except (OSError, NotImplementedError): return False
    finally: shutil.rmtree(d, ignore_errors=True)


SYMLINKS = can_symlink()


def put(d, files):
    for rel, content in files.items():
        p = os.path.join(d, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(content if isinstance(content, str) else json.dumps(content, indent=1))


def cli_run(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e): code = cli.run(list(argv))
    return code, o.getvalue() + e.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "proj"); os.makedirs(self.root)


class Leaks(Base):
    def test_review_leak_cases(self):
        for name, files in R.LEAK_CASES.items():
            with self.subTest(name):
                d = os.path.join(self.tmp, name); os.makedirs(d); put(d, files)
                c1, o1 = cli_run("lock", d, "--json")
                raw = open(os.path.join(d, core.LOCKFILE), encoding="utf-8").read() if os.path.exists(os.path.join(d, core.LOCKFILE)) else ""
                c2, o2 = cli_run("verify", d, "--json")
                c3, o3 = cli_run("lock", d, "--json", "--strict", "--out", os.path.join(self.tmp, name + ".strict.json"))
                self.assertNotIn("FAKESECRET", raw + o1 + o2 + o3)
                self.assertIn(c1, (0, 2)); self.assertIn(c2, (0, 2))

    def test_secret_like_object_children_judged_by_own_key(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "x", "oauth": {"clientId": "app-1", "clientSecret": "FAKESECRET123"}}}}})
        doc = core.lock(self.root)
        self.assertEqual(doc["configs"][".mcp.json"]["s"]["oauth"]["clientId"], "app-1")
        self.assertNotIn("FAKESECRET", json.dumps(doc))


class Detection(Base):
    EXPECT = {"node_dir_entry": ("UNCHANGED", "is a folder"), "url_path_change_redacted_query": ("UNCHANGED", "URL redacted"),
              "long_flag_overredacted": ("UNCHANGED", "key-like argument redacted"), "nan_unchanged_should_be_0": ("CANT_LOCK", "non-standard")}

    def test_review_detect_cases(self):
        for case in R.DETECT_CASES:
            name, before, after = case[:3]
            with self.subTest(name):
                d = os.path.join(self.tmp, name); os.makedirs(d); put(d, before)
                want, frag = self.EXPECT.get(name, ("CHANGED", None))
                if want == "CANT_LOCK":
                    with self.assertRaises(core.CantVerify) as cm: core.lock(d)
                    self.assertIn(frag, str(cm.exception)); continue
                lp = os.path.join(self.tmp, name + ".json"); core.write_lock(d, core.lock(d), lp)
                self.assertEqual(core.verify(d, lp)["verdict"], "UNCHANGED")
                put(d, after); r = core.verify(d, lp)
                self.assertEqual(r["verdict"], want, r["changes"])
                if frag: self.assertTrue(any(frag.split()[0] in g for g in r["coverage_gaps"]), r["coverage_gaps"])

    def test_cwd_resolves_relative_script(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "node", "args": ["index.js"], "cwd": "${workspaceFolder}/srv"}}}, "srv/index.js": "1"})
        self.assertIn("srv/index.js", core.lock(self.root)["launched_files"])

    def test_env_file_never_digested(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "docker", "args": ["run", "--env-file", "prod.vars", "img@sha256:" + "a" * 64]}}}, "prod.vars": "API_TOKEN=x\n", ".env": "A=1"})
        doc = core.lock(self.root); self.assertEqual(doc["launched_files"], {})
        self.assertTrue(any("not read" in g for g in doc["coverage_gaps"]))

    def test_dotenv_named_launch_arg_not_digested(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv", "args": [".env.local"]}}}, ".env.local": "K=v"})
        self.assertEqual(core.lock(self.root)["launched_files"], {})

    def test_missing_extra_config_at_verify_is_removed(self):
        put(self.root, {"conf/extra.json": {"mcpServers": {"s": {"command": "x"}}}})
        c = os.path.join(self.root, "conf/extra.json"); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root, [c]), lp); os.remove(c)
        r = core.verify(self.root, lp, extra_configs=[c]); self.assertEqual(r["verdict"], "CHANGED")
        self.assertEqual(r["changes"][0]["kind"], "config-removed")

    def test_hook_script_with_shell_punctuation(self):  # held-out set 2 case 1 shape
        put(self.root, {".claude/settings.json": {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": 'if [ "$X" = "true" ]; then bash "$CLAUDE_PROJECT_DIR"/scripts/setup.sh; fi'}]}]}}, "scripts/setup.sh": "x"})
        self.assertIn("scripts/setup.sh", core.lock(self.root)["launched_files"])

    def test_jsonc_cr_line_comment(self):
        put(self.root, {".vscode/mcp.json": '{"servers": {"s": {"command": "srv"}, // c\r"t": {"command": "srv2"}}}'})
        self.assertEqual(sorted(core.lock(self.root)["configs"][".vscode/mcp.json"]), ["s", "t"])


class Robustness(Base):
    def test_deep_nesting_is_cant_verify(self):
        put(self.root, {".mcp.json": "[" * 100000})
        code, out = cli_run("lock", self.root, "--json"); self.assertEqual(code, 2)

    def test_malformed_lockfile_shapes(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv"}}}}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root), lp)
        for bad in (5, {"s": "x"}, {"s": 5}):
            with self.subTest(bad):
                d = json.load(open(lp)); d["configs"][".mcp.json"] = bad; json.dump(d, open(os.path.join(self.tmp, "m.json"), "w"))
                self.assertEqual(core.verify(self.root, os.path.join(self.tmp, "m.json"))["verdict"], "CANT_VERIFY")

    def test_internal_error_exits_2_not_1(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv"}}}})
        with mock.patch.object(core, "compare", side_effect=TypeError("boom")):
            self.assertEqual(core.verify(self.root, None)["verdict"], "CANT_VERIFY")
        with mock.patch.object(cli, "main", side_effect=RuntimeError("boom")):
            self.assertEqual(cli_run("verify", self.root)[0], 2)


class NoNetworkPaths(Base):
    UNC = ["\\\\192.0.2.1\\share\\server.js", "//192.0.2.1/share/server.js", "\\\\?\\UNC\\192.0.2.1\\s\\x.js"]

    def test_unc_arguments_never_reach_the_filesystem(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "node", "args": self.UNC, "cwd": "\\\\192.0.2.1\\share"}}},
                        ".claude/settings.json": {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "node \\\\192.0.2.1\\share\\h.js"}]}]}}})
        calls = []
        real_stat, real_lstat = os.stat, os.lstat
        def spy(fn):
            def w(p, *a, **k):
                calls.append(str(p)); return fn(p, *a, **k)
            return w
        with mock.patch("os.stat", spy(real_stat)), mock.patch("os.lstat", spy(real_lstat)):
            doc = core.lock(self.root)
        self.assertFalse([c for c in calls if "192.0.2.1" in c], "a network path reached the filesystem")
        self.assertEqual(doc["launched_files"], {})

    def test_network_like(self):
        for p in self.UNC: self.assertTrue(paths.network_like(p))
        for p in ("C:\\x", "/usr/bin/x", "rel/x"): self.assertFalse(paths.network_like(p))


@unittest.skipUnless(SYMLINKS, "symlinks not available")
class LinkedFolders(Base):
    def test_symlinked_skills_folder_inside_is_followed(self):  # held-out set 2: 9 of 30 refusals
        put(self.root, {".agents/skills/review/SKILL.md": "v1", ".mcp.json": {"mcpServers": {}}})
        os.makedirs(os.path.join(self.root, ".claude")); os.symlink("../.agents/skills", os.path.join(self.root, ".claude/skills"))
        lp = os.path.join(self.tmp, "l.json"); doc = core.lock(self.root); core.write_lock(self.root, doc, lp)
        self.assertEqual(doc["instruction_files"][".claude/skills"], {"symlink": "../.agents/skills"})
        self.assertIn(".claude/skills/review/SKILL.md", doc["instruction_files"])
        put(self.root, {".agents/skills/review/SKILL.md": "v2"})
        self.assertEqual([c["where"] for c in core.verify(self.root, lp)["changes"]], [".claude/skills/review/SKILL.md"])

    def test_linked_parent_outside_refused(self):
        out = os.path.join(self.tmp, "outside"); put(out, {"settings.json": {"permissions": {}}})
        os.symlink(out, os.path.join(self.root, ".claude"))
        with self.assertRaises(core.CantVerify): core.lock(self.root)

    def test_linked_vscode_outside_refused(self):
        out = os.path.join(self.tmp, "outv"); put(out, {"mcp.json": {"servers": {"s": {"command": "x"}}}})
        os.symlink(out, os.path.join(self.root, ".vscode"))
        with self.assertRaises(core.CantVerify): core.lock(self.root)

    def test_nested_link_outside_in_skills_not_read(self):
        out = os.path.join(self.tmp, "o"); put(out, {"private.txt": "x"}); put(self.root, {".claude/skills/a/SKILL.md": "x"})
        os.symlink(out, os.path.join(self.root, ".claude/skills/vendor"))
        doc = core.lock(self.root)
        self.assertNotIn(".claude/skills/vendor/private.txt", doc["instruction_files"])
        self.assertEqual(set(doc["instruction_files"][".claude/skills/vendor"]), {"symlink"})

    def test_link_loop_terminates(self):
        put(self.root, {".claude/skills/a/SKILL.md": "x"}); os.symlink("..", os.path.join(self.root, ".claude/skills/a/up"))
        core.lock(self.root)  # must return, not recurse forever


@unittest.skipUnless(WINDOWS, "junctions are Windows-only")
class Junctions(Base):
    def junction(self, link, target):
        import _winapi; _winapi.CreateJunction(target, link)

    def test_junction_skills_outside_not_read(self):
        out = os.path.join(self.tmp, "o"); put(out, {"private-notes.txt": "x"}); os.makedirs(os.path.join(self.root, ".claude"))
        self.junction(os.path.join(self.root, ".claude", "skills"), out)
        doc = core.lock(self.root) if os.path.exists(os.path.join(self.root, ".mcp.json")) else None
        put(self.root, {".mcp.json": {"mcpServers": {}}}); doc = core.lock(self.root)
        self.assertNotIn(".claude/skills/private-notes.txt", doc["instruction_files"])
        self.assertIn("symlink", doc["instruction_files"][".claude/skills"])

    def test_junction_parent_outside_refused(self):
        out = os.path.join(self.tmp, "c"); put(out, {"settings.json": {}})
        self.junction(os.path.join(self.root, ".claude"), out)
        with self.assertRaises(core.CantVerify): core.lock(self.root)

    def test_junction_loop(self):
        put(self.root, {".claude/skills/a/SKILL.md": "x"})
        self.junction(os.path.join(self.root, ".claude", "skills", "a", "loop"), os.path.join(self.root, ".claude", "skills"))
        core.lock(self.root)


if __name__ == "__main__":
    unittest.main()


class LayerDirect(Base):
    """One test per redaction or safety layer, on inputs no other layer handles (mutation run r3 showed these
    layers overlapping, so the end-to-end cases alone did not prove each layer)."""
    def s(self, text):
        from vraelis.agents.redact import scrub
        return scrub(text, [], "t")

    def test_authorization_header_text(self):  # multi-word value: only the header rule covers the words after the first
        self.assertNotIn("zzhide", self.s("Authorization: Custom zzhide"))
    def test_bearer_text(self): self.assertNotIn("zzhide", self.s("use bearer zzhide now"))
    def test_basic_text(self): self.assertNotIn("zzhide", self.s("basic zzhide"))
    def test_u_in_command_text(self): self.assertNotIn("zzhide", self.s("curl -u bot:zzhide x"))
    def test_token_prefix_text(self): self.assertNotIn("ghp_zz", self.s("x ghp_zz y"))
    def test_jwt_text(self): self.assertNotIn("eyJabcde", self.s("x eyJabcdefg.eyJhijklm.sig y"))
    def test_opaque_text(self): self.assertNotIn("abcdefghij", self.s("x abcdefghijklmnopqrstuvwxyz0123456789 y"))
    def test_opaque_keeps_docker_digest(self): self.assertIn("sha256:" + "a1" * 32, self.s("img@sha256:" + "a1" * 32))

    def test_helper_keeps_program_only(self):
        put(self.root, {".claude/settings.json": {"apiKeyHelper": "get-key --profile prod"}})
        self.assertEqual(core.lock(self.root)["settings"][".claude/settings.json"]["apiKeyHelper"], "get-key")

    def test_network_path_gap_reported(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "node", "args": ["\\\\192.0.2.1\\s\\x.js"]}}}})
        self.assertTrue(any("network path is not read" in g for g in core.lock(self.root)["coverage_gaps"]))

    def test_deep_nesting_direct(self):
        put(self.root, {".mcp.json": "[" * 100000})
        with self.assertRaises(core.CantVerify) as cm: core.lock(self.root)
        self.assertIn("nested too deeply", str(cm.exception))

    def test_read_lock_rejects_bad_config_shape(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv"}}}}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root), lp)
        d = json.load(open(lp)); d["configs"][".mcp.json"] = {"s": 5}; json.dump(d, open(lp, "w"))
        with self.assertRaises(core.CantVerify) as cm: core.read_lock(lp)
        self.assertIn("malformed lockfile config", str(cm.exception))

    def test_nested_field_change_reported_by_leaf(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "x", "oauth": {"clientId": "a", "port": 1}}}}}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root), lp)
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "x", "oauth": {"clientId": "b", "port": 1}}}}})
        self.assertEqual([c["where"] for c in core.verify(self.root, lp)["changes"]], [".mcp.json > s > oauth.clientId"])


class PathsDirect(Base):
    def link(self, link, target):
        if os.name == "nt":
            import _winapi; _winapi.CreateJunction(target, link)
        else: os.symlink(target, link)

    def test_resolve_refuses_link_leaving_project(self):
        out = os.path.join(self.tmp, "o"); os.makedirs(out); open(os.path.join(out, "f"), "w").write("x")
        self.link(os.path.join(self.root, "l"), out)
        with self.assertRaises(paths.Outside) as cm: paths.resolve(self.root, "l/f")
        self.assertIn("link leaves the project", str(cm.exception))

    def test_resolve_follows_link_inside(self):
        os.makedirs(os.path.join(self.root, "real")); open(os.path.join(self.root, "real", "f"), "w").write("x")
        self.link(os.path.join(self.root, "l"), os.path.join(self.root, "real"))
        links = []
        self.assertEqual(os.path.normcase(paths.resolve(self.root, "l/f", links)), os.path.normcase(os.path.join(self.root, "real", "f")))
        self.assertEqual(len(links), 1)

    def test_config_through_inside_link_refused(self):
        os.makedirs(os.path.join(self.root, "real")); put(self.root, {"real/mcp.json": {"mcpServers": {"s": {"command": "x"}}}})
        self.link(os.path.join(self.root, ".vscode"), os.path.join(self.root, "real"))
        with self.assertRaises(core.CantVerify) as cm: core.lock(self.root)
        self.assertIn("symbolic link or junction is not supported", str(cm.exception))

    def test_link_chain_depth_limited(self):
        put(self.root, {"d3/SKILL.md": "x", ".mcp.json": {"mcpServers": {}}})
        self.link(os.path.join(self.root, "d2"), os.path.join(self.root, "d3"))
        os.makedirs(os.path.join(self.root, "d1")); self.link(os.path.join(self.root, "d1", "in"), os.path.join(self.root, "d2"))
        os.makedirs(os.path.join(self.root, ".claude")); self.link(os.path.join(self.root, ".claude", "skills"), os.path.join(self.root, "d1"))
        os.makedirs(os.path.join(self.root, "d3", "deeper")); self.link(os.path.join(self.root, "d3", "deeper", "again"), os.path.join(self.root, "d1"))
        doc = core.lock(self.root)
        self.assertTrue(any("nested too deep" in g for g in doc["coverage_gaps"]), doc["coverage_gaps"])

    def test_folder_reached_twice_reported(self):
        put(self.root, {".claude/skills/a/SKILL.md": "x"})
        self.link(os.path.join(self.root, ".claude", "skills", "a", "up"), os.path.join(self.root, ".claude", "skills"))
        self.assertTrue(any("reached again" in g for g in core.lock(self.root)["coverage_gaps"]))

    def test_lock_destination_link_refused(self):
        put(self.root, {".mcp.json": {"mcpServers": {}}}); tgt = os.path.join(self.tmp, "tgt"); os.makedirs(tgt)
        dst = os.path.join(self.tmp, "dst"); self.link(dst, tgt)
        with self.assertRaises(core.CantVerify): core.write_lock(self.root, core.lock(self.root), dst)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() != 0, "needs a non-root POSIX user")
    def test_unreadable_watched_folder(self):
        put(self.root, {".claude/skills/a/SKILL.md": "x"}); d = os.path.join(self.root, ".claude/skills/a"); os.chmod(d, 0)
        self.addCleanup(os.chmod, d, 0o755)
        with self.assertRaises(core.CantVerify): core.lock(self.root)
