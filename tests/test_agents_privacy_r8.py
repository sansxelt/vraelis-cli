"""r8 regressions for Codex's public-release review of 0.1.0:
AL-PUB-01: raw config keys named `names` / `pinned_values` bypassed structure-only masking (now judged by provenance).
AL-PUB-02: a gitignored .mcp.json exported plaintext values because its file name classed it as shared (now the
project's own ignore rules decide)."""
import io, json, os, shutil, sys, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis.agents import core, cli, ignore


def put(d, files):
    for rel, content in files.items():
        p = os.path.join(d, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f: f.write(content if isinstance(content, str) else json.dumps(content))


def run(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e): code = cli.run(list(argv))
    return code, o.getvalue(), e.getvalue()


SERVER = {"mcpServers": {"s": {"command": "node", "args": ["srv.js", "--team", "acmeteamvalue"], "env": {"API_TOKEN": "tokvalue1"}}}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "proj"); os.makedirs(self.root)


class RawKeysAreDataPUB01(Base):
    LOCAL = {"names": ["rawnamesvalue"], "pinned_values": {"k": "rawpinnedvalue"}, "nested": {"names": "rawnested", "pinned_values": ["rawlist"]},
             "env": {"MY_VAR": "envvalue"}}

    def test_local_settings_raw_keys_masked(self):
        put(self.root, {".claude/settings.local.json": self.LOCAL})
        doc = core.lock(self.root); raw = json.dumps(doc)
        for v in ("rawnamesvalue", "rawpinnedvalue", "rawnested", "rawlist", "envvalue"): self.assertNotIn(v, raw)
        rec = doc["settings"][".claude/settings.local.json"]
        self.assertEqual(rec["names"], [core.LOCAL_MARK]); self.assertEqual(rec["pinned_values"], {"k": core.LOCAL_MARK})
        self.assertEqual(rec["env"]["names"], ["MY_VAR"])  # generated names are kept

    def test_outside_config_raw_keys_masked_in_lock_and_verify_json(self):
        user = os.path.join(self.tmp, "user.json")
        with open(user, "w") as f: json.dump({"mcpServers": {"s": {"command": "x", "meta": {"names": ["srvnamesvalue"], "pinned_values": {"a": "srvpinned"}}}}, "names": ["topnames"]}, f)
        lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root, [user]), lp)
        raw = open(lp, encoding="utf-8").read()
        for v in ("srvnamesvalue", "srvpinned", "topnames"): self.assertNotIn(v, raw)
        with open(user, "w") as f: json.dump({"mcpServers": {"s": {"command": "x", "meta": {"names": ["srvnamesvalue2", "more"], "pinned_values": {"a": "srvpinned2"}}}}, "names": ["topnames2"]}, f)
        code, out, _ = run("verify", self.root, "--lockfile", lp, "--config", user, "--json")
        for v in ("srvnamesvalue", "srvpinned", "topnames"): self.assertNotIn(v, out)
        self.assertEqual(code, 1)  # the added list entry is a structure change

    def test_explicit_pins_in_local_file_kept(self):
        put(self.root, {".claude/settings.local.json": {"env": {"MY_VAR": "pinnedok"}}})
        rec = core.lock(self.root, pin_env=["MY_VAR"])["settings"][".claude/settings.local.json"]
        self.assertEqual(rec["env"]["pinned_values"], {"MY_VAR": "pinnedok"})

    def test_shared_file_raw_keys_still_recorded(self):
        put(self.root, {".claude/settings.json": {"names": ["sharedvalue"]}})
        self.assertEqual(core.lock(self.root)["settings"][".claude/settings.json"]["names"], ["sharedvalue"])


class IgnoreRulesPUB02(Base):
    def lock_raw(self, files):
        put(self.root, files); doc = core.lock(self.root); return doc, json.dumps(doc)

    def test_gitignored_mcp_json_structure_only(self):
        doc, raw = self.lock_raw({".gitignore": ".mcp.json\n", ".mcp.json": SERVER, "srv.js": "1\n"})
        for v in ("acmeteamvalue", "tokvalue1", "srv.js\"", "node"): self.assertNotIn(v, raw.replace("srv.js\": {", ""))
        self.assertEqual(doc["configs"][".mcp.json"]["s"]["env"]["names"], ["API_TOKEN"])
        self.assertTrue(any("excluded from version control by the project's ignore rules" in g for g in doc["coverage_gaps"]))
        self.assertIn("srv.js", doc["launched_files"])  # launched files are still pinned by digest

    def test_not_ignored_mcp_json_recorded(self):
        doc, raw = self.lock_raw({".gitignore": "node_modules/\n", ".mcp.json": SERVER})
        self.assertIn("acmeteamvalue", raw)

    def test_negation_reincludes(self):
        _, raw = self.lock_raw({".gitignore": "*.json\n!.mcp.json\n", ".mcp.json": SERVER})
        self.assertIn("acmeteamvalue", raw)

    def test_ignored_folder_cannot_be_reincluded(self):
        doc, raw = self.lock_raw({".gitignore": ".cursor/\n!.cursor/mcp.json\n", ".cursor/mcp.json": SERVER})
        self.assertNotIn("acmeteamvalue", raw)

    def test_nested_gitignore_and_settings_json(self):
        _, raw = self.lock_raw({".claude/.gitignore": "settings.json\n", ".claude/settings.json": {"permissions": {"allow": ["Bash(secretcmd)"]}}})
        self.assertNotIn("secretcmd", raw)

    def test_info_exclude_only_in_repo_root(self):
        _, raw = self.lock_raw({".git/info/exclude": ".mcp.json\n", ".mcp.json": SERVER})
        self.assertNotIn("acmeteamvalue", raw)

    def test_unreadable_rules_treated_as_private(self):
        os.makedirs(os.path.join(self.root, ".gitignore"))  # a folder, not a file
        doc, raw = self.lock_raw({".mcp.json": SERVER})
        self.assertNotIn("acmeteamvalue", raw)
        self.assertTrue(any("could not be read safely" in g for g in doc["coverage_gaps"]))

    def test_no_value_leaks_through_notices(self):
        doc, raw = self.lock_raw({".gitignore": ".mcp.json\n", ".mcp.json": {"mcpServers": {"s": {"command": "npx", "args": ["-y", "privpkgname@latest"]}}}})
        self.assertNotIn("privpkgname", raw)


class Matcher(unittest.TestCase):
    def ig(self, rules, rel, files=None):
        files = dict(files or {}); files.setdefault(".gitignore", rules)
        return ignore.ignored(rel, lambda r: files.get(r, ""), False)

    def test_patterns(self):
        cases = [("*.json", ".mcp.json", True), ("/.mcp.json", "sub/.mcp.json", False), (".mcp.json", "sub/.mcp.json", True),
                 ("sub/.mcp.json", "sub/.mcp.json", True), ("sub/.mcp.json", "a/sub/.mcp.json", False), ("**/sub/x", "a/b/sub/x", True),
                 ("a/**", "a/b/c", True), ("a/**/c", "a/c", True), ("a/**/c", "a/x/y/c", True), ("[ab].json", "a.json", True),
                 ("[!ab].json", "a.json", False), ("?.json", "ab.json", False), ("\\#x", "#x", True), ("# comment", "# comment", False),
                 ("**/x", "x", True), ("d/*.json", "d/e/f.json", False), ("\\!x", "!x", True), ("x   ", "x", True), ("x/", "x", False), ("x/", "x/y", True), ("*", "a/b", True), ("a*b", "a/b", False)]
        for rules, rel, want in cases:
            with self.subTest(rules=rules, rel=rel): self.assertEqual(self.ig(rules + "\n", rel), want)

    def test_deeper_file_wins_and_last_rule_wins(self):
        self.assertFalse(self.ig("*.json\n", "d/.mcp.json", {"d/.gitignore": "!.mcp.json\n"}))
        self.assertTrue(self.ig("!x\nx\n", "x"))
        self.assertFalse(self.ig("", "d/x", {"d/.gitignore": "*\n!x\n"}))  # a .gitignore never judges its own folder

    def test_unknown_propagates(self):
        self.assertIs(ignore.ignored("a/b", lambda r: ignore.UNKNOWN if r == "a/.gitignore" else "", False), ignore.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
