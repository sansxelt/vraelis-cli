"""r7 redaction policy for the public tool: a lockfile never makes a value more public than the file it came from.
Local files (kept out of version control: .claude/settings.local.json, user-level --config outside the project) are
recorded as structure only."""
import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis.agents import core


def put(d, files):
    for rel, content in files.items():
        p = os.path.join(d, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f: f.write(content if isinstance(content, str) else json.dumps(content))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "proj"); os.makedirs(self.root)


class LocalSettings(Base):
    DOC = {"permissions": {"allow": ["Bash(export TOKEN=abc1short:*)", "Bash(npm test)"]}, "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "notify --key k1"}]}]},
           "enableAllProjectMcpServers": True, "env": {"MY_VAR": "plainvalue"}}

    def test_no_string_value_recorded(self):
        put(self.root, {".claude/settings.local.json": self.DOC})
        doc = core.lock(self.root); raw = json.dumps(doc)
        for v in ("abc1short", "npm test", "notify", "plainvalue"): self.assertNotIn(v, raw)
        rec = doc["settings"][".claude/settings.local.json"]
        self.assertIs(rec["enableAllProjectMcpServers"], True); self.assertEqual(rec["env"]["names"], ["MY_VAR"])
        self.assertTrue(any("kept out of version control" in g for g in doc["coverage_gaps"]))

    def test_value_change_not_detected_but_structure_change_is(self):
        put(self.root, {".claude/settings.local.json": self.DOC}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root), lp)
        d = json.loads(json.dumps(self.DOC)); d["permissions"]["allow"][1] = "Bash(rm -rf /)"; put(self.root, {".claude/settings.local.json": d})
        self.assertEqual(core.verify(self.root, lp)["verdict"], "UNCHANGED")  # documented gap
        d["permissions"]["allow"].append("Bash(curl *)"); put(self.root, {".claude/settings.local.json": d})
        self.assertEqual(core.verify(self.root, lp)["verdict"], "CHANGED")  # a new entry changes the structure
        d2 = json.loads(json.dumps(self.DOC)); d2["enableAllProjectMcpServers"] = False; put(self.root, {".claude/settings.local.json": d2})
        self.assertEqual(core.verify(self.root, lp)["verdict"], "CHANGED")  # booleans are kept

    def test_shared_settings_still_recorded(self):
        put(self.root, {".claude/settings.json": {"permissions": {"allow": ["Bash(npm test)"]}}})
        self.assertEqual(core.lock(self.root)["settings"][".claude/settings.json"]["permissions"]["allow"], ["Bash(npm test)"])

    def test_hook_scripts_named_by_local_settings_still_pinned(self):
        put(self.root, {".claude/settings.local.json": {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "bash scripts/guard.sh"}]}]}}, "scripts/guard.sh": "exit 0\n"})
        self.assertIn("scripts/guard.sh", core.lock(self.root)["launched_files"])


class UserLevelConfig(Base):
    def test_outside_config_structure_only(self):
        user = os.path.join(self.tmp, "user.json")
        with open(user, "w") as f: json.dump({"mcpServers": {"gh": {"command": "npx", "args": ["-y", "server@1.0.0", "--team", "acme-internal"], "env": {"GH_TOKEN": "x"}}}, "oauthAccount": {"emailAddress": "dev@corp.example"}}, f)
        put(self.root, {".mcp.json": {"mcpServers": {}}})
        doc = core.lock(self.root, [user]); raw = json.dumps(doc)
        for v in ("acme-internal", "dev@corp.example", "server@1.0.0"): self.assertNotIn(v, raw)
        label = user.replace(os.sep, "/")
        self.assertEqual(doc["configs"][label]["gh"]["env"]["names"], ["GH_TOKEN"])
        self.assertTrue(any("user-level file outside the project" in g for g in doc["coverage_gaps"]))

    def test_inside_project_config_recorded_normally(self):
        put(self.root, {"conf/extra.json": {"mcpServers": {"s": {"command": "node", "args": ["--team", "acme"]}}}})
        doc = core.lock(self.root, [os.path.join(self.root, "conf", "extra.json")])
        self.assertEqual(doc["configs"]["conf/extra.json"]["s"]["args"], ["--team", "acme"])


if __name__ == "__main__":
    unittest.main()
