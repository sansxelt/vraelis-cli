"""r9 regressions for Codex AL-011-IGNORE-01 (review of 0.1.1): ignore rules that git honours but r8 did not parse
must not let a config's values into the lockfile."""
import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis.agents import core, ignore

SERVER = {"mcpServers": {"s": {"command": "node", "args": ["--team", "synthvalue9"]}}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "proj"); os.makedirs(self.root)

    def lock_with(self, rules):
        with open(os.path.join(self.root, ".gitignore"), "w", newline="") as f: f.write(rules)
        with open(os.path.join(self.root, ".mcp.json"), "w") as f: json.dump(SERVER, f)
        return json.dumps(core.lock(self.root))


class CodexCounterexamples(Base):
    def test_posix_classes_codex(self):
        for rules in ("[[:punct:]]mcp.json\n", ".[[:alpha:]]cp.json\n"):
            with self.subTest(rules=rules): self.assertNotIn("synthvalue9", self.lock_with(rules))

    def test_more_posix_classes(self):
        for rules in ("[[:punct:]][[:lower:]]*\n", ".mcp.[[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]]\n", "[^[:space:]]mcp.json\n",
                      ".m[[:xdigit:]]p.json\n", "[[:alpha:][:punct:]]mcp.json\n"):
            with self.subTest(rules=rules): self.assertNotIn("synthvalue9", self.lock_with(rules))

    def test_case_insensitive_repositories(self):  # core.ignorecase=true is the default on Windows and macOS
        for rules in (".MCP.json\n", ".Mcp.Json\n", ".[[:upper:]]cp.json\n", "*.JSON\n"):
            with self.subTest(rules=rules): self.assertNotIn("synthvalue9", self.lock_with(rules))

    def test_unsupported_pattern_is_private(self):
        for rules in ("[[:nosuch:]]mcp.json\n", ".[[:alpha:]\n", "x\\\n"):
            with self.subTest(rules=rules):
                raw = self.lock_with(rules); self.assertNotIn("synthvalue9", raw)
                self.assertIn("could not be read safely", raw)

    def test_still_shared_when_git_would_not_ignore(self):
        for rules in ("[[:digit:]]*\n", ".[M]cp.json\n", "!.mcp.json\n", "[!.]mcp.json\n"):
            with self.subTest(rules=rules): self.assertIn("synthvalue9", self.lock_with(rules))


class Wildmatch(unittest.TestCase):
    def ig(self, rules, rel):
        return ignore.ignored(rel, lambda r: rules if r == ".gitignore" else "", False)

    def test_cases(self):
        cases = [("[]]x", "]x", True), ("[!]]x", "]x", False), ("[a-]x", "-x", True), (".[n-l]cp.json", ".mcp.json", False),
                 (".[n-l]cp.json", ".ncp.json", True), ("[[]x", "[x", True), (".m**.json", "sub/.mcp.json", True),
                 ("su**/.mcp.json", "sub/x/.mcp.json", False), ("**/**/mcp.json", ".cursor/mcp.json", True),
                 ("[A-Z]mcp.json", "1mcp.json", False), ("x\r", "x", True), (".mcp.json\\ ", ".mcp.json", False)]
        for rules, rel, want in cases:
            with self.subTest(rules=rules, rel=rel): self.assertEqual(self.ig(rules + "\n", rel), want)


if __name__ == "__main__":
    unittest.main()
