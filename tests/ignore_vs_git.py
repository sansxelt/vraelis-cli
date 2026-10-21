"""Differential check (r9, Codex AL-011-IGNORE-01): addonlock/ignore.py against `git check-ignore --no-index`.

Expected answer for every (rules, path): ignored if git ignores it with core.ignorecase=false OR =true (ignore.py
reads neither setting, so it must cover both). ignore.py must return exactly that; UNKNOWN (treated as private) is
accepted only for rule sets containing a pattern listed in UNSUPPORTED_OK. Exits 1 on any mismatch.
Usage: python -I tests/ignore_vs_git.py [--quick]"""
import os, random, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vraelis.agents import ignore

PATTERNS = [
    # r8 corpus
    "*.json", ".mcp.json", "/.mcp.json", "mcp.json", ".cursor/", ".cursor", "/.cursor/", ".cursor/*", ".cursor/**",
    "**/mcp.json", "**/.vscode", ".vscode/mcp.json", "/.vscode/mcp.json", "!.mcp.json", "!mcp.json", "!.cursor/mcp.json",
    "!*.json", "*", "!*/", "*/", ".*", "!.claude/", ".claude/settings.json", "settings.json", "!settings.json",
    ".claude/*.json", ".claude/**/settings.json", "[.]mcp.json", "?mcp.json", "*.js[o]n", "# .mcp.json", "\\#x",
    "a/**/b", "sub/", "sub/.mcp.json", "/sub", "**/sub/**", "mcp.json/", ".claude/settings*", "!/.claude/settings.json",
    # r9: Codex's counterexamples and POSIX classes
    "[[:punct:]]mcp.json", ".[[:alpha:]]cp.json", "[[:punct:]][[:lower:]]*", "!.[[:alnum:]]cp.json", "[[:upper:]]*",
    ".mcp.[[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]]", "[[:digit:]]*", "[![:alpha:]]mcp.json", "[^[:space:]]mcp.json",
    ".m[[:xdigit:]]p.json", "[[:graph:]]mcp.json", "[[:print:]]mcp.json", "[[:blank:]]mcp.json", ".[[:alpha:]-]cp.json",
    "[[:alpha:][:punct:]]mcp.json", "[a[:digit:]]*", "[[]x", "[]]x", "[!]]mcp.json", "[a-]x", "[-a]x", ".[l-n]cp.json",
    ".[n-l]cp.json", ".[[:alpha:]",
    # r9: case variants (core.ignorecase=true on Windows/macOS repositories)
    ".MCP.json", ".Mcp.Json", "!.MCP.JSON", ".CURSOR/", ".Claude/Settings.json", "SUB/", "[A-Z]mcp.json", ".[M]cp.json",
    # r9: star runs that are not folder wildcards, escapes
    ".m**.json", "**.json", "a**", "su**/.mcp.json", ".cursor/**mcp.json", "**/**/mcp.json", "\\.mcp.json", ".mcp\\.json",
    "\\!.mcp.json", ".mcp.json\\ ", ".m?p.*",
]
UNSUPPORTED_OK = {".[[:alpha:]", "[[:nosuch:]]mcp.json", ".mcp.json\\"}
PATTERNS += sorted(UNSUPPORTED_OK)
PATHS = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".claude/settings.json", "sub/.mcp.json", "sub/deep/.mcp.json",
         "a/b", "a/x/y/b", "1mcp.json", "]x", "[x", "-x", "x", "#x", "!.mcp.json"]
NESTED = [None, ("sub", "*\n!.mcp.json"), ("sub", "*\n!*/\n!.mcp.json"), ("sub", "!.mcp.json"), ("sub", "*.json"),
          (".claude", "settings.json"), (".claude", "!settings.json"), (".cursor", "!mcp.json"), ("sub", "[[:punct:]]mcp.json"),
          (".claude", "SETTINGS.JSON"), ("sub", ".MCP.json\r\n")]


def git_ignored(d, ci):
    r = subprocess.run(["git", "-c", "core.excludesFile=", "-c", f"core.ignorecase={'true' if ci else 'false'}", "check-ignore",
                        "--no-index", "--stdin"], cwd=d, input=("\n".join(PATHS) + "\n").encode(), capture_output=True)
    if r.returncode not in (0, 1): raise RuntimeError(r.stderr.decode())
    return set(r.stdout.decode().split("\n")) - {""}  # bytes: text mode on Windows would send each path with a '\r'


def main():
    quick = "--quick" in sys.argv
    rnd = random.Random(20261021)
    d = tempfile.mkdtemp(); subprocess.run(["git", "init", "-q", d], check=True)
    try:
        for p in PATHS:
            fp = os.path.join(d, *p.split("/")); os.makedirs(os.path.dirname(fp), exist_ok=True)
            with open(fp, "w") as f: f.write("{}")
        rule_sets = [[p] for p in PATTERNS] + [rnd.sample(PATTERNS, k) for k in (2, 3, 4) for _ in range(40 if quick else 200)]
        cases = mism = unknown = 0
        for rules in rule_sets:
            for nested in NESTED:
                files = {".gitignore": "\n".join(rules) + "\n"}
                if nested: files[f"{nested[0]}/.gitignore"] = nested[1] + "\n"
                for n in (".gitignore", "sub/.gitignore", ".claude/.gitignore", ".cursor/.gitignore"):
                    fp = os.path.join(d, *n.split("/"))
                    if os.path.exists(fp): os.remove(fp)
                for n, t in files.items():
                    with open(os.path.join(d, *n.split("/")), "w", newline="") as f: f.write(t)
                expect = git_ignored(d, False) | git_ignored(d, True)
                allowed_unknown = any(r in UNSUPPORTED_OK for r in rules)
                for p in PATHS:
                    mine = ignore.ignored(p, lambda r: files.get(r, ""), False); cases += 1
                    if mine is ignore.UNKNOWN:
                        unknown += 1
                        if allowed_unknown: continue
                    if mine is ignore.UNKNOWN or mine != (p in expect):
                        mism += 1
                        if mism <= 20: print("MISMATCH", repr(rules), repr(nested), p, "mine", "UNKNOWN" if mine is ignore.UNKNOWN else mine, "git", p in expect)
        print(f"{cases} cases, {mism} mismatches, {unknown} unknown (treated as private; allowed only for {sorted(UNSUPPORTED_OK)})")
        return 1 if mism else 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
