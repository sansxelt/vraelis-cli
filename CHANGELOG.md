# Changelog

## 0.1.2 (2026-10-21)

These are privacy fixes in `vraelis agents` from an independent AI review of 0.1.1. No real credential exposure was
demonstrated.

- **Ignore rules git honours could be missed.** In 0.1.1 the reader of a project's own ignore rules missed POSIX
  classes. For example, `[[:punct:]]mcp.json` or `.[[:alpha:]]cp.json` make git ignore `.mcp.json`, but 0.1.1 treated
  the file as shared and recorded its values.
  - The matcher now follows git's own matching rules: brackets, POSIX classes, and when `**` spans folders.
  - Any pattern it cannot parse makes the file count as private.
- **Case-insensitive repositories.** Git ignores case on Windows and macOS repositories by default, so `.MCP.json`
  also ignores `.mcp.json` there. The repository's setting is not read, so a file now counts as ignored if git would
  ignore it under either setting.
- The matcher is checked against `git check-ignore` on a corpus that includes these cases. The check fails on any
  disagreement.

## 0.1.1 (2026-10-21)

These are privacy and reporting fixes from an independent AI review of 0.1.0. No real credential exposure was
demonstrated. Upgrade if you use `vraelis agents` with gitignored configs or user-level `--config` files.

- **`vraelis agents`: structure-only masking could be bypassed.** In 0.1.0, any raw config key named `names` or
  `pinned_values` kept its values. Now masking keeps only the env and header records the tool itself generated.
- **`vraelis agents`: visibility now follows the project's own ignore rules, not just file names.** In 0.1.0, a
  gitignored `.mcp.json` had its values recorded because its name classed it as shared. Now any project config or
  settings file that the project's ignore rules exclude is recorded as structure only.
- **`vraelis models`: presence-only files are now shown in normal output.** Files named like secrets files appear
  under "Not checked (presence only)" in `lock`, `verify` and `diff`, and the result claims byte identity only for
  files that were digested. In 0.1.0 a `.env` edit returned Unchanged, and the gap was visible only with `--json`.
- Lockfiles are compatible, but `verify` may now report Changed for a gitignored config locked by 0.1.0. That is
  because its values are no longer recorded. Re-lock after reading the new lockfile.

## 0.1.0 (2026-10-20)

This is the first public release (alpha). It ships one CLI with two tools.

- **`vraelis models`**: `lock`, `verify`, `diff`, plus an optional `signature`.
  - Files named like secrets files are listed as present and are never digested.
  - The structural checker uses revision 5.4: memory-mapped reads, with one file open at a time.
- **`vraelis agents`** (preview): `lock`, `verify`, `diff`.
  - Local, uncommitted settings files are recorded as structure only.
  - Line-ending-only differences are tolerated for documentation files, never for scripts.
- Plain `python -m vraelis` is refused. Use the `vraelis` command, `python -I -m vraelis`, or `python -P -m vraelis`.
- Code is identical to release candidate 0.1.0rc1 apart from the version string and one docstring line in `vraelis/__init__.py`. VENDORED.md lists the source commits
  and the SHA-256 of every module.
