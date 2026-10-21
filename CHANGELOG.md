# Changelog

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
