"""vraelis: offline lockfiles for AI model folders (`vraelis models`) and AI coding-agent add-ons (`vraelis agents`).

Alpha. The two subpackages are the tested tools vendored unchanged apart from each program name (see VENDORED.md).
`python -m vraelis` puts the current folder first on sys.path; the current folder is removed here before anything else
is imported, and __main__ refuses to run without -I or -P (a folder containing its own `vraelis/` package would run
before this code, which nothing in-package can prevent)."""
import os as _os, sys as _sys
_cwd = _os.path.normcase(_os.path.abspath(_os.getcwd()))
_sys.path[:] = [p for p in _sys.path if p not in ("", ".") and _os.path.normcase(_os.path.abspath(p)) != _cwd]
__version__ = "0.1.0"
