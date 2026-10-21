"""Add-on Lock (private prototype).

r5 (review 3, H2): `python -m addonlock` puts the current folder first on sys.path, so a project file named after a
standard module (shlex.py, json.py, ...) would run when the tool is run from inside the project. The current folder
is removed from sys.path here, before the package imports anything else. Prefer `python -I -m addonlock` or the
`addonlock` console script."""
import os as _os, sys as _sys
_cwd = _os.path.normcase(_os.path.abspath(_os.getcwd()))
_sys.path[:] = [p for p in _sys.path if p not in ("", ".") and _os.path.normcase(_os.path.abspath(p)) != _cwd]
__version__ = "0.0.1"
