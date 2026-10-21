"""Model Lock prototype (private, not released).

r6 (ported from Add-on Lock review 3, H2): `python -m modellock` puts the current folder first on sys.path, so a model
folder containing json.py or hashlib.py would run that file when the tool is run from inside the folder. The current
folder is removed from sys.path here, before the package imports anything else. Prefer `python -I -m modellock`."""
import os as _os, sys as _sys
_cwd = _os.path.normcase(_os.path.abspath(_os.getcwd()))
_sys.path[:] = [p for p in _sys.path if p not in ("", ".") and _os.path.normcase(_os.path.abspath(p)) != _cwd]
__version__ = "0.0.1"
