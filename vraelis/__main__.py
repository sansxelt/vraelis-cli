"""Entry point for `python -I -m vraelis` (installed) or `PYTHONPATH=<checkout> python -P -m vraelis` (source).

With a plain `python -m vraelis`, a folder that contains its own `vraelis` package or same-named modules can run before
any of this code; isolated (-I) or safe-path (-P) mode closes that, and so does the installed `vraelis` command.
Started through -m without either, vraelis refuses (exit 2)."""
import sys

if not (sys.flags.isolated or getattr(sys.flags, "safe_path", False)):
    print("Can't verify: run vraelis in isolated mode: python -I -m vraelis ... (or use the installed `vraelis` command). "
          "Without -I, Python can run code from the current folder before vraelis starts.", file=sys.stderr)
    sys.exit(2)

from .cli import run

sys.exit(run())
