"""Entry point for the standalone Vraelis Prompto executables (built with PyInstaller).

A frozen executable imports only from its own bundle, never from the current folder, so the -I / -P guard in
vraelis/__main__.py is not needed here."""
import sys

from vraelis.cli import run

sys.exit(run())
