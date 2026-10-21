"""vraelis command line: dispatches to the two tools.

  vraelis models lock|verify|diff|signature ...   pin and verify the exact bytes of an AI model folder
  vraelis agents lock|verify|diff ...             pin and verify an AI coding agent's add-on configuration

Exit codes (both tools): 0 unchanged, 1 changed, 2 can't verify (including any internal error), 3 lock refused."""
import sys

from . import __version__

USAGE = """usage: vraelis {models,agents} ...

  vraelis models lock|verify|diff|signature   pin and verify the exact bytes of an AI model folder (offline;
                                              `signature` is optional and contacts Sigstore)
  vraelis agents lock|verify|diff             pin and verify an AI coding agent's add-on configuration (offline;
                                              never launches anything)

Exit codes: 0 unchanged, 1 changed, 2 can't verify, 3 lock refused. Results say what they show and what they do not;
nothing here is a security assessment. Run `vraelis models -h` or `vraelis agents -h` for details."""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE); return 0 if argv else 2
    if argv[0] == "--version":
        print(f"vraelis {__version__}"); return 0
    tool, rest = argv[0], argv[1:]
    if tool == "models":
        from .models import cli as models_cli
        return models_cli.main(rest)
    if tool == "agents":
        from .agents import cli as agents_cli
        return agents_cli.main(rest)
    print(f"vraelis: unknown tool {tool!r}\n\n{USAGE}", file=sys.stderr)
    return 2


def run(argv=None):
    """Any unexpected error exits 2 (Can't verify), never 1 (Changed)."""
    try: return main(argv)
    except SystemExit: raise
    except BaseException as e:  # noqa: BLE001 - the exit code must never claim a verdict after a crash
        if isinstance(e, KeyboardInterrupt): raise
        print(f"Can't verify: internal error: {type(e).__name__}", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(run())
