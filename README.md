# Vraelis Prompto

**Alpha (0.1.2).** Product page: [vraelis.com/prompto](https://vraelis.com/prompto). The command is `vraelis`. No outside user has run it yet. Interfaces and lockfile formats may change.

`vraelis` keeps a lockfile of exactly what you approved, then tells you later whether it is still the same. It runs
offline, uses only the Python standard library, never loads a model and never launches anything.

- `vraelis models` pins the exact bytes of an AI model folder (safetensors, GGUF, configs, tokenizer). It also checks
  the folder's structure: truncated weights, bad GGUF headers, shard indexes naming missing shards, Git LFS pointers
  and invalid JSON. Optionally, it checks a publisher's Sigstore signature against a signer you name.
- `vraelis agents` (**preview**) pins an AI coding agent's add-ons:
  - MCP servers (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`);
  - Claude Code settings (hooks and permissions, as separate diffable entries);
  - skills, agents and commands;
  - the local scripts those configs launch.

Every result is one of **Unchanged**, **Changed** or **Can't verify**, and says what it shows and what it does not.
Nothing here is a security assessment (see NOTICE).

## Download

Standalone executables, no Python needed (unsigned for now, so Windows and macOS warn on first run). Check each file
against `SHA256SUMS-downloads` from the same release.

| System | File |
|---|---|
| Windows (x64) | [vraelis-0.1.2-windows-x64.exe](https://github.com/sansxelt/vraelis-cli/releases/download/v0.1.2/vraelis-0.1.2-windows-x64.exe) |
| macOS (Apple silicon) | [vraelis-0.1.2-macos-arm64.tar.gz](https://github.com/sansxelt/vraelis-cli/releases/download/v0.1.2/vraelis-0.1.2-macos-arm64.tar.gz) |
| macOS (Intel) | [vraelis-0.1.2-macos-x64.tar.gz](https://github.com/sansxelt/vraelis-cli/releases/download/v0.1.2/vraelis-0.1.2-macos-x64.tar.gz) |
| Linux (x64) | [vraelis-0.1.2-linux-x64.tar.gz](https://github.com/sansxelt/vraelis-cli/releases/download/v0.1.2/vraelis-0.1.2-linux-x64.tar.gz) |

They are built from the release's source by `.github/workflows/downloads.yml` and smoke-tested before they are attached.

## Install with pip

Python 3.11 or newer. Not on PyPI yet: install the wheel from the
[latest GitHub release](https://github.com/sansxelt/vraelis-cli/releases/latest) and check it against `SHA256SUMS`
from the same release.

```
pip install https://github.com/sansxelt/vraelis-cli/releases/download/v0.1.2/vraelis-0.1.2-py3-none-any.whl
pip install "vraelis[signature] @ https://github.com/sansxelt/vraelis-cli/releases/download/v0.1.2/vraelis-0.1.2-py3-none-any.whl"   # adds model-signing 1.1.1 for the optional signature check
```

## Use

```
vraelis models lock   ./my-model        # writes ./my-model/modellock.json
vraelis models verify ./my-model        # Unchanged / Changed / Can't verify
vraelis models diff   approved.json new.json
vraelis models signature ./my-model --identity <expected signer> --issuer <OIDC issuer>   # optional, contacts Sigstore

vraelis agents lock   ./project         # writes ./project/addonlock.json
vraelis agents verify ./project
```

| Exit code | Meaning |
|---|---|
| 0 | Unchanged |
| 1 | Changed (each change is listed) |
| 2 | Can't verify (missing or invalid lockfile, unsafe path or link, unreadable file, any internal error) |
| 3 | `lock --strict` refused |

### Running it safely

You can run it as the installed `vraelis` command, as `python -I -m vraelis`, or from a checkout with
`PYTHONPATH=<checkout> python -P -m vraelis`.

A plain `python -m vraelis` is refused. Python would put the current folder first on its module path, so a folder
containing its own `vraelis` package could run code before vraelis starts.

## What a result does not show

- That a model, add-on or server is safe, correct or behaves as intended.
- Which model a device or server actually loads, or which tools a server exposes at run time (nothing is launched).
- Who published the files, unless you run the optional signature check against a signer you chose.
- Changes inside packages fetched at launch (`npx`, `uvx`, `docker`). Floating or unpinned packages are flagged.
- Changes in files a launched script itself imports or loads. Each launched script carries this note.

## Secrets

**`vraelis models`**
- Records file names, sizes and digests only.
- A file named like a secrets file (`.env`, keys, `id_rsa`, `.npmrc`, ...) is recorded as present only. It is never
  digested or measured.
  - Its content is therefore not checked. `lock`, `verify` and `diff` list such files under "Not checked (presence
    only)".

**`vraelis agents`**
- Never records env or header values unless you pin them. Pinned values are stored in plain text, by your choice.
- Some files are recorded as structure only:
  - `.claude/settings.local.json`;
  - user-level `--config` files;
  - any project config or settings file that the project's own ignore rules exclude.
- Structure only means keys, booleans, numbers, env and header names, and values you pinned.
- The ignore rules it reads are `.git/info/exclude` and the `.gitignore` files inside the project. It never runs git,
  and it does not read ignore rules above the project folder or git's global excludes file. A file excluded only by
  those rules is treated as shared.
- Patterns follow git's own matching rules, including classes such as `[[:punct:]]`.
  - A file counts as ignored if git would ignore it with either case-sensitive or case-insensitive matching.
  - Any pattern it cannot parse makes the file count as private.
- In shared project files, credentials it recognises are redacted on a best-effort basis. **Read a lockfile before you
  commit or share it.**

## Related tools: when to use something else

These tools do overlapping jobs, several of them well. This list is from a scan on 20 Oct 2026, so check each
project's current docs. No head-to-head comparison has been run yet.

| If you want | Consider |
|---|---|
| Signed model releases, verified against the publisher's identity | [OpenSSF model_signing](https://github.com/sigstore/model-transparency) (`vraelis models signature` wraps its 1.1.1 verifier) |
| To check a model downloaded from the Hugging Face Hub against the Hub's own revision | `hf cache verify` in [huggingface_hub](https://huggingface.co/docs/huggingface_hub/main/en/package_reference/cli) |
| A model lockfile that also covers `hf:` and `ollama:` references | [knowyourai](https://github.com/ppradyoth/knowyourai) |
| To scan pickle files for malicious code (vraelis does not) | [ModelScan](https://github.com/protectai/modelscan), [picklescan](https://github.com/mmaitre314/picklescan), [fickling](https://github.com/trailofbits/fickling) |
| Agent add-on pinning across many clients, including npm tarball integrity and runtime probing | [heldfast](https://github.com/rufat325/heldfast), [kova](https://github.com/ian-hickey/kova) |
| To pin MCP tool descriptions (this needs the server to be launched) | [AgentGate](https://github.com/wookat/agentgate) |
| To enforce, rather than report, which MCP servers and settings are allowed in Claude Code | Claude Code [managed MCP settings](https://code.claude.com/docs/en/managed-mcp) and the [`ConfigChange` hook](https://code.claude.com/docs/en/hooks) |

What vraelis tries to do in one place is different, but not yet shown to be better:
- a "Can't verify" result kept separate from "Changed";
- completeness checks (missing shards, LFS pointer stubs, truncation);
- for agents, permission and hook changes reported as entries, launched-script bytes, and env and header names without
  their values;
- never launching anything.

## How it was tested

Testing was self-run, not independent, and no outside user has run it yet.

**Model checks**
- Three sets of real broken releases, collected blind by a separate agent, with predictions committed first.
- On the third set, 23 of 24 predictions matched, 5 of 22 runnable defects were detected, and there were 0 false alarms
  on 15 healthy models.
- It is a narrow structural gate. Most real breakage (wrong config values, templates, tokenizers) is outside what it
  checks.

**Agent add-ons**
- Four sets of real configuration changes from 61 public repositories, collected blind.
- On the most recent set, all 30 predictions matched: 19 of 22 changes were detected, with 0 false alarms.
- The 3 misses were in code loaded by launched scripts, or in a project folder run as a whole.

**Reviews and unit tests**
- Adversarial reviews by separate AI agents found and fixed:
  - in the agents tool: 28, 21 and 14 findings;
  - in the models tool's later changes: 6 findings.
- There were also repeated reviews by another AI engineering agent. AI review is not independent human review.
- Unit tests and mutation tests cover both tools: each guard is removed in turn and must fail a test.
- CI runs the suite on Linux, Windows and macOS with Python 3.11 to 3.13.

## Contributing and security

- Bug reports and pull requests are welcome.
- Report a security issue privately as described in [SECURITY.md](SECURITY.md).

Licence: Apache-2.0 (LICENSE, NOTICE).
