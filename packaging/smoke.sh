#!/usr/bin/env bash
# Smoke-test a standalone executable the way a user would run it: from another folder, never importing code from the
# current folder. Usage: packaging/smoke.sh <path to executable>
set -euo pipefail
E="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
T="$(mktemp -d)"; cd "$T"
mkdir -p m proj trap/vraelis
printf 'x' > m/model.safetensors
printf '{"mcpServers":{"a":{"command":"node","args":["s.js"]}}}' > proj/.mcp.json
printf 'x' > proj/s.js
"$E" --version
"$E" models lock m >/dev/null
"$E" models verify m >/dev/null
printf 'y' > m/model.safetensors
set +e; "$E" models verify m >/dev/null; rc=$?; set -e; test "$rc" = 1
"$E" agents lock proj >/dev/null
"$E" agents verify proj >/dev/null
printf 'y' >> proj/s.js
set +e; "$E" agents verify proj >/dev/null; rc=$?; set -e; test "$rc" = 1
# A folder holding its own `vraelis` package must not run: the executable imports only from its own bundle.
printf 'raise SystemExit("imported from the current folder")\n' > trap/vraelis/__init__.py
cp trap/vraelis/__init__.py trap/vraelis/cli.py
(cd trap && "$E" --version)
echo "smoke test passed"
