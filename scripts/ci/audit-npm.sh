#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
args=(--audit-level=high)
if [[ "${SAURON_NPM_AUDIT_OFFLINE:-0}" == "1" ]]; then
  args+=(--offline)
fi

for directory in \
  sdk/typescript sdk/mcp-server dashboard redteam redteam/loadtest \
  examples/typescript-quickstart; do
  printf '[npm audit] %s\n' "$directory"
  (cd "$ROOT/$directory" && npm audit "${args[@]}")
done
