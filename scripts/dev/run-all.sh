#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key
export SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}"

step() { printf '\n[run-all] %s\n' "$*"; }

install_if_needed() {
  local dir="$1"
  if [[ ! -d "${dir}/node_modules" ]]; then
    (cd "$dir" && npm install --silent)
  fi
}

step "core cargo test + binaries + static checks"
(cd "$ROOT/core" && cargo test && cargo build --bins && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings)

step "immutable CI action references"
"$ROOT/scripts/ci/check-actions-pinned.sh"

step "transparent proof lock + image-ID + verifier checks"
"$ROOT/scripts/ci/verify-transparent-zk.sh"

step "dev leash demo smoke"
"$ROOT/core/tests/smoke_dev_leash_demo.sh"

step "agentic sdk build + crypto/enforcement/stats tests"
install_if_needed "$ROOT/agentic"
(cd "$ROOT/agentic" && npm run build && npm test && npm run test:enforcement && npm run test:stats)

step "python sdk tests"
python -m pytest "$ROOT/clients/python/tests" -q

step "go sdk tests"
(cd "$ROOT/clients/go/sauronid" && go test ./...)

step "redteam build"
install_if_needed "$ROOT/redteam"
(cd "$ROOT/redteam" && npm run build)

step "dashboard tests + lint + build"
install_if_needed "$ROOT/dashboard"
(cd "$ROOT/dashboard" && npm test && npm run lint && npm run build)

step "core confidence suite with leash e2e + redteam"
CONF_SHARED_ITERS="${CONF_SHARED_ITERS:-1}" \
CONF_MIGRATION_ITERS="${CONF_MIGRATION_ITERS:-1}" \
CONF_RESTART_ITERS="${CONF_RESTART_ITERS:-1}" \
CONF_MATRIX_AGENT_TYPES="${CONF_MATRIX_AGENT_TYPES:-claude,openai}" \
# The confidence suite is part of the untracked ZKP issuer-dependent e2e set
# (see .gitignore); it hard-exits without an issuer, which no longer exists.

step "all checks passed"
