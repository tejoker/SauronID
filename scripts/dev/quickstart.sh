#!/usr/bin/env bash
# SauronID quickstart — cold clone to a running, 16-attack-suite-passing core.
#
# No time estimate here on purpose. A cold build compiles several hundred
# crates and takes roughly 15-45 minutes depending on hardware and cache state,
# which is what README.md says; the "~60s" this line used to claim was the warm
# rerun and set an expectation the first run could never meet.
#
# Default mode: development, advisory call-sig (existing scenarios pass).
# Set SAURON_REQUIRE_CALL_SIG=1 in env to run fail-closed empirical suite.
#
# What this does:
#   1. Builds the Rust core (release).
#   2. Builds the TypeScript clients (redteam, agentic).
#   3. Starts the core in the background, waits for /admin/stats to respond.
#   4. Seeds 10 dev clients + 10 dev users via core HTTP APIs.
#   5. Runs the 9-scenario invariant suite.
#   6. (If SAURON_REQUIRE_CALL_SIG=1) Runs the 16-attack empirical suite.
#   7. Reports a green or red final status.
#
# Cleanup happens on exit: server is killed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# ────────────────────────────────────────────────────────────────────────
RED="\033[0;31m"
GRN="\033[0;32m"
YLW="\033[0;33m"
BLD="\033[1m"
RST="\033[0m"

step() { echo -e "\n${BLD}▸ $*${RST}"; }
ok()   { echo -e "  ${GRN}✓${RST} $*"; }
fail() { echo -e "  ${RED}✗${RST} $*"; }

# ────────────────────────────────────────────────────────────────────────
# 0. Defaults — operator can override via env
# ────────────────────────────────────────────────────────────────────────
export ENV="${ENV:-development}"
# shellcheck source=scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key
# The core binds $PORT, so the port belongs in one variable rather than being
# spelled 3001 in three places. Overridable so this can run beside an existing
# stack (a `docker compose up` already publishing 3001) instead of fighting it
# for the port — the previous version killed whatever held 3001 and then bound
# it, which is a rude default on a developer's own machine.
export PORT="${PORT:-3001}"
export SAURON_CORE_URL="${SAURON_CORE_URL:-http://127.0.0.1:$PORT}"
export SAURON_URL="${SAURON_URL:-$SAURON_CORE_URL}"
export RUST_LOG="${RUST_LOG:-warn}"

# Fail closed by default: with the call-signature layer advisory, an unsigned
# request gets 200 and the same body as a signed one, so an evaluator would be
# looking at a leash that is not holding. Set SAURON_REQUIRE_CALL_SIG=0 to run
# advisory during a first integration — that path also runs the 9-scenario
# invariant suite instead of the 16-attack fail-closed suite.
ENFORCE_MODE="${SAURON_REQUIRE_CALL_SIG:-1}"
case "$ENFORCE_MODE" in
    1|true|yes|TRUE|YES|True|Yes) ENFORCE_MODE=1 ;;
    *) ENFORCE_MODE=0 ;;
esac

# ────────────────────────────────────────────────────────────────────────
# 1. Cleanup any previous run + ensure deps exist
# ────────────────────────────────────────────────────────────────────────
step "Pre-flight"
if ! command -v cargo >/dev/null 2>&1; then
    fail "cargo not found — install rustup from https://rustup.rs"
    exit 1
fi
if ! command -v node >/dev/null 2>&1; then
    fail "node not found — install Node 18+ from https://nodejs.org"
    exit 1
fi
# A Rust toolchain is not enough: several dependencies build C and every
# binary needs a linker. Without one the build dies minutes later, deep inside
# a build script, as "error: linker `cc` not found" — check it here instead.
if ! command -v cc >/dev/null 2>&1; then
    fail "no C linker on PATH (cc) — cargo cannot link any binary"
    echo "      Debian/Ubuntu : sudo apt-get install build-essential pkg-config"
    echo "      Fedora/RHEL   : sudo dnf install gcc gcc-c++ make pkgconf"
    echo "      macOS         : xcode-select --install"
    exit 1
fi

# Free any lingering server on the target port. fuser (psmisc) is absent on
# macOS and on slim Linux images, so fall back through what is actually there.
free_port() {
    local port="$1"
    if command -v fuser >/dev/null 2>&1; then
        fuser -k "${port}/tcp" 2>/dev/null || true
    elif command -v lsof >/dev/null 2>&1; then
        lsof -ti "tcp:${port}" 2>/dev/null | xargs -r kill 2>/dev/null || true
    else
        # Nothing to enumerate with: a stale listener surfaces as a bind error
        # at startup, which names the port clearly enough to act on.
        return 0
    fi
}
free_port "$PORT"
sleep 1
ok "ports clear, toolchain present"

# ────────────────────────────────────────────────────────────────────────
# 2. Build the Rust core
# ────────────────────────────────────────────────────────────────────────
step "Build Rust core (release)"
cd "$ROOT/core"
cargo build --release --features demo 2>&1 | tail -3
ok "core compiled"

# ────────────────────────────────────────────────────────────────────────
# 3. Build the TS clients
# ────────────────────────────────────────────────────────────────────────
step "Build redteam (TS)"
cd "$ROOT/redteam"
npm ci --ignore-scripts --silent
npm run build --silent
ok "redteam compiled"

step "Build agentic SDK (TS)"
cd "$ROOT/sdk/typescript"
npm ci --ignore-scripts --silent
npm run build --silent
ok "agentic compiled"

# ────────────────────────────────────────────────────────────────────────
# 4. Start the core, wait for health
# ────────────────────────────────────────────────────────────────────────
step "Start core (ENV=$ENV, enforce_call_sig=$ENFORCE_MODE)"
cd "$ROOT/core"
rm -f sauron.db sauron.db-shm sauron.db-wal
if [ "$ENFORCE_MODE" = "1" ]; then
    export SAURON_REQUIRE_CALL_SIG=1
fi
# Dev-only: the seed step and the suites read deployment-global admin views
# (/admin/stats, /admin/users), which regular tenant-scoped keys cannot.
export SAURON_ADMIN_CROSS_TENANT=1
# Dev-only: seeding and the empirical suite use /dev/register_user and
# /dev/buy_tokens, which are unmounted unless explicitly enabled.
export SAURON_ENABLE_DEV_ENDPOINTS=1
# Dev-only: the empirical suite is a deliberate localhost load generator; the
# default per-IP limiter (200 rps, burst 50) throttles it into 429s.
export SAURON_GLOBAL_RATE_LIMIT_RPS=5000
export SAURON_GLOBAL_RATE_LIMIT_BURST=2000
# Cargo writes to $CARGO_TARGET_DIR when it is set, which is common (a shared
# target dir, sccache, or simply a checkout whose own target/ is not writable).
# Hardcoding ./target/release meant the build succeeded and the launch then
# failed with "no such file or directory" pointing at a path cargo never used.
CORE_BIN="${CARGO_TARGET_DIR:-$ROOT/core/target}/release/sauron-core"
if [ ! -x "$CORE_BIN" ]; then
    fail "built core binary not found at $CORE_BIN"
    exit 1
fi
"$CORE_BIN" > /tmp/sauron-quickstart.log 2>&1 &
CORE_PID=$!
trap 'kill $CORE_PID 2>/dev/null || true; free_port "$PORT"' EXIT

# Wait for readiness (liveness endpoint; authz-free)
for i in $(seq 1 30); do
    if curl -sf "$SAURON_CORE_URL/healthz" >/dev/null 2>&1; then
        ok "core ready (pid=$CORE_PID)"
        break
    fi
    printf '.'
    sleep 1
    if [ "$i" = "30" ]; then
        fail "core failed to come up; check /tmp/sauron-quickstart.log"
        tail -30 /tmp/sauron-quickstart.log
        exit 1
    fi
done

# ────────────────────────────────────────────────────────────────────────
# 5. Seed clients + users
# ────────────────────────────────────────────────────────────────────────
step "Seed clients + users"
bash seed.sh > /tmp/sauron-seed.log 2>&1
ok "seeded 10 clients + 10 users"

# ────────────────────────────────────────────────────────────────────────
# 6. Run the test suite appropriate to the mode
#
# Advisory mode (default): the 9-scenario invariant suite. It uses legacy
# call shapes that pre-date the extended per-call-sig coverage, so it only
# fits cleanly when call-sig is advisory.
#
# Fail-closed mode (SAURON_REQUIRE_CALL_SIG=1): the 16-attack empirical
# suite. Every scenario sends the full header set including the
# config-digest. This is the production-shape verification.
# ────────────────────────────────────────────────────────────────────────
cd "$ROOT/redteam"
if [ "$ENFORCE_MODE" = "1" ]; then
    step "Run 16-attack empirical suite (fail-closed mode)"
    if node dist/scenarios/suites/empirical-suite.js > /tmp/sauron-empirical.log 2>&1; then
        grep "empirical:" /tmp/sauron-empirical.log
        ok "empirical 16/16"
    else
        fail "empirical suite failed; tail of log:"
        tail -25 /tmp/sauron-empirical.log
        exit 1
    fi
else
    step "Run KYA invariant suite (9 scenarios, advisory mode)"
    if node dist/index.js > /tmp/sauron-invariants.log 2>&1; then
        grep "all .* run(s) passed\|FAIL" /tmp/sauron-invariants.log | head -3
        ok "invariants pass"
    else
        fail "invariants failed; tail of log:"
        tail -20 /tmp/sauron-invariants.log
        exit 1
    fi
fi

# ────────────────────────────────────────────────────────────────────────
# 8. Final status
# ────────────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════"
echo -e "  ${GRN}${BLD}SauronID quickstart: GREEN${RST}"
echo "════════════════════════════════════════"
echo
echo "  Core:        $SAURON_CORE_URL"
echo "  Metrics:     $SAURON_CORE_URL/metrics"
echo "  Admin key:   $SAURON_ADMIN_KEY"
echo "  Logs:        /tmp/sauron-quickstart.log"
echo
echo "  Next:"
echo "    • run a Python adapter: see sdk/python/sauronid_client/README.md"
echo "    • verify an audit anchor: redteam/"
echo "    • production deploy: deploy/README.md"
echo
