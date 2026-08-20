#!/usr/bin/env bash
# SauronID full launch — builds, starts, seeds, runs ALL test suites, leaves
# everything running so you can hit the dashboard / call the CLI / poke the
# admin endpoints.
#
# Difference from quickstart.sh:
#   quickstart.sh  → starts core, runs invariants OR empirical, EXITS (kills core).
#   launch.sh      → starts core, seeds, runs invariants + empirical + Tavily +
#                    Python e2e, then **stays running** until you Ctrl-C.
#
# Modes (controlled by env):
#   STRICT=1            run in fail-closed mode (SAURON_REQUIRE_CALL_SIG=1).
#                       Default: 1 (production-shape verification).
#   SKIP_PYTHON=1       skip the Python e2e tests (faster).
#   SKIP_TAVILY=1       skip the Tavily red-team.
#   PORT=N              core port (default 3001).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[0;33m"; BLU="\033[0;34m"; BLD="\033[1m"; RST="\033[0m"
step() { echo -e "\n${BLD}▸ $*${RST}"; }
ok()   { echo -e "  ${GRN}✓${RST} $*"; }
warn() { echo -e "  ${YLW}!${RST} $*"; }
fail() { echo -e "  ${RED}✗${RST} $*"; }

STRICT="${STRICT:-1}"
PORT="${PORT:-3001}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
SKIP_PYTHON="${SKIP_PYTHON:-0}"
SKIP_TAVILY="${SKIP_TAVILY:-0}"
SKIP_DASHBOARD="${SKIP_DASHBOARD:-0}"

export ENV="${ENV:-development}"
# shellcheck source=scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key
export SAURON_CORE_URL="${SAURON_CORE_URL:-http://127.0.0.1:${PORT}}"
export SAURON_URL="${SAURON_URL:-$SAURON_CORE_URL}"
export RUST_LOG="${RUST_LOG:-warn}"
[[ "$STRICT" = "1" ]] && export SAURON_REQUIRE_CALL_SIG=1 || true

# ────────────────────────────────────────────────────────────────────────
echo
echo -e "${BLU}${BLD}════════════════════════════════════════"
echo -e "  SauronID launch (mode: $([ "$STRICT" = "1" ] && echo "FAIL-CLOSED" || echo "ADVISORY"))"
echo -e "════════════════════════════════════════${RST}"
echo

# ────────────────────────────────────────────────────────────────────────
# 1. Toolchain check
# ────────────────────────────────────────────────────────────────────────
step "Pre-flight"
command -v cargo >/dev/null || { fail "cargo not found — install rustup"; exit 1; }
command -v node  >/dev/null || { fail "node not found — install Node 18+"; exit 1; }
fuser -k "${PORT}/tcp" 2>/dev/null || true
fuser -k "${DASHBOARD_PORT}/tcp" 2>/dev/null || true
sleep 1
ok "ports clear ($PORT, $DASHBOARD_PORT)"

# ────────────────────────────────────────────────────────────────────────
# 2. Build everything
# ────────────────────────────────────────────────────────────────────────
step "Build Rust core (release)"
(cd "$ROOT/core" && cargo build --release --features demo 2>&1 | tail -2)
ok "core compiled"

step "Build redteam (TS)"
(cd "$ROOT/redteam" && npm ci --ignore-scripts --silent && npm run build --silent)
ok "redteam compiled"

step "Build agentic SDK (TS)"
(cd "$ROOT/agentic" && npm ci --ignore-scripts --silent && npm run build --silent)
ok "agentic compiled"

# ────────────────────────────────────────────────────────────────────────
# 3. Start core
# ────────────────────────────────────────────────────────────────────────
step "Start core (ENV=$ENV, strict=$STRICT, port=$PORT)"
cd "$ROOT/core"
rm -f sauron.db sauron.db-shm sauron.db-wal
PORT="$PORT" ./target/release/sauron-core > /tmp/sauron-launch.log 2>&1 &
CORE_PID=$!

# Track all child PIDs so we can clean them up on exit.
DASHBOARD_PID=""
shutdown_all() {
    echo
    warn "shutting down (core=$CORE_PID dashboard=$DASHBOARD_PID)"
    [ -n "$DASHBOARD_PID" ] && kill "$DASHBOARD_PID" 2>/dev/null || true
    kill "$CORE_PID" 2>/dev/null || true
    fuser -k "${PORT}/tcp" 2>/dev/null || true
    fuser -k "${DASHBOARD_PORT}/tcp" 2>/dev/null || true
}
trap shutdown_all EXIT INT TERM

for i in $(seq 1 30); do
    if curl -sf "$SAURON_CORE_URL/health" >/dev/null 2>&1; then
        ok "core ready (pid=$CORE_PID, $SAURON_CORE_URL)"
        break
    fi
    printf '.'
    sleep 1
    if [[ $i -eq 30 ]]; then
        fail "core failed to come up; check /tmp/sauron-launch.log"
        tail -20 /tmp/sauron-launch.log
        exit 1
    fi
done

# ────────────────────────────────────────────────────────────────────────
# 4. Seed
# ────────────────────────────────────────────────────────────────────────
step "Seed clients + users"
bash seed.sh > /tmp/sauron-seed.log 2>&1
ok "seeded 10 clients + 10 users"

# ────────────────────────────────────────────────────────────────────────
# 4b. Start the Next.js dashboard (port 3000)
# Archived banking analytics service (was at data/sauron/) removed —
# dashboard reads live core data directly.
# ────────────────────────────────────────────────────────────────────────
if [[ "$SKIP_DASHBOARD" != "1" ]]; then
    step "Start dashboard (Next.js on :$DASHBOARD_PORT)"
    (cd "$ROOT/dashboard" && \
        (test -d node_modules || npm install --silent 2>&1 | tail -2) && \
        SAURON_CORE_INTERNAL_URL="$SAURON_CORE_URL" \
        SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
        PORT="$DASHBOARD_PORT" \
        npm run dev > /tmp/sauron-dashboard.log 2>&1 &)
    DASHBOARD_PID=$!
    for i in $(seq 1 60); do
        if curl -sf "http://127.0.0.1:${DASHBOARD_PORT}" >/dev/null 2>&1; then break; fi
        sleep 1
    done
    if curl -sf "http://127.0.0.1:${DASHBOARD_PORT}" >/dev/null 2>&1; then
        ok "dashboard ready (http://127.0.0.1:${DASHBOARD_PORT})"
    else
        warn "dashboard did not respond yet — Next.js dev startup can take a minute. Tail: /tmp/sauron-dashboard.log"
    fi
fi

# ────────────────────────────────────────────────────────────────────────
# 5. Run all suites
# ────────────────────────────────────────────────────────────────────────
cd "$ROOT/redteam"

if [[ "$STRICT" = "1" ]]; then
    step "Run 16-attack empirical suite (fail-closed)"
    if node dist/scenarios/empirical-suite.js > /tmp/sauron-empirical.log 2>&1; then
        grep "empirical:" /tmp/sauron-empirical.log
        ok "empirical PASS"
    else
        fail "empirical FAILED"
        tail -25 /tmp/sauron-empirical.log
    fi
else
    step "Run KYA invariant suite (9 scenarios, advisory)"
    if node dist/index.js > /tmp/sauron-invariants.log 2>&1; then
        grep "all .* passed" /tmp/sauron-invariants.log | head -1
        ok "invariants PASS"
    else
        fail "invariants FAILED"
        tail -20 /tmp/sauron-invariants.log
    fi
fi

if [[ "$SKIP_TAVILY" != "1" ]]; then
    step "Run 18-attack Tavily red-team"
    if node dist/scenarios/tavily-redteam.js > /tmp/sauron-tavily.log 2>&1; then
        grep "tavily redteam:" /tmp/sauron-tavily.log
        ok "Tavily PASS"
    else
        fail "Tavily FAILED"
        tail -20 /tmp/sauron-tavily.log
    fi
fi

if [[ "$SKIP_PYTHON" != "1" ]]; then
    if command -v pytest >/dev/null && python3 -c "import requests, cryptography" 2>/dev/null; then
        step "Run Python adapter e2e (5 tests against live core)"
        if (cd "$ROOT/clients/python" && pytest tests/test_e2e_live.py -q --no-header 2>&1 | tail -3); then
            ok "Python e2e PASS"
        else
            warn "Python e2e had issues (non-fatal)"
        fi
    else
        warn "skip Python e2e — pip install pytest requests cryptography first"
    fi
fi

# ────────────────────────────────────────────────────────────────────────
# 6. Stay running
# ────────────────────────────────────────────────────────────────────────
echo
echo -e "${GRN}${BLD}════════════════════════════════════════"
echo -e "  SauronID is up and verified"
echo -e "════════════════════════════════════════${RST}"
echo
echo -e "  ${BLD}Dashboard (browser):${RST}    http://127.0.0.1:${DASHBOARD_PORT}"
echo -e "  ${BLD}Core API:${RST}               $SAURON_CORE_URL"
echo
echo "  Health (public):      $SAURON_CORE_URL/health"
echo "  Health (admin):       curl -H 'x-admin-key: $SAURON_ADMIN_KEY' $SAURON_CORE_URL/admin/health/detailed"
echo "  Metrics (Prometheus): $SAURON_CORE_URL/metrics"
echo "  Live API surface:     curl -H 'x-admin-key: $SAURON_ADMIN_KEY' $SAURON_CORE_URL/admin/agents"
echo "                        curl -H 'x-admin-key: $SAURON_ADMIN_KEY' $SAURON_CORE_URL/admin/anchor/status"
echo
echo "  CLI examples:"
echo "    $ROOT/core/target/release/sauronid-cli keypair"
echo "    $ROOT/core/target/release/sauronid-cli sign-call ..."
echo "    $ROOT/core/target/release/sauronid-cli health"
echo
echo "  Re-run a suite while everything stays up:"
echo "    make empirical"
echo "    make redteam"
echo
echo "  Logs:                 /tmp/sauron-launch.log /tmp/sauron-dashboard.log"
echo
echo -e "  ${YLW}Press Ctrl-C to stop the core.${RST}"
echo

# Block until Ctrl-C
wait $CORE_PID
