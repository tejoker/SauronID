#!/usr/bin/env bash
# Boot a fresh SauronID core on :3021 (dev mode, throwaway SQLite DB), run the
# load driver, tear the core down, print where the results landed.
#
# Tunables (env): N_USERS, C, DURATION_S, PORT, LOADTEST_DB.
#   smoke:     N_USERS=4  C=4  DURATION_S=60  ./run.sh
#   sustained: N_USERS=16 C=16 DURATION_S=900 ./run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# shellcheck source=../../scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key

PORT="${PORT:-3021}"
N_USERS="${N_USERS:-4}"
C="${C:-4}"
DURATION_S="${DURATION_S:-60}"
DB="${LOADTEST_DB:-${TMPDIR:-/tmp}/sauronid-loadtest-$PORT.db}"
CORE_BIN="$ROOT/core/target/release/sauron-core"
ACTION_TOOL="$ROOT/core/target/release/agent-action-tool"

[[ -x "$CORE_BIN" ]] || { echo "missing $CORE_BIN (cd core && cargo build --release --features demo — this harness uses /dev/*)"; exit 1; }
[[ -x "$ACTION_TOOL" ]] || { echo "missing $ACTION_TOOL"; exit 1; }
[[ -d "$HERE/node_modules" ]] || { echo "run 'npm install' in $HERE first"; exit 1; }

STAMP="$(date +%Y%m%dT%H%M%S)"
RESULTS_DIR="$HERE/results"
mkdir -p "$RESULTS_DIR"
CORE_LOG="$RESULTS_DIR/core-$STAMP.log"
RESULTS_FILE="$RESULTS_DIR/run-$STAMP.json"

# Fresh DB every run — soak numbers on a pre-grown DB are a different test.
rm -f "$DB" "$DB-wal" "$DB-shm"

# Backend selection. Default stays SQLite so existing runs are comparable; set
# SAURON_DB_BACKEND=postgres + DATABASE_URL to soak the Postgres tier instead.
# The SQLite path is still handed a DATABASE_PATH because the core opens that
# pool either way — under Postgres it is the dev-only default, not the store.
BACKEND="${SAURON_DB_BACKEND:-sqlite}"
if [[ "$BACKEND" == "postgres" || "$BACKEND" == "pg" || "$BACKEND" == "postgresql" ]]; then
    if [[ -z "${DATABASE_URL:-}" ]]; then
        echo "[run.sh] SAURON_DB_BACKEND=$BACKEND needs DATABASE_URL" >&2
        exit 1
    fi
    echo "[run.sh] backend=postgres ($( echo "$DATABASE_URL" | sed -E 's#//[^@]*@#//***@#' ))"
else
    echo "[run.sh] backend=sqlite"
fi

echo "[run.sh] booting core on :$PORT (db=$DB, log=$CORE_LOG)"
ENV=development \
SAURON_REQUIRE_CALL_SIG=1 \
SAURON_ENABLE_DEV_ENDPOINTS=1 \
SAURON_ADMIN_CROSS_TENANT=1 \
SAURON_GLOBAL_RATE_LIMIT_RPS=5000 \
SAURON_GLOBAL_RATE_LIMIT_BURST=2000 \
SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
SAURON_DB_BACKEND="$BACKEND" \
DATABASE_URL="${DATABASE_URL:-}" \
PORT="$PORT" \
DATABASE_PATH="$DB" \
"$CORE_BIN" >"$CORE_LOG" 2>&1 &
CORE_PID=$!
cleanup() { kill "$CORE_PID" 2>/dev/null || true; wait "$CORE_PID" 2>/dev/null || true; }
trap cleanup EXIT

for i in $(seq 1 60); do
    if curl -sf "http://localhost:$PORT/healthz" >/dev/null 2>&1; then break; fi
    sleep 0.5
    if [[ $i -eq 60 ]]; then
        echo "[run.sh] core did not become healthy; last log lines:" >&2
        tail -n 20 "$CORE_LOG" >&2
        exit 1
    fi
done
echo "[run.sh] core healthy (pid $CORE_PID)"

set +e
(
    cd "$HERE" &&
    CORE_URL="http://localhost:$PORT" \
    CORE_PID="$CORE_PID" \
    DATABASE_PATH="$DB" \
    SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
    SAURONID_AGENT_ACTION_TOOL="$ACTION_TOOL" \
    N_USERS="$N_USERS" C="$C" DURATION_S="$DURATION_S" \
    RESULTS_FILE="$RESULTS_FILE" \
    npx tsx loadtest.ts
)
DRIVER_RC=$?
set -e

# Post-run forensics while core is still up: nonce/egress table sizes and the
# background GC's own accounting (SAURON_GC_INTERVAL_SECS default 300s).
if command -v sqlite3 >/dev/null 2>&1; then
    echo "[run.sh] table sizes after run:"
    sqlite3 "$DB" \
        "SELECT 'agent_call_nonces', COUNT(*) FROM agent_call_nonces;
         SELECT 'agent_egress_log', COUNT(*) FROM agent_egress_log;
         SELECT 'risk_rate_counters', COUNT(*) FROM risk_rate_counters;" || true
fi
echo "[run.sh] core GC log lines (sauron::gc):"
grep 'sauron::gc' "$CORE_LOG" | tail -n 10 || echo "  (none yet — GC ticks every 300s)"

cleanup
trap - EXIT

echo "[run.sh] core log:      $CORE_LOG"
echo "[run.sh] results file:  $RESULTS_FILE"
exit "$DRIVER_RC"
