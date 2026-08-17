#!/usr/bin/env bash
# Postgres backend integration test.
#
# ## What this used to assert, and why it is inverted
#
# This test was written to PASS when the two backends disagreed. Phase 3's
# Postgres swap was incomplete: `SAURON_DB_BACKEND=postgres` built a Postgres
# pool that almost nothing used, so an agent registered through the normal path
# landed in the SQLite sidecar and the Postgres `agents` table stayed empty.
# The test registered an agent, saw it in SQLite, saw Postgres empty, and
# reported "DRIFT CONFIRMED" as a success. Its passing was the bug it existed
# to document.
#
# The call-site sweep moved acquisition to the dispatching guard, so that is no
# longer true, and the assertion is now the other way round:
#
#   1. Start the core with SAURON_DB_BACKEND=postgres against a schema-complete
#      Postgres.
#   2. Register agents through the ordinary path.
#   3. Assert the rows are in the Postgres `agents` table.
#   4. Assert the SQLite sidecar's `agents` table is EMPTY.
#
# Step 4 is the one that matters. Step 3 alone would also pass on a build that
# wrote to both, and "it worked" and "it wrote to the backend you configured"
# are different claims.
#
# Skipped automatically when Docker is not available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=../../scripts/lib/dev_secrets.sh
source "${ROOT}/scripts/lib/dev_secrets.sh"
load_dev_admin_key
CORE_BIN="$ROOT/core/target/release/sauron-core"
TEST_DB_NAME="sauronid_drift_test"
PG_PORT=15432
PG_USER="sauronid"
PG_PASS="sauronid_drift_test"
DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${TEST_DB_NAME}"
# Not 3001: a docker-compose stack commonly holds that port, and this test must
# never silently talk to a server it did not start — it would then be asserting
# about somebody else's database.
CORE_PORT="${DRIFT_CORE_PORT:-3101}"
SIDECAR="$ROOT/core/target/drift-sidecar.db"

red()   { echo -e "\033[0;31m$*\033[0m"; }
green() { echo -e "\033[0;32m$*\033[0m"; }
ylw()   { echo -e "\033[0;33m$*\033[0m"; }

CORE_PID=""
cleanup() {
    [[ -n "$CORE_PID" ]] && kill "$CORE_PID" 2>/dev/null || true
    # Belt and braces: a leftover server would fail the next run's port check.
    [[ -n "$CORE_PID" ]] && { sleep 1; kill -9 "$CORE_PID" 2>/dev/null || true; }
    docker rm -f sauronid_drift_pg >/dev/null 2>&1 || true
    rm -f "$SIDECAR" "$SIDECAR-shm" "$SIDECAR-wal"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    ylw "[SKIP] docker unavailable; cannot run the Postgres backend test"
    exit 0
fi

if [[ ! -x "$CORE_BIN" ]]; then
    red "[ERROR] core binary not found at $CORE_BIN; run 'cargo build --release' first"
    exit 1
fi

if (exec 3<>/dev/tcp/127.0.0.1/"$CORE_PORT") 2>/dev/null; then
    red "[ERROR] port $CORE_PORT is already in use."
    echo "  This test must own the server it asserts about. Free the port, or set"
    echo "  DRIFT_CORE_PORT to one that is free."
    exit 1
fi

# 1. Postgres, with the COMPLETE schema.
#
# The previous version applied only 0001_initial.sql. That was survivable when
# nothing read Postgres; now that everything does, a missing migration shows up
# as `relation "policies" does not exist` at boot rather than as drift.
echo "▸ starting Postgres docker on :$PG_PORT"
docker run -d --name sauronid_drift_pg \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASS" \
    -e POSTGRES_DB="$TEST_DB_NAME" \
    -p "${PG_PORT}:5432" \
    postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do
    docker exec sauronid_drift_pg pg_isready -U "$PG_USER" -d "$TEST_DB_NAME" >/dev/null 2>&1 && break
    sleep 1
done

echo "▸ applying every migration in migrations/postgres/"
for f in "$ROOT"/migrations/postgres/*.sql; do
    if ! docker exec -i sauronid_drift_pg psql -q -v ON_ERROR_STOP=1 \
            -U "$PG_USER" -d "$TEST_DB_NAME" < "$f" >/tmp/drift-migrate.log 2>&1; then
        red "[ERROR] migration $(basename "$f") failed:"
        tail -5 /tmp/drift-migrate.log
        exit 1
    fi
done

# 2. Boot the core against Postgres, with its own sidecar file.
echo "▸ starting core on :$CORE_PORT with SAURON_DB_BACKEND=postgres"
rm -f "$SIDECAR" "$SIDECAR-shm" "$SIDECAR-wal"
(cd "$ROOT/core" && \
    SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
    ENV=development \
    SAURON_RUNTIME_ENV=development \
    SAURON_ENABLE_DEV_ENDPOINTS=1 \
    SAURON_ADMIN_CROSS_TENANT=1 \
    SAURON_GLOBAL_RATE_LIMIT_RPS=5000 \
    SAURON_GLOBAL_RATE_LIMIT_BURST=2000 \
    PORT="$CORE_PORT" \
    DATABASE_PATH="$SIDECAR" \
    SAURON_DB_BACKEND=postgres \
    DATABASE_URL="$DATABASE_URL" \
    exec "$CORE_BIN" > /tmp/sauron-drift.log 2>&1) &
CORE_PID=$!
for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:${CORE_PORT}/admin/stats" \
        -H "x-admin-key: $SAURON_ADMIN_KEY" >/dev/null 2>&1 && break
    sleep 1
done
if ! curl -sf "http://127.0.0.1:${CORE_PORT}/admin/stats" \
        -H "x-admin-key: $SAURON_ADMIN_KEY" >/dev/null 2>&1; then
    red "[ERROR] core did not come up; last lines of /tmp/sauron-drift.log:"
    tail -20 /tmp/sauron-drift.log
    exit 1
fi

# 3. Register agents through the ordinary path.
# seed.sh reads SAURON_URL, not SAURON_CORE_URL — passing the wrong one sent it
# at whatever was on the default port, which is how this test previously
# seeded somebody else's server and then asserted about its own database.
SAURON_URL="http://127.0.0.1:${CORE_PORT}" bash "$ROOT/core/seed.sh" >/tmp/drift-seed.log 2>&1 || true
(cd "$ROOT/redteam" && \
    SAURON_CORE_URL="http://127.0.0.1:${CORE_PORT}" \
    API_URL="http://127.0.0.1:${CORE_PORT}" \
    SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
    node dist/index.js >/tmp/drift-redteam.log 2>&1 || true)

# 4. Where did the rows go?
echo
echo "═══════════════════════════════════════════════════════════"
echo "  Postgres backend verification"
echo "═══════════════════════════════════════════════════════════"

PG_AGENTS=$(docker exec -i sauronid_drift_pg psql -U "$PG_USER" -d "$TEST_DB_NAME" \
    -tAc "SELECT COUNT(*) FROM agents;" | tr -d '[:space:]')
PG_NONCES=$(docker exec -i sauronid_drift_pg psql -U "$PG_USER" -d "$TEST_DB_NAME" \
    -tAc "SELECT COUNT(*) FROM agent_call_nonces;" | tr -d '[:space:]')
PG_RECEIPTS=$(docker exec -i sauronid_drift_pg psql -U "$PG_USER" -d "$TEST_DB_NAME" \
    -tAc "SELECT COUNT(*) FROM agent_action_receipts;" | tr -d '[:space:]')

# The sidecar is a plain SQLite file. If the table is missing entirely that is
# also "no rows here", which is the claim being checked.
sidecar_count() {
    python3 - "$SIDECAR" "$1" <<'PY'
import sqlite3, sys
try:
    con = sqlite3.connect(sys.argv[1])
    print(con.execute(f"SELECT COUNT(*) FROM {sys.argv[2]}").fetchone()[0])
except Exception:
    print(0)
PY
}
SQLITE_AGENTS=$(sidecar_count agents)
SQLITE_RECEIPTS=$(sidecar_count agent_action_receipts)

echo "  Postgres agents                : ${PG_AGENTS}"
echo "  Postgres agent_call_nonces     : ${PG_NONCES}"
echo "  Postgres agent_action_receipts : ${PG_RECEIPTS}"
echo "  SQLite sidecar agents          : ${SQLITE_AGENTS}"
echo "  SQLite sidecar receipts        : ${SQLITE_RECEIPTS}"
echo

FAILED=0
if [[ "$PG_AGENTS" -eq 0 ]]; then
    red "FAIL: no agents in Postgres — registration is not reaching the configured backend."
    FAILED=1
fi
if [[ "$SQLITE_AGENTS" -ne 0 ]]; then
    red "FAIL: ${SQLITE_AGENTS} agents in the SQLite sidecar — the write path is still pinned."
    FAILED=1
fi
if [[ "$SQLITE_RECEIPTS" -ne 0 ]]; then
    red "FAIL: ${SQLITE_RECEIPTS} receipts in the SQLite sidecar — the action path is still pinned."
    FAILED=1
fi

if [[ "$FAILED" -eq 0 ]]; then
    green "OK: ${PG_AGENTS} agents and ${PG_RECEIPTS} receipts in Postgres, none in the sidecar."
    echo "    SAURON_DB_BACKEND=postgres moves the deployment, which is what it claims."
    exit 0
fi

echo "  Server log: /tmp/sauron-drift.log"
exit 1
