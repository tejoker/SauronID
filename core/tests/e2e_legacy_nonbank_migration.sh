#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${E2E_PORT:-3316}"
API_URL="${API_URL:-http://127.0.0.1:${PORT}}"
ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}"
DB_PATH="${E2E_DB_PATH:-/tmp/sauron-nonbank-migration-${USER:-user}-$$.db}"
LOG_PATH="${E2E_LOG_PATH:-/tmp/sauron-nonbank-migration-${USER:-user}-$$.log}"

SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${DB_PATH}" "${DB_PATH}-wal" "${DB_PATH}-shm"
}
trap cleanup EXIT

ensure_binary() {
  if [[ -n "${E2E_BINARY:-}" ]]; then
    echo "${E2E_BINARY}"
    return
  fi
  if [[ "${E2E_FORCE_BUILD:-0}" != "1" && -x "${ROOT_DIR}/target/debug/sauron-core" ]]; then
    echo "${ROOT_DIR}/target/debug/sauron-core"
    return
  fi
  (cd "${ROOT_DIR}" && cargo build --bin sauron-core >/dev/null)
  echo "${ROOT_DIR}/target/debug/sauron-core"
}

start_server() {
  local binary="$1"
  local revoke_flag="$2"
  ENV=development \
  SAURON_ADMIN_KEY="${ADMIN_KEY}" \
  SAURON_REVOKE_LEGACY_DELEGATED_NONBANK="${revoke_flag}" \
  DATABASE_PATH="${DB_PATH}" \
  PORT="${PORT}" \
  "${binary}" >"${LOG_PATH}" 2>&1 &
  SERVER_PID="$!"
  for _ in $(seq 1 90); do
    if curl -sf "${API_URL}/admin/stats" -H "x-admin-key: ${ADMIN_KEY}" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "Server failed to start. Log:" >&2
  tail -n 80 "${LOG_PATH}" >&2 || true
  exit 1
}

stop_server() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
    SERVER_PID=""
  fi
}

BINARY="$(ensure_binary)"

rand_suffix=$(python3 - <<'PY'
import time, random
print(f"{int(time.time())}{random.randint(1000,9999)}")
PY
)
agent_id="agt_legacy_nonbank_${rand_suffix}"

printf '[E2E migration] boot with migration disabled\n'
start_server "${BINARY}" "0"
stop_server

printf '[E2E migration] insert active delegated_nonbank agent\n'
python3 - <<PY
import sqlite3, time
path = ${DB_PATH@Q}
agent_id = ${agent_id@Q}
now = int(time.time())
conn = sqlite3.connect(path)
conn.execute(
    """
    INSERT INTO agents
      (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, issued_at, expires_at, revoked)
    VALUES (?, ?, ?, ?, 'delegated_nonbank', ?, ?, ?, 0)
    """,
    (
        agent_id,
        'legacy_human_ki',
        'sha256:legacy-nonbank',
        '{"scope":["prove:age"]}',
        '',
        now,
        now + 3600,
    ),
)
conn.commit()
conn.close()
PY

printf '[E2E migration] boot with migration enabled\n'
start_server "${BINARY}" "1"

revoked=$(python3 - <<PY
import sqlite3
path = ${DB_PATH@Q}
agent_id = ${agent_id@Q}
conn = sqlite3.connect(path)
row = conn.execute("SELECT revoked FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
conn.close()
print('' if row is None else row[0])
PY
)

if [[ "${revoked}" != "1" ]]; then
  echo "Expected legacy delegated_nonbank agent to be revoked, got revoked=${revoked}" >&2
  exit 1
fi

echo "[PASS] legacy delegated_nonbank migration revoked active agent"
