#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# shellcheck source=tests/lib/zkp_fixture.sh
source "${ROOT_DIR}/tests/lib/zkp_fixture.sh"

SHARED_ITERS="${CONF_SHARED_ITERS:-6}"
MIGRATION_ITERS="${CONF_MIGRATION_ITERS:-6}"
RESTART_ITERS="${CONF_RESTART_ITERS:-6}"
MATRIX_AGENT_TYPES="${CONF_MATRIX_AGENT_TYPES:-claude,openai,gemini,qwen,mistral,openclaw,autogen,langgraph,crewai}"
MATRIX_JITTER_MS_MAX="${CONF_MATRIX_JITTER_MS_MAX:-0}"
MATRIX_FAULT_PROBE_PCT="${CONF_MATRIX_FAULT_PROBE_PCT:-0}"
LOG_DIR="${CONF_LOG_DIR:-/tmp/sauron-confidence-logs-$$}"
FAIL_BUNDLE="${CONF_FAIL_BUNDLE:-/tmp/sauron-confidence-failure-$$.tar.gz}"
ISSUER_URL="${CONF_ISSUER_URL:-http://127.0.0.1:4000}"
ISSUER_PORT="${CONF_ISSUER_PORT:-4000}"
ISSUER_SEED="${CONF_ISSUER_SEED:-sauron-confidence-issuer-seed-v1}"

mkdir -p "$LOG_DIR"

cleanup_pid=""
cleanup_db=""
cleanup_issuer_pid=""
cleanup() {
  if [[ -n "$cleanup_pid" ]]; then
    kill "$cleanup_pid" >/dev/null 2>&1 || true
    wait "$cleanup_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$cleanup_issuer_pid" ]]; then
    kill "$cleanup_issuer_pid" >/dev/null 2>&1 || true
    wait "$cleanup_issuer_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$cleanup_db" ]]; then
    rm -f "$cleanup_db" "$cleanup_db-wal" "$cleanup_db-shm"
  fi
}
on_exit() {
  local code="$?"
  cleanup
  if [[ "$code" -ne 0 ]]; then
    tar -czf "$FAIL_BUNDLE" -C "$LOG_DIR" . >/dev/null 2>&1 || true
    echo "[CONF] failure bundle: $FAIL_BUNDLE" >&2
  fi
  return "$code"
}
trap on_exit EXIT

ensure_zkp_fixture_bundle

if ! command -v node >/dev/null 2>&1; then
  echo "[CONF] node is required to run issuer verifier" >&2
  exit 1
fi

if [[ ! -f "${ROOT_DIR}/../zkp/issuer/dist/server.js" ]]; then
  echo "[CONF] missing zkp/issuer/dist/server.js; build issuer first" >&2
  exit 1
fi

echo "[CONF] start issuer verifier"
ISSUER_DATA_DIR="${LOG_DIR}/issuer-data" \
ISSUER_SEED="${ISSUER_SEED}" \
PORT="${ISSUER_PORT}" \
node "${ROOT_DIR}/../zkp/issuer/dist/server.js" >"${LOG_DIR}/issuer.log" 2>&1 &
cleanup_issuer_pid="$!"

issuer_ready=0
for _ in $(seq 1 90); do
  if curl -sf "${ISSUER_URL}/status" >/dev/null 2>&1; then
    issuer_ready=1
    break
  fi
  sleep 1
done
if [[ "$issuer_ready" -ne 1 ]]; then
  echo "[CONF] issuer failed to start" >&2
  tail -n 80 "${LOG_DIR}/issuer.log" >&2 || true
  exit 1
fi

cargo build --bin sauron-core >/dev/null

echo "[CONF] phase1 shared-server suites"
for i in $(seq 1 "$SHARED_ITERS"); do
  port=$((3400 + i))
  db="${LOG_DIR}/shared-${i}.db"
  log="${LOG_DIR}/shared-${i}.server.log"
  cleanup_db="$db"
  rm -f "$db" "$db-wal" "$db-shm"

  ENV=development \
  SAURON_ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}" \
  SAURON_ISSUER_URL="${ISSUER_URL}" \
  DATABASE_PATH="$db" \
  PORT="$port" \
  ./target/debug/sauron-core >"$log" 2>&1 &
  pid=$!
  cleanup_pid="$pid"

  ready=0
  for _ in $(seq 1 90); do
    if curl -sf "http://127.0.0.1:${port}/admin/stats" -H 'x-admin-key: super_secret_hackathon_key' >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "[CONF] boot failed iteration ${i}" >&2
    tail -n 80 "$log" >&2 || true
    exit 1
  fi

  API_URL="http://127.0.0.1:${port}" E2E_ISSUER_URL="${ISSUER_URL}" tests/e2e_kya_delegated.sh >"${LOG_DIR}/shared-${i}.delegated.log"
  API_URL="http://127.0.0.1:${port}" E2E_ISSUER_URL="${ISSUER_URL}" tests/e2e_kya_autonomous.sh >"${LOG_DIR}/shared-${i}.autonomous.log"
  API_URL="http://127.0.0.1:${port}" E2E_ISSUER_URL="${ISSUER_URL}" tests/e2e_agent_payment_authorize.sh >"${LOG_DIR}/shared-${i}.payment-authorize.log"
  API_URL="http://127.0.0.1:${port}" \
  E2E_ISSUER_URL="${ISSUER_URL}" \
  AGENT_TYPES="$MATRIX_AGENT_TYPES" \
  MATRIX_JITTER_MS_MAX="$MATRIX_JITTER_MS_MAX" \
  MATRIX_FAULT_PROBE_PCT="$MATRIX_FAULT_PROBE_PCT" \
  tests/e2e_agent_matrix.sh >"${LOG_DIR}/shared-${i}.matrix.log"

  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  cleanup_pid=""

  rm -f "$db" "$db-wal" "$db-shm"
  cleanup_db=""

  echo "[CONF] shared iteration ${i} PASS"
done

echo "[CONF] phase2 migration suites"
for i in $(seq 1 "$MIGRATION_ITERS"); do
  mig_port=$((3500 + i))
  E2E_PORT="$mig_port" \
  E2E_ISSUER_URL="${ISSUER_URL}" \
  E2E_DB_PATH="${LOG_DIR}/migration-${i}.db" \
  E2E_LOG_PATH="${LOG_DIR}/migration-${i}.server.log" \
  E2E_BINARY="${ROOT_DIR}/target/debug/sauron-core" \
  tests/e2e_legacy_nonbank_migration.sh >"${LOG_DIR}/migration-${i}.runner.log"
  echo "[CONF] migration iteration ${i} PASS"
done

echo "[CONF] phase3 restart/ring suites"
for i in $(seq 1 "$RESTART_ITERS"); do
  restart_port=$((3600 + i))
  E2E_PORT="$restart_port" \
  E2E_ISSUER_URL="${ISSUER_URL}" \
  E2E_DB_PATH="${LOG_DIR}/restart-${i}.db" \
  E2E_LOG_PATH="${LOG_DIR}/restart-${i}.server.log" \
  tests/e2e_ring_restore_consent.sh >"${LOG_DIR}/restart-${i}.runner.log"
  echo "[CONF] restart iteration ${i} PASS"
done

echo "[CONF] ALL PASS"
echo "[CONF] logs: ${LOG_DIR}"
