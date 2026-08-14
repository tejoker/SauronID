#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
# shellcheck source=../../scripts/lib/dev_secrets.sh
source "${REPO_ROOT}/scripts/lib/dev_secrets.sh"
load_dev_admin_key
PORT="${E2E_PORT:-3991}"
API_URL="${API_URL:-http://127.0.0.1:${PORT}}"
DB_PATH="${E2E_DB_PATH:-/tmp/sauron-leash-demo-${USER:-user}-$$.db}"
LOG_PATH="${E2E_LOG_PATH:-/tmp/sauron-leash-demo-${USER:-user}-$$.log}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${DB_PATH}" "${DB_PATH}-wal" "${DB_PATH}-shm" "${LOG_PATH}"
}
trap cleanup EXIT

(cd "${ROOT_DIR}" && cargo build --bins >/dev/null)

ENV=development \
SAURON_ENABLE_DEV_ENDPOINTS=1 \
SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
DATABASE_PATH="${DB_PATH}" \
PORT="${PORT}" \
"${ROOT_DIR}/target/debug/sauron-core" >"${LOG_PATH}" 2>&1 &
SERVER_PID="$!"

ready=0
for _ in $(seq 1 90); do
  # /healthz, not /admin/stats. The latter is a deployment-global view that
  # answers 401 to a tenant-scoped admin key, so it can never be a liveness
  # probe here — the loop just burned its retries on 401s and reported "core did
  # not become ready" while the core was up and healthy the whole time.
  if curl -sf "${API_URL}/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  echo "core did not become ready" >&2
  tail -n 80 "${LOG_PATH}" >&2 || true
  exit 1
fi

tmp_response=$(mktemp)
status=$(curl -sS -o "${tmp_response}" -w '%{http_code}' -X POST "${API_URL}/dev/leash/demo" -H 'content-type: application/json' -d '{}')
result=$(cat "${tmp_response}")
rm -f "${tmp_response}"
if [[ "${status}" != "200" ]]; then
  echo "dev leash demo returned HTTP ${status}: ${result}" >&2
  tail -n 80 "${LOG_PATH}" >&2 || true
  exit 1
fi
python3 - "$result" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
required = [
    "valid_leash_passes",
    "missing_signature_fails",
    "bad_signature_fails",
    "tampered_amount_fails",
    "wrong_merchant_fails",
    "nonce_replay_fails",
    "ajwt_replay_fails",
    "revoked_agent_fails",
    "out_of_ring_agent_fails",
]
missing = [k for k in required if doc.get(k) is not True]
receipt_ok = doc.get("receipt_verification", {}).get("valid") is True
if missing or not receipt_ok:
    print(json.dumps(doc, indent=2))
    raise SystemExit(f"leash demo failed: missing={missing} receipt_ok={receipt_ok}")
print(json.dumps({k: doc[k] for k in required}, sort_keys=True))
PY
