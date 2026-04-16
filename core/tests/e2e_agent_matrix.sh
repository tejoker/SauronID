#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:3001}"
BANK_SITE="${E2E_BANK_SITE:-BNP Paribas}"
ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}"
AGENT_TYPES="${AGENT_TYPES:-claude,openai,gemini,qwen,mistral,openclaw,crewai,langgraph,autogen}"
MATRIX_JITTER_MS_MAX="${MATRIX_JITTER_MS_MAX:-0}"
MATRIX_FAULT_PROBE_PCT="${MATRIX_FAULT_PROBE_PCT:-0}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# shellcheck source=tests/lib/zkp_fixture.sh
source "${ROOT_DIR}/tests/lib/zkp_fixture.sh"
ensure_zkp_fixture_bundle
zkp_require_issuer

json_get() {
  local key="$1"
  python3 -c 'import json,sys
key=sys.argv[1]
raw=sys.stdin.read()
try:
  obj=json.loads(raw)
except Exception:
  print("")
  sys.exit(0)
cur=obj
for part in key.split("."):
  if isinstance(cur, dict):
    cur=cur.get(part)
  else:
    cur=None
    break
print(json.dumps(cur) if isinstance(cur,(dict,list)) else ("" if cur is None else cur))' "$key"
}

ensure_client() {
  local name="$1"
  local ctype="$2"
  curl -sS -X POST "${API_URL}/admin/clients" \
    -H "x-admin-key: ${ADMIN_KEY}" \
    -H 'content-type: application/json' \
    -d "{\"name\":\"${name}\",\"client_type\":\"${ctype}\"}" >/dev/null || true
}

maybe_jitter() {
  if [[ "${MATRIX_JITTER_MS_MAX}" -le 0 ]]; then
    return
  fi
  local ms=$((RANDOM % (MATRIX_JITTER_MS_MAX + 1)))
  python3 - <<PY
import time
time.sleep(${ms} / 1000.0)
PY
}

should_fault_probe() {
  if [[ "${MATRIX_FAULT_PROBE_PCT}" -le 0 ]]; then
    return 1
  fi
  if [[ "${MATRIX_FAULT_PROBE_PCT}" -ge 100 ]]; then
    return 0
  fi
  local roll=$((RANDOM % 100))
  [[ "$roll" -lt "${MATRIX_FAULT_PROBE_PCT}" ]]
}

run_fault_probe() {
  local stage="$1"
  local body='{"site_name":"","requested_claims":["age_over_threshold"]}'
  local tmp_file
  tmp_file=$(mktemp)
  local code
  code=$(curl -sS -o "$tmp_file" -w '%{http_code}' -X POST "${API_URL}/kyc/request" \
    -H 'content-type: application/json' \
    -d "$body" || true)
  if [[ "$code" == "200" ]]; then
    echo "fault probe unexpectedly succeeded at stage=${stage}" >&2
    cat "$tmp_file" >&2 || true
    rm -f "$tmp_file"
    return 1
  fi
  rm -f "$tmp_file"
  return 0
}

create_consent_request() {
  local site_name="$1"
  local attempts=0
  while [[ $attempts -lt 6 ]]; do
    maybe_jitter
    if should_fault_probe; then
      run_fault_probe "create_consent_request" || return 1
    fi
    local req_res
    req_res=$(curl -sS -X POST "${API_URL}/kyc/request" \
      -H 'content-type: application/json' \
      -d "{\"site_name\":\"${site_name}\",\"requested_claims\":[\"age_over_threshold\",\"age_threshold\"]}")
    local request_id
    request_id=$(printf '%s' "${req_res}" | json_get "request_id")
    if [[ -n "${request_id}" ]]; then
      printf '%s' "${request_id}"
      return 0
    fi

    if grep -qi "UNIQUE constraint failed: consent_log.request_id" <<<"${req_res}"; then
      attempts=$((attempts + 1))
      sleep 1
      continue
    fi

    echo "Unable to create consent request: ${req_res}" >&2
    return 1
  done

  echo "Unable to create consent request after retries (request_id collision)" >&2
  return 1
}

rand_suffix=$(python3 - <<'PY'
import time, random
print(f"{int(time.time())}{random.randint(1000,9999)}")
PY
)

IFS=',' read -r -a raw_types <<< "${AGENT_TYPES}"
agent_types=()
for raw in "${raw_types[@]}"; do
  t="${raw//[[:space:]]/}"
  if [[ -n "${t}" ]]; then
    agent_types+=("${t}")
  fi
done

if [[ ${#agent_types[@]} -eq 0 ]]; then
  echo "No agent types provided in AGENT_TYPES" >&2
  exit 1
fi

RETAIL_SITE="${E2E_RETAIL_SITE:-e2e-agent-matrix-${rand_suffix}}"
ensure_client "${BANK_SITE}" "BANK"
ensure_client "${RETAIL_SITE}" "ZKP_ONLY"

credits=$(( ${#agent_types[@]} * 4 + 4 ))
curl -sS -X POST "${API_URL}/dev/buy_tokens" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"amount\":${credits}}" >/dev/null

email="matrix_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"

printf '[E2E matrix] register user\n'
register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${BANK_SITE}\",\"email\":\"${email}\",\"password\":\"${password}\",\"first_name\":\"Matrix\",\"last_name\":\"User\",\"date_of_birth\":\"1990-01-01\",\"nationality\":\"FRA\"}")
user_pub=$(printf '%s' "${register_res}" | json_get "public_key_hex")
if [[ -z "${user_pub}" ]]; then
  echo "register_user failed: ${register_res}" >&2
  exit 1
fi

printf '[E2E matrix] auth user session\n'
auth_res=$(curl -sS -X POST "${API_URL}/user/auth" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
session=$(printf '%s' "${auth_res}" | json_get "session")
key_image=$(printf '%s' "${auth_res}" | json_get "key_image")
if [[ -z "${session}" || -z "${key_image}" ]]; then
  echo "user/auth failed: ${auth_res}" >&2
  exit 1
fi

for t in "${agent_types[@]}"; do
  printf '[E2E matrix][%s] delegated register\n' "${t}"
  delegated_checksum="sha256:${t}:delegated:${rand_suffix}"
  delegated_res=$(curl -sS -X POST "${API_URL}/agent/register" \
    -H 'content-type: application/json' \
    -H "x-sauron-session: ${session}" \
    -d "{\"human_key_image\":\"${key_image}\",\"agent_checksum\":\"${delegated_checksum}\",\"intent_json\":\"{\\\"type\\\":\\\"${t}\\\",\\\"scope\\\":[\\\"prove:age\\\"]}\",\"public_key_hex\":\"${user_pub}\",\"ttl_secs\":3600}")
  delegated_ajwt=$(printf '%s' "${delegated_res}" | json_get "ajwt")
  delegated_id=$(printf '%s' "${delegated_res}" | json_get "agent_id")
  delegated_assurance=$(printf '%s' "${delegated_res}" | json_get "assurance_level")
  if [[ -z "${delegated_ajwt}" || -z "${delegated_id}" || "${delegated_assurance}" != "delegated_bank" ]]; then
    echo "delegated register failed for ${t}: ${delegated_res}" >&2
    exit 1
  fi

  request_id=$(create_consent_request "${RETAIL_SITE}") || {
    echo "kyc/request failed for delegated ${t}" >&2
    exit 1
  }

  consent_res=$(curl -sS -X POST "${API_URL}/agent/kyc/consent" \
    -H 'content-type: application/json' \
    -d "{\"ajwt\":\"${delegated_ajwt}\",\"site_name\":\"${RETAIL_SITE}\",\"request_id\":\"${request_id}\"}")
  consent_token=$(printf '%s' "${consent_res}" | json_get "consent_token")
  if [[ -z "${consent_token}" ]]; then
    echo "agent/kyc/consent failed for delegated ${t}: ${consent_res}" >&2
    exit 1
  fi

  retrieve_body="$(zkp_build_retrieve_payload_json "${consent_token}" "${RETAIL_SITE}" "prove_age")"
  retrieve_res=$(curl -sS -X POST "${API_URL}/kyc/retrieve" \
    -H 'content-type: application/json' \
    -H "x-agent-ajwt: ${delegated_ajwt}" \
    -d "${retrieve_body}")
  trust=$(printf '%s' "${retrieve_res}" | json_get "identity.trust_verified")
  assurance_out=$(printf '%s' "${retrieve_res}" | json_get "identity.agent_assurance_level")
  if [[ "${trust}" != "True" && "${trust}" != "true" ]]; then
    echo "delegated retrieve trust failed for ${t}: ${retrieve_res}" >&2
    exit 1
  fi
  if [[ "${assurance_out}" != "delegated_bank" ]]; then
    echo "delegated assurance mismatch for ${t}: ${retrieve_res}" >&2
    exit 1
  fi

  revoke_res=$(curl -sS -X DELETE "${API_URL}/agent/${delegated_id}" \
    -H "x-sauron-session: ${session}")
  revoked=$(printf '%s' "${revoke_res}" | json_get "revoked")
  if [[ "${revoked}" != "True" && "${revoked}" != "true" ]]; then
    echo "delegated revoke failed for ${t}: ${revoke_res}" >&2
    exit 1
  fi

  printf '[E2E matrix][%s] autonomous issue\n' "${t}"
  autonomous_checksum="sha256:${t}:autonomous:${rand_suffix}"
  vc_res=$(curl -sS -X POST "${API_URL}/agent/vc/issue" \
    -H 'content-type: application/json' \
    -H "x-sauron-session: ${session}" \
    -d "{\"human_key_image\":\"${key_image}\",\"agent_checksum\":\"${autonomous_checksum}\",\"description\":\"${t} autonomous agent\",\"scope\":[\"prove_age\",\"read_identity\"],\"ttl_hours\":24}")
  autonomous_ajwt=$(printf '%s' "${vc_res}" | json_get "ajwt")
  autonomous_id=$(printf '%s' "${vc_res}" | json_get "agent_id")
  autonomous_assurance=$(printf '%s' "${vc_res}" | json_get "assurance_level")
  if [[ -z "${autonomous_ajwt}" || -z "${autonomous_id}" || "${autonomous_assurance}" != "autonomous_web3" ]]; then
    echo "autonomous issue failed for ${t}: ${vc_res}" >&2
    exit 1
  fi

  policy_res=$(curl -sS -X POST "${API_URL}/policy/authorize" \
    -H 'content-type: application/json' \
    -d "{\"agent_id\":\"${autonomous_id}\",\"action\":\"payment_initiation\"}")
  allowed=$(printf '%s' "${policy_res}" | json_get "allowed")
  if [[ "${allowed}" != "False" && "${allowed}" != "false" ]]; then
    echo "autonomous policy deny failed for ${t}: ${policy_res}" >&2
    exit 1
  fi

  request_id=$(create_consent_request "${RETAIL_SITE}") || {
    echo "kyc/request failed for autonomous ${t}" >&2
    exit 1
  }

  consent_res=$(curl -sS -X POST "${API_URL}/agent/kyc/consent" \
    -H 'content-type: application/json' \
    -d "{\"ajwt\":\"${autonomous_ajwt}\",\"site_name\":\"${RETAIL_SITE}\",\"request_id\":\"${request_id}\"}")
  consent_token=$(printf '%s' "${consent_res}" | json_get "consent_token")
  if [[ -z "${consent_token}" ]]; then
    echo "agent/kyc/consent failed for autonomous ${t}: ${consent_res}" >&2
    exit 1
  fi

  retrieve_body="$(zkp_build_retrieve_payload_json "${consent_token}" "${RETAIL_SITE}" "prove_age")"
  retrieve_res=$(curl -sS -X POST "${API_URL}/kyc/retrieve" \
    -H 'content-type: application/json' \
    -H "x-agent-ajwt: ${autonomous_ajwt}" \
    -d "${retrieve_body}")
  trust=$(printf '%s' "${retrieve_res}" | json_get "identity.trust_verified")
  assurance_out=$(printf '%s' "${retrieve_res}" | json_get "identity.agent_assurance_level")
  if [[ "${trust}" != "True" && "${trust}" != "true" ]]; then
    echo "autonomous retrieve trust failed for ${t}: ${retrieve_res}" >&2
    exit 1
  fi
  if [[ "${assurance_out}" != "autonomous_web3" ]]; then
    echo "autonomous assurance mismatch for ${t}: ${retrieve_res}" >&2
    exit 1
  fi

  echo "  [PASS] ${t}: delegated + autonomous"
done

echo "[PASS] agent matrix e2e (${AGENT_TYPES})"
