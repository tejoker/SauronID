#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:3001}"
BANK_SITE="${E2E_BANK_SITE:-BNP Paribas}"
ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}"
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
  local body
  body=$(cat <<JSON
{"name":"${name}","client_type":"${ctype}"}
JSON
)
  curl -sS -X POST "${API_URL}/admin/clients" \
    -H "x-admin-key: ${ADMIN_KEY}" \
    -H 'content-type: application/json' \
    -d "${body}" >/dev/null || true
}

rand_suffix=$(python3 - <<'PY'
import time, random
print(f"{int(time.time())}{random.randint(1000,9999)}")
PY
)
RETAIL_SITE="${E2E_RETAIL_SITE:-e2e-zkp-${rand_suffix}}"

ensure_client "${BANK_SITE}" "BANK"
ensure_client "${RETAIL_SITE}" "ZKP_ONLY"

curl -sS -X POST "${API_URL}/dev/buy_tokens" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"amount\":3}" >/dev/null

email="delegated_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"

printf '[E2E delegated] register user\n'
register_body=$(cat <<JSON
{
  "site_name": "${BANK_SITE}",
  "email": "${email}",
  "password": "${password}",
  "first_name": "Alice",
  "last_name": "Delegated",
  "date_of_birth": "1990-01-01",
  "nationality": "FRA"
}
JSON
)
register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" -H 'content-type: application/json' -d "${register_body}")
user_pub=$(printf '%s' "$register_res" | json_get "public_key_hex")
if [[ -z "$user_pub" ]]; then
  echo "register_user failed: $register_res" >&2
  exit 1
fi

printf '[E2E delegated] auth user session\n'
auth_body=$(cat <<JSON
{"email":"${email}","password":"${password}"}
JSON
)
auth_res=$(curl -sS -X POST "${API_URL}/user/auth" -H 'content-type: application/json' -d "${auth_body}")
session=$(printf '%s' "$auth_res" | json_get "session")
key_image=$(printf '%s' "$auth_res" | json_get "key_image")
if [[ -z "$session" || -z "$key_image" ]]; then
  echo "user_auth failed: $auth_res" >&2
  exit 1
fi

printf '[E2E delegated] register delegated agent\n'
agent_body=$(cat <<JSON
{
  "human_key_image": "${key_image}",
  "agent_checksum": "sha256:e2e-delegated-${rand_suffix}",
  "intent_json": "{\"scope\":[\"prove:age\"]}",
  "public_key_hex": "${user_pub}",
  "ttl_secs": 3600
}
JSON
)
agent_res=$(curl -sS -X POST "${API_URL}/agent/register" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "${agent_body}")
ajwt=$(printf '%s' "$agent_res" | json_get "ajwt")
agent_id=$(printf '%s' "$agent_res" | json_get "agent_id")
assurance=$(printf '%s' "$agent_res" | json_get "assurance_level")
if [[ -z "$ajwt" || -z "$agent_id" ]]; then
  echo "agent/register failed: $agent_res" >&2
  exit 1
fi

echo "  assurance_level=${assurance}"
if [[ "$assurance" != "delegated_bank" ]]; then
  echo "expected delegated_bank assurance, got: $assurance" >&2
  exit 1
fi

printf '[E2E delegated] policy checks\n'
deny_policy=$(curl -sS -X POST "${API_URL}/policy/authorize" -H 'content-type: application/json' -d "{\"agent_id\":\"${agent_id}\",\"action\":\"payment_initiation\"}")
deny_allowed=$(printf '%s' "$deny_policy" | json_get "allowed")
if [[ "$deny_allowed" != "True" && "$deny_allowed" != "true" ]]; then
  echo "expected delegated_bank payment policy allow, got: $deny_policy" >&2
  exit 1
fi
allow_policy=$(curl -sS -X POST "${API_URL}/policy/authorize" -H 'content-type: application/json' -d "{\"agent_id\":\"${agent_id}\",\"action\":\"prove_age\"}")
allow_allowed=$(printf '%s' "$allow_policy" | json_get "allowed")
if [[ "$allow_allowed" != "True" && "$allow_allowed" != "true" ]]; then
  echo "expected delegated prove_age policy allow, got: $allow_policy" >&2
  exit 1
fi

printf '[E2E delegated] create consent request\n'
req_body=$(cat <<JSON
{
  "site_name": "${RETAIL_SITE}",
  "requested_claims": ["age_over_threshold", "age_threshold"]
}
JSON
)
req_res=$(curl -sS -X POST "${API_URL}/kyc/request" -H 'content-type: application/json' -d "${req_body}")
request_id=$(printf '%s' "$req_res" | json_get "request_id")
if [[ -z "$request_id" ]]; then
  echo "kyc/request failed: $req_res" >&2
  exit 1
fi

printf '[E2E delegated] agent consent\n'
consent_body=$(cat <<JSON
{
  "ajwt": "${ajwt}",
  "site_name": "${RETAIL_SITE}",
  "request_id": "${request_id}"
}
JSON
)
consent_res=$(curl -sS -X POST "${API_URL}/agent/kyc/consent" -H 'content-type: application/json' -d "${consent_body}")
consent_token=$(printf '%s' "$consent_res" | json_get "consent_token")
if [[ -z "$consent_token" ]]; then
  echo "agent/kyc/consent failed: $consent_res" >&2
  exit 1
fi

printf '[E2E delegated] retrieve with delegated binding + proof\n'
retrieve_body="$(zkp_build_retrieve_payload_json "${consent_token}" "${RETAIL_SITE}" "prove_age")"
retrieve_res=$(curl -sS -X POST "${API_URL}/kyc/retrieve" \
  -H 'content-type: application/json' \
  -H "x-agent-ajwt: ${ajwt}" \
  -d "${retrieve_body}")
mode=$(printf '%s' "$retrieve_res" | json_get "disclosure_mode")
trust=$(printf '%s' "$retrieve_res" | json_get "identity.trust_verified")
is_agent=$(printf '%s' "$retrieve_res" | json_get "identity.is_agent")
if [[ "$mode" != "zkp_only" || "$trust" != "True" && "$trust" != "true" || "$is_agent" != "True" && "$is_agent" != "true" ]]; then
  echo "kyc/retrieve failed expectations: $retrieve_res" >&2
  exit 1
fi

echo "[PASS] delegated KYA e2e"