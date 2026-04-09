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
NONBANK_SITE="${E2E_NONBANK_SITE:-e2e-full-kyc-${rand_suffix}}"

ensure_client "${BANK_SITE}" "BANK"
ensure_client "${RETAIL_SITE}" "ZKP_ONLY"
ensure_client "${NONBANK_SITE}" "FULL_KYC"

curl -sS -X POST "${API_URL}/dev/buy_tokens" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"amount\":3}" >/dev/null

email="autonomous_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"

printf '[E2E autonomous] register user\n'
register_body=$(cat <<JSON
{
  "site_name": "${BANK_SITE}",
  "email": "${email}",
  "password": "${password}",
  "first_name": "Bob",
  "last_name": "Autonomous",
  "date_of_birth": "1991-01-01",
  "nationality": "FRA"
}
JSON
)
register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" -H 'content-type: application/json' -d "${register_body}")
if [[ -z "$(printf '%s' "$register_res" | json_get "public_key_hex")" ]]; then
  echo "register_user failed: $register_res" >&2
  exit 1
fi

printf '[E2E autonomous] auth user session\n'
auth_res=$(curl -sS -X POST "${API_URL}/user/auth" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
session=$(printf '%s' "$auth_res" | json_get "session")
key_image=$(printf '%s' "$auth_res" | json_get "key_image")
if [[ -z "$session" || -z "$key_image" ]]; then
  echo "user_auth failed: $auth_res" >&2
  exit 1
fi

printf '[E2E autonomous] issue autonomous agent VC\n'
vc_body=$(cat <<JSON
{
  "human_key_image": "${key_image}",
  "agent_checksum": "sha256:e2e-autonomous-${rand_suffix}",
  "description": "Autonomous test agent",
  "scope": ["prove:age"],
  "ttl_hours": 24
}
JSON
)
vc_res=$(curl -sS -X POST "${API_URL}/agent/vc/issue" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "${vc_body}")
ajwt=$(printf '%s' "$vc_res" | json_get "ajwt")
agent_id=$(printf '%s' "$vc_res" | json_get "agent_id")
assurance=$(printf '%s' "$vc_res" | json_get "assurance_level")
if [[ -z "$ajwt" || -z "$agent_id" ]]; then
  echo "agent/vc/issue failed: $vc_res" >&2
  exit 1
fi
if [[ "$assurance" != "autonomous_web3" ]]; then
  echo "expected autonomous_web3 assurance, got: $assurance" >&2
  exit 1
fi

printf '[E2E autonomous] verify token assurance\n'
verify_res=$(curl -sS -X POST "${API_URL}/agent/verify" \
  -H 'content-type: application/json' \
  -d "{\"ajwt\":\"${ajwt}\"}")
verified=$(printf '%s' "$verify_res" | json_get "valid")
verify_assurance=$(printf '%s' "$verify_res" | json_get "assurance_level")
if [[ "$verified" != "True" && "$verified" != "true" ]]; then
  echo "agent/verify failed: $verify_res" >&2
  exit 1
fi
if [[ "$verify_assurance" != "autonomous_web3" ]]; then
  echo "verify assurance mismatch: $verify_res" >&2
  exit 1
fi

printf '[E2E autonomous] policy checks\n'
deny_policy=$(curl -sS -X POST "${API_URL}/policy/authorize" -H 'content-type: application/json' -d "{\"agent_id\":\"${agent_id}\",\"action\":\"payment_initiation\"}")
deny_allowed=$(printf '%s' "$deny_policy" | json_get "allowed")
if [[ "$deny_allowed" != "False" && "$deny_allowed" != "false" ]]; then
  echo "expected autonomous payment policy deny, got: $deny_policy" >&2
  exit 1
fi
allow_policy=$(curl -sS -X POST "${API_URL}/policy/authorize" -H 'content-type: application/json' -d "{\"agent_id\":\"${agent_id}\",\"action\":\"prove_age\"}")
allow_allowed=$(printf '%s' "$allow_policy" | json_get "allowed")
if [[ "$allow_allowed" != "True" && "$allow_allowed" != "true" ]]; then
  echo "expected autonomous prove_age policy allow, got: $allow_policy" >&2
  exit 1
fi

printf '[E2E autonomous] run consent + retrieve via autonomous agent\n'
req_res=$(curl -sS -X POST "${API_URL}/kyc/request" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"requested_claims\":[\"age_over_threshold\",\"age_threshold\"]}")
request_id=$(printf '%s' "$req_res" | json_get "request_id")
if [[ -z "$request_id" ]]; then
  echo "kyc/request failed: $req_res" >&2
  exit 1
fi

consent_res=$(curl -sS -X POST "${API_URL}/agent/kyc/consent" \
  -H 'content-type: application/json' \
  -d "{\"ajwt\":\"${ajwt}\",\"site_name\":\"${RETAIL_SITE}\",\"request_id\":\"${request_id}\"}")
consent_token=$(printf '%s' "$consent_res" | json_get "consent_token")
if [[ -z "$consent_token" ]]; then
  echo "agent/kyc/consent failed: $consent_res" >&2
  exit 1
fi

retrieve_body="$(zkp_build_retrieve_payload_json "${consent_token}" "${RETAIL_SITE}" "prove_age")"
retrieve_res=$(curl -sS -X POST "${API_URL}/kyc/retrieve" \
  -H 'content-type: application/json' \
  -H "x-agent-ajwt: ${ajwt}" \
  -d "${retrieve_body}")
trust=$(printf '%s' "$retrieve_res" | json_get "identity.trust_verified")
assurance_out=$(printf '%s' "$retrieve_res" | json_get "identity.agent_assurance_level")
if [[ "$trust" != "True" && "$trust" != "true" ]]; then
  echo "trust verification failed: $retrieve_res" >&2
  exit 1
fi
if [[ "$assurance_out" != "autonomous_web3" ]]; then
  echo "identity assurance mismatch: $retrieve_res" >&2
  exit 1
fi

printf '[E2E autonomous] issue VC with non-bank KYA proof\n'
nonbank_email="nonbank_${rand_suffix}@sauron.local"
nonbank_password="Passw0rd!${rand_suffix}"

nonbank_register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${NONBANK_SITE}\",\"email\":\"${nonbank_email}\",\"password\":\"${nonbank_password}\",\"first_name\":\"Nina\",\"last_name\":\"Nonbank\",\"date_of_birth\":\"1992-01-01\",\"nationality\":\"FRA\"}")
if [[ -z "$(printf '%s' "$nonbank_register_res" | json_get "public_key_hex")" ]]; then
  echo "non-bank register_user failed: $nonbank_register_res" >&2
  exit 1
fi

nonbank_auth_res=$(curl -sS -X POST "${API_URL}/user/auth" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"${nonbank_email}\",\"password\":\"${nonbank_password}\"}")
nonbank_session=$(printf '%s' "$nonbank_auth_res" | json_get "session")
nonbank_key_image=$(printf '%s' "$nonbank_auth_res" | json_get "key_image")
if [[ -z "$nonbank_session" || -z "$nonbank_key_image" ]]; then
  echo "non-bank user_auth failed: $nonbank_auth_res" >&2
  exit 1
fi

nonbank_vc_body="$(zkp_build_nonbank_vc_issue_payload_json "${nonbank_key_image}" "sha256:e2e-autonomous-nonbank-${rand_suffix}" "Autonomous non-bank test agent" '["prove_age"]')"
nonbank_vc_res=$(curl -sS -X POST "${API_URL}/agent/vc/issue" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${nonbank_session}" \
  -d "${nonbank_vc_body}")
nonbank_ajwt=$(printf '%s' "$nonbank_vc_res" | json_get "ajwt")
nonbank_assurance=$(printf '%s' "$nonbank_vc_res" | json_get "assurance_level")
if [[ -z "$nonbank_ajwt" || "$nonbank_assurance" != "autonomous_web3" ]]; then
  echo "non-bank /agent/vc/issue failed: $nonbank_vc_res" >&2
  exit 1
fi

echo "[PASS] autonomous KYA e2e"