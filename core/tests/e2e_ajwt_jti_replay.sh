#!/usr/bin/env bash
# Second /agent/kyc/consent with the same A-JWT must fail (server-side jti replay guard).
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
  curl -sS -X POST "${API_URL}/admin/clients" \
    -H "x-admin-key: ${ADMIN_KEY}" \
    -H 'content-type: application/json' \
    -d "{\"name\":\"${name}\",\"client_type\":\"${ctype}\"}" >/dev/null || true
}

rand_suffix=$(python3 - <<'PY'
import time, random
print(f"{int(time.time())}{random.randint(1000,9999)}")
PY
)
RETAIL_SITE="${E2E_RETAIL_SITE:-e2e-jti-${rand_suffix}}"

ensure_client "${BANK_SITE}" "BANK"
ensure_client "${RETAIL_SITE}" "ZKP_ONLY"

curl -sS -X POST "${API_URL}/dev/buy_tokens" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"amount\":5}" >/dev/null

email="jti_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"

register_body=$(cat <<JSON
{
  "site_name": "${BANK_SITE}",
  "email": "${email}",
  "password": "${password}",
  "first_name": "Jti",
  "last_name": "Replay",
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

auth_res=$(curl -sS -X POST "${API_URL}/user/auth" -H 'content-type: application/json' \
  -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
session=$(printf '%s' "$auth_res" | json_get "session")
key_image=$(printf '%s' "$auth_res" | json_get "key_image")
if [[ -z "$session" || -z "$key_image" ]]; then
  echo "user_auth failed: $auth_res" >&2
  exit 1
fi

agent_body=$(cat <<JSON
{
  "human_key_image": "${key_image}",
  "agent_checksum": "sha256:jti-replay-${rand_suffix}",
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
if [[ -z "$ajwt" || -z "$agent_id" ]]; then
  echo "agent/register failed: $agent_res" >&2
  exit 1
fi

req_res=$(curl -sS -X POST "${API_URL}/kyc/request" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"requested_claims\":[\"age_over_threshold\",\"age_threshold\"]}")
request_id=$(printf '%s' "$req_res" | json_get "request_id")
if [[ -z "$request_id" ]]; then
  echo "kyc/request failed: $req_res" >&2
  exit 1
fi

consent_body=$(cat <<JSON
{
  "ajwt": "${ajwt}",
  "site_name": "${RETAIL_SITE}",
  "request_id": "${request_id}"
}
JSON
)

code1=$(curl -sS -o /tmp/jti_consent1.json -w '%{http_code}' -X POST "${API_URL}/agent/kyc/consent" \
  -H 'content-type: application/json' \
  -d "${consent_body}")
if [[ "$code1" != "200" ]]; then
  echo "first agent/kyc/consent expected 200, got ${code1}: $(cat /tmp/jti_consent1.json)" >&2
  exit 1
fi

req_res2=$(curl -sS -X POST "${API_URL}/kyc/request" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"requested_claims\":[\"age_over_threshold\",\"age_threshold\"]}")
request_id2=$(printf '%s' "$req_res2" | json_get "request_id")
if [[ -z "$request_id2" ]]; then
  echo "second kyc/request failed: $req_res2" >&2
  exit 1
fi

consent_body2=$(cat <<JSON
{
  "ajwt": "${ajwt}",
  "site_name": "${RETAIL_SITE}",
  "request_id": "${request_id2}"
}
JSON
)

code2=$(curl -sS -o /tmp/jti_consent2.json -w '%{http_code}' -X POST "${API_URL}/agent/kyc/consent" \
  -H 'content-type: application/json' \
  -d "${consent_body2}")
if [[ "$code2" == "200" ]]; then
  echo "second consent with same A-JWT should fail; got 200: $(cat /tmp/jti_consent2.json)" >&2
  exit 1
fi

echo "[PASS] A-JWT jti replay blocked on second /agent/kyc/consent (http ${code2})"
