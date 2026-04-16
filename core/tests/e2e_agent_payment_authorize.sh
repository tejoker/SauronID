#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:3001}"
BANK_SITE="${E2E_BANK_SITE:-BNP Paribas}"
ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}"

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

email="pay_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"
merchant_ok="mrc_ok_${rand_suffix}"
merchant_bad="mrc_bad_${rand_suffix}"
payment_ref="payref_${rand_suffix}"

ensure_client "${BANK_SITE}" "BANK"

printf '[E2E payment-auth] register user\n'
register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${BANK_SITE}\",\"email\":\"${email}\",\"password\":\"${password}\",\"first_name\":\"Pay\",\"last_name\":\"Flow\",\"date_of_birth\":\"1990-01-01\",\"nationality\":\"FRA\"}")
user_pub=$(printf '%s' "$register_res" | json_get "public_key_hex")
if [[ -z "$user_pub" ]]; then
  echo "register_user failed: $register_res" >&2
  exit 1
fi

printf '[E2E payment-auth] auth user\n'
auth_res=$(curl -sS -X POST "${API_URL}/user/auth" -H 'content-type: application/json' \
  -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
session=$(printf '%s' "$auth_res" | json_get "session")
key_image=$(printf '%s' "$auth_res" | json_get "key_image")
if [[ -z "$session" || -z "$key_image" ]]; then
  echo "user_auth failed: $auth_res" >&2
  exit 1
fi

tmp_pop_json=$(mktemp)
node - "$tmp_pop_json" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");
const outPath = process.argv[2];
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const publicJwk = publicKey.export({ format: "jwk" });
const privateJwk = privateKey.export({ format: "jwk" });
fs.writeFileSync(
  outPath,
  JSON.stringify({
    pop_public_key_b64u: publicJwk.x,
    private_jwk: privateJwk
  })
);
NODE
pop_public_key_b64u=$(python3 - "$tmp_pop_json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["pop_public_key_b64u"])
PY
)
if [[ -z "$pop_public_key_b64u" ]]; then
  echo "failed to generate pop_public_key_b64u" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

intent_json=$(python3 - "$merchant_ok" <<'PY'
import json,sys
merchant=sys.argv[1]
print(json.dumps({
  "action":"payment_initiation",
  "scope":["payment_initiation"],
  "maxAmount":12.34,
  "currency":"EUR",
  "constraints":{"merchant_allowlist":[merchant]}
}, separators=(',', ':')))
PY
)

printf '[E2E payment-auth] register pop-enabled agent\n'
agent_res=$(curl -sS -X POST "${API_URL}/agent/register" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"human_key_image\":\"${key_image}\",\"agent_checksum\":\"sha256:pay-${rand_suffix}\",\"intent_json\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$intent_json"),\"public_key_hex\":\"${user_pub}\",\"pop_public_key_b64u\":\"${pop_public_key_b64u}\",\"ttl_secs\":3600}")
ajwt=$(printf '%s' "$agent_res" | json_get "ajwt")
agent_id=$(printf '%s' "$agent_res" | json_get "agent_id")
if [[ -z "$ajwt" || -z "$agent_id" ]]; then
  echo "agent/register failed: $agent_res" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

pop_challenge_res=$(curl -sS -X POST "${API_URL}/agent/pop/challenge" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"agent_id\":\"${agent_id}\"}")
pop_challenge_id=$(printf '%s' "$pop_challenge_res" | json_get "pop_challenge_id")
challenge=$(printf '%s' "$pop_challenge_res" | json_get "challenge")
if [[ -z "$pop_challenge_id" || -z "$challenge" ]]; then
  echo "agent/pop/challenge failed: $pop_challenge_res" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

sign_pop_jws() {
  local challenge_payload="$1"
  node - "$tmp_pop_json" "$challenge_payload" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");
const inputPath = process.argv[2];
const challenge = process.argv[3];
const pop = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
const payload = Buffer.from(challenge, "utf8").toString("base64url");
const signingInput = `${header}.${payload}`;
const privateKey = crypto.createPrivateKey({ key: pop.private_jwk, format: "jwk" });
const signature = crypto.sign(null, Buffer.from(signingInput), privateKey).toString("base64url");
process.stdout.write(`${signingInput}.${signature}`);
NODE
}

pop_jws=$(sign_pop_jws "$challenge")

printf '[E2E payment-auth] deny over maxAmount\n'
code_over=$(curl -sS -o /tmp/pay_auth_over.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" \
  -H 'content-type: application/json' \
  -d "{\"ajwt\":\"${ajwt}\",\"amount_minor\":1235,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_ok}\",\"payment_ref\":\"${payment_ref}_over\",\"pop_challenge_id\":\"${pop_challenge_id}\",\"pop_jws\":\"${pop_jws}\"}")
if [[ "$code_over" == "200" ]]; then
  echo "over-limit payment authorization should fail: $(cat /tmp/pay_auth_over.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

pop_challenge_res2=$(curl -sS -X POST "${API_URL}/agent/pop/challenge" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"agent_id\":\"${agent_id}\"}")
pop_challenge_id2=$(printf '%s' "$pop_challenge_res2" | json_get "pop_challenge_id")
challenge2=$(printf '%s' "$pop_challenge_res2" | json_get "challenge")
pop_jws2=$(sign_pop_jws "$challenge2")

printf '[E2E payment-auth] deny non-allowlisted merchant\n'
code_merchant=$(curl -sS -o /tmp/pay_auth_merchant.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" \
  -H 'content-type: application/json' \
  -d "{\"ajwt\":\"${ajwt}\",\"amount_minor\":1000,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_bad}\",\"payment_ref\":\"${payment_ref}_merchant\",\"pop_challenge_id\":\"${pop_challenge_id2}\",\"pop_jws\":\"${pop_jws2}\"}")
if [[ "$code_merchant" == "200" ]]; then
  echo "merchant-allowlist check should fail: $(cat /tmp/pay_auth_merchant.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

pop_challenge_res3=$(curl -sS -X POST "${API_URL}/agent/pop/challenge" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"agent_id\":\"${agent_id}\"}")
pop_challenge_id3=$(printf '%s' "$pop_challenge_res3" | json_get "pop_challenge_id")
challenge3=$(printf '%s' "$pop_challenge_res3" | json_get "challenge")
pop_jws3=$(sign_pop_jws "$challenge3")

printf '[E2E payment-auth] authorize valid charge\n'
code_ok=$(curl -sS -o /tmp/pay_auth_ok.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" \
  -H 'content-type: application/json' \
  -d "{\"ajwt\":\"${ajwt}\",\"amount_minor\":1234,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_ok}\",\"payment_ref\":\"${payment_ref}\",\"pop_challenge_id\":\"${pop_challenge_id3}\",\"pop_jws\":\"${pop_jws3}\"}")
if [[ "$code_ok" != "200" ]]; then
  echo "valid payment authorization should succeed: $(cat /tmp/pay_auth_ok.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi
authorization_id=$(cat /tmp/pay_auth_ok.json | json_get "authorization_id")
if [[ -z "$authorization_id" ]]; then
  echo "missing authorization_id in success payload: $(cat /tmp/pay_auth_ok.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

pop_challenge_res4=$(curl -sS -X POST "${API_URL}/agent/pop/challenge" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"agent_id\":\"${agent_id}\"}")
pop_challenge_id4=$(printf '%s' "$pop_challenge_res4" | json_get "pop_challenge_id")
challenge4=$(printf '%s' "$pop_challenge_res4" | json_get "challenge")
pop_jws4=$(sign_pop_jws "$challenge4")

printf '[E2E payment-auth] deny replayed A-JWT (JTI)\n'
code_replay=$(curl -sS -o /tmp/pay_auth_replay.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" \
  -H 'content-type: application/json' \
  -d "{\"ajwt\":\"${ajwt}\",\"amount_minor\":500,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_ok}\",\"payment_ref\":\"${payment_ref}_replay\",\"pop_challenge_id\":\"${pop_challenge_id4}\",\"pop_jws\":\"${pop_jws4}\"}")
if [[ "$code_replay" == "200" ]]; then
  echo "replayed ajwt should fail: $(cat /tmp/pay_auth_replay.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

rm -f "$tmp_pop_json"
echo "[PASS] strict agent payment authorization e2e"
