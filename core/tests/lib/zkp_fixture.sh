#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

E2E_ISSUER_URL="${E2E_ISSUER_URL:-http://127.0.0.1:4000}"
E2E_ZKP_FIXTURE_PATH="${E2E_ZKP_FIXTURE_PATH:-${TESTS_DIR}/fixtures/zkp_fixtures.json}"

ensure_zkp_fixture_bundle() {
  if [[ -f "${E2E_ZKP_FIXTURE_PATH}" ]]; then
    return
  fi
  node "${TESTS_DIR}/generate_zkp_fixtures.js" "${E2E_ZKP_FIXTURE_PATH}"
}

zkp_require_issuer() {
  if curl -sf "${E2E_ISSUER_URL}/status" >/dev/null 2>&1; then
    return
  fi
  echo "Issuer unavailable at ${E2E_ISSUER_URL}. Start zkp issuer before running e2e." >&2
  exit 1
}

zkp_build_retrieve_payload_json() {
  local consent_token="$1"
  local site_name="$2"
  local required_action="$3"
  python3 - "${E2E_ZKP_FIXTURE_PATH}" "${consent_token}" "${site_name}" "${required_action}" <<'PY'
import json
import sys

fixture_path, consent_token, site_name, required_action = sys.argv[1:5]
with open(fixture_path, "r", encoding="utf-8") as f:
    doc = json.load(f)
age = doc["age_verification"]
payload = {
    "consent_token": consent_token,
    "site_name": site_name,
    "required_action": required_action,
    "zkp_proof": age["proof"],
    "zkp_circuit": age["circuit"],
    "zkp_public_signals": age["public_signals"],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

zkp_build_nonbank_vc_issue_payload_json() {
  local human_key_image="$1"
  local agent_checksum="$2"
  local description="$3"
  local scope_json="$4"
  python3 - "${E2E_ZKP_FIXTURE_PATH}" "${human_key_image}" "${agent_checksum}" "${description}" "${scope_json}" <<'PY'
import json
import sys

fixture_path, human_key_image, agent_checksum, description, scope_raw = sys.argv[1:6]
with open(fixture_path, "r", encoding="utf-8") as f:
    doc = json.load(f)
cred = doc["credential_verification"]
scope = json.loads(scope_raw)
payload = {
    "human_key_image": human_key_image,
    "agent_checksum": agent_checksum,
    "description": description,
    "scope": scope,
    "ttl_hours": 24,
    "zkp_proof": cred["proof"],
    "zkp_circuit": cred["circuit"],
    "zkp_public_signals": cred["public_signals"],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}
