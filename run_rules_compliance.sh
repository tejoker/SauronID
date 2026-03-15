#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_CMD="${PYTHON_CMD:-python3}"

PASS_COUNT=0
FAIL_COUNT=0

declare -a TEST_IDS
declare -a TEST_DESC
declare -a TEST_STATUS
declare -a TEST_NOTE

record_result() {
  local id="$1"
  local desc="$2"
  local status="$3"
  local note="$4"

  TEST_IDS+=("$id")
  TEST_DESC+=("$desc")
  TEST_STATUS+=("$status")
  TEST_NOTE+=("$note")

  if [[ "$status" == "PASS" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

run_case() {
  local id="$1"
  local desc="$2"
  local cmd="$3"

  echo "[RUN] $id - $desc"
  local output
  if output=$(bash -lc "cd '$ROOT_DIR' && $cmd" 2>&1); then
    echo "[PASS] $id"
    record_result "$id" "$desc" "PASS" ""
  else
    echo "[FAIL] $id"
    local note
    note=$(echo "$output" | tail -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')
    record_result "$id" "$desc" "FAIL" "$note"
  fi
}

run_group_case() {
  local ids_csv="$1"
  local desc_csv="$2"
  local cmd="$3"

  echo "[RUN] $ids_csv - shared command"
  local output
  if output=$(bash -lc "cd '$ROOT_DIR' && $cmd" 2>&1); then
    IFS=',' read -r -a ids <<< "$ids_csv"
    IFS='|' read -r -a descs <<< "$desc_csv"
    for i in "${!ids[@]}"; do
      local id="${ids[$i]}"
      local desc="${descs[$i]}"
      echo "[PASS] $id"
      record_result "$id" "$desc" "PASS" ""
    done
  else
    local note
    note=$(echo "$output" | tail -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')
    IFS=',' read -r -a ids <<< "$ids_csv"
    IFS='|' read -r -a descs <<< "$desc_csv"
    for i in "${!ids[@]}"; do
      local id="${ids[$i]}"
      local desc="${descs[$i]}"
      echo "[FAIL] $id"
      record_result "$id" "$desc" "FAIL" "$note"
    done
  fi
}

run_group_case "1,3" "AgeVerification soundness|Merkle inclusion validity" "cd zkp/sdk && npm run build && npm run test:quick"
run_case "2" "Under-constrained circuit audit" "cd zkp && npm run audit:circuits"
run_case "4" "OID4VP selective disclosure by presentation definition" "cd zkp/acquirer-sdk && npm run build && npm test"
run_case "5" "OID4VCI pre-authorized code replay protection" "cd zkp/issuer && npm test"
run_case "6" "CAMARA strict silent-auth IP to SIM check" "cd zkp/camara && npm run build && npm test && npm run test:card-login"
run_group_case "7,8,9" "Agent checksum integrity|Delegation chain traceability|PoP anti-replay binding" "cd agentic && npm run build && npm test"
run_case "10" "Anomaly engine detects synthetic anomalies" "cd anomaly-engine && ${PYTHON_CMD} test_rule10.py"
run_case "11" "Revocation smart contract ACL and privacy" "cd contracts/revocation && HARDHAT_DISABLE_TELEMETRY_PROMPT=1 HARDHAT_DISABLE_TELEMETRY_PROMPTS=1 npm test -- --grep 'RevocationRegistry|AgentDelegationRegistry'"

if [[ -n "${SUBGRAPH_URL:-}" ]]; then
  run_case "12" "Subgraph indexing latency SLA" "cd contracts/revocation && HARDHAT_DISABLE_TELEMETRY_PROMPT=1 HARDHAT_DISABLE_TELEMETRY_PROMPTS=1 SUBGRAPH_URL='${SUBGRAPH_URL}' npm test -- --grep 'Subgraph latency SLA'"
else
  record_result "12" "Subgraph indexing latency SLA" "FAIL" "SUBGRAPH_URL not set; latency check requires a live GraphQL subgraph endpoint"
fi

echo ""
echo "================ Rule Compliance Summary ================"
printf '%-5s | %-4s | %-55s | %s\n' "Test" "Res" "Description" "Note"
echo "--------------------------------------------------------------------------------------------------------------------------------"
for i in "${!TEST_IDS[@]}"; do
  printf '%-5s | %-4s | %-55s | %s\n' "${TEST_IDS[$i]}" "${TEST_STATUS[$i]}" "${TEST_DESC[$i]}" "${TEST_NOTE[$i]}"
done

echo "--------------------------------------------------------------------------------------------------------------------------------"
echo "PASS: $PASS_COUNT"
echo "FAIL: $FAIL_COUNT"

if [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
