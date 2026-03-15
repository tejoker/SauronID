#!/usr/bin/env bash
# audit_circuits.sh — Zero-trust structural audit for Circom circuits.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
CIRCUITS_DIR="$ROOT/circuits"
TMP_DIR="$ROOT/build/.audit_tmp"

export PATH="$HOME/.local/bin:$PATH"

if ! command -v circom >/dev/null 2>&1; then
  echo "[ERROR] circom is required but not found in PATH"
  exit 1
fi

mkdir -p "$TMP_DIR"

CIRCUITS=("AgeVerification" "MerkleInclusion" "CredentialVerification")

echo "═══════════════════════════════════════════════════"
echo "  SauronID — Circuit Structural Audit"
echo "═══════════════════════════════════════════════════"

for circuit in "${CIRCUITS[@]}"; do
  circuit_file="$CIRCUITS_DIR/${circuit}.circom"
  log_file="$TMP_DIR/${circuit}.inspect.log"

  echo ""
  echo "────────────────────────────────────────────────"
  echo "  Auditing: $circuit"
  echo "────────────────────────────────────────────────"

  # --inspect triggers Circom's static checks, including unconstrained signal warnings.
  if ! circom "$circuit_file" --r1cs --inspect -o "$TMP_DIR" -l "$ROOT/node_modules" >"$log_file" 2>&1; then
    cat "$log_file"
    echo "[ERROR] Inspection failed for $circuit"
    exit 1
  fi

  if grep -qi "warning" "$log_file"; then
    # CA02 warnings are common in circomlib internals and are not actionable here.
    if grep -Ei "warning\[[^]]+\]" "$log_file" | grep -Ev "warning\[CA02\]" >/dev/null; then
      cat "$log_file"
      echo "[ERROR] Actionable static analysis warnings detected for $circuit"
      exit 1
    fi
  fi

  echo "  ✓ No static warnings detected"

done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Circuit audit passed"
echo "═══════════════════════════════════════════════════"
