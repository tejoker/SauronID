#!/usr/bin/env bash
# compile.sh — Compile all Circom circuits to R1CS + WASM
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
BUILD_DIR="$ROOT/build"
CIRCUITS_DIR="$ROOT/circuits"

export PATH="$HOME/.local/bin:$PATH"

echo "═══════════════════════════════════════════════════"
echo "  SauronID — Circuit Compilation"
echo "═══════════════════════════════════════════════════"

mkdir -p "$BUILD_DIR"

CIRCUITS=("AgeVerification" "MerkleInclusion" "CredentialVerification")

for circuit in "${CIRCUITS[@]}"; do
    echo ""
    echo "────────────────────────────────────────────────"
    echo "  Compiling: $circuit"
    echo "────────────────────────────────────────────────"

    circom "$CIRCUITS_DIR/${circuit}.circom" \
        --r1cs \
        --wasm \
        --sym \
        -o "$BUILD_DIR/" \
        -l "$ROOT/node_modules"

    # Print constraint count
    if [ -f "$BUILD_DIR/${circuit}.r1cs" ]; then
        echo "  ✓ R1CS: $BUILD_DIR/${circuit}.r1cs"
        snarkjs r1cs info "$BUILD_DIR/${circuit}.r1cs" 2>/dev/null || true
    fi

    if [ -d "$BUILD_DIR/${circuit}_js" ]; then
        echo "  ✓ WASM: $BUILD_DIR/${circuit}_js/"
    fi

    echo "  ✓ SYM:  $BUILD_DIR/${circuit}.sym"
done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  All circuits compiled successfully!"
echo "═══════════════════════════════════════════════════"
