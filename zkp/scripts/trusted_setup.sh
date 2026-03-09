#!/usr/bin/env bash
# trusted_setup.sh — Execute Powers of Tau ceremony + circuit-specific Phase 2
#
# This creates the proving keys (.zkey) and verification keys needed for
# Groth16 proof generation and verification.
#
# For production, use a multi-party computation ceremony.
# This script runs a LOCAL ceremony suitable for development/hackathon.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
BUILD_DIR="$ROOT/build"
KEYS_DIR="$ROOT/build/keys"

export PATH="$HOME/.local/bin:$PATH"

echo "═══════════════════════════════════════════════════"
echo "  SauronID — Trusted Setup Ceremony"
echo "═══════════════════════════════════════════════════"

mkdir -p "$KEYS_DIR"

# ─── Phase 1: Powers of Tau (Universal — BN128) ──────────
# Power 18 supports circuits up to 2^18 = 262144 constraints
PTAU_POWER=18
PTAU_FILE="$KEYS_DIR/pot${PTAU_POWER}_final.ptau"

if [ -f "$PTAU_FILE" ]; then
    echo "  ⚡ Phase 1 (Powers of Tau) already exists: $PTAU_FILE"
else
    echo ""
    echo "────────────────────────────────────────────────"
    echo "  Phase 1: Powers of Tau (bn128, power=$PTAU_POWER)"
    echo "────────────────────────────────────────────────"

    echo "  [1/4] Generating initial ceremony..."
    snarkjs powersoftau new bn128 $PTAU_POWER "$KEYS_DIR/pot${PTAU_POWER}_0.ptau" -v

    echo "  [2/4] Contributing entropy (SauronID Dev)..."
    snarkjs powersoftau contribute \
        "$KEYS_DIR/pot${PTAU_POWER}_0.ptau" \
        "$KEYS_DIR/pot${PTAU_POWER}_1.ptau" \
        --name="SauronID Hackathon Ceremony" \
        -e="SauronID-hackeurope-2024-trusted-setup-entropy"

    echo "  [3/4] Applying random beacon..."
    snarkjs powersoftau beacon \
        "$KEYS_DIR/pot${PTAU_POWER}_1.ptau" \
        "$KEYS_DIR/pot${PTAU_POWER}_beacon.ptau" \
        0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
        10

    echo "  [4/4] Preparing Phase 2..."
    snarkjs powersoftau prepare phase2 \
        "$KEYS_DIR/pot${PTAU_POWER}_beacon.ptau" \
        "$PTAU_FILE" \
        -v

    # Cleanup intermediate files
    rm -f "$KEYS_DIR/pot${PTAU_POWER}_0.ptau" \
          "$KEYS_DIR/pot${PTAU_POWER}_1.ptau" \
          "$KEYS_DIR/pot${PTAU_POWER}_beacon.ptau"

    echo "  ✓ Phase 1 complete: $PTAU_FILE"
fi

# ─── Phase 2: Circuit-specific setup ─────────────────────
CIRCUITS=("AgeVerification" "MerkleInclusion" "CredentialVerification")

for circuit in "${CIRCUITS[@]}"; do
    R1CS_FILE="$BUILD_DIR/${circuit}.r1cs"
    ZKEY_FINAL="$KEYS_DIR/${circuit}_final.zkey"
    VKEY_FILE="$KEYS_DIR/${circuit}_verification_key.json"

    if [ ! -f "$R1CS_FILE" ]; then
        echo "  ⚠ Skipping $circuit — R1CS not found. Run compile.sh first."
        continue
    fi

    if [ -f "$ZKEY_FINAL" ]; then
        echo "  ⚡ Phase 2 for $circuit already exists."
        continue
    fi

    echo ""
    echo "────────────────────────────────────────────────"
    echo "  Phase 2: $circuit"
    echo "────────────────────────────────────────────────"

    echo "  [1/3] Groth16 setup..."
    snarkjs groth16 setup \
        "$R1CS_FILE" \
        "$PTAU_FILE" \
        "$KEYS_DIR/${circuit}_0.zkey"

    echo "  [2/3] Contributing to $circuit ceremony..."
    snarkjs zkey contribute \
        "$KEYS_DIR/${circuit}_0.zkey" \
        "$ZKEY_FINAL" \
        --name="SauronID ${circuit} Phase 2" \
        -e="SauronID-${circuit}-phase2-entropy"

    echo "  [3/3] Exporting verification key..."
    snarkjs zkey export verificationkey \
        "$ZKEY_FINAL" \
        "$VKEY_FILE"

    # Cleanup
    rm -f "$KEYS_DIR/${circuit}_0.zkey"

    echo "  ✓ Phase 2 complete for $circuit"
    echo "    Proving key:      $ZKEY_FINAL"
    echo "    Verification key: $VKEY_FILE"
done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Trusted Setup Complete!"
echo ""
echo "  Keys directory: $KEYS_DIR"
ls -la "$KEYS_DIR/"
echo "═══════════════════════════════════════════════════"
