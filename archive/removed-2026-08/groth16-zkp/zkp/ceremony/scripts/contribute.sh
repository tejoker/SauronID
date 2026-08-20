#!/usr/bin/env bash
#
# contribute.sh — STUB skeleton for a Phase 2 Groth16 contribution.
#
# DO NOT use this script for a real production ceremony as-is. A real
# multi-party ceremony coordinates contributors over weeks via a public
# coordinator and uses an air-gapped contribution machine per party.
#
# See zkp/ceremony/README.md for the full procedure.
#
# Usage:
#   contribute.sh <circuit_name> <contributor_index> <random_entropy>
#
# Example:
#   contribute.sh ActionSumBound 3 "$(head -c 256 /dev/urandom | base64)"

set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <circuit_name> <contributor_index> <random_entropy>" >&2
    exit 64
fi

CIRCUIT="$1"
INDEX="$2"
ENTROPY="$3"

BUILD_DIR="$(cd "$(dirname "$0")/../.." && pwd)/circuits/build/${CIRCUIT}"
PREV_ZKEY="${BUILD_DIR}/${CIRCUIT}_$(printf '%04d' $((INDEX - 1))).zkey"
NEXT_ZKEY="${BUILD_DIR}/${CIRCUIT}_$(printf '%04d' "${INDEX}").zkey"

cat <<EOF
[STUB] contribute.sh — Phase 2 contribution skeleton
  circuit          : ${CIRCUIT}
  contributor idx  : ${INDEX}
  previous zkey    : ${PREV_ZKEY}
  next zkey        : ${NEXT_ZKEY}

This stub does NOT run a real ceremony. A real run would invoke:

  snarkjs zkey contribute \\
      "${PREV_ZKEY}" \\
      "${NEXT_ZKEY}" \\
      --name="contributor-${INDEX}" \\
      -v -e="\${ENTROPY}"

and publish the contribution attestation. The contributor MUST then securely
delete the random tape (toxic waste) and document the destruction.

See zkp/ceremony/README.md for the full procedure.
EOF
