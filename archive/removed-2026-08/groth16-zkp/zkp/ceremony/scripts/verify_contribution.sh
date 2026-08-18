#!/usr/bin/env bash
#
# verify_contribution.sh — STUB skeleton verifying one Phase 2 contribution.
#
# Real verification ensures that:
#   1. The new zkey is well-formed.
#   2. It is a valid extension of the previous zkey.
#   3. The contributor's attestation hash appears in the public log.
#
# Usage:
#   verify_contribution.sh <circuit_name> <contributor_index>

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <circuit_name> <contributor_index>" >&2
    exit 64
fi

CIRCUIT="$1"
INDEX="$2"

BUILD_DIR="$(cd "$(dirname "$0")/../.." && pwd)/circuits/build/${CIRCUIT}"
PREV_ZKEY="${BUILD_DIR}/${CIRCUIT}_$(printf '%04d' $((INDEX - 1))).zkey"
NEW_ZKEY="${BUILD_DIR}/${CIRCUIT}_$(printf '%04d' "${INDEX}").zkey"

cat <<EOF
[STUB] verify_contribution.sh — Phase 2 verification skeleton
  circuit          : ${CIRCUIT}
  contributor idx  : ${INDEX}
  previous zkey    : ${PREV_ZKEY}
  new zkey         : ${NEW_ZKEY}

A real run would invoke:

  snarkjs zkey verify \\
      "circuits/build/${CIRCUIT}/${CIRCUIT}.r1cs" \\
      "powersOfTau28_hez_final_<n>.ptau" \\
      "${NEW_ZKEY}"

…and confirm that the contribution-hash chain is intact and that the
contributor's public attestation matches the published log.

See zkp/ceremony/README.md.
EOF
