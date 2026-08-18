#!/usr/bin/env bash
# deploy/nitro/run.sh — operator workflow for building + running the SauronID
# Nitro enclave image, then capturing an attestation document the operator
# can POST to the core API.
#
# Pre-reqs (NOT installed by this script):
#   - AWS EC2 m5n / r5n / c5n instance (or any Nitro-capable family)
#   - nitro-cli (`sudo dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel`)
#   - Docker (build host) — the build stage runs inside Amazon Linux 2023
#   - Enclave allocator service enabled (`sudo systemctl start nitro-enclaves-allocator`)
#   - Operator-side env: SAURON_CORE_URL pointing at the running core API
#
# Workflow:
#   1. Build the EIF (enclave image file) from Dockerfile.enclave.
#   2. Boot the enclave with a sane CPU+memory allocation.
#   3. Read the attestation document over vsock from the enclave's
#      `nitro-enclave` daemon.
#   4. Print the base64-encoded document for the operator to POST to
#      /v1/attestation/nitro/verify (or pipe to curl directly if the operator
#      sets POST_NOW=1).

set -euo pipefail

# ── Config (operator-overridable via env) ────────────────────────────────────
REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
IMAGE_TAG="${IMAGE_TAG:-sauronid-nitro-enclave:dev}"
EIF_PATH="${EIF_PATH:-${REPO_ROOT}/deploy/nitro/sauronid-enclave.eif}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"      # arbitrary CID > 3
ENCLAVE_PORT="${ENCLAVE_PORT:-5005}"  # matches Dockerfile.enclave ENV
ENCLAVE_CPUS="${ENCLAVE_CPUS:-2}"
ENCLAVE_MEM_MB="${ENCLAVE_MEM_MB:-512}"
SAURON_CORE_URL="${SAURON_CORE_URL:-http://localhost:4000}"
SAURON_ADMIN_KEY="${SAURON_ADMIN_KEY:-}"   # set when POST_NOW=1
POST_NOW="${POST_NOW:-0}"
EXPECTED_MEASUREMENT_HEX="${EXPECTED_MEASUREMENT_HEX:-}"
PARENT_NONCE="${PARENT_NONCE:-}"

# ── Helpers ──────────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[deploy/nitro/run.sh] $*" >&2; }

ensure_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found in PATH. Install pre-reqs first."
}

random_nonce_b64() {
    head -c 16 /dev/urandom | base64 -w0
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
ensure_cmd docker
ensure_cmd nitro-cli
ensure_cmd jq
ensure_cmd curl
ensure_cmd base64

# ── Stage 1: build the Docker image + EIF ────────────────────────────────────
note "building Docker image '${IMAGE_TAG}' from ${REPO_ROOT}/deploy/nitro/Dockerfile.enclave"
docker build \
    -f "${REPO_ROOT}/deploy/nitro/Dockerfile.enclave" \
    -t "${IMAGE_TAG}" \
    "${REPO_ROOT}"

note "building EIF -> ${EIF_PATH}"
nitro-cli build-enclave \
    --docker-uri "${IMAGE_TAG}" \
    --output-file "${EIF_PATH}"

# ── Stage 2: launch the enclave ──────────────────────────────────────────────
note "terminating any existing enclave (best-effort)"
nitro-cli describe-enclaves | jq -r '.[].EnclaveID' | while read -r eid; do
    [ -z "$eid" ] || nitro-cli terminate-enclave --enclave-id "$eid" || true
done

note "launching enclave with cid=${ENCLAVE_CID} cpus=${ENCLAVE_CPUS} mem=${ENCLAVE_MEM_MB}MB"
nitro-cli run-enclave \
    --eif-path "${EIF_PATH}" \
    --cpu-count "${ENCLAVE_CPUS}" \
    --memory "${ENCLAVE_MEM_MB}" \
    --enclave-cid "${ENCLAVE_CID}"

# ── Stage 3: capture the attestation document ────────────────────────────────
NONCE_B64="${PARENT_NONCE:-$(random_nonce_b64)}"
REQ_JSON=$(printf '{"nonce_b64":"%s"}\n' "${NONCE_B64}")

note "requesting attestation document over vsock (cid=${ENCLAVE_CID} port=${ENCLAVE_PORT})"
# socat ships in amazon-linux-extras; ncat (nmap-ncat) is the alternative.
# We fall back to a python one-liner if neither is present.
if command -v socat >/dev/null 2>&1; then
    RESP=$(printf '%s' "${REQ_JSON}" | socat - VSOCK-CONNECT:"${ENCLAVE_CID}":"${ENCLAVE_PORT}")
elif command -v ncat >/dev/null 2>&1; then
    RESP=$(printf '%s' "${REQ_JSON}" | ncat --vsock "${ENCLAVE_CID}" "${ENCLAVE_PORT}")
else
    die "neither socat nor ncat installed; cannot speak vsock"
fi

DOC_B64=$(echo "${RESP}" | jq -r '.document_b64')
PUBKEY_B64=$(echo "${RESP}" | jq -r '.public_key_b64')
IS_STUB=$(echo "${RESP}" | jq -r '.stub')

if [ "${IS_STUB}" = "true" ]; then
    cat >&2 <<EOF
WARNING: enclave returned a STUB attestation document. The 'nitro-enclave'
binary is currently built without the aws-nitro-enclaves-nsm-api crate. See
deploy/nitro/README.md "Enabling real NSM" for the one-line dep edit.
EOF
fi

note "ephemeral public key (base64): ${PUBKEY_B64}"
note "attestation document (base64), copy to operator console:"
echo "${DOC_B64}"

# ── Stage 4 (optional): post to the core API ─────────────────────────────────
if [ "${POST_NOW}" = "1" ]; then
    [ -n "${SAURON_ADMIN_KEY}" ] || die "POST_NOW=1 but SAURON_ADMIN_KEY is unset"
    [ -n "${EXPECTED_MEASUREMENT_HEX}" ] \
        || die "POST_NOW=1 but EXPECTED_MEASUREMENT_HEX is unset"
    note "POST ${SAURON_CORE_URL}/v1/attestation/nitro/verify"
    curl -sS -X POST \
        -H "Content-Type: application/json" \
        -H "x-admin-key: ${SAURON_ADMIN_KEY}" \
        -d "$(jq -nc \
            --arg blob "${DOC_B64}" \
            --arg meas "${EXPECTED_MEASUREMENT_HEX}" \
            '{attestation_blob_b64: $blob, expected_measurement_hash: $meas}')" \
        "${SAURON_CORE_URL}/v1/attestation/nitro/verify" \
        | jq .
fi
