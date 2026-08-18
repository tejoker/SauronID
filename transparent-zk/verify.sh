#!/usr/bin/env bash
set -euo pipefail

# Self-locating, and deliberately references nothing outside this directory:
# transparent-zk/ is published on its own to a public mirror so customers can
# reproduce the guest image IDs without the rest of the repository. This is the
# script they run, unchanged — the same file the release gate runs.
ZK="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$ZK/image-ids.json"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  }
}

require cargo
require jq
require sha256sum
require docker

# The pins in image-ids.json are only reproducible from a containerised guest
# build. Built locally, the guest ELF embeds this machine's absolute paths and
# the image ID changes with the working directory, so checking a local build
# against published pins can only ever fail. See transparent-zk/methods/build.rs.
export SAURON_ZK_DOCKER_BUILD=1

docker buildx version >/dev/null 2>&1 || {
  printf 'docker buildx is required: the risc0 guest build uses `docker build --output`\n' >&2
  exit 1
}

check_lock() {
  local relative="$1"
  local expected actual
  expected="$(jq -er --arg path "$relative" '.lock_sha256[$path]' "$MANIFEST")"
  actual="$(sha256sum "$ZK/$relative" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    printf 'lock digest mismatch for %s: expected %s, got %s\n' \
      "$relative" "$expected" "$actual" >&2
    exit 1
  fi
}

check_lock Cargo.lock
check_lock verifier/Cargo.lock
check_lock methods/guest/Cargo.lock
check_lock methods/action-policy-guest/Cargo.lock

# `risc0-build` compiles the guest with its deterministic release profile even
# when the host utility uses Cargo's debug profile. Reserve the much heavier
# host release build for signed release tags that also generate proofs.
profile_args=()
if [[ "${SAURON_TRANSPARENT_FULL_PROVE:-0}" == "1" ]]; then
  profile_args+=(--release)
fi

cargo build --locked "${profile_args[@]}" --manifest-path "$ZK/Cargo.toml"

generated="$(mktemp)"
expected="$(mktemp)"
stats_proof="$(mktemp)"
action_proof="$(mktemp)"
trap 'rm -f "$generated" "$expected" "$stats_proof" "$action_proof"' EXIT

cargo run --quiet --locked "${profile_args[@]}" --manifest-path "$ZK/Cargo.toml" \
  --bin sauron-transparent-prover -- --image-ids | jq -S . >"$generated"
jq -S '.programs' "$MANIFEST" >"$expected"
cmp --silent "$expected" "$generated" || {
  printf 'transparent guest image IDs differ from image-ids.json\n' >&2
  diff -u "$expected" "$generated" >&2 || true
  exit 1
}

cargo test --locked "${profile_args[@]}" --manifest-path "$ZK/verifier/Cargo.toml"

# Proof generation is deliberately a release-only cost. Pull requests still
# reproduce the ELF/image IDs and test the verifier without spending minutes on
# two full STARK proofs. Release tags pass each untrusted proof file through the
# separate customer verifier, rather than trusting the prover's self-check.
if [[ "${SAURON_TRANSPARENT_FULL_PROVE:-0}" == "1" ]]; then
  cargo run --quiet --locked --release --manifest-path "$ZK/Cargo.toml" \
    --bin sauron-transparent-prover -- \
    --stats "$ZK/fixtures/stats-one-record.json" >"$stats_proof"
  cargo run --quiet --locked --release --manifest-path "$ZK/verifier/Cargo.toml" \
    -- "$stats_proof" >/dev/null

  cargo run --quiet --locked --release --manifest-path "$ZK/Cargo.toml" \
    --bin sauron-transparent-prover -- \
    --action-policy "$ZK/fixtures/action-policy-one-record.json" >"$action_proof"
  cargo run --quiet --locked --release --manifest-path "$ZK/verifier/Cargo.toml" \
    -- "$action_proof" >/dev/null
fi

printf 'transparent ZK locks, image IDs, verifier%s: OK\n' \
  "$(if [[ "${SAURON_TRANSPARENT_FULL_PROVE:-0}" == "1" ]]; then printf ', and native proofs'; fi)"
