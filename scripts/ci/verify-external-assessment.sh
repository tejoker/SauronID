#!/usr/bin/env bash
set -euo pipefail

expected_commit=${1:-}
manifest=release/external-assessment.json
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
[[ -n "$expected_commit" ]] || { echo "usage: $0 <release-commit-sha>" >&2; exit 2; }
[[ "${SAURON_REVIEWER_KEY_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "SAURON_REVIEWER_KEY_SHA256 must come from the protected independent-review environment" >&2
  exit 1
}
[[ -f "$manifest" ]] || { echo "missing independent assessment manifest: $manifest" >&2; exit 1; }

status=$(jq -er '.status' "$manifest")
commit=$(jq -er '.reviewed_commit' "$manifest")
reviewer=$(jq -er '.reviewer_organization' "$manifest")
report=$(jq -er '.report_sha256' "$manifest")
public_key=$(jq -er '.reviewer_public_key_pem' "$manifest")
signature=$(jq -er '.statement_signature_b64' "$manifest")
crypto=$(jq -r '.scope.crypto_protocols' "$manifest")
pentest=$(jq -r '.scope.deployment_penetration_test' "$manifest")
critical=$(jq -er '.open_findings.critical' "$manifest")
high=$(jq -er '.open_findings.high' "$manifest")

[[ "$status" == "approved" ]] || { echo "independent assessment is not approved" >&2; exit 1; }
[[ "$commit" == "$expected_commit" ]] || { echo "assessment covers $commit, release is $expected_commit" >&2; exit 1; }
[[ -n "$reviewer" && "$reviewer" != "PENDING" ]] || { echo "independent reviewer organization missing" >&2; exit 1; }
[[ "$report" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid report SHA-256" >&2; exit 1; }
[[ "$public_key" == release/reviewers/*.pem && -f "$public_key" ]] || { echo "pinned reviewer public key missing" >&2; exit 1; }
actual_key_sha=$(sha256sum "$public_key" | awk '{print $1}')
[[ "$actual_key_sha" == "$SAURON_REVIEWER_KEY_SHA256" ]] || {
  echo "reviewer public key does not match the protected trust anchor" >&2
  exit 1
}
[[ "$signature" != "PENDING" ]] || { echo "reviewer signature missing" >&2; exit 1; }
[[ "$crypto" == "true" && "$pentest" == "true" ]] || { echo "assessment must cover crypto and deployment penetration testing" >&2; exit 1; }
[[ "$critical" == "0" && "$high" == "0" ]] || { echo "release has open critical/high external findings" >&2; exit 1; }

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
statement=$(mktemp)
sigfile=$(mktemp)
trap 'rm -f "$statement" "$sigfile"' EXIT
jq -cS 'del(.statement_signature_b64)' "$manifest" >"$statement"
printf '%s' "$signature" | openssl base64 -d -A >"$sigfile" 2>/dev/null || {
  echo "reviewer signature is not valid base64" >&2
  exit 1
}
openssl pkeyutl -verify -pubin -inkey "$public_key" -rawin \
  -in "$statement" -sigfile "$sigfile" >/dev/null 2>&1 || {
  echo "independent assessment signature verification failed" >&2
  exit 1
}

echo "independent assessment approved for $expected_commit by $reviewer"
