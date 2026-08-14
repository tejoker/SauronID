#!/usr/bin/env bash
set -euo pipefail

OWNER="${OWNER:-tejoker}"
REPO="${REPO:-SauronID}"
# confidence-gate is gone: it ran core/tests/run_confidence_suite.sh, which is
# untracked with the rest of the ZKP issuer-dependent e2e surface.
CHECKS="${CHECKS:-release-gate,test-sqlite,test-postgres,kya-e2e}"
TARGET_BRANCHES=("$@")
if [[ ${#TARGET_BRANCHES[@]} -eq 0 ]]; then
  TARGET_BRANCHES=(main pocv1)
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found. Install gh first." >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated. Run: gh auth login" >&2
  exit 1
fi

IFS=',' read -r -a check_contexts <<< "$CHECKS"
json_contexts=""
for c in "${check_contexts[@]}"; do
  c_trimmed="${c//[[:space:]]/}"
  if [[ -n "$c_trimmed" ]]; then
    json_contexts+="\"$c_trimmed\","
  fi
done
json_contexts="${json_contexts%,}"

if [[ -z "$json_contexts" ]]; then
  echo "No status checks configured. Set CHECKS env var." >&2
  exit 1
fi

for branch in "${TARGET_BRANCHES[@]}"; do
  echo "Applying branch protection on ${OWNER}/${REPO}:${branch}"

  gh api --method PUT \
    "repos/${OWNER}/${REPO}/branches/${branch}/protection" \
    --header "Accept: application/vnd.github+json" \
    --input - <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": [${json_contexts}]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1
  },
  "restrictions": null
}
JSON

done

echo "Branch protection applied."
