#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
manifest=release/manifest.json
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

expected_tag=$(jq -er '.release_tag' "$manifest")
actual_tag=${1:-$expected_tag}
[[ "$actual_tag" == "$expected_tag" ]] || { echo "tag $actual_tag does not match manifest $expected_tag" >&2; exit 1; }
release_version=${expected_tag#v}
[[ "$expected_tag" == v[0-9]* && "$release_version" != "$expected_tag" ]] || {
  echo "release tag must be a v-prefixed version" >&2
  exit 1
}

core=$(sed -n 's/^version = "\([^"]*\)"/\1/p' core/Cargo.toml | head -1)
python=$(sed -n 's/^version = "\([^"]*\)"/\1/p' sdk/python/pyproject.toml | head -1)
agentic=$(jq -er '.version' sdk/typescript/package.json)
tool=$(jq -er '.version' packaging/npm-agent-action-tool/package.json)

[[ "$core" == "$(jq -er '.components.core' "$manifest")" ]] || { echo "core version drift" >&2; exit 1; }
[[ "$python" == "$(jq -er '.components.python' "$manifest")" ]] || { echo "Python version drift" >&2; exit 1; }
[[ "$core" == "$release_version" && "$python" == "$release_version" ]] || {
  echo "release tag, core, and Python versions must match" >&2
  exit 1
}
[[ "$agentic" == "$(jq -er '.components.agentic_npm' "$manifest")" ]] || { echo "agentic version drift" >&2; exit 1; }
[[ "$tool" == "$(jq -er '.components.agent_action_tool_npm' "$manifest")" ]] || { echo "tool version drift" >&2; exit 1; }
# PostgreSQL became a supported topology once `DbHandle::lock()` started
# dispatching (every call site, not a subset) and the tier was measured — see
# Runs load profiles C and D. The allowlist stays an allowlist: a topology
# string nobody has run a soak against must not reach a release.
case "$(jq -er '.supported_topology' "$manifest")" in
  single-node-sqlite|single-node-sqlite-or-postgres) ;;
  *) echo "unsupported or misleading topology" >&2; exit 1 ;;
esac
[[ "$(jq -er '.high_availability' "$manifest")" == "false" ]] || { echo "HA must remain false until the Postgres port and failover suite are complete" >&2; exit 1; }
grep -Fq "## [${expected_tag#v}]" CHANGELOG.md || { echo "CHANGELOG has no ${expected_tag#v} release entry" >&2; exit 1; }
[[ "$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)" == "1.91.1" ]] || {
  echo "release Rust toolchain must remain pinned to 1.91.1" >&2
  exit 1
}

for dockerfile in core/Dockerfile dashboard/Dockerfile; do
  if grep -E '^FROM [^[:space:]]+($|[[:space:]])' "$dockerfile" | grep -vq '@sha256:[0-9a-f]\{64\}'; then
    echo "$dockerfile contains a mutable base-image reference" >&2
    exit 1
  fi
done

grep -Fq 'cargo build --locked --release' core/Dockerfile || {
  echo "core container build must enforce Cargo.lock" >&2
  exit 1
}
grep -Fq 'COPY package.json package-lock.json ./' dashboard/Dockerfile || {
  echo "dashboard container build must require package-lock.json" >&2
  exit 1
}

# Prevent a future workflow edit from creating a publishing path that bypasses
# the protected independent-review environment. This parser intentionally only
# accepts the simple top-level jobs/needs form used by this workflow.
python3 scripts/ci/verify-release-dag.py .github/workflows/release-publish.yml

echo "release metadata OK: $expected_tag"
