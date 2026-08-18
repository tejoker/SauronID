#!/usr/bin/env bash
# Publish transparent-zk/ to the public mirror as a squashed snapshot.
#
# Why a mirror at all: the product's verifiability claim needs the guest source
# public — a customer must be able to rebuild the guests and compare image IDs
# against transparent-zk/image-ids.json, or the published ID means nothing. That
# requires exactly this one directory and nothing else: the guest ELF is all the
# image ID covers, and transparent-zk/ has no path dependency on the rest of the
# repository (the dependency runs the other way, core -> transparent-zk/types).
# So the gateway, policy engine, dashboard and deployment can stay private
# without weakening a single proof.
#
# Why squashed: the private repository's history must never reach a public
# remote. Each release replaces the mirror's tree wholesale and commits once, so
# there is nothing to leak even if a file was private in an earlier version. The
# cost is that the mirror carries no development history, which is the point.
#
# Run by .github/workflows/release-publish.yml after the release gate has
# already reproduced the image IDs, so an unverified guest can never be
# published as if it were reviewed.
set -euo pipefail

VERSION="${1:?usage: mirror-transparent-zk.sh <version> (e.g. v0.2.0)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# MIRROR_DRY_RUN=1 pushes to a throwaway local bare repository instead of
# GitHub, so the whole path — snapshot contents, self-containment, commit, tag —
# is testable without credentials or a public remote.
DRY_RUN="${MIRROR_DRY_RUN:-0}"

if [[ "$DRY_RUN" == "1" ]]; then
  : "${MIRROR_LOCAL_DEST:?MIRROR_LOCAL_DEST is required when MIRROR_DRY_RUN=1}"
  remote="$MIRROR_LOCAL_DEST"
else
  : "${MIRROR_REPO:?MIRROR_REPO is required (owner/name of the public mirror)}"
  : "${MIRROR_TOKEN:?MIRROR_TOKEN is required (PAT with contents:write on the mirror)}"
  remote="https://x-access-token:${MIRROR_TOKEN}@github.com/${MIRROR_REPO}.git"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
repo="$work/mirror"

# A brand-new mirror repository has no commits, so clone is allowed to fail and
# we fall back to an empty local repository pointed at the same remote.
git clone --quiet --depth 1 "$remote" "$repo" 2>/dev/null || {
  echo "mirror has no commits yet; initialising"
  git init --quiet -b main "$repo"
  git -C "$repo" remote add origin "$remote"
}

# Replace the tree wholesale rather than copying over it: a file deleted from
# transparent-zk must disappear from the mirror too.
find "$repo" -mindepth 1 -maxdepth 1 -not -name .git -exec rm -rf {} +

# The transparent-zk/ prefix is preserved deliberately. Every command in the
# README and in verify.sh is written against that path, so keeping it means
# documentation and scripts work byte-identically in both repositories.
mkdir -p "$repo/transparent-zk"
tar -c -C "$ROOT" \
  --exclude='target' --exclude='target-*' --exclude='.git' \
  transparent-zk | tar -x -C "$repo" --strip-components=0
# The root LICENSE is now a map that marks most of the repository proprietary.
# The mirror must carry the Apache text itself, or the published guest source
# would ship under terms that contradict the whole point of publishing it.
cp "$ROOT/LICENSE-APACHE-2.0" "$repo/LICENSE"
# @@REPO@@ matters as much as @@VERSION@@: the README carries the cosign
# command a customer runs to check the image was built by us. Left as a
# literal "OWNER/REPO" it shipped verification instructions that cannot be
# copied — the one artifact where that is least acceptable.
SOURCE_REPO="${GITHUB_REPOSITORY:-tejoker/SauronID}"
sed -e "s/@@VERSION@@/${VERSION}/g" -e "s#@@REPO@@#${SOURCE_REPO}#g" \
  "$ROOT/scripts/release/mirror-README.md" >"$repo/README.md"
if grep -q "@@" "$repo/README.md"; then
  echo "[FATAL] unsubstituted placeholder left in the mirror README:" >&2
  grep -n "@@" "$repo/README.md" >&2
  exit 1
fi

# Fail loudly if the snapshot is missing anything a customer needs, rather than
# publishing a mirror that cannot reproduce the pins.
for required in \
  transparent-zk/verify.sh \
  transparent-zk/image-ids.json \
  transparent-zk/methods/build.rs \
  transparent-zk/methods/guest/Cargo.lock \
  transparent-zk/methods/action-policy-guest/Cargo.lock \
  transparent-zk/verifier/Cargo.toml \
  transparent-zk/types/Cargo.toml; do
  [[ -e "$repo/$required" ]] || {
    printf 'snapshot is missing %s\n' "$required" >&2
    exit 1
  }
done

# Every relative reference must resolve inside the snapshot. Checking the text
# for `../..` is not the same test and gives false positives: verifier/src/main.rs
# includes ../../image-ids.json, which lands in transparent-zk/ and is correct.
# Resolve each reference instead, and require that it exists and stays inside.
escapes=0
check_ref() {
  local from="$1" raw="$2" target
  target="$(realpath -m "$(dirname "$from")/$raw")"
  case "$target" in
    "$repo"/transparent-zk | "$repo"/transparent-zk/*)
      [[ -e "$target" ]] || {
        printf 'dangling reference: %s -> %s\n' "${from#"$repo/"}" "$raw" >&2
        escapes=1
      }
      ;;
    *)
      printf 'reference escapes the snapshot: %s -> %s\n' "${from#"$repo/"}" "$raw" >&2
      escapes=1
      ;;
  esac
}

while IFS= read -r -d '' file; do
  case "$file" in
    *.toml)
      # Path dependencies. Registry and git deps have no `path` key.
      while IFS= read -r raw; do
        check_ref "$file" "$raw"
      done < <(grep -oE 'path *= *"[^"]+"' "$file" | sed -E 's/.*"(.*)"/\1/')
      ;;
    *.rs)
      while IFS= read -r raw; do
        check_ref "$file" "$raw"
      done < <(grep -oE 'include_(str|bytes)!\("[^"]+"\)' "$file" |
        sed -E 's/.*"(.*)".*/\1/')
      ;;
  esac
done < <(find "$repo/transparent-zk" \( -name '*.toml' -o -name '*.rs' \) -print0)

[[ "$escapes" -eq 0 ]] || exit 1

git -C "$repo" add -A
if git -C "$repo" diff --cached --quiet; then
  echo "guest source unchanged since the last snapshot; tagging existing commit"
else
  git -C "$repo" \
    -c user.name="SauronID release" \
    -c user.email="release@sauronid.invalid" \
    commit --quiet -m "transparent-zk snapshot ${VERSION}

Reproducible guest source for SauronID ${VERSION}. Squashed snapshot; see
README.md for how to rebuild the guests and compare image IDs."
fi

git -C "$repo" tag -f "$VERSION"

# Push to whatever the mirror's default branch actually is. Assuming `main`
# publishes a second branch on a mirror created with a different default, which
# leaves visitors on an empty default branch.
branch="$(git -C "$repo" ls-remote --symref origin HEAD 2>/dev/null |
  awk '/^ref:/ { sub("refs/heads/", "", $2); print $2; exit }')"
git -C "$repo" push --quiet origin "HEAD:${branch:-main}"
git -C "$repo" push --quiet --force origin "refs/tags/$VERSION"

printf 'mirrored transparent-zk %s -> %s\n' "$VERSION" \
  "$(if [[ "$DRY_RUN" == "1" ]]; then printf '%s (dry run)' "$MIRROR_LOCAL_DEST"; else printf '%s' "$MIRROR_REPO"; fi)"
