#!/usr/bin/env bash
# Assert every COPY source in every Dockerfile exists relative to the build
# context the compose files actually pass, and that a Rust manifest's path
# dependencies are inside that context.
#
# This exists because core/Cargo.toml gained a path dependency on
# ../transparent-zk/types while core/Dockerfile still built with context core/.
# Every image in the repo failed at `cargo fetch --locked` for two months and no
# workflow noticed, because catching it in CI otherwise costs a full docker
# build. This check costs milliseconds and needs no daemon.
set -euo pipefail

cd "$(dirname "$0")/../.."
fail=0
note() { printf '  %s\n' "$*"; }
bad() {
    printf '  FAIL %s\n' "$*"
    fail=1
}

# context|dockerfile — the pairs the compose files and run scripts use.
# Override with arguments to check a single pair (used by this script's own
# negative test against the pre-fix Dockerfile).
PAIRS="${*:-"
.|core/Dockerfile
.|deploy/nitro/Dockerfile.enclave
dashboard|dashboard/Dockerfile
"}"

for pair in $PAIRS; do
    [ -n "$pair" ] || continue
    ctx="${pair%%|*}"
    dockerfile="${pair##*|}"
    echo "== $dockerfile (context: $ctx)"
    [ -f "$dockerfile" ] || {
        bad "$dockerfile does not exist"
        continue
    }

    # COPY sources, skipping --from=<stage> copies (those resolve inside the
    # image, not the context) and skipping flags.
    while read -r line; do
        case "$line" in *--from=*) continue ;; esac
        # Drop the COPY keyword and the destination (last field).
        set -- $line
        shift
        n=$#
        i=0
        for src in "$@"; do
            i=$((i + 1))
            [ "$i" -lt "$n" ] || break # last field is the destination
            case "$src" in --*) continue ;; esac
            if [ -e "$ctx/$src" ]; then
                note "ok   $src"
            else
                # Expand as a glob; an unmatched pattern stays literal, so the
                # -e test below still fails. (compgen -G is unusable here: it
                # echoes non-glob words back as literal completions.)
                # shellcheck disable=SC2206
                matches=($ctx/$src)
                if [ -e "${matches[0]}" ]; then
                    note "ok   $src (glob)"
                else
                    bad "COPY $src is outside the build context $ctx/"
                fi
            fi
        done
    done < <(grep -E '^[[:space:]]*COPY[[:space:]]' "$dockerfile" || true)
done

# Cargo path dependencies must also live inside the context that builds them.
echo "== cargo path dependencies reachable from context ."
while read -r dep; do
    resolved="core/$dep"
    if [ -f "$(realpath -m "$resolved")/Cargo.toml" ] &&
        case "$(realpath -m "$resolved")" in "$(pwd)"/*) true ;; *) false ;; esac then
        note "ok   core -> $dep"
    else
        bad "core path dependency $dep is not inside the repository root context"
    fi
done < <(grep -oE 'path = "[^"]+"' core/Cargo.toml | sed 's/path = "//; s/"//')

# Every compose build context must exist. Compose validates all of them when it
# loads the file, so one service pointing at a deleted directory kills `up` for
# every other service too — which is how a removed hardhat-node context broke the
# e2e job long after nothing referenced it.
echo "== compose build contexts exist"
if ! python3 - "$(pwd)" <<'PY'; then
import os, sys, glob
try:
    import yaml
except ImportError:
    print("  (pyyaml unavailable — skipped)")
    sys.exit(0)
root = sys.argv[1]
bad = False


def check_pair(source, name, base, ctx, dockerfile):
    """Assert one (context, dockerfile) pair is buildable, wherever it came from."""
    global bad
    ctx_abs = os.path.normpath(os.path.join(base, ctx))
    df_abs = os.path.normpath(os.path.join(base, dockerfile)) if os.path.isabs(
        dockerfile) or dockerfile.startswith(("./", "../")) or os.path.exists(
        os.path.join(base, dockerfile)) else os.path.normpath(
        os.path.join(ctx_abs, dockerfile))
    for label, path in (("context", ctx_abs), ("dockerfile", df_abs)):
        if os.path.exists(path):
            print(f"  ok   {source}:{name} {label} {os.path.relpath(path, root)}")
        else:
            print(f"  FAIL {source}:{name} {label} "
                  f"{os.path.relpath(path, root)} does not exist")
            bad = True
    # Anything building core/Dockerfile must see core's path dependency, so its
    # context has to be the repository root, not core/.
    if df_abs.endswith(os.path.join("core", "Dockerfile")):
        dep = os.path.join(ctx_abs, "transparent-zk", "types", "Cargo.toml")
        if os.path.exists(dep):
            print(f"  ok   {source}:{name} context covers transparent-zk/types")
        else:
            print(f"  FAIL {source}:{name} context {os.path.relpath(ctx_abs, root)} "
                  "cannot see transparent-zk/types (cargo will fail to load the manifest)")
            bad = True


# Workflow image builds get the same treatment as compose. They were exempt, and
# that is precisely where the bug survived: release-publish.yml built the core
# image with `context: ./core`, which cannot see transparent-zk/types, so every
# release tag's core image failed while compose stayed correct.
for f in sorted(glob.glob(".github/workflows/*.yml")):
    doc = yaml.safe_load(open(f)) or {}
    for job_name, job in (doc.get("jobs") or {}).items():
        include = (((job.get("strategy") or {}).get("matrix") or {}).get("include")) or []
        for entry in include:
            if not isinstance(entry, dict) or "dockerfile" not in entry:
                continue
            check_pair(f, f"{job_name}/{entry.get('name', '?')}", root,
                       entry.get("context", "."), entry["dockerfile"])

for f in sorted(glob.glob("docker-compose*.yml") + glob.glob("deploy/docker-compose*.yml")):
    base = os.path.dirname(os.path.join(root, f)) or root
    for name, svc in (yaml.safe_load(open(f)) or {}).get("services", {}).items():
        # An `environment` entry that parses as a mapping instead of a string
        # means an unquoted ": " somewhere in the value — typically inside a
        # ${VAR:?message}. Compose then refuses to load the whole file with
        # "unexpected type map[string]interface {}", so every service dies.
        for i, item in enumerate(svc.get("environment") or []):
            if not isinstance(item, str):
                print(f"  FAIL {f}:{name} environment[{i}] parses as "
                      f"{type(item).__name__}, not a string — quote the entry")
                bad = True
        b = svc.get("build")
        if not b:
            continue
        ctx = b if isinstance(b, str) else b.get("context", ".")
        dockerfile = "Dockerfile" if isinstance(b, str) else b.get("dockerfile", "Dockerfile")
        check_pair(f, name, base, ctx, dockerfile)
sys.exit(1 if bad else 0)
PY
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "docker context verification FAILED"
    exit 1
fi
echo "docker context verification passed"
