#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Sauron seed script — minimal dev clients + users via core HTTP APIs only.
# (No synthetic CSV pipeline — SauronID is the identity stack, not demo datagen.)
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../scripts/lib/dev_secrets.sh
source "${SCRIPT_DIR}/../scripts/lib/dev_secrets.sh"
require_admin_key

SERVER="${SAURON_URL:-http://localhost:3001}"
ADMIN_KEY="$SAURON_ADMIN_KEY"

# Look for data dir: first sibling (local dev), then /app/data (Docker)
if [[ -d "${SCRIPT_DIR}/../data" ]]; then
    DATA_DIR="$(cd "${SCRIPT_DIR}/../data" && pwd)"
elif [[ -d "${SCRIPT_DIR}/data" ]]; then
    DATA_DIR="${SCRIPT_DIR}/data"
else
    DATA_DIR=""
fi
ok()   { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; }

post_json() {
    local url="$1"
    local data="$2"
    shift 2
    curl -sf -X POST "$url" \
        -H "Content-Type: application/json" \
        "$@" \
        -d "$data"
}

# ──────────────────────────────────────────────────────────────────────────────
# 0. Wait for server
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "=== Sauron seed script ==="
echo "Server: $SERVER"
echo

printf "Waiting for server..."
for i in $(seq 1 30); do
    if curl -sf "$SERVER/admin/stats" -H "x-admin-key: $ADMIN_KEY" >/dev/null 2>&1; then
        echo " ready."
        break
    fi
    printf "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo " TIMEOUT. Make sure backend is running on $SERVER."
        exit 1
    fi
done

echo
echo "--- Inline seed (HTTP only) ---"

# ──────────────────────────────────────────────────────────────────────────────
# 1. Create 5 FULL_KYC clients (banks / crypto exchanges)
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "--- Creating FULL_KYC clients ---"

FULL_KYC_CLIENTS=("Monzo" "Revolut" "Binance" "Kraken" "Coinbase")

for name in "${FULL_KYC_CLIENTS[@]}"; do
    resp=$(post_json "$SERVER/admin/clients" \
        "{\"name\":\"$name\",\"client_type\":\"FULL_KYC\"}" \
        -H "x-admin-key: $ADMIN_KEY" 2>&1) && ok "$name (FULL_KYC)" || fail "$name: $resp"
done

# ──────────────────────────────────────────────────────────────────────────────
# 2. Create 5 ZKP_ONLY clients (social / sharing platforms)
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "--- Creating ZKP_ONLY clients ---"

ZKP_ONLY_CLIENTS=("Discord" "Tinder" "Airbnb" "Uber" "Twitch")

for name in "${ZKP_ONLY_CLIENTS[@]}"; do
    resp=$(post_json "$SERVER/admin/clients" \
        "{\"name\":\"$name\",\"client_type\":\"ZKP_ONLY\"}" \
        -H "x-admin-key: $ADMIN_KEY" 2>&1) && ok "$name (ZKP_ONLY)" || fail "$name: $resp"
done

# ──────────────────────────────────────────────────────────────────────────────
# 3. Register 10 users via /dev/register_user
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "--- Registering users ---"

# Format: "email|password|first_name|last_name|date_of_birth|nationality"
USERS=(
    "alice@sauron.dev|pass_alice|Alice|Dubois|1998-05-12|FR"
    "bob@sauron.dev|pass_bob|Bob|Martin|1993-11-03|CH"
    "charlie@sauron.dev|pass_charlie|Charlie|Durand|2001-02-28|BE"
    "diana@sauron.dev|pass_diana|Diana|Lemaire|1990-07-19|CA"
    "eve@sauron.dev|pass_eve|Eve|Leroy|1985-03-30|FR"
    "frank@sauron.dev|pass_frank|Frank|Petit|1979-09-14|CH"
    "grace@sauron.dev|pass_grace|Grace|Roux|1996-12-01|BE"
    "heidi@sauron.dev|pass_heidi|Heidi|Moreau|1994-08-22|CA"
    "ivan@sauron.dev|pass_ivan|Ivan|Simon|1988-04-05|FR"
    "judy@sauron.dev|pass_judy|Judy|Michel|1999-01-17|CH"
)

# Each demo user gets a throwaway Ed25519 OWNER key. The public half is bound to
# their key image exactly as /register binds a real one; the private half is
# written to core/.demo-owner-keys.json (gitignored) so the demo can sign agent
# mandates with the SAME code path production uses — one code path, two
# credential postures, rather than a demo shortcut that diverges from reality.
#
# These keys are disposable and public knowledge by construction: anything they
# authorise lives only in this dev database. Production owners generate their own
# and never hand them to anyone, including the operator.
# The seed runs in its own throwaway container, so this must land somewhere the
# host can read it. docker-compose bind-mounts ./deploy/demo to /demo-out.
DEMO_OWNER_KEYS="${SAURON_DEMO_OWNER_KEYS:-${SCRIPT_DIR}/.demo-owner-keys.json}"
mkdir -p "$(dirname "${DEMO_OWNER_KEYS}")" 2>/dev/null || true
: >"${DEMO_OWNER_KEYS}.tmp"

for entry in "${USERS[@]}"; do
    IFS='|' read -r email password first_name last_name dob nationality <<< "$entry"
    # sauronid-cli ships in the runtime image and uses the same ed25519 library
    # the server verifies with, so no Python crypto dependency is needed here.
    owner=$("${SAURONID_CLI:-./sauronid-cli}" owner-keygen 2>/dev/null) || owner=""
    if [[ -n "$owner" ]]; then
        owner_pub=$(printf '%s' "$owner" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_b64u"])')
        payload=$(printf '{"site_name":"Monzo","email":"%s","password":"%s","first_name":"%s","last_name":"%s","date_of_birth":"%s","nationality":"%s","auth_public_key_b64u":"%s"}' \
            "$email" "$password" "$first_name" "$last_name" "$dob" "$nationality" "$owner_pub")
        printf '%s\t%s\n' "$email" "$owner" >>"${DEMO_OWNER_KEYS}.tmp"
    else
        # No `cryptography` module available: fall back to a password-only demo
        # user. Everything except owner-signed mandates still works.
        payload=$(printf '{"site_name":"Monzo","email":"%s","password":"%s","first_name":"%s","last_name":"%s","date_of_birth":"%s","nationality":"%s"}' \
            "$email" "$password" "$first_name" "$last_name" "$dob" "$nationality")
    fi
    resp=$(post_json "$SERVER/dev/register_user" "$payload" 2>&1) \
        && ok "$first_name $last_name <$email>" \
        || fail "$email: $resp"
done

if [[ -s "${DEMO_OWNER_KEYS}.tmp" ]]; then
    python3 - "${DEMO_OWNER_KEYS}.tmp" "${DEMO_OWNER_KEYS}" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
out = {}
for line in open(src):
    email, blob = line.rstrip("\n").split("\t", 1)
    out[email] = json.loads(blob)
json.dump(out, open(dst, "w"), indent=2)
open(dst, "a").write("\n")
PY
    ok "owner keys for $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "${DEMO_OWNER_KEYS}") demo users -> $(basename "${DEMO_OWNER_KEYS}")"
fi
rm -f "${DEMO_OWNER_KEYS}.tmp"

# ──────────────────────────────────────────────────────────────────────────────
# 4. Summary
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "--- Summary ---"
curl -sf "$SERVER/admin/clients" -H "x-admin-key: $ADMIN_KEY" | \
    python3 -c "
import sys, json
clients = json.load(sys.stdin)
full = [c for c in clients if c.get('client_type') == 'FULL_KYC']
zkp  = [c for c in clients if c.get('client_type') == 'ZKP_ONLY']
print(f'  Clients: {len(clients)} total ({len(full)} FULL_KYC, {len(zkp)} ZKP_ONLY)')
" 2>/dev/null || echo "  (could not fetch client summary)"

curl -sf "$SERVER/admin/stats" -H "x-admin-key: $ADMIN_KEY" | \
    python3 -c "
import sys, json
s = json.load(sys.stdin)
print(f'  Users:   {s.get(\"total_users\", \"?\")}')
print(f'  Tokens A issued: {s.get(\"total_tokens_a_issued\", \"?\")}')
" 2>/dev/null || echo "  (could not fetch stats)"

echo
echo "=== Seed complete (inline fallback). ==="