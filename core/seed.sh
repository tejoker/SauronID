#!/bin/bash
set -euo pipefail

SERVER="${SAURON_URL:-http://localhost:3000}"
ADMIN_KEY="super_secret_hackathon_key"

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
    if curl -sf "$SERVER/health" >/dev/null 2>&1 || \
       curl -o /dev/null -sw "%{http_code}" "$SERVER/oprf" 2>/dev/null | grep -qE '^(200|405|422)'; then
        echo " ready."
        break
    fi
    printf "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo " TIMEOUT. Make sure 'cargo run' is running on port 3000."
        exit 1
    fi
done

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

for entry in "${USERS[@]}"; do
    IFS='|' read -r email password first_name last_name dob nationality <<< "$entry"
    payload=$(printf '{"email":"%s","password":"%s","first_name":"%s","last_name":"%s","date_of_birth":"%s","nationality":"%s"}' \
        "$email" "$password" "$first_name" "$last_name" "$dob" "$nationality")
    resp=$(post_json "$SERVER/dev/register_user" "$payload" 2>&1) \
        && ok "$first_name $last_name <$email>" \
        || fail "$email: $resp"
done

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
echo "=== Seed complete. ==="

echo "[INFO] Opération terminée. Le dashboard est peuplé."