#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Sauron seed script — delegates to data/seed_sauron.py if CSVs are available,
# falls back to minimal inline seed (10 users, 10 clients) otherwise.
# ──────────────────────────────────────────────────────────────────────────────

SERVER="${SAURON_URL:-http://localhost:3001}"
ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Look for data dir: first sibling (local dev), then /app/data (Docker)
if [[ -d "${SCRIPT_DIR}/../data" ]]; then
    DATA_DIR="$(cd "${SCRIPT_DIR}/../data" && pwd)"
elif [[ -d "${SCRIPT_DIR}/data" ]]; then
    DATA_DIR="${SCRIPT_DIR}/data"
else
    DATA_DIR=""
fi
SEED_PY="${DATA_DIR:+${DATA_DIR}/seed_sauron.py}"

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

# ──────────────────────────────────────────────────────────────────────────────
# Try Python seeder — reads companies.csv & personas.csv (harmonized data)
# ──────────────────────────────────────────────────────────────────────────────
if [[ -n "$SEED_PY" && -f "$SEED_PY" && -f "$DATA_DIR/companies.csv" && -f "$DATA_DIR/personas.csv" ]]; then
    echo
    echo "--- Using unified Python seeder (data/seed_sauron.py) ---"
    SEED_USERS="${SEED_USERS:-200}"
    python3 "$SEED_PY" --server "$SERVER" --users "$SEED_USERS" --no-wait
    echo
    echo "=== Seed complete (Python seeder). ==="
    exit 0
fi

echo
echo "--- CSVs not found, falling back to inline seed ---"

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
echo "=== Seed complete (inline fallback). ==="