#!/usr/bin/env bash
# start-test.sh — démarrage rapide sans build (mode dev)
# Utilise le binaire Rust déjà compilé + npm run dev pour les frontends

set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key

# ── Couleurs ─────────────────────────────────────────────────────────────────
GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; RST='\033[0m'
log()  { echo -e "${GRN}[start-test]${RST} $*"; }
warn() { echo -e "${YLW}[warn]${RST} $*"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
PIDS=()
cleanup() {
  echo ""
  log "Arrêt de tous les processus..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  log "Arrêté."
}
trap cleanup INT TERM

# ── 1. Backend Rust ──────────────────────────────────────────────────────────
log "[1/4] Backend Rust → :3001"
cd "$ROOT/core"

BINARY="./target/release/sauron-core"
if [ ! -f "$BINARY" ]; then
  warn "Binaire release introuvable, utilisation de debug..."
  BINARY="./target/debug/sauron-core"
fi
if [ ! -f "$BINARY" ]; then
  warn "Aucun binaire trouvé — lance 'cargo build' d'abord !"
  warn "Fallback: cargo run (lent au premier démarrage)"
  ENV="${ENV:-development}" \
  SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
  SAURON_ISSUER_URL="${SAURON_ISSUER_URL:-http://localhost:4000}" \
  SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}" \
  cargo run --bin sauron-core &
else
  ENV="${ENV:-development}" \
  SAURON_ADMIN_KEY="$SAURON_ADMIN_KEY" \
  SAURON_ISSUER_URL="${SAURON_ISSUER_URL:-http://localhost:4000}" \
  SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}" \
  "$BINARY" &
fi
CORE_PID=$!
PIDS+=("$CORE_PID")

# ── Attendre que le backend soit prêt ────────────────────────────────────────
log "Attente du backend..."
for i in $(seq 1 120); do
  if curl -sf http://localhost:3001/admin/stats \
       -H "x-admin-key: $SAURON_ADMIN_KEY" > /dev/null 2>&1; then
    log "Backend prêt ✓"
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo -e "${RED}[error]${RST} Backend non disponible après 120s."
    exit 1
  fi
done

# ── 2. Seed ──────────────────────────────────────────────────────────────────
log "[2/4] Seed (clients + users)..."
cd "$ROOT/core"
SAURON_URL=http://localhost:3001 bash seed.sh

# (The pre-pivot Python KYC service lives in the `archive/banking-2025` git tag.)

# ── 3. Mandate Console Dashboard (Next.js) ──────────────────────────────────
log "[3/4] Dashboard → :3000"
cd "$ROOT/dashboard"
if [ ! -d "node_modules" ]; then
  warn "Installation des dépendances npm (dashboard)..."
  npm install --silent
fi
NEXT_PUBLIC_API_URL=http://localhost:3001 \
SAURON_CORE_INTERNAL_URL=http://localhost:3001 \
SAURONID_ALLOW_UNAUTHENTICATED_ADMIN_PROXY=1 \
  npm run dev -- -p 3000 &
DASH_PID=$!
PIDS+=("$DASH_PID")


# ── Résumé ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GRN}Partner + Bank + Dashboard (proxy) →${RST} http://localhost:3000"
echo -e "  ${GRN}Rust Backend API                    →${RST} http://localhost:3001"
echo ""
echo -e "  ${YLW}Ctrl+C pour tout arrêter${RST}"
echo ""

wait
