#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

# ── Check .env ───────────────────────────────────────────────────────────────
if [ ! -f "$ROOT/KYC/.env" ]; then
  echo "[error] KYC/.env not found. Copy KYC/.env and set GEMINI_API_KEY."
  exit 1
fi

source "$ROOT/KYC/.env"
if [ -z "$GEMINI_API_KEY" ] || [ "$GEMINI_API_KEY" = "your_key_here" ]; then
  echo "[error] GEMINI_API_KEY is not set in KYC/.env"
  exit 1
fi

# ── Cleanup on exit ──────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "[stop] Shutting down..."
  kill "$CORE_PID" "$NEXT_PID" "$KYC_PID" 2>/dev/null
  wait "$CORE_PID" "$NEXT_PID" "$KYC_PID" 2>/dev/null
  echo "[stop] Done."
}
trap cleanup INT TERM

# ── Backend (Rust) ───────────────────────────────────────────────────────────
echo "[1/5] Building backend (cargo build --release)..."
cd "$ROOT/core"
cargo build --release 2>&1

echo "[2/5] Starting sauron-core on :3001..."
./target/release/sauron-core &
CORE_PID=$!

# ── Seed (clients + users) ───────────────────────────────────────────────────────────
echo "[3/5] Seeding database (10 clients + 10 users)..."
cd "$ROOT/core"
SAURON_URL=http://localhost:3001 bash seed.sh

# ── KYC (Python) ─────────────────────────────────────────────────────────────
echo "[4/5] Setting up KYC Python environment..."
cd "$ROOT/KYC"

if [ ! -d ".venv" ]; then
  echo "      Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q -r requirements.txt

echo "      Starting KYC service on :8000..."
uvicorn main:app --host 0.0.0.0 --port 8000 &
KYC_PID=$!
deactivate

# ── Frontend (Next.js) ───────────────────────────────────────────────────────
echo "[5/5] Building and starting Next.js on :3000..."
cd "$ROOT/admin"
npm run build 2>&1
npm run start -- -p 3000 &
NEXT_PID=$!

# ── Ready ────────────────────────────────────────────────────────────────
echo ""
echo "  Frontend → http://localhost:3000"
echo "  Backend  → http://localhost:3001"
echo "  KYC      → http://localhost:8000"
echo ""
echo "  Press Ctrl+C to stop everything."
echo ""

wait "$CORE_PID" "$KYC_PID" "$NEXT_PID"
