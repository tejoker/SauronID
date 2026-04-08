#!/usr/bin/env bash
if command -v docker >/dev/null 2>&1; then SAURON_ALLOW_DEV_MOCK_PROOF=1 docker compose up --build -d; else echo "[launch_all] docker not found, switching to local stack via start.sh"; bash "$(cd "$(dirname "$0")" && pwd)/start.sh"; fi
