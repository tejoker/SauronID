#!/usr/bin/env bash
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then ENV=development docker compose up --build -d; else echo "[launch_all] docker unavailable in this environment, switching to local stack via start.sh"; bash "$(cd "$(dirname "$0")" && pwd)/start.sh"; fi
