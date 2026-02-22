#!/bin/bash
set -e
echo "=== Building Sauron analytics data ==="
python build_data.py
echo "=== Running compute_analytics ==="
python compute_analytics.py || echo "[WARN] compute_analytics.py skipped or failed"
echo "=== Starting Sauron dashboard ==="
exec uvicorn app:app --host 0.0.0.0 --port 8002
