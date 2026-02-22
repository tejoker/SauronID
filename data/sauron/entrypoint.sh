#!/bin/bash
set -e
echo "=== Building Sauron analytics data (historical charts) ==="
python build_data.py || echo "[WARN] build_data.py failed — dashboard will use live Rust data only"
echo "=== Running compute_analytics ==="
python compute_analytics.py || echo "[WARN] compute_analytics.py skipped — insights tabs may be empty"
echo "=== Starting Sauron dashboard ==="
exec uvicorn app:app --host 0.0.0.0 --port 8002
