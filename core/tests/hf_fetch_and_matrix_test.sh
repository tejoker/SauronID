#!/usr/bin/env bash
set -euo pipefail

# Fetch a Hugging Face agent model repo, then run Sauron's model-agnostic
# agent contract test against the running core API.
#
# Usage:
#   bash core/tests/hf_fetch_and_matrix_test.sh [model_id]
#
# Env:
#   API_URL                  default: http://127.0.0.1:3001
#   SAURON_ADMIN_KEY         default: super_secret_hackathon_key
#   HF_TOKEN                 optional Hugging Face token (for gated/private repos)
#   HF_LOCAL_DIR             default: ./.hf-agents
#   MATRIX_JITTER_MS_MAX     default: 0
#   MATRIX_FAULT_PROBE_PCT   default: 0

MODEL_ID="${1:-Qwen/Qwen2.5-0.5B-Instruct}"
API_URL="${API_URL:-http://127.0.0.1:3001}"
SAURON_ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}"
HF_LOCAL_DIR="${HF_LOCAL_DIR:-./.hf-agents}"
MATRIX_JITTER_MS_MAX="${MATRIX_JITTER_MS_MAX:-0}"
MATRIX_FAULT_PROBE_PCT="${MATRIX_FAULT_PROBE_PCT:-0}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

require_cmd python3
require_cmd bash
require_cmd curl

mkdir -p "$HF_LOCAL_DIR"

echo "[HF] downloading model snapshot: ${MODEL_ID}"
python3 - "$MODEL_ID" "$HF_LOCAL_DIR" "${HF_TOKEN:-}" <<'PY'
import os
import re
import sys

model_id = sys.argv[1]
local_dir = sys.argv[2]
token = sys.argv[3] or None

try:
    from huggingface_hub import snapshot_download
except Exception:
    raise SystemExit(
        "huggingface_hub is not installed. Install it with: python3 -m pip install --user huggingface_hub"
    )

safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", model_id)
target = os.path.join(local_dir, safe)
os.makedirs(target, exist_ok=True)

path = snapshot_download(
    repo_id=model_id,
    local_dir=target,
    local_dir_use_symlinks=False,
    token=token,
)
print(path)
PY

echo "[HF] model snapshot fetched successfully"

agent_type="$(python3 - "$MODEL_ID" <<'PY'
import sys
s = sys.argv[1].lower()
if "qwen" in s:
    print("qwen")
elif "mistral" in s:
    print("mistral")
elif "gemini" in s:
    print("gemini")
elif "claude" in s:
    print("claude")
elif "openai" in s or "gpt" in s:
    print("openai")
else:
    print("hf_generic")
PY
)"

echo "[SMOKE] waiting for core API at ${API_URL}"
ready=0
for _ in $(seq 1 60); do
  if curl -sf "${API_URL}/admin/stats" -H "x-admin-key: ${SAURON_ADMIN_KEY}" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "core API is not reachable at ${API_URL}" >&2
  exit 1
fi

echo "[SMOKE] running agent matrix with fetched model label: ${agent_type}"
API_URL="${API_URL}" \
SAURON_ADMIN_KEY="${SAURON_ADMIN_KEY}" \
AGENT_TYPES="${agent_type}" \
MATRIX_JITTER_MS_MAX="${MATRIX_JITTER_MS_MAX}" \
MATRIX_FAULT_PROBE_PCT="${MATRIX_FAULT_PROBE_PCT}" \
bash "${ROOT_DIR}/tests/e2e_agent_matrix.sh"

echo "[PASS] Hugging Face fetch + agentic matrix test complete"
