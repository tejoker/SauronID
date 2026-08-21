#!/usr/bin/env bash
# democtl — drive the SauronID demo across the GPU box + cloud VM.
#
# All connection identity (SSH targets, core URL, admin key) lives ONLY in
# deploy/demo.local.env (gitignored). This script is generic and committed —
# it contains no hostnames or secrets. The boxes never need a git checkout;
# this rsyncs just the files each one needs.
#
#   cp deploy/demo.local.env.example deploy/demo.local.env   # fill it in
#   scripts/demo/democtl.sh preflight
#   scripts/demo/democtl.sh sync-vm && scripts/demo/democtl.sh deploy-vm
#   scripts/demo/democtl.sh sync-gpu
#   scripts/demo/democtl.sh agent          # full demo
#   scripts/demo/democtl.sh attacks        # attacks-only (fast)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/demo.local.env"

usage() {
  cat <<'EOF'
democtl — drive the SauronID demo across the GPU box + cloud VM.

Identity lives ONLY in deploy/demo.local.env (gitignored); this script holds no
hostnames/secrets and ships files via rsync (no git clone on the boxes).

  cp deploy/demo.local.env.example deploy/demo.local.env   # fill it in

  No-Docker path (recommended):
    build-native    compile core (+dashboard if BUILD_DASHBOARD=1) locally
    deploy-native   ship artifacts + run vm-setup.sh on the VM (systemd + Caddy)

  Docker path (alternative):
    sync-vm         rsync core/dashboard/deploy to the VM
    deploy-vm       build + start the compose stack on the VM

  Common:
    preflight       check GPU model, VM docker/health, core /health
    tool-check      verify the Ollama model emits native tool_calls (gate)
    sync-gpu        rsync agent code + agent-action-tool to the GPU box
    agent | attacks run the demo on the GPU box (attacks = fast subset)
    receipts        write signed receipts + anchor (makes Act 5 show a batch)
    runner          bring up the agent-runner + tunnel (powers the Agent Console)
    runner-stop     stop the agent-runner + tunnel
    autorun [secs]  background loop: keep dashboard Activity/Proofs growing live
    autorun-stop    stop the background loop
    status          print core /health + anchor status
EOF
}

# Help needs no config.
if [[ "${1:-help}" =~ ^(help|-h|--help)$ ]]; then usage; exit 0; fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "FATAL: $ENV_FILE not found." >&2
  echo "       cp deploy/demo.local.env.example deploy/demo.local.env  and fill it in." >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${GPU_HOST:?set GPU_HOST in demo.local.env}"
: "${VM_HOST:?set VM_HOST in demo.local.env}"
GPU_PORT="${GPU_PORT:-22}"; VM_PORT="${VM_PORT:-22}"
GPU_DIR="${GPU_DIR:-~/sauronid-demo}"; VM_DIR="${VM_DIR:-~/sauronid-demo}"

ssh_gpu() { ssh -p "$GPU_PORT" "$GPU_USER@$GPU_HOST" "$@"; }
ssh_vm()  { ssh -p "$VM_PORT"  "$VM_USER@$VM_HOST"  "$@"; }

RSYNC_EXCL=(--exclude '.git' --exclude 'target' --exclude 'node_modules'
            --exclude '.next' --exclude '.venv' --exclude '__pycache__'
            --exclude '*.db' --exclude '*.db-*' --exclude 'deploy/secrets'
            --exclude 'deploy/.env' --exclude 'deploy/demo.local.env')

rsync_gpu() { rsync -az --delete -e "ssh -p $GPU_PORT" "${RSYNC_EXCL[@]}" "$@"; }
rsync_vm()  { rsync -az          -e "ssh -p $VM_PORT"  "${RSYNC_EXCL[@]}" "$@"; }

cmd="${1:-help}"
case "$cmd" in

  preflight)
    echo "== GPU box =="
    ssh_gpu "echo ' host: '\$(hostname); \
             ollama list | grep -q '${OLLAMA_MODEL%%:*}' && echo ' ollama model ${OLLAMA_MODEL}: present' || echo ' MODEL ${OLLAMA_MODEL} MISSING'; \
             nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader | sed 's/^/ gpu mem: /'; \
             df -h /mnt/NVME1 2>/dev/null | tail -1 | sed 's/^/ nvme: /'"
    echo "== Cloud VM =="
    ssh_vm "echo ' host: '\$(hostname); docker --version 2>/dev/null | sed 's/^/ /' || echo ' DOCKER MISSING'"
    echo "== Core reachability (from here) =="
    if curl -fsS --max-time 8 "$CORE_URL/health" >/dev/null 2>&1; then
      echo " $CORE_URL/health: OK"
    else
      echo " $CORE_URL/health: NOT reachable (deploy the VM first, or check TLS/DNS)"
    fi
    ;;

  sync-vm)
    echo "rsync core/ dashboard/ deploy/ schemas/ migrations/ -> $VM_USER@$VM_HOST:$VM_DIR"
    ssh_vm "mkdir -p $VM_DIR"
    rsync_vm "$REPO_ROOT/core" "$REPO_ROOT/dashboard" "$REPO_ROOT/deploy" \
             "$REPO_ROOT/schemas" "$REPO_ROOT/migrations" "$VM_USER@$VM_HOST:$VM_DIR/"
    echo "Done. Ensure $VM_DIR/deploy/.env exists ON THE VM (server secrets stay there), then: democtl deploy-vm"
    ;;

  deploy-vm)
    ssh_vm "cd $VM_DIR/deploy && { [ -f .env ] || { echo 'FATAL: create $VM_DIR/deploy/.env on the VM first (see .env.deploy.example)'; exit 1; }; } && bash ./deploy.sh"
    ;;

  build-native)
    echo "==> building core (release) locally"
    # --features demo: democtl provisions through /dev/register_user and
    # /dev/buy_tokens, both behind that cargo feature.
    cargo build --release --features demo --manifest-path "$REPO_ROOT/core/Cargo.toml"
    dist="$REPO_ROOT/deploy/native/dist"
    rm -rf "$dist"; mkdir -p "$dist"
    cp "$REPO_ROOT/core/target/release/sauron-core" "$dist/"
    [[ -f "$REPO_ROOT/core/seed.sh" ]] && cp "$REPO_ROOT/core/seed.sh" "$dist/" || true
    [[ -f "$REPO_ROOT/deploy/secrets/solana-devnet.json" ]] && cp "$REPO_ROOT/deploy/secrets/solana-devnet.json" "$dist/" || true
    if [[ "${BUILD_DASHBOARD:-0}" == "1" ]]; then
      echo "==> building dashboard (standalone) locally"
      # --legacy-peer-deps: the lockfile has a peer-dep conflict that npm ci
      # rejects; the resolved tree builds fine.
      # NEXT_PUBLIC_* are inlined at build time — bake the real public URLs so
      # the Settings page shows them instead of the localhost defaults. The
      # dashboard URL is derived from CORE_URL (core.<…> -> dash.<…>).
      dash_url="$(printf '%s' "${CORE_URL:-}" | sed 's#//core\.#//dash.#')"
      ( cd "$REPO_ROOT/dashboard" && npm install --legacy-peer-deps && \
        NEXT_PUBLIC_CORE_URL="${CORE_URL:-}" NEXT_PUBLIC_DASH_API_URL="$dash_url" npm run build )
      mkdir -p "$dist/dashboard/.next"
      cp -r "$REPO_ROOT/dashboard/.next/standalone/." "$dist/dashboard/"
      cp -r "$REPO_ROOT/dashboard/.next/static" "$dist/dashboard/.next/static"
      cp -r "$REPO_ROOT/dashboard/public" "$dist/dashboard/public"
    fi
    echo "staged -> $dist"; ls -1 "$dist"
    ;;

  deploy-native)
    [[ -x "$REPO_ROOT/deploy/native/dist/sauron-core" ]] || { echo "run 'build-native' first" >&2; exit 1; }
    echo "==> rsync native package -> $VM_USER@$VM_HOST:$VM_DIR/native"
    ssh_vm "mkdir -p $VM_DIR/native"
    # Ship everything in deploy/native EXCEPT the VM-side secret env files
    # (core.env/site.env live on the VM and must not be overwritten).
    rsync -az -e "ssh -p $VM_PORT" --exclude 'core.env' --exclude 'site.env' \
      "$REPO_ROOT/deploy/native/" "$VM_USER@$VM_HOST:$VM_DIR/native/"
    echo "==> running vm-setup.sh on the VM (sudo)"
    ssh_vm "cd $VM_DIR/native && { [ -f core.env ] && [ -f site.env ]; } || { echo 'Create core.env + site.env on the VM (cp the .example files and edit), then re-run deploy-native.'; exit 1; }; sudo bash vm-setup.sh"
    ;;

  sync-gpu)
    # The agent-action-tool mints valid Ristretto ring keypairs; the core
    # rejects anything else, so this binary is REQUIRED (verified on hardware).
    echo "==> building agent-action-tool"
    cargo build --release --manifest-path "$REPO_ROOT/core/Cargo.toml" --bin agent-action-tool
    echo "rsync scripts/ clients/ + agent-action-tool -> $GPU_USER@$GPU_HOST:$GPU_DIR"
    ssh_gpu "mkdir -p $GPU_DIR"
    rsync_gpu "$REPO_ROOT/scripts" "$REPO_ROOT/clients" "$GPU_USER@$GPU_HOST:$GPU_DIR/"
    rsync -az -e "ssh -p $GPU_PORT" "$REPO_ROOT/core/target/release/agent-action-tool" \
      "$GPU_USER@$GPU_HOST:$GPU_DIR/agent-action-tool"
    ;;

  tool-check)
    : "${OLLAMA_MODEL:?set OLLAMA_MODEL in demo.local.env}"
    echo "Probing '$OLLAMA_MODEL' tool-calling on $GPU_HOST (localhost:11434)…"
    ssh_gpu bash -s <<EOF
curl -s --max-time 120 http://localhost:11434/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"$OLLAMA_MODEL","tool_choice":"auto","temperature":0,"messages":[{"role":"user","content":"Fetch https://example.com and summarize."}],"tools":[{"type":"function","function":{"name":"web_fetch","description":"HTTP GET a URL","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}]}' \
  | python3 -c 'import sys,json
d=json.load(sys.stdin); m=d["choices"][0]["message"]; tc=m.get("tool_calls")
if tc:
    print("  TOOL CALLS OK ->", tc[0]["function"]["name"])
else:
    print("  NO TOOL CALLS — model unsuitable for the demo. content:", (m.get("content") or "")[:160]); sys.exit(1)'
EOF
    echo "  '$OLLAMA_MODEL' is demo-ready."
    ;;

  agent|attacks)
    extra=""; [[ "$cmd" == "attacks" ]] && extra="--only-attacks"
    : "${CORE_URL:?set CORE_URL in demo.local.env}"
    : "${SAURON_ADMIN_KEY:?set SAURON_ADMIN_KEY in demo.local.env}"
    # Build the remote env prefix (only non-empty keys are exported).
    # qwen3:14b verified to emit native tool_calls; qwen2.5-coder does NOT.
    # SAURONID_AGENT_ACTION_TOOL points at the shipped binary (required).
    remote_env="SAURON_DEMO_OLLAMA=1 OLLAMA_MODEL='${OLLAMA_MODEL:-qwen3:14b}' SAURONID_AGENT_ACTION_TOOL='$GPU_DIR/agent-action-tool'"
    for k in GEMINI_API_KEY GROQ_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY; do
      v="${!k:-}"; [[ -n "$v" ]] && remote_env="$remote_env $k='$v'"
    done
    echo "Running demo on GPU box against $CORE_URL ($cmd)…"
    ssh_gpu "cd $GPU_DIR && \
      { [ -d .venv ] || python3 -m venv .venv; } && . .venv/bin/activate && \
      pip install -q -e clients/python requests cryptography && \
      $remote_env python3 scripts/demo_real_agent.py --core '$CORE_URL' --admin-key '$SAURON_ADMIN_KEY' $extra"
    ;;

  receipts)
    # Writes signed action receipts via the full challenge->authorize flow and
    # triggers an anchor, so Act 5 shows a real Bitcoin (OpenTimestamps) batch.
    # Run this once before the demo if you want the anchor visible.
    : "${CORE_URL:?set CORE_URL in demo.local.env}"
    : "${SAURON_ADMIN_KEY:?set SAURON_ADMIN_KEY in demo.local.env}"
    echo "Writing signed receipts + triggering anchor on $CORE_URL …"
    ssh_gpu "cd $GPU_DIR && \
      { [ -d .venv ] || python3 -m venv .venv; } && . .venv/bin/activate && \
      pip install -q -e clients/python requests cryptography && \
      SAURON_CORE_URL='$CORE_URL' SAURON_ADMIN_KEY='$SAURON_ADMIN_KEY' SAURONID_AGENT_ACTION_TOOL='$GPU_DIR/agent-action-tool' \
      python3 scripts/simulate_real_actions.py run --n-actions 2"
    echo "== anchor status =="
    curl -s "$CORE_URL/admin/anchor/status" -H "x-admin-key: $SAURON_ADMIN_KEY"; echo
    ;;

  status)
    : "${CORE_URL:?set CORE_URL in demo.local.env}"
    echo "health: $(curl -s --max-time 8 "$CORE_URL/health")"
    echo -n "anchor: "; curl -s "$CORE_URL/admin/anchor/status" -H "x-admin-key: $SAURON_ADMIN_KEY"; echo
    ;;

  autorun)
    # Background loop on the GPU box: one signed action + anchor every N sec,
    # so the dashboard Activity + Proofs grow live during the talk. No terminal
    # to keep open here — it runs detached on the box. Stop with: autorun-stop.
    interval="${2:-75}"
    : "${CORE_URL:?set CORE_URL in demo.local.env}"
    : "${SAURON_ADMIN_KEY:?set SAURON_ADMIN_KEY in demo.local.env}"
    ssh_gpu "cat > $GPU_DIR/autorun.sh" <<EOF
#!/usr/bin/env bash
cd $GPU_DIR && . .venv/bin/activate
export SAURON_CORE_URL='$CORE_URL'
export SAURON_ADMIN_KEY='$SAURON_ADMIN_KEY'
export SAURONID_AGENT_ACTION_TOOL='$GPU_DIR/agent-action-tool'
while true; do
  python3 scripts/simulate_real_actions.py run --n-actions 1 >/dev/null 2>&1 || true
  sleep $interval
done
EOF
    ssh_gpu "chmod +x $GPU_DIR/autorun.sh; nohup $GPU_DIR/autorun.sh >/tmp/sauron-autorun.log 2>&1 & echo \$! > /tmp/sauron-autorun.pid; sleep 1; echo 'autorun started (every ${interval}s), pid '\$(cat /tmp/sauron-autorun.pid)"
    ;;

  autorun-stop)
    ssh_gpu "[ -f /tmp/sauron-autorun.pid ] && kill \$(cat /tmp/sauron-autorun.pid) 2>/dev/null; rm -f /tmp/sauron-autorun.pid; echo 'autorun stopped'"
    ;;

  runner)
    # Bring up the agent-runner + the reverse tunnel on the GPU box (idempotent
    # restart). The dashboard Agent Console reaches the runner via this tunnel.
    : "${CORE_URL:?set CORE_URL in demo.local.env}"
    : "${SAURON_ADMIN_KEY:?set SAURON_ADMIN_KEY in demo.local.env}"
    : "${VM_HOST:?set VM_HOST in demo.local.env}"
    ssh_gpu "cat > $GPU_DIR/runner-launch.sh" <<EOF
#!/usr/bin/env bash
cd $GPU_DIR && . .venv/bin/activate
pip install -q -e clients/python requests cryptography beautifulsoup4 2>/dev/null || true
export SAURON_CORE_URL='$CORE_URL'
export SAURON_ADMIN_KEY='$SAURON_ADMIN_KEY'
export SAURONID_AGENT_ACTION_TOOL='$GPU_DIR/agent-action-tool'
export OLLAMA_MODEL='${OLLAMA_MODEL:-gemma4:e4b}'
export OLLAMA_HOST='localhost:11434'
export GROQ_API_KEY='${GROQ_API_KEY:-}'
export TAVILY_API_KEY='${TAVILY_API_KEY:-}'
exec python3 scripts/demo/agent_runner.py
EOF
    ssh_gpu "cat > $GPU_DIR/tunnel-launch.sh" <<EOF
#!/usr/bin/env bash
while true; do
  ssh -N -R 8765:localhost:8765 -o StrictHostKeyChecking=accept-new -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 $VM_USER@$VM_HOST
  sleep 3
done
EOF
    ssh_gpu "chmod +x $GPU_DIR/runner-launch.sh $GPU_DIR/tunnel-launch.sh
      [ -f /tmp/sauron-runner.pid ] && kill \$(cat /tmp/sauron-runner.pid) 2>/dev/null
      pid=\$(ss -ltnp 2>/dev/null | grep '127.0.0.1:8765' | grep -oP 'pid=\K[0-9]+' | head -1); [ -n \"\$pid\" ] && kill \$pid 2>/dev/null
      sleep 1
      nohup $GPU_DIR/runner-launch.sh >/tmp/sauron-runner.log 2>&1 & echo \$! >/tmp/sauron-runner.pid
      [ -f /tmp/sauron-tunnel.pid ] && kill \$(cat /tmp/sauron-tunnel.pid) 2>/dev/null; sleep 1
      nohup $GPU_DIR/tunnel-launch.sh >/tmp/sauron-tunnel.log 2>&1 & echo \$! >/tmp/sauron-tunnel.pid
      sleep 4; echo \"runner: \$(curl -s localhost:8765/health 2>/dev/null || echo DOWN)\""
    echo -n "via tunnel from VM: "; ssh_vm "curl -s --max-time 6 localhost:8765/health 2>/dev/null || echo UNREACHABLE"; echo
    ;;

  runner-stop)
    ssh_gpu "for f in /tmp/sauron-runner.pid /tmp/sauron-tunnel.pid /tmp/runner.pid; do [ -f \$f ] && kill \$(cat \$f) 2>/dev/null; rm -f \$f; done
      pid=\$(ss -ltnp 2>/dev/null | grep '127.0.0.1:8765' | grep -oP 'pid=\K[0-9]+' | head -1); [ -n \"\$pid\" ] && kill \$pid 2>/dev/null
      echo 'runner + tunnel stopped'"
    ;;

  help|*)
    usage
    ;;
esac
