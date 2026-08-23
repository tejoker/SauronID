# SauronID demo — cloud VM + local agent (self-contained guide)

> **How to use this file:** paste it into an AI chat assistant and ask for help
> with any step ("help me create the AWS VM", "my core won't start", "explain
> the env vars"). It is self-contained — everything the assistant needs is here.
> Replace every `<PLACEHOLDER>`. Lines marked **VERIFIED** were tested on real
> hardware end-to-end; trust them over generic advice.

---

## 1. What you're building

A real LLM agent runs on a **GPU box you own** and does real work (web research
via a tool). Every action it takes is cryptographically bound and audited by a
**SauronID core** running on a **cloud VM**, and the audit log is anchored to
Bitcoin. The demo then shows the same agent being attacked (replay, tampering,
config-swap, post-revocation) and SauronID blocking each in real time.

```
  GPU box (yours)                         Cloud VM (AWS EC2 or GCP GCE)
  ┌────────────────────────┐   HTTPS      ┌──────────────────────────────────┐
  │ Ollama  → qwen3:14b     │  + per-call  │ Caddy (auto-TLS)                 │
  │ demo_real_agent.py  ───────signature──▶│   → SauronID core (1 binary)     │
  │ (Python)                │             │   SQLite + Bitcoin anchoring     │
  └────────────────────────┘             └──────────────────────────────────┘
                                              └─▶ Bitcoin (OpenTimestamps, free)
```

The two machines share no trust: the core independently re-verifies every
request (token signature, per-call signature, single-use nonce, config digest).

---

## 2. Key facts (VERIFIED — they prevent the common mistakes)

1. **The core is ONE ~27 MB binary.** It bundles SQLite and links TLS
   statically; on the VM it needs only `ca-certificates`. No Docker, no Rust,
   no database server required.
2. **Build it on Ubuntu 22.04** (glibc 2.35) and the binary runs on Ubuntu
   22.04 **and** 24.04 VMs. (Building on a newer OS would NOT run on an older
   VM — build on the older one.)
3. **Demo env posture:** `ENV=development` + `SAURON_ENABLE_DEV_ENDPOINTS=1`
   (needed to onboard the demo user) **and** `SAURON_REQUIRE_CALL_SIG=1` (so the
   attack demo is real). Full production mode disables user onboarding and
   breaks the demo — use this posture.
4. **Model: `gemma4:e4b` (recommended) or `qwen3:14b`.** Both emit native
   `tool_calls`. Prefer **`gemma4:e4b`** — it reliably returns a final answer
   (verified 2/2). `qwen3:14b` is a *thinking* model and sometimes doesn't
   converge within the turn limit (Act 2 prints "did not return a final
   answer"). **Do NOT use `qwen2.5-coder:7b`** — it prints the tool call as
   plain text and the agent loop never fires.
5. **The `agent-action-tool` binary is REQUIRED on the GPU box.** It mints valid
   Ristretto ring keys; the core rejects anything else. Random/placeholder keys
   fail with `public_key_hex is not a valid Ristretto point`.
6. **You must seed the demo user once** against the cloud core
   (`POST /dev/register_user`), because the demo only logs in. See §6.
7. **Anchoring:** Bitcoin via OpenTimestamps is free, no key, no funding
   (`SAURON_BITCOIN_ANCHOR_PROVIDER=opentimestamps`). A visible anchor **batch**
   only forms after the signed *action-receipt* flow runs
   (`simulate_real_actions.py run`), not the chat/attack flow alone. Solana is
   optional and its devnet faucet is currently rate-limited — leave it off.
8. **Domains without buying one:** use `sslip.io`. If your VM IP is
   `203.0.113.7`, then `core.203-0-113-7.sslip.io` resolves to it automatically
   and Caddy gets a real Let's Encrypt cert. (Replace dots with dashes.)
9. **Open ports on the VM:** 22 (SSH), 80 + 443 (Caddy/TLS).
10. **Cost:** ~$0. VM is pennies/hour; Bitcoin OTS + local model are free.

---

## 3. Prerequisites

- A cloud account (AWS or GCP) — a small VM: AWS `t3.small` or GCP `e2-small`,
  **Ubuntu 22.04**.
- The GPU box with **Ollama** running and a tool-capable model pulled
  (`qwen3:14b` recommended). Ollama exposes an OpenAI-compatible API at
  `http://localhost:11434/v1/chat/completions`.
- A build machine running **Ubuntu 22.04** with Rust installed, holding the
  SauronID repo (this is where you compile the core binary + the action tool).
  Often the same machine you run the deploy commands from.
- The repo provides a driver, `scripts/demo/democtl.sh`, that automates all of
  the below over SSH. This guide gives both the driver commands **and** the
  manual equivalents so an assistant can help you debug either way.

---

## 4. Provision the VM

**AWS (EC2):** launch Ubuntu 22.04 `t3.small`; security group opens 22, 80, 443.
SSH in, then:
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates
```

**GCP (GCE):**
```bash
gcloud compute instances create sauronid-demo \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --machine-type=e2-small --tags=http-server,https-server
# then SSH in and: sudo apt-get update && sudo apt-get install -y ca-certificates
```

Note the VM's **public IP** → `<VM_IP>`. Your hostnames are:
- core: `core.<VM_IP-with-dashes>.sslip.io`
- dashboard (optional): `dash.<VM_IP-with-dashes>.sslip.io`

---

## 5. Deploy the core to the VM (no Docker)

### Option A — with the repo's driver (recommended)
On your build machine, in the repo:
```bash
# one-time private config (gitignored): SSH targets, core URL, admin key, model
cp deploy/demo.local.env.example deploy/demo.local.env   # then edit it

scripts/demo/democtl.sh build-native     # compiles the core binary locally
scripts/demo/democtl.sh deploy-native     # ships it to the VM; first run tells
                                           # you to create the env files (below)
```
On the VM, create the two env files (secrets stay on the VM):
```bash
cd ~/sauronid-demo/native
cp core.env.example core.env   # edit: secrets + flags (see §5.1)
cp site.env.example site.env   # edit: domains + dashboard auth (see §5.2)
```
Then on the build machine run `deploy-native` again — it installs Caddy, lays
out `/opt/sauronid`, and starts the `sauronid-core` systemd service behind TLS.

### Option B — fully manual (no driver)
1. Build on the Ubuntu-22.04 machine:
   `cargo build --release --manifest-path core/Cargo.toml`
   → binary at `core/target/release/sauron-core`.
2. Copy it to the VM: `scp core/target/release/sauron-core <user>@<VM_IP>:/tmp/`
3. On the VM:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin sauronid
   sudo mkdir -p /opt/sauronid/data
   sudo install -m0755 /tmp/sauron-core /opt/sauronid/sauron-core
   sudo nano /opt/sauronid/core.env        # paste §5.1
   sudo chmod 600 /opt/sauronid/core.env
   sudo chown -R sauronid:sauronid /opt/sauronid
   ```
4. Install the systemd unit (§5.3), install Caddy (§5.4), start both.

### 5.1 `core.env` (the core's environment — systemd EnvironmentFile, plain KEY=VAL)
Generate the secrets first:
`for v in SAURON_ADMIN_KEY SAURON_TOKEN_SECRET SAURON_JWT_SECRET SAURON_OPRF_SEED SAURON_ISSUER_SHARED_SECRET; do echo "$v=$(openssl rand -hex 32)"; done`
```ini
ENV=development
SAURON_ENABLE_DEV_ENDPOINTS=1
PORT=3001
DATABASE_PATH=/opt/sauronid/data/sauron.db

SAURON_ADMIN_KEY=<paste>
SAURON_TOKEN_SECRET=<paste>
SAURON_JWT_SECRET=<paste>
SAURON_OPRF_SEED=<paste>
SAURON_ISSUER_SHARED_SECRET=<paste>

SAURON_REQUIRE_CALL_SIG=1
SAURON_REQUIRE_AGENT_TYPE=1
SAURON_POLICY_ENFORCEMENT_MODE=enforce
SAURON_ACCEPT_SINGLE_NODE_SQLITE=1

SAURON_ALLOWED_ORIGINS=https://dash.<VM_IP-dashes>.sslip.io

SAURON_DISABLE_ZKP=1
SAURON_DISABLE_COMPLIANCE=1

SAURON_BITCOIN_ANCHOR_PROVIDER=opentimestamps
SAURON_SOLANA_ENABLED=0
SAURONID_TENANTS=default
```

### 5.2 `site.env` (Caddy's environment for domains + dashboard auth)
```ini
CORE_DOMAIN=core.<VM_IP-dashes>.sslip.io
DASH_DOMAIN=dash.<VM_IP-dashes>.sslip.io
ACME_EMAIL=<you@example.com>
DASH_USER=demo
DASH_BASICAUTH_HASH=<output of: caddy hash-password --plaintext 'a-password'>
ENABLE_DASHBOARD=0
```
(`ENABLE_DASHBOARD=0` = core API only, leanest. The terminal output carries the
whole story; the dashboard is just a visual. Set `1` only if you want it, which
also installs Node 20 on the VM.)

### 5.3 systemd unit `/etc/systemd/system/sauronid-core.service`
```ini
[Unit]
Description=SauronID core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sauronid
Group=sauronid
WorkingDirectory=/opt/sauronid
EnvironmentFile=/opt/sauronid/core.env
ExecStart=/opt/sauronid/sauron-core
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now sauronid-core
journalctl -u sauronid-core -f      # watch logs
```

### 5.4 Caddy (TLS reverse proxy)
Install (official apt repo):
```bash
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update && sudo apt-get install -y caddy
```
Feed `site.env` to Caddy and use this `/etc/caddy/Caddyfile` (core only):
```caddyfile
{
	email {$ACME_EMAIL}
}
{$CORE_DOMAIN} {
	reverse_proxy 127.0.0.1:3001
}
```
Make Caddy read `site.env`:
```bash
sudo mkdir -p /etc/systemd/system/caddy.service.d
printf '[Service]\nEnvironmentFile=/opt/sauronid/site.env\n' | sudo tee /etc/systemd/system/caddy.service.d/sauronid.conf
sudo systemctl daemon-reload && sudo systemctl restart caddy
```

### 5.5 Verify the core is up
```bash
curl https://core.<VM_IP-dashes>.sslip.io/health      # -> {"ok":true}
```
(Give Caddy ~30 s on first start to obtain the certificate.)

---

## 6. Seed the demo user (one-time, against the cloud core)

The demo logs in as a user; create that user once:
```bash
curl -s -X POST https://core.<VM_IP-dashes>.sslip.io/dev/register_user \
  -H 'content-type: application/json' \
  -d '{"site_name":"Monzo","email":"alice@sauron.dev","password":"pass_alice","first_name":"Alice","last_name":"Dubois","date_of_birth":"1998-05-12","nationality":"FR"}'
# verify:
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://core.<VM_IP-dashes>.sslip.io/user/auth \
  -H 'content-type: application/json' -d '{"email":"alice@sauron.dev","password":"pass_alice"}'   # -> 200
```
(`/dev/register_user` works only because `SAURON_ENABLE_DEV_ENDPOINTS=1`.)

---

## 7. Run the agent (on the GPU box)

### 7.0 Confirm the model emits tool calls (do this first)
```bash
curl -s http://localhost:11434/v1/chat/completions -H 'content-type: application/json' -d '{
  "model":"qwen3:14b","tool_choice":"auto",
  "messages":[{"role":"user","content":"fetch https://example.com"}],
  "tools":[{"type":"function","function":{"name":"web_fetch","description":"GET a url",
    "parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}]
}' | grep -q '"tool_calls"' && echo "TOOL CALLS OK" || echo "NO TOOL CALLS — switch model"
```

### 7.1 Get the agent code + the required tool onto the GPU box
You need: `scripts/demo_real_agent.py`, the Python client package
(`sdk/python`), and the **`agent-action-tool`** binary
(`cargo build --release --manifest-path core/Cargo.toml --bin agent-action-tool`,
then copy `core/target/release/agent-action-tool` to the GPU box). The repo's
`scripts/demo/democtl.sh sync-gpu` does all three automatically.

Set up Python once:
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e sdk/python requests cryptography
```

### 7.2 Run it
```bash
export SAURON_DEMO_OLLAMA=1
export OLLAMA_MODEL=qwen3:14b
export OLLAMA_HOST=localhost:11434
export SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool
# optional online agent for the hybrid demo. Set ONE of these:
#   GROQ_API_KEY    — free tier, OpenAI-compatible, reliable. EASIEST. console.groq.com
#   GEMINI_API_KEY  — needs a project WITH free-tier quota (a standard AI Studio
#                     AIza... key) or billing; some keys report limit:0 and 429.
# Note: even with NO online key, the cloud agent is still registered + leashed
# (Act 4 attacks run against it); the key only enables its live chat in Act 2.
python3 scripts/demo_real_agent.py \
  --core https://core.<VM_IP-dashes>.sslip.io \
  --admin-key <the SAURON_ADMIN_KEY from the VM's core.env>
```
(Or with the driver from your build machine: `scripts/demo/democtl.sh agent`.)

Useful flags: `--only-attacks` (fast 2-min subset), `--skip-anchor`,
`--skip-forensics`, `--skip-chat`.

### 7.3 Make the Bitcoin anchor batch appear (optional, for Act 5)
The chat/attack acts log egress but don't create the *receipts* that get
anchored. To show a real Merkle batch + Bitcoin proof, run the signed-action
flow once, then trigger an anchor:
```bash
export SAURON_CORE_URL=https://core.<VM_IP-dashes>.sslip.io
export SAURON_ADMIN_KEY=<same admin key>
export SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool
python3 scripts/simulate_real_actions.py run --n-actions 2
# then check status:
curl -s https://core.<VM_IP-dashes>.sslip.io/admin/anchor/status -H "x-admin-key: $SAURON_ADMIN_KEY"
# expect: agent_action_batches>=1, bitcoin_total>=1, bitcoin_pending_upgrade>=1
```
(Bitcoin block inclusion takes ~1 h; the "pending" attestation is created
immediately and is the point — "committed to Bitcoin, inclusion in progress.")

---

## 8. What the demo shows (6 acts) — VERIFIED output

| Act | What happens | Expected result |
|-----|--------------|-----------------|
| 1 Auth+register | log in as alice, register an agent per provider (local + any cloud keys) | agent_ids printed |
| 2 Tool-use chat | local qwen3:14b calls `web_fetch`, summarizes a page | real multi-turn answer; every call logged as signed egress |
| 3 Policy | agent tries disallowed tool / over-budget / PII | 3 DENY (allowlist, budget, scope) before any network call |
| 4a Replay | re-send a captured signed call | 1st **200**, 2nd **409** |
| 4b Body mutation | tamper the body after signing | **401** |
| 4c Config drift | swap the system prompt | **401**; then a legitimate rotation → **200** |
| 4d Post-revoke | act after revocation | **401** |
| 5 Anchor | Merkle root → Bitcoin OTS (see §7.3) | batch + pending Bitcoin attestation |
| 6 Forensics | reconstruct the agent's timeline | egress rows + config-rotation history with digests |

The narrative: **capability kept** (Act 2 — it does real work), **compromise
contained** (Acts 3–4 — every attack blocked in <5 ms), **provably audited**
(Acts 5–6 — anchored to Bitcoin, reconstructable).

---

## 9. Troubleshooting (symptom → cause → fix)

| Symptom | Cause | Fix |
|---|---|---|
| `public_key_hex is not a valid Ristretto point` at register | the `agent-action-tool` isn't being used | build + ship it; set `SAURONID_AGENT_ACTION_TOOL` (§7.1) |
| Agent "did not return a final answer" / no tool runs | model doesn't emit native `tool_calls` | use `qwen3:14b` / `gemma4:e4b`, not `qwen2.5-coder` (§7.0) |
| `/dev/register_user` → 404 | dev endpoints disabled | set `SAURON_ENABLE_DEV_ENDPOINTS=1` in `core.env`, restart core |
| `/user/auth` → 401 | user not seeded | run the seed curl (§6) |
| core panics `production requires SAURON_ADMIN_KEY` | running production mode without keys | use the demo posture: `ENV=development` + the env in §5.1 |
| `curl …/health` fails / TLS error | Caddy hasn't issued the cert yet, or 80/443 closed, or DNS not resolving | wait ~30 s; open 80+443; confirm `core.<dashes>.sslip.io` resolves to the VM IP |
| Act 5 shows "no new anchor batch" | only egress was written, no receipts | run `simulate_real_actions.py run` first (§7.3) |
| Solana airdrop fails | public devnet faucets rate-limited | keep `SAURON_SOLANA_ENABLED=0`; Bitcoin OTS alone is enough |
| binary won't run on VM (`GLIBC_… not found`) | built on a newer OS than the VM | build on Ubuntu 22.04 (matches/older than the VM) |

---

## 10. Security caveats (state these; don't overclaim)

- **Demo posture, not production.** `ENV=development` enables a convenience
  onboarding endpoint. Real user onboarding would use a proper KYC/registration
  flow. The **agent governance** (binding, per-call signatures, anchoring,
  revocation) is exercised for real.
- **Dashboard has no built-in auth.** If you enable it, it sits behind Caddy
  HTTP basic-auth only — fine for a controlled demo, not real RBAC.
- **Single-node SQLite**, no HA. The partial Postgres backend is not a
  production or failover path; keep pilots off revenue-critical traffic.
- **PoP keys are server-derived**, so the core operator is trusted.
  Hardware-rooted keys (AWS Nitro / TPM2) are roadmap, not in this demo.
- **Solana is devnet** (if enabled) — not a durability guarantee.

---

## 11. Quick command recap (with the repo driver)
```bash
# build machine (repo):
cp deploy/demo.local.env.example deploy/demo.local.env   # fill in once
scripts/demo/democtl.sh build-native
scripts/demo/democtl.sh deploy-native     # create core.env+site.env on the VM, then re-run
# seed the user once (§6 curl)
scripts/demo/democtl.sh sync-gpu
scripts/demo/democtl.sh tool-check         # green-light the model
scripts/demo/democtl.sh agent              # run the full demo  (or: attacks)
```
