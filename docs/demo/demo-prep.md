# Demo prep — plain-language checklist

What you'll have at the end: a real agent on your 4060Ti, governed by a SauronID
core in the cloud, with a live audit trail and a public anchor. Roughly 1 hour
of prep, ~$0.

---

## 0. FIRST: private identity config (nothing committed)

The boxes are driven over SSH from your dev machine; their identity (GPU SSH
target, VM IP, core URL, admin key) lives in **one gitignored file** and is
never committed. Code reaches the boxes by `rsync`, not `git clone`, so the
boxes never hold a repo and the repo never holds your hosts.

```bash
cp deploy/demo.local.env.example deploy/demo.local.env   # gitignored
# edit deploy/demo.local.env: GPU_HOST/PORT/USER, VM_HOST/USER, CORE_URL,
# SAURON_ADMIN_KEY (same value as the VM's deploy/.env), OLLAMA_MODEL, opt keys
```

The driver is `scripts/demo/democtl.sh`. **No-Docker path (recommended):**
```bash
scripts/demo/democtl.sh build-native    # compile the core locally (this box)
scripts/demo/democtl.sh deploy-native   # ship binary + run systemd + Caddy on VM
scripts/demo/democtl.sh sync-gpu        # rsync agent code to the GPU box
scripts/demo/democtl.sh agent           # run the full demo (or: attacks)
scripts/demo/democtl.sh preflight       # check GPU model + core /health
```
(`sync-vm` + `deploy-vm` are the Docker alternative.) The VM's server secrets
(`native/core.env`, `native/site.env`) are created **on the VM** and stay there
— never on your laptop or in the repo.

---

## 1. The 4060Ti box (mostly ready)

Already has Ollama + models. Storage: the **system disk is 95% full**, but
**`/mnt/NVME1` has 521 GB free** — so room exists. You still don't need to pull
anything; good models are already installed. (If you ever do pull one, point
Ollama at the NVMe: `OLLAMA_MODELS=/mnt/NVME1/ollama-models` in the ollama
service env.) Use one that's already installed:

**VERIFIED on this box** (full demo ran end-to-end):
- **`qwen3:14b`** — recommended. Emits native `tool_calls`; drove a real 2-turn
  `web_fetch` and summary in the live test. (Default in `demo.local.env`.)
- `gemma4:e4b` — also emits native `tool_calls`; fine alternative.
- **`qwen2.5-coder:7b` — do NOT use.** It prints the tool call as plain text
  instead of `tool_calls`, so the agent loop never fires.

Re-confirm tool-calling any time:
```bash
ssh projectx@zetroc.fr -p 16641
curl -s http://localhost:11434/v1/chat/completions -H 'content-type: application/json' -d '{
  "model":"qwen3:14b","tool_choice":"auto",
  "messages":[{"role":"user","content":"fetch https://example.com"}],
  "tools":[{"type":"function","function":{"name":"web_fetch","description":"GET a url",
    "parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}]
}' | grep -q '"tool_calls"' && echo "TOOL CALLS OK" || echo "NO TOOL CALLS — switch model"
```

You don't clone anything here — `scripts/demo/democtl.sh sync-gpu` rsyncs the
agent code **and builds + ships the `agent-action-tool`** (required: it mints
valid Ristretto ring keys — the core rejects anything else). `democtl.sh agent`
creates the venv, `pip install`s the client, and points the demo at the tool.

---

## 2. The cloud VM — ordered actions (no Docker)

The core is a ~27 MB near-static binary (only needs glibc + `ca-certificates`),
built on **this dev box** (Ubuntu 22.04) and shipped to the VM. No Rust, Node,
or Docker on the VM — just Caddy (and Node only if you enable the dashboard).

1. **Create a VM.** Ubuntu 22.04 (or 24.04), AWS `t3.small` / GCP `e2-small`.
   Open ports **22, 80, 443**. Note its **public IP** (`VM_IP`). No toolchains
   to install — `vm-setup.sh` adds Caddy via apt.
2. **Build the artifacts on your dev box:** `scripts/demo/democtl.sh build-native`
   (set `BUILD_DASHBOARD=1` in `demo.local.env` first if you want the dashboard).
3. **Ship them once** so the env templates land on the VM:
   `scripts/demo/democtl.sh deploy-native`  (first run tells you to create the
   server env, below — that's expected).
4. **On the VM**, create the server env (secrets stay on the VM):
   ```bash
   cd ~/sauronid-demo/native
   cp core.env.example core.env   # secrets + flags (see §4); DATABASE_PATH preset
   cp site.env.example site.env   # domains (see §3) + dashboard basic-auth + ENABLE_DASHBOARD
   ```
5. **(Optional) Solana** — see §5 / `docs/demo/demo-anchoring.md`. Default is off
   (Bitcoin OTS only, free).
6. **Deploy:** `scripts/demo/democtl.sh deploy-native` (runs `vm-setup.sh`:
   installs Caddy, lays out `/opt/sauronid`, starts the `sauronid-core` systemd
   service behind TLS).
7. **Verify:** `scripts/demo/democtl.sh preflight` (checks core `/health`).

Doing **both clouds**? Repeat 1–7 on each VM (`build-native` once; point
`demo.local.env` at each VM in turn for `deploy-native`). Each gets its own IP →
its own sslip.io names.

> Prefer Docker instead? The `deploy/` compose path still works:
> `democtl sync-vm` + `democtl deploy-vm` after installing Docker on the VM.

---

## 3. Domains — you do NOT need to buy one

A "domain" is just a name that points at your VM's IP so TLS (https) can work.
**Use `sslip.io` — it's free and automatic.** If your VM IP is `203.0.113.7`:

```
CORE_DOMAIN=core.203-0-113-7.sslip.io
DASH_DOMAIN=dash.203-0-113-7.sslip.io
SAURON_ALLOWED_ORIGINS=https://dash.203-0-113-7.sslip.io
```

`sslip.io` resolves `anything.<dashed-ip>.sslip.io` straight to that IP — no DNS
setup, no purchase. Caddy then gets a real Let's Encrypt certificate for it
automatically. (Just replace the dots in your IP with dashes.)

---

## 4. Secrets — one command, paste, forget

"Secrets" are just long random strings the core uses internally to sign tokens.
You generate them once and paste them into the VM's server env. You don't
memorize or share them (except `SAURON_ADMIN_KEY`, which the agent command and
dashboard both use — put the SAME value in `demo.local.env`).

```bash
for v in SAURON_ADMIN_KEY SAURON_TOKEN_SECRET SAURON_JWT_SECRET SAURON_OPRF_SEED SAURON_ISSUER_SHARED_SECRET; do
  echo "$v=$(openssl rand -hex 32)"
done
```
Paste the 5 lines into the VM's **`native/core.env`** (no-Docker) or
**`deploy/.env`** (Docker). Then the dashboard password hash (only if
`ENABLE_DASHBOARD=1`) — goes in `native/site.env` (or `deploy/.env`):
```bash
# needs caddy locally, or run on the VM after vm-setup installs it:
caddy hash-password --plaintext 'pick-a-password'   # or: docker run --rm caddy caddy hash-password ...
# paste output into DASH_BASICAUTH_HASH ; set DASH_USER=demo
```

---

## 5. Anchoring — Bitcoin works out of the box; Solana optional

Full detail + the verified Bitcoin proof: **`docs/demo/demo-anchoring.md`**.

- **Bitcoin (OpenTimestamps): already working, free, no key.** Leave
  `SAURON_BITCOIN_ANCHOR_PROVIDER=opentimestamps`. The dashboard `/anchors` page
  shows the Merkle root with a pending Bitcoin attestation immediately (full
  block proof ~1 h later). This alone proves the anchor story.
- **Solana: optional.** Free on devnet but the faucet is currently gated; set
  `SAURON_SOLANA_ENABLED=0` to skip, or do the 2-minute web-faucet step in
  `docs/demo/demo-anchoring.md` if you want the on-chain memo too.

---

## 6. Can you use OpenAI / Anthropic? (and the subscription question)

The demo's "agent" is **our** SauronID wrapper around an LLM's tool-calling — it
is **not** OpenAI's hosted "Assistants/Agents" product. It talks to an LLM over
a normal API.

- **API keys are NOT your chat subscription.** ChatGPT Plus and Claude Pro do
  **not** include API access. To call OpenAI or Anthropic you need a separate,
  pay-per-token **API key** (platform.openai.com / console.anthropic.com).
  Neither one is "included in a subscription" — both bill the API separately.
- **You don't need either for this demo.** The local Ollama model on your 4060Ti
  is the star and is free. The cloud LLM is an *optional* second agent (the
  "hybrid" story).
- **If you want a free cloud agent:** use **Groq** (free tier, very fast) or
  **Google Gemini** (free tier via an AI Studio key). Both already wired in the
  demo. Set `GROQ_API_KEY=...` or `GEMINI_API_KEY=...`.
- **If you specifically want OpenAI:** it's OpenAI-compatible, so I can add an
  `openai` provider in ~5 lines — ask me. Otherwise stick to local + Groq/Gemini
  and spend $0.

Bottom line: **local-only is fine and free.** Add Groq/Gemini free tier if you
want to show the hybrid multi-agent audit trail.

---

## 7. Network — what actually needs internet

Your demo has two always-on machines:
- the **4060Ti** at `zetroc.fr` (its own internet — not the venue's),
- the **cloud VM** (its own internet).

The agent runs on the 4060Ti and calls the cloud core over the internet — both
ends are always online, so the demo itself doesn't depend on the venue's wifi.

The only thing that needs the venue connection is **your presentation laptop**,
to (a) SSH into the 4060Ti to launch the agent and (b) open the dashboard in a
browser. So: just make sure your laptop has internet, and have a phone hotspot
as backup. That's the whole "network" concern.

---

## 8. Go-live (after the dry run)

From your dev machine (reads `deploy/demo.local.env`, runs on the GPU box):
```bash
scripts/demo/democtl.sh tool-check # gate: confirm the model emits tool_calls
scripts/demo/democtl.sh agent      # full six-act demo
scripts/demo/democtl.sh attacks    # attacks-only, ~2 min
```
Run `agent` once end-to-end the day before. Open the dashboard `/requests` and
`/anchors` tabs on your laptop while it runs.

Equivalent manual run (SSH'd into the GPU box, in `$GPU_DIR`):
```bash
. .venv/bin/activate
export SAURON_DEMO_OLLAMA=1 OLLAMA_MODEL=qwen2.5-coder:7b
python3 scripts/demo_real_agent.py --core https://core.<domain> --admin-key <ADMIN_KEY>
```
