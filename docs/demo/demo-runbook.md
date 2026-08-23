# SauronID demo runbook — local GPU agent + cloud core

End-to-end demo: a **real LLM agent runs on your 4060Ti box**, every action it
takes is cryptographically bound and audited by a **SauronID core deployed in
the cloud**, and the whole trail is anchored to Solana + Bitcoin. The narrative
is **capability with safety**: the agent does genuinely useful work, and the
same agent is shown attempting high-risk actions that SauronID blocks or
contains in real time.

```
  ┌──────────────────────────────────────────┐         ┌────────────────────────────────────────────┐
  │  4060Ti box (yours, on-prem)              │         │  Cloud VM (AWS EC2 or GCP GCE)               │
  │                                           │  HTTPS  │                                              │
  │  Ollama  ──serves──►  qwen2.5:14b  (local)│  +per-  │   Caddy (auto-TLS)                           │
  │     ▲                                     │  call   │     ├── core.<domain>  → SauronID core (Rust)│
  │     │ OpenAI-compatible                   │  sig    │     └── dash.<domain>  → dashboard (Next.js) │
  │  demo_real_agent.py  ──────────────────────────────►│         (basic-auth gated)                   │
  │  (+ optional cloud LLM agents: hybrid)    │         │   SQLite volume · Solana devnet · BTC OTS    │
  └──────────────────────────────────────────┘         └────────────────────────────────────────────┘
                                                              │ anchors merkle roots
                                                              ▼
                                                   Solana devnet memo + Bitcoin OpenTimestamps
```

The agent box and the core never share a trust boundary: the core re-verifies
every request independently (A-JWT signature, intent leash, per-call DPoP
signature, single-use nonce + JTI, agent config digest, rate limits).

---

## Part A — Deploy the cloud core + dashboard

### A1. Provision a VM

This is a stateful app (SQLite file + a long-running OpenTimestamps upgrader
background task), so use a small always-on VM, not serverless. ~2 vCPU / 4 GB
is plenty.

**AWS (EC2):**
```bash
# Ubuntu 22.04 LTS, t3.small. Open 22, 80, 443 in the security group.
# After SSH in:
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin git
sudo usermod -aG docker $USER && newgrp docker
```

**GCP (GCE):**
```bash
# Ubuntu 22.04 LTS, e2-small. Allow http/https + tcp:22 firewall tags.
gcloud compute instances create sauronid-demo \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --machine-type=e2-small --tags=http-server,https-server
# After SSH in: same docker install as AWS above.
```

> Doing **both clouds**: the deploy package is identical on each VM. Build per
> cloud (the dashboard bakes its own `CORE_DOMAIN` at build time), and give each
> its own DNS pair. You can point the same agent at either core URL, or run two
> agents to show portability.

### A2. DNS

Create two A-records pointing at the VM's public IP:
- `core.<your-domain>` → VM IP
- `dash.<your-domain>` → VM IP

Caddy obtains Let's Encrypt certs automatically once these resolve and 80/443
are open.

### A3. Configure + launch

```bash
git clone <this-repo> sauronid && cd sauronid/deploy
cp .env.deploy.example .env

# Generate the four root secrets:
for v in SAURON_ADMIN_KEY SAURON_TOKEN_SECRET SAURON_JWT_SECRET SAURON_OPRF_SEED SAURON_ISSUER_SHARED_SECRET; do
  echo "$v=$(openssl rand -hex 32)"; done   # paste into .env

# Dashboard basic-auth hash:
docker run --rm caddy caddy hash-password --plaintext 'pick-a-strong-password'
# paste output into DASH_BASICAUTH_HASH

# Edit .env: set CORE_DOMAIN, DASH_DOMAIN, ACME_EMAIL, SAURON_ALLOWED_ORIGINS=https://<DASH_DOMAIN>

./setup-solana.sh     # creates + funds secrets/solana-devnet.json (devnet, free)
./deploy.sh           # builds + starts caddy + core + dashboard
```

Verify:
```bash
curl https://core.<your-domain>/health      # {"status":"ok",...}
# open https://dash.<your-domain>  (basic-auth prompt → your DASH_USER/password)
```

---

## Part B — The agent box (4060Ti)

### B1. Local model via Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &                       # exposes OpenAI-compatible API on :11434
ollama pull qwen2.5:14b              # ~9 GB, fits 16 GB comfortably
# Tighter on VRAM? use:  ollama pull llama3.1:8b
```

Quick sanity check that the OpenAI-compatible surface works:
```bash
curl http://localhost:11434/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"qwen2.5:14b","messages":[{"role":"user","content":"say hi"}]}'
```

### B2. SauronID Python client

```bash
git clone <this-repo> sauronid && cd sauronid
python3 -m venv .venv && . .venv/bin/activate
pip install -e sdk/python requests cryptography
# Build the ring-signing helper so actions use real ring signatures (optional;
# the demo falls back to placeholders if absent):
cargo build --release --manifest-path core/Cargo.toml --bin agent-action-tool
```

### B3. Point the agent at the cloud core and run

```bash
export SAURON_DEMO_OLLAMA=1            # enable the local model as a governed agent
export OLLAMA_MODEL=qwen2.5:14b
# Hybrid: also include hosted agents under the same audit trail (optional)
export ANTHROPIC_API_KEY=sk-ant-...    # optional
export GROQ_API_KEY=gsk_...            # optional

python3 scripts/demo_real_agent.py \
  --core https://core.<your-domain> \
  --admin-key "$SAURON_ADMIN_KEY"      # the value from the cloud .env
```

---

## Part C — What the demo shows (capability ↔ safety)

`demo_real_agent.py` runs six acts. Map each to "what an unconstrained agent
could do" vs "what SauronID does about it." Watch it live on the dashboard
`/requests` and `/anchors` pages as it runs.

| Act | What the agent does (capability) | Without SauronID | With SauronID |
|-----|----------------------------------|------------------|---------------|
| **2 — real tool-use** | Local + cloud agents call a `web_fetch` tool to do real research | Tool calls are invisible and unattributable | Every LLM call + tool call is PoP-signed and logged as egress, live on `/requests` |
| **3 — policy** | Agent attempts tool/spend/data actions | A compromised prompt calls any tool, spends without limit, touches PII | Policy denies disallowed tool, over-budget spend, and denied data-scope **before** the network call |
| **4a replay** | Re-sends a captured signed request | Replay succeeds → duplicate action | Single-use nonce → HTTP 409 |
| **4b body mutation** | Tampers the request body after signing | Mutated payment/command goes through | Body-hash mismatch → 401 |
| **4c config drift** | Silently swaps the agent's system prompt / model | Agent runs attacker's config undetected | Config-digest mismatch → 401; legitimate rotation via `/checksum/update` → 200 (and is anchored) |
| **4d post-revocation** | Keeps acting after being revoked | Revoked agent keeps working | Every call after revoke → 401 |
| **5 — anchor** | — | Audit log is mutable, deniable | Merkle root anchored to Solana (≤30 s) + Bitcoin OTS (~1 h); externally verifiable |
| **6 — forensics** | — | No reliable timeline | Full reconstructed timeline: every call + config rotation with body hashes and the config digest active at each step |

So the story is not "lock the agent down." It's: **the agent keeps full
capability for the actions that benefit the user (Act 2), and the actions that
would be catastrophic if the agent were compromised (Acts 3–4) are blocked or
contained — all of it provably audited (Acts 5–6).**

Run subsets for a tighter live demo:
```bash
python3 scripts/demo_real_agent.py --core https://core.<domain> --admin-key ... --skip-anchor --skip-forensics
python3 scripts/demo_real_agent.py --core https://core.<domain> --admin-key ... --only-attacks
```

---

## Honest caveats (state these in the demo)

- **Dashboard auth**: the dashboard has no built-in user auth (roadmap B5). It
  sits behind Caddy HTTP basic-auth here — fine for a controlled demo, not a
  substitute for real RBAC. Do not remove the basic-auth gate.
- **Data tier**: single-node SQLite (`SAURON_ACCEPT_SINGLE_NODE_SQLITE=1`). No
  HA. The Postgres port is incomplete and must not be presented as an HA
  upgrade path; production pilots need a dedicated node, monitored backups,
  and a rehearsed restore until the port and failover tests are complete.
- **Anchoring**: Solana **devnet** + free OTS calendars. Devnet is not a
  durability guarantee; for a real anchor, fund a mainnet keypair and set
  `SAURON_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com` +
  `SAURON_SOLANA_NETWORK=mainnet` (same code path). Bitcoin OTS block inclusion
  takes ~1 h — the dashboard shows the honest pending/confirmed states.
- **Trust model**: PoP keys are server-derived today, so the operator of the
  core is trusted. Hardware-rooted PoP (AWS Nitro / TPM2) is roadmap; see
  `docs/security/threat-model.md` and `docs/operations/tee-deployment.md`.

## Teardown

```bash
# cloud VM
cd sauronid/deploy && docker compose -f docker-compose.deploy.yml down       # keep data
docker compose -f docker-compose.deploy.yml down -v                          # wipe volumes
# agent box
pkill ollama
```
