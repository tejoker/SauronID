# SauronID Operations Runbook

How to deploy, monitor, rotate, and recover SauronID. Read this before going to production.

## TLS termination

SauronID core binds plain HTTP on `0.0.0.0:${PORT:-3001}`. **Never expose this port directly to the internet.** TLS termination is the operator's responsibility — deploy behind a reverse proxy (nginx, Caddy, AWS ALB, Cloudflare, etc.) that handles certificate management and forwards verified HTTPS traffic to the core.

Minimum requirements for the reverse proxy:
- TLS 1.2+, prefer 1.3
- Strict `Host` header validation matching `SAURON_ALLOWED_ORIGINS`
- Forward `X-Forwarded-For` so the rate limiter sees real client IPs (read by `risk.rs`)
- Connection timeout ≤30s (per-call signature window is 60s; longer connections add no value)
- **Must not rewrite the request line** — see below. This is the one that bites.

## Reverse proxy requirements

Read this before you put anything in front of the core. It is the most common
cause of a deployment that worked locally and returns `401 call_sig_invalid`
the moment it goes behind a proxy.

The call-signature payload binds `target_uri` as the **exact bytes** of the
request line's path and query, with no normalisation on either side. That is
deliberate: canonicalising a URI is a notorious source of client/server
disagreement, and a signature over the literal bytes cannot disagree. The cost
is that any intermediary which *rewrites* those bytes invalidates the signature
the client computed over the original.

Rewrites that break every signed call:

| Rewrite | Example | Who does it by default |
|---|---|---|
| Collapsing duplicate slashes | `/agent//egress/log` → `/agent/egress/log` | nginx (`merge_slashes on`) |
| Decoding percent-escapes in the path | `/agent/a%2Fb` → `/agent/a/b` | nginx, Apache |
| Re-encoding unreserved characters | `/agent/a~b` → `/agent/a%7Eb` | some CDNs and WAFs |
| Resolving dot segments | `/agent/x/../egress/log` → `/agent/egress/log` | nginx, Envoy |
| Sorting, deduplicating or stripping query parameters | `?b=2&a=1` → `?a=1&b=2` | caching CDNs |
| Appending or removing a trailing slash | `/agent/token` → `/agent/token/` | many ingress controllers |

TLS termination, header addition, and load balancing are all fine. Only the
request line is sensitive.

### nginx

```nginx
# Off, so nginx forwards the path exactly as received.
merge_slashes off;

location / {
    # $request_uri is the raw, un-decoded original. Using $uri here instead
    # would forward nginx's normalised copy and break every signature.
    proxy_pass http://127.0.0.1:3001$request_uri;

    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Caddy

Caddy's `reverse_proxy` preserves the request line as received, so the default
is already correct. Do not add `uri strip_prefix`, `uri replace`, or
`rewrite` on the proxied route — each of those edits the signed bytes.

```caddy
core.example.com {
    reverse_proxy 127.0.0.1:3001
}
```

### Envoy / Istio

Set `normalize_path: false` and `merge_slashes: false` on the HTTP connection
manager. Both default to normalising.

### AWS ALB, Cloudflare, other managed edges

Managed edges vary by configuration and change behaviour between versions, so
verify rather than assume. The check takes one command against a deployed
instance — a signed call whose path contains a character a normaliser would
touch:

```bash
# Should return the same status as the same call without the %2F.
# A 401 with code "call_sig_invalid" here means the edge is rewriting the path.
curl -i "https://core.example.com/agent/egress/log?probe=a%2Fb"   # + your signed headers
```

If you cannot stop an edge from normalising, terminate TLS at something that
does not (Caddy, or nginx configured as above) and put that between the edge
and the core.

## Deployment profiles

SauronID exposes optional surfaces beyond the core agent-binding stack. Pick a profile.

### Profile A: Pure agent binding (recommended for new deployments)

Agent identity, per-call signatures, intent leash, replay protection, audit anchoring. No bank KYC, no end-user KYC consent flow, no ZKP issuer integration, no compliance screening. This is what you want for AI-agent identity at a SaaS / DePIN / agentic-marketplace company.

```bash
export ENV=production
export SAURON_ADMIN_KEY=$(openssl rand -hex 32)            # ≥ 32 bytes
export SAURON_TOKEN_SECRET=$(openssl rand -hex 32)
export SAURON_JWT_SECRET=$(openssl rand -hex 32)
export SAURON_OPRF_SEED=$(openssl rand -hex 32)
export SAURON_ALLOWED_ORIGINS=https://app.example.com,https://api.example.com
export SAURON_REQUIRE_CALL_SIG=1                           # MANDATORY in production — per-call DPoP signature; missing/invalid → 401
# export SAURON_ACCEPT_DPOP=1                              # opt-in: accept RFC 9449 `DPoP:` proofs instead of x-sauron-call-sig (no body/config binding — see docs/sdk-integration.md)
# export SAURON_ACCEPT_DPOP_IN_PROD=1                      # required acknowledgment before SAURON_ACCEPT_DPOP takes effect in production (fail-closed otherwise)
export SAURON_REQUIRE_AGENT_TYPE=1                         # MANDATORY in production — /agent/register must carry agent_type + checksum_inputs (server-computed digest)
export SAURON_POLICY_ENFORCEMENT_MODE=enforce              # MANDATORY in production — bound policy denies short-circuit action endpoints with 403
export SAURON_DISABLE_BANK_KYC=1
export SAURON_DISABLE_USER_KYC=1
export SAURON_DISABLE_ZKP=1
export SAURON_DISABLE_COMPLIANCE=1
export SAURON_BITCOIN_ANCHOR_PROVIDER=opentimestamps       # real Bitcoin anchoring, no key custody
export SAURON_SOLANA_ENABLED=1                             # dual-anchor on Solana
export SAURON_SOLANA_RPC_URL=https://api.devnet.solana.com
export SAURON_SOLANA_NETWORK=devnet
export SAURON_SOLANA_KEYPAIR_PATH=/etc/sauronid/solana-keypair.json
export SAURON_ACCEPT_SINGLE_NODE_SQLITE=1                  # acknowledge single-node DB until Postgres swap
# Leave BOTH of the following unset unless you specifically need them.
# export SAURON_ENABLE_HE=1                                # mounts POST /v1/stats/submit-encrypted. OFF by default: the Paillier
#                                                          # implementation is unreviewed (NEEDS_CRYPTO_REVIEW) and built on
#                                                          # num-bigint, which is not constant-time. Admin-gated, but an unused
#                                                          # crypto surface should not be reachable at all. See
#                                                          # docs/homomorphic-encryption.md.
# export SAURON_NITRO_ALLOW_STUB=1                         # lets the `nitro-enclave` binary start WITHOUT real NSM access, in which
#                                                          # case every attestation document it emits is a placeholder no production
#                                                          # verifier accepts. Local plumbing work only — never a deployment.

# Sprint 11 multi-tenancy (see docs/multi-tenancy.md). SauronID is
# single-operator multi-tenant out-of-the-box: every legacy request lands
# on the reserved `default` tenant. Operators that need real isolation
# distribute an `x-sauron-tenant-id: <id>` header to downstream SDK
# consumers (or mint admin JWTs carrying a `tnt` claim). The variable
# below is reserved for an 11.5 enhancement that overrides the default
# tenant string for legacy callers; leaving it unset preserves today's
# back-compat (412-test baseline + dashboard demo flow).
# export SAURON_DEFAULT_TENANT_ID=default
```

### Profile B: Full identity stack (legacy / regulated deployments)

Everything in profile A plus optional KYC consent flow, sanctions/PEP screening (operator wires provider), ZKP credentials.

```bash
# all of profile A, then:
unset SAURON_DISABLE_BANK_KYC
unset SAURON_DISABLE_USER_KYC
unset SAURON_DISABLE_ZKP
unset SAURON_DISABLE_COMPLIANCE
export SAURON_COMPLIANCE_JURISDICTION_MODE=enforce
export SAURON_COMPLIANCE_JURISDICTION_ALLOWLIST=US,GB,FR,DE
export SAURON_COMPLIANCE_SANCTIONS_MODE=enforce
export SAURON_COMPLIANCE_PEP_MODE=enforce
# wire your screening provider into core/src/compliance_screening.rs (Phase 1.1 deliverable)
```

## Secret backends

### Vault Transit (recommended)

Wraps the four root secrets (`SAURON_TOKEN_SECRET`, `SAURON_JWT_SECRET`, `SAURON_OPRF_SEED`, `SAURON_ADMIN_KEY`) so plaintext never appears in env or on disk. Implementation: `core/src/secret_provider.rs::VaultTransitClient` — blocking `reqwest` POST against `/v1/transit/decrypt/<key>`, executed on a dedicated OS thread so it is safe inside `#[tokio::main]`. Plaintext is held only in `ServerState` / `AdminAuthConfig` memory until process exit.

```bash
# operator (one time per cluster)
vault secrets enable transit
vault write -f transit/keys/sauronid-root

# wrap each plaintext into ciphertext (do this on a trusted host, then store the ciphertext)
for s in SAURON_TOKEN_SECRET SAURON_JWT_SECRET SAURON_OPRF_SEED SAURON_ADMIN_KEY; do
  pt=$(printf '%s' "${!s}" | base64)
  ct=$(vault write -field=ciphertext transit/encrypt/sauronid-root plaintext="$pt")
  echo "${s}_WRAPPED=$ct"
done
```

```bash
# runtime
export SAURON_VAULT_TRANSIT_ENABLED=1
export SAURON_VAULT_ADDR=https://vault.example.com:8200
export SAURON_VAULT_TOKEN=hvs.…                            # service token with transit/decrypt/sauronid-root capability
export SAURON_VAULT_TRANSIT_KEY=sauronid-root
export SAURON_TOKEN_SECRET_WRAPPED=vault:v1:…
export SAURON_JWT_SECRET_WRAPPED=vault:v1:…
export SAURON_OPRF_SEED_WRAPPED=vault:v1:…
export SAURON_ADMIN_KEY_WRAPPED=vault:v1:…
# do NOT set the plaintext SAURON_*_SECRET env vars
```

`SAURON_ADMIN_KEYS` (the multi-key rotation list) also accepts `vault:v…` ciphertext entries when `SAURON_VAULT_TRANSIT_ENABLED=1`. Each comma-separated entry is decrypted in place at startup.

#### Migration from plaintext

A wrapping helper lives at `scripts/vault-secret-migration.sh`. Run it on a trusted host with `VAULT_ADDR` / `VAULT_TOKEN` set and the plaintext `SAURON_*_SECRET` env vars exported; it emits the four `*_WRAPPED` lines to stdout. Copy the output into your secrets manager (k8s `Secret`, Doppler, 1Password Secrets Automation, AWS Secrets Manager, …) and then scrub the plaintext from wherever it lived before.

```bash
SAURON_TOKEN_SECRET=… SAURON_JWT_SECRET=… SAURON_OPRF_SEED=… SAURON_ADMIN_KEY=… \
  ./scripts/vault-secret-migration.sh
```

#### Vault auth methods

The current implementation uses a **static token** (`SAURON_VAULT_TOKEN`). For production rollouts you should switch to a short-lived credential issued by a Vault auth method:

- **AppRole** — bootstrapped via a wrapped `secret_id`; ideal for VM / VM-like deployments.
- **Kubernetes auth** — service-account JWT exchanged for a Vault token at startup; ideal for the k8s manifests under `deploy/`.

Neither is wired in this sprint. Upgrade path: implement a `VaultTokenSource` trait in `secret_provider.rs` with `Static`, `AppRole`, and `Kubernetes` variants; refresh tokens on the existing decrypt path. Tracked under "Vault token lifecycle" in `docs/roadmap.md`.

#### Past states

Prior to S6 the resolver shipped only the env-var fallback path with a stubbed Vault call. The stub has been removed; the live HTTP client is the only Vault code path.

### AWS KMS (planned, Phase 1B)

Set `SAURON_AWS_KMS_ENABLED=1`, `SAURON_AWS_KMS_KEY_ID=arn:aws:kms:…`. Adapter is stubbed; wire `aws-sdk-kms` in the `secret_provider::resolve_via_kms` function before flipping the flag.

### Plain env (dev only)

Set the plaintext `SAURON_*_SECRET` vars directly. Server warns and uses derived secrets if any are unset in dev mode.

## Monitoring

### Metrics

Prometheus endpoint at `GET /metrics`. Scrape every 15 s. Key counters:

- `http_requests_total{method, path, status}` — request rate by route + status
- `http_request_duration_seconds_bucket{method, path}` — latency histogram

Suggested alerts:

| Alert | Condition |
|---|---|
| Spike in 401 on `/agent/payment/authorize` | rate > 10/min sustained 5 min — possible call-sig brute force |
| Spike in 409 on `/kyc/retrieve` or `/merchant/payment/consume` | rate > 1/min sustained 1 min — possible TOCTOU race attempt |
| OTS upgrader silent | `bitcoin_merkle_anchors WHERE ots_upgraded=0 AND created_at < NOW() - 24h` count > 0 — calendar may be down |
| GC silent | No `[sauron::gc] pruned` log line in 30 min — task may have crashed |

### Logs

`tracing` JSON output via `SAURON_LOG_FORMAT=json`. Ship to ELK / Loki / Datadog.

Important targets:

- `sauron::startup` — boot sequence
- `sauron::security` — auth failures, signature mismatches
- `sauron::call_sig` — per-call signature verification (advisory + enforce)
- `sauron::gc` — background pruning
- `sauron::bitcoin_anchor` — OTS calendar interactions
- `tower_http::trace::on_request` / `on_response` — every HTTP call

## Key rotation

### Per-agent PoP keys

Agents may rotate at any time:

1. Agent generates a new Ed25519 keypair locally.
2. Agent calls `/agent/register` with the new `pop_public_key_b64u` (server creates a new agent record).
3. Agent stops using the old A-JWT; outstanding tokens expire naturally.

Recommended cadence: per process restart, or weekly.

### Admin key

```bash
# generate new
NEW_ADMIN_KEY=$(openssl rand -hex 32)

# add to keys list (multi-key rotation supported)
export SAURON_ADMIN_KEYS="$NEW_ADMIN_KEY,$OLD_ADMIN_KEY"
# restart server (rolling)
# update all clients to use NEW_ADMIN_KEY
# after a full update, drop OLD_ADMIN_KEY:
export SAURON_ADMIN_KEYS="$NEW_ADMIN_KEY"
# restart server
```

### JWT signing secret / Token secret / OPRF seed

These are **not safely rotatable in-flight** — they're embedded in agent A-JWTs and OPRF user identities. Rotation requires invalidating all outstanding tokens and re-onboarding all agents/users. Plan for this in a maintenance window.

If using Vault Transit, rotate the *wrapping* key without rotating the underlying secret: `vault write -f transit/keys/sauronid-root/rotate`. Existing wrapped secrets keep working; new encryptions use the latest version.

### OTS anchor / Bitcoin

OpenTimestamps anchors are append-only and immutable; no rotation. The calendar list (`SAURON_OTS_CALENDARS`) can be changed at runtime; future anchors use the new list, existing anchors continue to upgrade against their original calendar.

## Recovery

### DB corruption / loss

SQLite is single-node. If `sauron.db` is lost:

- Agent registrations: lost. All agents must re-register.
- Audit log: lost.
- ZKP credentials: lost; users re-claim from the issuer (issuer's pre-auth codes survive in the issuer's own state).

**Action**: ship Phase 3 (Postgres) before claiming production readiness. Until then, snapshot `sauron.db` to S3 every 5 minutes via `litestream` or `cron + sqlite3 .backup`.

### Lost admin keys

If all admin keys are lost simultaneously, the cluster is unrecoverable from outside. Bring up a new cluster and re-register all clients/agents.

Mitigation: split admin keys across multiple operators; maintain at least 2 active keys at all times in `SAURON_ADMIN_KEYS`.

### Postgres backend (Phase 3, in progress)

SauronID ships dual storage backends: `sqlite` (default; `r2d2 + rusqlite` pool, single-node) and `postgres` (opt-in; `sqlx::PgPool`, real replication). Switch with `SAURON_DB_BACKEND`.

Postgres backend recommended for production; SQLite default acceptable for dev/staging. See `docs/roadmap.md` Plan 2 for migration progress — M1 (serializable transaction helper + `agent_call_nonces` / `ajwt_used_jtis` / `risk_rate_counters` ported, race-tested in CI) shipped 2026-05-15. Remaining tables (M2-M4) are still SQLite-only; production deployments that touch those tables must keep `SAURON_ACCEPT_SINGLE_NODE_SQLITE=1`.

#### Local Postgres dev

```bash
docker compose -f deploy/docker-compose-postgres.yml up -d
psql "postgres://sauronid:dev@localhost:5432/sauronid" -f migrations/postgres/0001_initial.sql

# or, with sqlx-cli installed:
cargo install sqlx-cli --no-default-features --features postgres
sqlx migrate run --source migrations/postgres --database-url postgres://sauronid:dev@localhost:5432/sauronid
```

Run SauronID against Postgres:

```bash
export SAURON_DB_BACKEND=postgres
export DATABASE_URL=postgres://sauronid:dev@localhost:5432/sauronid
export SAURON_PG_POOL_SIZE=16          # optional, default 16
./target/release/sauron-core
# look for `[sauron::repo] repository pool ready backend=postgres` at startup
```

#### Migration progress

| Module | rusqlite | sqlx::PgPool | TOCTOU-fix preserved? |
|---|:-:|:-:|:-:|
| `agent_call_nonces` (call-sig replay) | ✓ | ✓ | ✓ via `is_unique_violation` |
| `ajwt_used_jtis` | ✓ | — | pending |
| `risk_rate_counters` | ✓ | — | pending |
| `agent_pop_challenges` | ✓ | — | pending |
| `consent_log` | ✓ | — | pending (atomic UPDATE-WHERE-OLD-VALUE) |
| `agent_payment_authorizations` | ✓ | — | pending (atomic UPDATE-WHERE-OLD-VALUE) |
| `bank_attestation_nonces` | ✓ | — | pending (atomic INSERT) |
| `credential_codes` | ✓ | — | pending (atomic UPDATE-WHERE-OLD-VALUE) |
| `agents` | ✓ | — | pending |
| `users`, `clients`, `merkle_leaves` | ✓ | — | pending |
| `bitcoin_merkle_anchors`, `solana_merkle_anchors` | ✓ | — | pending |
| `agent_action_*`, `agent_vcs`, `device_tokens`, `api_usage`, `requests_log` | ✓ | — | pending |
| `payment_smt_leaves`, `user_compliance_screening`, `bank_kyc_links` | ✓ | — | pending |

Each port follows the template in `core/src/repository.rs::consume_call_nonce`:

1. Add a typed method on `Repo` taking high-level intent (not raw SQL).
2. Match `&self` over `Sqlite` / `Postgres`, dispatch to the right driver.
3. Map driver-specific errors (e.g. `sqlx::Error::Database::is_unique_violation`) onto the same `RepoError::Replay` variant SQLite already produces from `UNIQUE` text matching.
4. Update callers from raw `db.execute(...)` to `state.repo.method(...).await`.
5. Run `bash scripts/dev/run-all.sh` (default + enforce). Both must stay green.

#### Dialect mapping

| SQLite (legacy) | Postgres (canonical) |
|---|---|
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` |
| `INTEGER` (epoch seconds) | `BIGINT` |
| `BLOB` | `BYTEA` |
| `IFNULL(x, y)` | `COALESCE(x, y)` |
| `INSERT OR IGNORE INTO t … VALUES …` | `INSERT INTO t … VALUES … ON CONFLICT DO NOTHING` |
| `INSERT OR REPLACE INTO t … VALUES …` | `INSERT INTO t … VALUES … ON CONFLICT (key) DO UPDATE SET …` |
| `?1`, `?2` numbered params | `$1`, `$2` (sqlx handles automatically) |
| `||` for string concat | `||` (works in both) |
| `strftime('%s','now')` | `EXTRACT(EPOCH FROM NOW())::BIGINT` |

#### Backups & recovery (Postgres)

Standard `pg_basebackup` + WAL archiving. For multi-region: streaming replication or a managed service (RDS, Cloud SQL, Crunchy Bridge). SauronID ships nothing custom here — the schema in `migrations/postgres/0001_initial.sql` is the only thing operators need to seed a new replica.

### Solana anchoring (Phase 2.3)

The default Solana path uses the **Memo Program** (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) — no custom program deploy required. Each merkle-root advance is timestamped on-chain as a memo containing `sauronid:v1:<root_hex>`.

#### Devnet setup (free, no funding cost)

```bash
# 1. Install Solana CLI on the operator host (one-time)
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

# 2. Generate a fee-payer keypair (one-time, store it securely)
solana-keygen new --no-bip39-passphrase \
    -o /etc/sauronid/solana-keypair.json
chmod 600 /etc/sauronid/solana-keypair.json

# 3. Airdrop devnet SOL (rate-limited to 2 SOL per request, repeat as needed)
PUBKEY=$(solana-keygen pubkey /etc/sauronid/solana-keypair.json)
solana airdrop 2 "$PUBKEY" --url https://api.devnet.solana.com

# 4. Configure SauronID core
export SAURON_SOLANA_ENABLED=1
export SAURON_SOLANA_RPC_URL=https://api.devnet.solana.com
export SAURON_SOLANA_NETWORK=devnet
export SAURON_SOLANA_KEYPAIR_PATH=/etc/sauronid/solana-keypair.json
# optional: export SAURON_SOLANA_MEMO_PREFIX="sauronid:v1:"
```

Each anchor costs ~0.000005 SOL (~$0.00001 mainnet, free on devnet). 2 SOL covers ~400 000 anchors.

#### Verify an anchor externally

```bash
# Take a signature from solana_merkle_anchors.signature
SIG=…
curl -s -X POST -H "content-type: application/json" \
     https://api.devnet.solana.com \
     -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$SIG\",{\"encoding\":\"json\"}]}"
# inspect the message log_messages — the memo will appear as
#   "Program log: Memo (len 76): \"sauronid:v1:<root_hex>\""
```

Or paste the signature into https://explorer.solana.com/?cluster=devnet — the memo body shows directly under "Instruction Data".

#### Mainnet flip

```bash
# Fund a new keypair with real SOL (~0.1 SOL covers ~20 000 anchors)
solana-keygen new --no-bip39-passphrase \
    -o /etc/sauronid/solana-mainnet-keypair.json
chmod 600 /etc/sauronid/solana-mainnet-keypair.json
# (transfer 0.1+ SOL from your treasury wallet to the printed pubkey)

export SAURON_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
export SAURON_SOLANA_NETWORK=mainnet
export SAURON_SOLANA_KEYPAIR_PATH=/etc/sauronid/solana-mainnet-keypair.json
# restart the core; same code path, real chain
```

For wrapping the keypair under Vault Transit, base64-encode the JSON file, encrypt to ciphertext, and reference via `SAURON_SOLANA_KEYPAIR_INLINE_WRAPPED` (resolved through `secret_provider.rs` → decoded + parsed as JSON byte array). _(Phase 2.3 ships path-on-disk + inline-JSON; the wrapped variant follows the same pattern as the other root secrets — landed in the same `resolve_secret` chain when the operator opts in.)_

#### Optional: custom Anchor program for richer semantics

For deployments that want on-chain authority + counter + per-update events, the `contracts/sauron_ledger/` Anchor program ships a `SauronState` PDA with `update_root([u8; 32])`. Deploy with:

```bash
cd contracts/sauron_ledger
anchor build
anchor deploy --provider.cluster devnet
# capture the program id printed
```

Then write a separate Rust client that constructs the Anchor instruction discriminator + arguments. _(Not implemented in this Phase; the Memo path covers the audit-anchoring use case.)_

### OTS calendar outage

Anchoring fails when all configured calendars are unreachable. The application continues running; merkle commitments accumulate in DB without anchors. Once a calendar comes back, you can manually re-submit pending roots:

```sql
SELECT merkle_root_hex FROM bitcoin_merkle_anchors WHERE provider = 'opentimestamps' AND ots_calendar_url = '';
```

(Re-submit logic not built; manual `curl` against the calendar's `/digest` works, then UPDATE the row.)

## Health checks

```bash
# liveness
curl -fsS http://localhost:3001/admin/stats -H "x-admin-key: $SAURON_ADMIN_KEY" >/dev/null && echo OK

# metrics endpoint
curl -fsS http://localhost:3001/metrics | head -5

# OTS upgrader sanity (should be 0 or small)
sqlite3 sauron.db "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE provider='opentimestamps' AND ots_upgraded=0 AND created_at < strftime('%s','now','-1 day');"
```

## CI gate (recommended)

Before merging:

```bash
cargo clippy -- -D warnings
cargo test --workspace
bash scripts/dev/run-all.sh                                  # 9-scenario default
SAURON_REQUIRE_CALL_SIG=1 bash scripts/dev/run-all.sh        # 9-scenario enforce
cargo audit                                      # dependency CVEs
```

## TPM2 attestation (M2)

Place vendor root DER certs (Infineon, STMicro, Microsoft, Intel, AMD, IBM —
download from each vendor's CA distribution point) at
`/etc/sauronid/tpm2-roots/` before accepting `tpm2_quote` registrations.
Override the path via `SAURON_TPM2_VENDOR_ROOTS_DIR`.

Without configured roots, the server returns a structured
`AttestationError::PartialImplementation` directing the operator to this
step. The verifier never silently accepts an unrooted chain.

```bash
# 1. Place at least one vendor root DER into the configured directory.
sudo mkdir -p /etc/sauronid/tpm2-roots
sudo cp infineon-tpm-root-ca.der /etc/sauronid/tpm2-roots/

# 2. Register an agent with attestation_kind=tpm2_quote. The five tpm2_*
#    fields (quote, attest, signature, aik_cert_pem, ek_cert_chain_pem) plus
#    tpm2_attestation_pubkey_b64u (format: "ed25519:<b64u>" |
#    "p256:<b64u SEC1>" | "rsa:<b64u SPKI DER>") are required.

# 3. On every verify, the flow is:
#    parse TPMS_ATTEST -> verify pcrDigest -> walk AIK->EK->root via webpki
#    -> verify AIK signature via ring.
```
