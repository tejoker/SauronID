# Production Readiness

SauronID's production claim is limited to the fail-closed agent-control core:
per-agent PoP keys, tenant/audience-bound call signatures, intent and policy
checks, one-use nonces/capabilities, and externally anchored audit receipts.
The repository is not, by itself, evidence that an AI agent cannot escape;
deployment network isolation and independent review remain release gates.

## Demo vs Production

- `ENV=development` enables demo helpers such as `/dev/register_user`, `/dev/buy_tokens`, `/dev/leash/demo`, `/dev/consent_profile`, and development-only mock ZKP proofs.
- Any non-development `ENV` / `SAURON_ENV` rejects dev helpers and requires explicit secrets.
- Mock anchoring is development-only and makes production health fail.
- Local Hardhat is for demos and tests, not production revocation infrastructure.

## Required Controls

- Set strong random `SAURON_ADMIN_KEY` or `SAURON_ADMIN_KEYS`; production rejects admin keys under 32 bytes.
- Set `SAURON_TOKEN_SECRET`, `SAURON_JWT_SECRET`, and
  `SAURON_AUDIT_HMAC_KEY` through a secret manager. Legacy OPRF authentication
  is disabled in production; do not provision `SAURON_OPRF_SEED` as a new
  authentication dependency.
- Set `SAURON_DASHBOARD_SESSION_SECRET` and `SAURON_DASHBOARD_OPERATORS` for the signed dashboard session. Use scrypt records for operator passwords; raw SHA-256 records are development-only.
- Keep the dashboard behind TLS and, where appropriate, the optional Caddy HTTP basic-auth defense-in-depth layer.
- Keep `SAURON_REQUIRE_CALL_SIG`, `SAURON_REQUIRE_AGENT_TYPE`,
  `SAURON_POLICY_REQUIRE_BINDING`, `SAURON_EGRESS_GATEWAY`, and
  `SAURON_ENFORCE_STATS_FRESHNESS` enabled. Production startup refuses an
  explicit disable unless the unsafe override is deliberately set.
- Set a finite positive `SAURON_MAX_ACTION_USD` global damage ceiling.
- Hardware attestation is optional. If selling that separate assurance tier,
  enable both attestation flags and supply authoritative measurements; otherwise
  leave it off and treat agents as hostile.
- Pin both reviewed guest image IDs in
  `SAURON_TRANSPARENT_IMAGE_IDS_JSON`; production startup validates the map.
- Use only structured production egress entries with explicit methods, path,
  byte caps, allowed headers, request-body policy and response disclosure mode.
- Keep legacy OPRF auth, unaudited Paillier, voluntary egress logging,
  server-derived PoP, custom checksums, legacy token MAC, and Groth16 disabled.
- Configure `SAURON_ALLOWED_ORIGINS` explicitly for deployed web origins.
- Use `SAURON_COMPLIANCE_JURISDICTION_MODE=enforce` with a non-empty `SAURON_COMPLIANCE_JURISDICTION_ALLOWLIST` where required.
- Use `SAURON_COMPLIANCE_SANCTIONS_MODE=enforce` and `SAURON_COMPLIANCE_PEP_MODE=enforce` after wiring a real screening provider.

## Data Tier

SQLite is the local/CI default. Production-like startup requires `SAURON_ACCEPT_SINGLE_NODE_SQLITE=1` to avoid silent HA claims. Before real production, replace or wrap the data tier with:

- managed backups and restore drills,
- migration tooling,
- encryption at rest,
- retention/deletion policy,
- replicated or managed high-availability storage,
- secrets and private key material moved out of ordinary application rows where possible.

For an explicitly accepted single-node deployment, create and validate online
snapshots with `scripts/ops/verify-sqlite-backup.sh`; a release drill must also
restore the produced file into a clean instance. The script exercises SQLite's
online backup API, integrity/foreign-key checks and critical-table presence. It
does not create HA. The partial Postgres adapter remains transitional and the
startup warning deliberately says SQLite is still load-bearing.

Partner private keys must be generated and retained by the partner/HSM. The
production registration API accepts only public material and does not return
or persist a generated private key. There is no column for one: the `clients`
table's `private_key_hex` was dropped in `migrations/postgres/0019` after it
had spent its whole life storing the constant `EXTERNAL_CUSTODY` and being read
by nothing.

### How far the Postgres port actually is

Setting `SAURON_DB_BACKEND=postgres` does **not** move the deployment off
SQLite, and the single-node acknowledgement is required with or without it.
Measure it from the source rather than from intent:

```bash
# Call sites that work against either backend
grep -rc '\.any_conn()' core/src --include='*.rs' | awk -F: '{n+=$2} END {print "dual-backend:", n}'
# Call sites still bound to rusqlite
grep -rcE '\b(db|conn|tx)\.(query_row|execute|prepare|query_map|execute_batch)\(' core/src --include='*.rs' \
  | awk -F: '{n+=$2} END {print "sqlite-only: ", n}'
```

At the time of writing that is 189 dual-backend against 131 SQLite-only —
roughly 59% converted. Schema parity is already complete: all 55 tables exist
in `migrations/postgres/`, so the gap is entirely in which call sites use the
abstraction, not in what Postgres can store.

**The receipts and anchors subsystem has to move as one unit.**
`agent_action_receipts` plus `bitcoin_merkle_anchors` / `solana_merkle_anchors`
are written by synchronous `&Connection` helpers
(`validate_agent_action`, `validate_anon_action`, the egress gateway) and read
from roughly thirteen places across six modules — including the anchor batcher,
which seals receipts into Bitcoin and Solana. Porting the writes alone puts the
readers on an empty Postgres table while the real rows stay in the SQLite
sidecar, and the failure is silent: anchoring simply stops finding anything to
anchor. That port was attempted once and reverted for exactly this reason.

Until it lands, the honest answer to "can we run this multi-AZ" is no, and the
honest answer to "when" is: after that subsystem moves. Full detail and the
per-table sweep is in [postgres-port-status.md](postgres-port-status.md).

## Proof and authentication boundary

- Production rejects Groth16 even if its compatibility flag is set. The
  RISC Zero verifier accepts pinned native `Succinct` STARK receipts
  from the two reviewed guests in `transparent-zk/`; fake and Groth16-compressed
  receipts fail closed.
- Human login uses the partner/bank-bound Ed25519 challenge flow at
  `/user/auth/challenge` and `/user/auth/finish`. The legacy password-derived
  endpoint is development-only. OPAQUE is needed only if passwords are added
  back as a requirement.
- The Paillier implementation is quarantined in production. It is not a
  production aggregation claim. Transparent local aggregation is the supported
  replacement; threshold HE is a separate future product choice.

## Release Gate

Before a demo or release, run:

```bash
bash scripts/dev/run-all.sh
```

For production-shaped container configuration, use `deploy/docker-compose.prod.yml` as a starting template. It intentionally requires secrets and does not ship development defaults.

At minimum, the gate should include:

- Rust unit tests and clippy,
- Agentic SDK tests,
- transparent guest review, reproducible image-ID comparison and native STARK
  receipts verified by the separate customer verifier on release tags; Circom
  circuit tests apply only to the quarantined legacy path,
- issuer/acquirer SDK tests,
- revocation contract tests,
- frontend lint and production builds,
- confidence suite and scripted KYA red-team on a machine that can bind local ports.
- current RustSec/npm/Python/Go advisory scans. The production core and minimal
  verifier must have no known vulnerability; prover-only upstream exceptions
  must be documented and re-evaluated on every RISC Zero release.

## Current Production Boundary

The code now fails closed on the known legacy crypto and policy bypasses, but
commercial release still requires all of the following outside this repo:

- force the agent workload's only network route through the capability gateway
  (separate namespace/VM, deny-by-default firewall and DNS policy);
- real TPM/Nitro end-to-end tests only if marketing the optional hardware tier;
- a managed HA data tier with backups, restore drills and tenant isolation;
- a real OpenTimestamps/chain provider and monitoring of pending/failed anchors;
- an independent cryptographic review and adversarial deployment test.

Without those controls, describe the build as hardened staging software, not
as a guarantee that no agent can run wild.
