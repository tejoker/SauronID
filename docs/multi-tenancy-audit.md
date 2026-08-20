# Multi-tenancy isolation audit

Sprint 3 deliverable. Table-by-table review of every persisted row in
`core/src/db.rs::init_schema` against the multi-tenant threat model.

Each row carries one of three verdicts:

| Verdict       | Meaning |
|---------------|---------|
| `SCOPED`      | Has a `tenant_id` column. Every query filters by it. Cross-tenant access blocked at the repository layer. |
| `KEEP_GLOBAL` | Intentionally NOT scoped. Either (a) the primary key carries enough entropy to be globally unique (session-scoped tables), (b) the table is operator-aggregate by design (anchor batches, public chain data), or (c) the table is legacy KYC/banking and disabled in the multi-tenant deployment. |
| `DEFER`       | Touched but not yet sweep-completed at the handler call-site level. Tracked under Known gaps. |

> Source of truth for the SCOPED set: the `tenant_scoped_tables` array
> in `core/src/db.rs` (lines 772-789). The verdict here mirrors that
> list plus the explicit KEEP_GLOBAL list documented in
> `core/src/tenancy/mod.rs` module docs.

---

## Agent registry + auth

| Table | Verdict | Why |
|-------|---------|-----|
| `agents` | SCOPED | Each agent belongs to one tenant. Registration writes `tenant_id` from the resolved `TenantId` extension; list/get queries filter by it. Mitigation: `core/src/agent.rs::list_agents` line 1354 — `WHERE human_key_image = ?1 AND tenant_id = ?2`. |
| `agent_vcs` | KEEP_GLOBAL | Agent VC credentials are keyed by `agent_id` (which is itself tenant-scoped via the `agents` row). Isolation inherits transitively through the FK-like relation; the VC payload alone leaks nothing without a matching `agent_id` whose tenant the caller cannot enumerate. |
| `agent_checksum_inputs` | KEEP_GLOBAL | Same rationale as `agent_vcs` — agent-scoped, inherited isolation. Operator-side checksum audit is per-`agent_id`. |
| `agent_checksum_audit` | KEEP_GLOBAL | Append-only checksum-rotation trail keyed by `agent_id`. Same inheritance argument. |

Attack vector if global stayed global: none beyond the existing
`agents`-row isolation. A caller who cannot resolve another tenant's
`agent_id` cannot index into these tables.

---

## Policy + spend

| Table | Verdict | Why |
|-------|---------|-----|
| `policies` | SCOPED | Composite key (tenant_id, policy_id). `PolicyStore::get_by_id_tenant` (core/src/policy/store.rs:213) returns None for cross-tenant lookups. Handler maps to 404 (no existence leak) at `core/src/policy/handlers.rs:153`. |
| `spend_ledger` | SCOPED | Primary key is `(tenant_id, policy_id, agent_id, period_start)` on both backends, and the upsert conflict target matches it. Verified by `tenant-spend-ledger-race.ts`, which now runs via `make redteam-suites` and passes on SQLite and PostgreSQL. Fixed 2026-08-19; see the note below for what the fix could and could not repair. |
| `spend_log` | SCOPED | Append-only ledger. `list_spend_log_inner_tenant` filters by tenant_id. Verified by `tenant-spend-history-leak.ts`. |
| `agent_policy_bindings` | SCOPED | Composite PK (tenant_id, agent_id). Bind handler (core/src/policy/binding_handlers.rs::bind_policy) verifies both `agent_id` and `policy_id` exist under the caller's tenant before writing — cross-tenant injection returns 400/404. Verified by `tenant-binding-injection.ts`. |

Attack vector if global stayed global: cross-tenant spend accounting
collisions (one tenant's spend exhausts another's budget), policy
existence enumeration, policy bypass via binding injection.

---

## Action receipts + anchors

| Table | Verdict | Why |
|-------|---------|-----|
| `agent_action_receipts` | SCOPED | tenant_id column added at S11. Cross-tenant receipt-id probes return None. The merkle leaf hash carries the receipt content but recovering it requires knowing the receipt_id, which is itself tenant-scoped. |
| `agent_action_anchors` | SCOPED (storage) but cross-tenant readable on `/admin/anchor/batches` BY DESIGN | Per-tenant anchor batching is staged for S11.5; today the table carries `tenant_id` and storage is partitioned. The admin batch-listing endpoint is intentionally operator-aggregate (see "What we don't isolate" below). |
| `bitcoin_merkle_anchors` | SCOPED (storage) | Anchored merkle root is by definition non-secret (it's published to the chain). The `tenant_id` partitions row ownership for retrieval; the root itself crosses tenants when batched. |
| `solana_merkle_anchors` | SCOPED (storage) | Same as bitcoin_merkle_anchors. |
| `merkle_leaves` | SCOPED | Per-tenant commitment ledger. |
| `agent_action_nonces` | KEEP_GLOBAL | Single-use one-time nonces. PK is a UUID-shaped string — global uniqueness preserves replay protection across tenants without needing a tenant filter. |

Attack vector if global stayed global: receipt enumeration / extraction
of another tenant's anchored receipts. Mitigation: receipt id space is
per-tenant. Anchor merkle root is public — see
`tenant-anchor-merkle-extraction.ts` for why root visibility ≠ receipt
extraction.

---

## Stats + DP

| Table | Verdict | Why |
|-------|---------|-----|
| `customer_stats` | SCOPED | Composite PK includes `tenant_id`. Submit handler (core/src/aggregation/handlers.rs:43) binds body.tenant_id to the middleware-resolved TenantId — body field is IGNORED for trust. |
| `cohort_definitions` | KEEP_GLOBAL | Cohorts are operator-level aggregations across tenants. Definition table is shared by design. Tenant-membership lives in the `tenant_ids_json` field; cohort aggregation filters published rows by that list. |
| `dp_budget_ledger` | KEEP_GLOBAL | Per-cohort ε budget. Cohorts are global so the ledger is global. Rotate endpoint (cohort/budget/rotate) requires admin auth + valid cohort_id. Verified by `tenant-cohort-budget-rotate-cross.ts`. |
| `dp_budget_publications` | KEEP_GLOBAL | Audit trail for ε spend. Inherits cohort-global rationale. |

Attack vector if SCOPED column were missing on `customer_stats`:
tenant B could enumerate / overwrite tenant A's claimed metric values.
Mitigation: middleware overrides body tenant before any DB write.

---

## Audit + security

| Table | Verdict | Why |
|-------|---------|-----|
| `security_audit_log` | SCOPED | tenant_id column. Query path (core/src/middleware/audit_log.rs:316) filters by tenant. The special `*` tenant is reserved for internal tooling and NOT exposed on the HTTP surface. |
| `audit_reports` | SCOPED | tenant_id column. `get_report` filters by tenant; cross-tenant report retrieval returns None → 404. Verified by `tenant-audit-report-leak.ts`. |
| `requests_log` | KEEP_GLOBAL | Anonymous request log (no PII, no tenant context required). Used for operator-level traffic shape analysis. |
| `api_usage` | KEEP_GLOBAL | Billing meter keyed by `client_name`. Pre-multi-tenant; today rolled up into operator-aggregate `/admin/stats`. Tenant-scoped billing lives in `core/src/tenancy/billing.rs` (S11.5 path). |

Attack vector if `security_audit_log` were global: tenant B could read
tenant A's auth-failure trail, learn A's IP addresses and probing
patterns. Mitigation: tenant filter in query path + admin auth at the
router layer.

---

## Sessions + nonces (KEEP_GLOBAL — opaque PKs)

| Table | Verdict | Why |
|-------|---------|-----|
| `agent_pop_challenges` | KEEP_GLOBAL | Single-use PoP challenge keyed by random `id`. Cross-tenant collision impossible at the PK level (random nonce). Lookup is by (id, agent_id); agent_id is tenant-scoped via the `agents` row. |
| `agent_call_nonces` | KEEP_GLOBAL | Single-use call-signature nonces. PK = (agent_id, nonce). Replay protection is global by design (a nonce burned for agent X under tenant A must also be burned for the same agent across any future query). |
| `ajwt_used_jtis` | KEEP_GLOBAL | Single-use A-JWT jti. JTI is UUID-shaped — replay protection across the entire deployment. |
| `bank_attestation_nonces` | KEEP_GLOBAL | Webhook-replay protection keyed by (provider_id, nonce). Provider-level not tenant-level. |
| `device_tokens` | KEEP_GLOBAL | Trusted device-binding tokens keyed by SHA-256(token). Cross-tenant collision impossible at the PK level. |

Attack vector: none — these are all replay-protection / single-use
primitives where global uniqueness is the security property.

---

## Compliance + KYC (legacy, mostly disabled)

| Table | Verdict | Why |
|-------|---------|-----|
| `users` | KEEP_GLOBAL | OPRF-derived identity registry. Single per-deployment directory by design — multi-tenant access control lives on `user_registrations` (SCOPED) and `consent_log` (SCOPED). |
| `clients` | KEEP_GLOBAL | Partner site registry (legacy bank/retail). Pre-multi-tenant; the multi-tenant deployment uses agent registration as the per-tenant identity primitive. |
| `bank_kyc_links` | KEEP_GLOBAL | Legacy. Pre-multi-tenant bank webhook attestation glue. Not used in the multi-tenant pipeline. |
| `user_credentials` | SCOPED | Cached BabyJubJub credentials. Migrated to tenant_id in the S11 ALTER block (core/src/db.rs:782). |
| `credential_codes` | SCOPED | Pre-auth codes for credential fetch. Tenant_id added at S11. |
| `user_registrations` | SCOPED | User ↔ client mapping; tenant_id added at S11. |
| `consent_log` | SCOPED | GDPR-auditable consent grants. tenant_id added at S11. |
| `user_compliance_screening` | KEEP_GLOBAL | Sanctions / PEP / risk-tier overlay keyed by user key_image_hex. Compliance lists are per-deployment, not per-tenant. |
| `company_data` | KEEP_GLOBAL | Pre-computed analytics per `company_id`. Pre-multi-tenant aggregation surface; deprecated in favour of `customer_stats`. |
| `payment_smt_leaves` | KEEP_GLOBAL | Payment SMT keyed by SHA256(agent_id|window_start). PK collision-resistant; agent_id is tenant-scoped. |
| `lightning_l402_invoices` | KEEP_GLOBAL | Lightning invoices keyed by UUID `invoice_id`. Agent-scoped via the agent_id column; tenant inherited transitively. |
| `agent_egress_log` | SCOPED | Outbound-call audit per agent. tenant_id added at S11. |
| `agent_payment_authorizations` | SCOPED | Pre-Stripe auth envelopes. tenant_id added at S11. |
| `risk_rate_counters` | SCOPED | Rate-limit buckets. tenant_id added at S11 — verified by `tenant-rate-limit-cross.ts` (noisy tenant cannot starve quiet tenant). |

Attack vector for the user/client/clients triplet if naively scoped:
identity registry would fork, breaking OPRF lookup. The accepted
trade-off is that the IDENTITY directory is global; everything that
EXPRESSES intent / consent / registration on top of it is per-tenant.

---

## Summary verdict table

| Table | Scope | Risk if global |
|-------|-------|----------------|
| agents | SCOPED | List enum + cross-tenant ops |
| agent_vcs | KEEP_GLOBAL | None (agent-scoped PK) |
| agent_checksum_inputs | KEEP_GLOBAL | None (agent-scoped PK) |
| agent_checksum_audit | KEEP_GLOBAL | None (agent-scoped PK) |
| policies | SCOPED | Policy id enum + cross-tenant evaluate |
| spend_ledger | CLOSED | Spend collision / cross-tenant budget exhaustion — fixed, see below |
| spend_log | SCOPED | Spend history leak |
| agent_policy_bindings | SCOPED | Binding injection / policy bypass |
| agent_action_receipts | SCOPED | Receipt enum / content leak |
| agent_action_anchors | SCOPED (storage), cross-tenant readable on admin | Documented — anchor batches are operator-aggregate |
| bitcoin_merkle_anchors | SCOPED (storage) | None — chain data is public |
| solana_merkle_anchors | SCOPED (storage) | None — chain data is public |
| merkle_leaves | SCOPED | Commitment-set leak |
| agent_action_nonces | KEEP_GLOBAL | None — random PK |
| customer_stats | SCOPED | Stat overwrite / enum |
| cohort_definitions | KEEP_GLOBAL | None — cohort IS cross-tenant unit |
| dp_budget_ledger | KEEP_GLOBAL | None — cohort-scoped |
| dp_budget_publications | KEEP_GLOBAL | None — cohort-scoped |
| security_audit_log | SCOPED | Cross-tenant audit trail leak |
| audit_reports | SCOPED | Cross-tenant report retrieval |
| requests_log | KEEP_GLOBAL | None — anonymous |
| api_usage | KEEP_GLOBAL | Legacy — billing per client_name |
| agent_pop_challenges | KEEP_GLOBAL | None — random PK |
| agent_call_nonces | KEEP_GLOBAL | None — replay protection global by design |
| ajwt_used_jtis | KEEP_GLOBAL | None — replay protection global |
| bank_attestation_nonces | KEEP_GLOBAL | None — provider-level |
| device_tokens | KEEP_GLOBAL | None — SHA256 PK |
| users | KEEP_GLOBAL | Documented — global identity registry |
| clients | KEEP_GLOBAL | Legacy partner registry |
| bank_kyc_links | KEEP_GLOBAL | Legacy KYC, disabled |
| user_credentials | SCOPED | Cred cache cross-leak |
| credential_codes | SCOPED | Pre-auth code reuse cross-tenant |
| user_registrations | SCOPED | Reg history leak |
| consent_log | SCOPED | GDPR consent leak |
| user_compliance_screening | KEEP_GLOBAL | None — overlay shared |
| company_data | KEEP_GLOBAL | Legacy analytics |
| payment_smt_leaves | KEEP_GLOBAL | None — SHA256 PK + agent-scoped |
| lightning_l402_invoices | KEEP_GLOBAL | None — UUID PK + agent-scoped |
| agent_egress_log | SCOPED | Egress history leak |
| agent_payment_authorizations | SCOPED | Payment auth cross-use |
| risk_rate_counters | SCOPED | Noisy-tenant DoS |

Total: 41 tables (init_schema). SCOPED: 19. KEEP_GLOBAL: 22. DEFER: 0
(every table sweep-completed at the storage layer; remaining work is
handler call-site sweep, see Known gaps below).

---

## What we don't isolate (by design)

- **Anchor batches** (`/admin/anchor/batches`) — operator-aggregate by
  design. Anchor roots are by definition public (they go on Bitcoin
  via OpenTimestamps + Solana via memo program). The list of batches
  is visible cross-tenant; the per-receipt extraction path requires a
  `receipt_id` from the tenant-scoped `agent_action_receipts` table.
  Verified by `tenant-anchor-merkle-extraction.ts`.
- **Public chain data** (Bitcoin txids, Solana signatures) — non-secret
  by definition.
- **Operator stats** (`/admin/stats`) — operator-aggregate. Counts
  every tenant's `users`/`clients`/`api_usage` together. This is the
  operator's billing + capacity dashboard, NOT a per-tenant view.
  Verified by `admin_stats_aggregates_across_tenants` test.
- **Cohort definitions + DP budgets** — cohorts ARE the cross-tenant
  aggregation unit; isolating them would defeat the purpose of the
  cross-tenant DP publish pipeline.
- **Single-use replay-protection nonces** (`ajwt_used_jtis`,
  `agent_action_nonces`, `agent_call_nonces`) — global uniqueness
  preserves the security property across tenants.
- **Identity registry** (`users`, `clients`) — single OPRF-derived
  directory per deployment; multi-tenant access lives on the
  per-tenant tables that reference it.
- **Static admin key holders** — anyone with `SAURON_ADMIN_KEY` can
  target any tenant by setting `x-sauron-tenant-id`. This is intentional
  (super-admin operator capability); audit-log middleware records the
  usage. Verified by `tenant-header-spoof.ts`.

---

## Known gaps

- **Agent handler call-site sweep — S11.5 progress.** The storage
  layer is fully scoped, but a handful of `agent.rs` handler call
  sites still use the legacy back-compat helpers (e.g.
  `record_spend_inner` defaults to `"default"` tenant). These do
  NOT introduce a cross-tenant leak (they write to the default tenant,
  which is invisible to other tenants), but they DO mean that
  background jobs / legacy CLI calls under the multi-tenant deployment
  may land in `default` instead of the operator's per-tenant
  partition. Tracking issue: see `core/src/tenancy/mod.rs::
  tenant_id_for_background_job` documented as deferred.
- **Admin credential boundary.** `/admin/agents` and the related data views
  are tenant-filtered. A static admin key is still an operator credential and
  can select a tenant header; tenant/customer administration must use JWTs
  with a `tnt` allowlist. Cross-tenant views require super-admin authority or
  the explicit global flag.
- **Per-tenant anchor batching.** Today the anchor batcher rolls
  receipts across tenants into a single root. This is correct for
  cross-tenant chain efficiency but means the chain anchor cannot
  itself be tenant-attributed without the receipt + merkle path.
  Documented; not a gap for the per-tenant TENANT_ISOLATION property.
- **Postgres path.** The `Repo::Postgres` arm has tenant scoping for
  the spend ledger but the binding handler's Postgres path is
  deferred to S11.6. The Sqlite path (default for the multi-tenant
  deployment) is fully scoped.

---

## Test coverage

### Rust integration tests — `core/tests/multi_tenancy.rs` (14 tests)

1. `policy_upload_as_tenant_a_does_not_leak_to_tenant_b_list`
2. `policy_get_by_id_returns_404_shape_across_tenants_no_existence_leak`
3. `spend_record_as_tenant_a_isolated_from_tenant_b_total`
4. `spend_log_list_is_tenant_scoped`
5. `evaluate_resolver_uses_tenant_scoped_authoritative_total`
6. `default_tenant_back_compat_legacy_record_spend_inner`
7. `tenant_registry_records_first_seen_and_lists_sorted`
8. `tenant_id_default_is_default_const_pinned`
9. `agent_registered_as_tenant_a_invisible_to_tenant_b_list`
10. `agent_lookup_by_id_returns_404_cross_tenant`
11. `admin_stats_aggregates_across_tenants` *(Sprint 3)*
12. `admin_agents_filters_to_callers_tenant` *(Sprint 3)*
13. `admin_audit_log_isolated_per_tenant` *(Sprint 3)*
14. `cross_tenant_evaluate_returns_404_not_403` *(Sprint 3)*

### Rust smoke battery — `core/tests/cross_tenant_battery.rs`

- `cross_tenant_smoke_policy_evaluate_spend_audit` — inline replay of
  the three most critical redteam scenarios (policy cross-evaluate,
  spend history leak, audit report leak) at the storage layer.

### TypeScript redteam scenarios — `redteam/src/scenarios/`

Sprint 12 baseline (3):

1. `tenant-list-leak.ts`
2. `tenant-spend-leak.ts`
3. `tenant-rate-limit-cross.ts`

Sprint 3 additions (12):

4. `tenant-policy-cross-evaluate.ts`
5. `tenant-binding-injection.ts`
6. `tenant-audit-report-leak.ts`
7. `tenant-spend-history-leak.ts`
8. `tenant-cohort-publish-cross.ts`
9. `tenant-tpm2-attestation-cross.ts`
10. `tenant-anchor-merkle-extraction.ts`
11. `tenant-jwt-claim-forgery.ts`
12. `tenant-header-spoof.ts`
13. `tenant-policy-store-enumeration.ts`
14. `tenant-spend-ledger-race.ts`
15. `tenant-cohort-budget-rotate-cross.ts`

Run the full 15-scenario battery via:

```bash
cd redteam && npm run build
SAURON_CORE_URL=http://127.0.0.1:3001 \
  SAURON_ADMIN_KEY=$ADMIN_KEY \
  node dist/scenarios/run-all-tenant-isolation.js
```

The runner emits one aggregated JSON envelope and exits non-zero on
any scenario that diverges from documented threat-model behaviour.

## Fixed 2026-08-19: `spend_ledger` was not tenant-scoped

Found 2026-08-18 by running `redteam/dist/scenarios/run-all-tenant-isolation.js`,
which nothing in the Makefile or CI had ever run.

`spend_ledger`'s primary key is `(policy_id, agent_id, period_start)` on both
backends — `core/src/db.rs` and `migrations/postgres/0003_spend_ledger.sql`.
Migration `0004_multi_tenant.sql` added `tenant_id` as a column and an index, but
did not extend the key. `Repo::record_spend_with_period_tenant` upserts with
`ON CONFLICT(policy_id, agent_id, period_start)`, so the conflict target is
tenant-blind.

Reproduced against a fresh SQLite core with `SAURON_ADMIN_CROSS_TENANT` unset:
two tenants each posting ten spends for the same `(agent_id, policy_id)` produced

    spend_log     20 rows, correctly split 10 / 10 per tenant
    spend_ledger   1 row, tenant_id = <tenant A>, total_usd = 1010.0

i.e. tenant B's 1000 landed in tenant A's authoritative total, and tenant B's own
ledger read returned nothing.

`get_spend_total` is what the `budget` and `daily_budget` invariants consult, so
the consequences run both ways:

- the non-owning tenant reads 0 and its spend cap never trips — a budget bypass;
- the owning tenant absorbs the other's spend and its agents are denied for money
  they did not spend — cross-tenant denial of service.

Exploiting it requires knowing a victim's `agent_id` and `policy_id`, both
server-minted hex, so this is not trivially reachable from outside. It is directly
reachable for an operator who reuses stable policy or agent identifiers across
tenants.

### The fix

`PRIMARY KEY (tenant_id, policy_id, agent_id, period_start)` on both backends,
with the upsert conflict target changed to match:

- `migrations/postgres/0023_spend_ledger_tenant_key.sql` drops and re-adds the
  constraint. Idempotent.
- `core/src/db.rs` declares the new key for fresh databases and rebuilds existing
  ones. SQLite cannot alter a primary key, so it is create-copy-drop-rename inside
  `BEGIN IMMEDIATE`, guarded on the old key still being present so it runs once.
  If the rebuild fails the process panics rather than serving a tenant-blind
  ledger.
- `Repo::record_spend_with_period_tenant` upserts on the four-column target in
  both arms.

Verified: the reproducing scenario now passes on both backends, and a legacy
database booted against the new binary migrated in place — key changed, both rows
preserved with their own totals, indexes intact, no scratch table left behind, and
a second boot did not re-run the rebuild.

### What the fix could not repair

No row was deleted or merged. A total that had already absorbed another tenant's
spend stays with the tenant that owned it — over-counted rather than lost, which is
the conservative direction for a cap. The victim tenant begins accumulating its own
row correctly from the migration onward.

`spend_log` was tenant-correct throughout, so an operator who needs the historical
split can rebuild it:

    SELECT tenant_id, policy_id, agent_id, SUM(amount_usd)
    FROM spend_log GROUP BY tenant_id, policy_id, agent_id;

### One thing the fix exposed

With two hot rows instead of one, a 20-way concurrent burst on PostgreSQL now
loses some writes to SERIALIZABLE retry exhaustion — they return non-200 and the
client can retry. That is correct fail-closed behaviour, and the ledger stays
exactly consistent with `spend_log`. The scenario's assertion had demanded that all
ten of one tenant's writes land, which was only ever true on SQLite because
`BEGIN IMMEDIATE` serialises writers. It now asserts the property it actually
describes: neither tenant's total may contain the other's increments.
