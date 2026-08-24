# Multi-tenancy

SauronID is a **single-operator, multi-tenant** control plane: one process
serves N logically isolated tenants. This document is the canonical reference
for *what is isolated*, *how the tenant id flows*, and *what is intentionally
NOT isolated* (and why).

## Model

A **tenant** is an opaque string id (`[A-Za-z0-9_-]{1,64}`). Examples:
`default`, `acme_corp`, `bank-eu-1`. There is no separate tenant CRUD
surface in v0.2.0 — operators provision tenants out-of-band by:

1. choosing an id;
2. distributing the id to downstream SDK callers (via header config or JWT
   `tnt` claim); and
3. (optionally) calling `TenantRegistry::ensure_tenant_exists()` so admin
   tooling can list known tenants.

The reserved tenant `default` exists at all times and is the **back-compat
sink**: every request without either routing signal lands here. Protected
operations still require their normal authentication and authorization; the
fallback does not grant access.

## How the tenant id flows

`core::tenancy::extract_tenant` is an axum middleware layered globally on
every `/v1/*`, `/admin/*`, `/agent/*` route. Resolution order:

1. **Validated admin JWT claim** `tnt` — authoritative when the request carries
   a `Bearer <jwt>` and `SAURON_ADMIN_JWT_HS256_SECRET` is configured.
2. **HTTP header** `x-sauron-tenant-id: <id>` — may restate the authenticated
   claim, but a conflict returns `403`. Without a JWT it is a routing signal,
   not authentication; protected handlers additionally verify a tenant-bound
   session, agent call signature, partner signature, or scoped admin grant.
3. **Fallback to `default`** when neither signal exists.

The resolved `TenantId` is inserted into request `Extensions`; handlers
extract it via `Extension<TenantId>`.

### Client SDKs

Both SDKs accept an optional `tenant_id` on construction. When set, the
SDK adds `x-sauron-tenant-id: <id>` to every outbound HTTP call:

- TypeScript: `new PolicyCache({ coreUrl, tenantId: "acme_corp" })`
- Python: `PolicyCache(core_url=..., tenant_id="acme_corp")`

This is purely additive — existing call sites without `tenant_id` keep
working unchanged on the `default` tenant.

## Data isolation matrix

### SCOPED (tenant-isolated)

Every row carries `tenant_id TEXT NOT NULL DEFAULT 'default'`; reads add
`WHERE tenant_id = ?` and inserts bind the resolved id.

| Table                              | Notes                                                                     |
|------------------------------------|---------------------------------------------------------------------------|
| `agents`                           | Tenant-scoped registry; `agent_id` is globally unique in v0.2.0.          |
| `policies`                         | Per-tenant policy DSL. Same `policy_id` may appear in multiple tenants.   |
| `agent_action_receipts`            | Per-tenant action receipts. Anchored under the tenant's batch.            |
| `agent_action_anchors`             | Per-tenant batch root. (See §"Anchor batches" for caveats.)               |
| `bitcoin_merkle_anchors`           | Per-tenant Bitcoin OP_RETURN anchors.                                     |
| `solana_merkle_anchors`            | Per-tenant Solana memo anchors.                                           |
| `agent_egress_log`                 | Per-tenant outbound-call log.                                             |
| `consent_log`                      | Per-tenant GDPR consent ledger.                                           |
| `agent_payment_authorizations`     | Per-tenant payment auth envelopes.                                        |
| `credential_codes`                 | Per-tenant ZKP pre-auth codes.                                            |
| `user_credentials`                 | Per-tenant cached BabyJubJub credentials.                                 |
| `user_registrations`               | Per-tenant user↔client linkage.                                           |
| `merkle_leaves`                    | Per-tenant commitment ledger.                                             |
| `risk_rate_counters`               | Per-tenant rate-limit budget. **Mandatory** — otherwise tenant A's        |
|                                    | traffic eats tenant B's quota.                                            |
| `spend_ledger`                     | Per-tenant authoritative spend total. Closes redteam A3b.                 |
| `spend_log`                        | Per-tenant append-only spend log.                                         |

### KEEP_GLOBAL (cross-tenant by design)

These tables stay global because:

- their primary keys carry enough entropy to avoid cross-tenant collision;
- their consumers always qualify by a tenant-scoped foreign key; OR
- they represent operator-level state that must aggregate across tenants.

| Table                          | Reason                                                                |
|--------------------------------|-----------------------------------------------------------------------|
| `users`                        | Single OPRF-derived identity registry; access control lives on        |
|                                | `user_registrations` + `consent_log` (both scoped).                   |
| `clients`                      | Operator-level partner registry.                                      |
| `bank_kyc_links`               | Bank↔user mapping, operator-level integration.                        |
| `bank_attestation_nonces`      | Webhook replay protection, primary-keyed by `(provider_id, nonce)`.   |
| `agent_pop_challenges`         | One-time challenges keyed by random id and globally unique agent id.  |
| `agent_call_nonces`            | Nonces keyed by globally unique agent id and nonce.                   |
| `ajwt_used_jtis`               | A-JWT jti replay protection, opaque jti (UUID); collision-free.       |
| `agent_action_nonces`          | Action-leash nonces, opaque PK.                                       |
| `agent_vcs`                    | Self-sovereign agent VC store, primary-keyed by `agent_id`.           |
| `device_tokens`                | Silent re-auth tokens, hashed PK.                                     |
| `api_usage`                    | Operator-level billing meter (aggregated separately for now).         |
| `requests_log`                 | Anonymous request log, no tenant linkage.                             |
| `company_data`                 | Pre-computed analytics, no tenant linkage.                            |
| `agent_checksum_inputs`        | Keyed by `agent_id`; tenant scope is inherited via the `agents` row.  |
| `agent_checksum_audit`         | Same — tenant scope inherited via `agent_id`.                         |
| `payment_smt_leaves`           | Orphan from S0 (data unused); leave alone.                            |
| `user_compliance_screening`    | Server-only overlay, operator-level (sanctions/PEP).                  |
| `lightning_l402_invoices`      | Operator-level Lightning macaroon store.                              |

## Admin endpoints — operator-global vs tenant-scoped

Admin data endpoints are tenant-scoped by default. Scoped admin JWTs can carry
a `tnt` tenant allowlist. Cross-tenant aggregation requires `admin:super` or
the explicit `SAURON_ADMIN_CROSS_TENANT=1` operator setting. Current split:

- **GLOBAL** (cross-tenant super-admin only): `/admin/stats`, `/admin/users`,
  `/admin/health/detailed`, `/admin/anchor/status`,
  `/admin/anchor/batches`, `/admin/anchor/agent-actions/*`,
  `/admin/clients`, `/admin/requests`.
- **TENANT-SCOPED**: `/admin/agents`,
  `/admin/per_agent_metrics`, `/admin/agent_actions/recent`,
  `/admin/egress/recent`, `/admin/checksum/audit/:agent_id`.

The tenant middleware resolves `TenantId`; these handlers consume it in their
SQL scope. Deployment-global tables refuse tenant-locked admins instead of
silently returning global rows.

## Deliberate operator-level sharing

1. **`users` is shared across tenants.** Two tenants can both reference
   the same `key_image_hex`. Access control is enforced on the
   tenant-scoped *registrations* (which client + which tenant), not on
   the identity row itself. A tenant has NO way to enumerate users that
   only belong to other tenants — its registration list filters by
   `tenant_id`.
2. **Background tasks operate operator-global.** The anchor batcher, GC,
   OTS upgrader, and Solana confirmer iterate across all tenants in one
   pass. They emit receipts/anchors per-tenant where applicable (writing
   the correct `tenant_id`) but DO NOT spawn per-tenant tasks.

The cross-tenant DP cohort publishing that used to head this list was archived
in 2026-08 with the rest of the cohort-stats surface:
[`archive/removed-2026-08/cohort-stats-compliance/`](../../archive/removed-2026-08/cohort-stats-compliance/).

## Cross-tenant test surface

`core/tests/multi_tenancy.rs` and the repository cross-tenant tests exercise
the isolation invariants we guarantee, including agents, policies, spend,
audit records, consent tokens, payment authorizations, credential codes,
user credentials, admin views, and authenticated tenant resolution.

Cross-tenant object lookups return the same not-found shape as nonexistent
objects so they do not reveal another tenant's object existence.

## Environment variables

| Variable                          | Purpose                                                          |
|-----------------------------------|------------------------------------------------------------------|
| `SAURON_ADMIN_JWT_HS256_SECRET`   | Enables `tnt`-claim resolution on Bearer JWTs.                   |
| `SAURON_DEFAULT_TENANT_ID`        | Reserved; `default` remains the v0.2.0 compatibility tenant.     |

## Operator playbook

### Creating a new tenant

1. Pick an id (e.g. `bank-eu-1`).
2. Register it through operator provisioning with
   `TenantRegistry::ensure_tenant_exists("bank-eu-1")`. The v0.2.0 registry
   is process-local, so repeat provisioning after restart.
3. Distribute the id to downstream SDK consumers via configuration.
4. Mint scoped admin grants/JWTs with `tnt: "bank-eu-1"`, and configure SDKs
   to send the same tenant id. The header alone is never an authorization
   credential.

### Migrating an existing single-tenant deployment

No action required. Every legacy row backfills to `default` via the
`ALTER TABLE … ADD COLUMN tenant_id … DEFAULT 'default'` migration, and
every legacy request (no header) continues to land on `default`.

### Removing a tenant

Not supported in v0.2.0. Do not manually delete selected rows: partial deletion
can invalidate audit and anchor evidence. Tenant erasure requires an
operator-reviewed migration, a retained-evidence policy, a verified backup,
and a post-operation isolation and integrity check.
