# API reference

The canonical, machine-readable reference is the OpenAPI 3.1 spec at
[`schemas/openapi.yaml`](https://github.com/tejoker/SauronID/blob/main/schemas/openapi.yaml)
in the repo — generated from the core router and kept in lockstep with the
handlers. This page summarizes the auth model so you can read the spec
fluently.

## Base URL

Dev stack (`docker compose up`): `http://localhost:3001`.

## Authentication schemes

| Scheme | Header(s) | Used by | Notes |
|---|---|---|---|
| Admin key | `x-admin-key` | `/admin/*`, `/v1/*` | Static key. Full-write keys allow any method; read-only keys allow GET/HEAD only. Dev stack value: `dev-only-admin-key-not-for-production`. |
| Admin JWT | `Authorization: Bearer <jwt>` | `/admin/*`, `/v1/*` | HS256. Scopes: `admin:read` (GET/HEAD), `admin:write` (mutating), `admin:super`/`admin:full`/`*`. Optional `tnt` claim restricts tenants. |
| User session | `x-sauron-session` | `/agent/register`, `/agent/token`, `/user/*` | Tenant-bound HMAC session from `POST /user/auth` (dev) or `/user/auth/challenge` + `/user/auth/finish` (production Ed25519 flow). 1h TTL. |
| Call-sig v2 | see table below | signed agent routes | Ed25519 per-call signature with the agent's registered PoP key. |
| Tenancy | `x-sauron-tenant-id` | everything | Optional; falls back to the `default` tenant. Admin JWTs may carry `tnt` instead. |

## Call-sig v2 header set

Routes marked with the `x-sauron-call-*` parameters in the spec sit behind
the `require_call_signature` middleware (enforced in production via
`SAURON_REQUIRE_CALL_SIG`, advisory in development). The SDKs emit all of
these on every `agent.call(...)`:

| Header | Content |
|---|---|
| `x-sauron-agent-id` | Registered agent id; must match any `agent_id` in the body. |
| `x-sauron-call-ts` | Unix milliseconds; bounded clock skew. |
| `x-sauron-call-nonce` | Single-use random nonce (replay protection). |
| `x-sauron-call-sig` | Base64url Ed25519 signature over the canonical payload. |
| `x-sauron-call-audience` | Audience string, default `sauron-core`. |
| `x-sauron-protocol-version` | `2`. |
| `x-sauron-agent-config-digest` | The binding checksum the server stored at registration. |
| `x-sauron-tenant-id` | Tenant id; part of the signed payload. |

The signed payload is a length-prefixed encoding under domain
`sauron.call.v2` of: version, agent_id, tenant_id, audience, method,
target_uri, content_type, body_sha256, config_digest, timestamp_ms, nonce.

## Error envelope

4xx responses from the central error type use:

```json
{
  "error": {
    "code": "snake_case_machine_readable",
    "message": "human-readable explanation",
    "fix": "actionable remediation hint"
  }
}
```

`code` is stable and safe to match on. Some legacy handlers still return a
plain-text error string; both content types are documented on the shared
error responses in the spec. Notable statuses: `401` (missing/invalid
credentials), `403` (policy/intent denial), `409` (replay/conflict), `413`
(egress byte caps), `426` (call-sig protocol upgrade required), `429` (rate
limit).

## Surface map

| Area | Paths | Auth |
|---|---|---|
| Health and metrics | `/healthz`, `/readyz`, `/metrics` | none |
| User auth | `/user/auth` (dev), `/user/auth/challenge`, `/user/auth/finish` | none |
| Agent lifecycle | `/agent/register`, `/agent/token`, `/agent/{id}`, `/agent/{id}/checksum/update` | session (+ call-sig on some) |
| Actions and payments | `/agent/action/challenge`, `/agent/payment/authorize`, `/policy/authorize`, `/agent/action/receipt/verify` | call-sig v2 |
| Egress | `/agent/egress/log`, `/agent/egress/capability`, `/agent/egress/proxy` | call-sig v2 |
| Policy DSL | `/v1/policy/upload`, `/v1/policy/list`, `/v1/policy/{id}`, `/v1/policy/evaluate` | admin |
| Spend ledger | `/v1/agents/{id}/spend`, `/v1/agents/{id}/spend/log`, `/v1/agents/{id}/policy_binding` | admin |
| Admin and anchoring | `/admin/*` | admin |
| Dev only | `/dev/register_user`, `/dev/leash/demo`, ... | `SAURON_ENABLE_DEV_ENDPOINTS=1` |
