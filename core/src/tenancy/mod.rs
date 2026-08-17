//! Multi-tenancy primitives (Sprint 11).
//!
//! SauronID is single-operator multi-tenant: a single deployed core process
//! serves N logically isolated tenants. Every legacy request (no tenant
//! header, no JWT `tnt` claim) is treated as `tenant_id = "default"`, which
//! preserves the 412-test backwards-compatibility baseline.
//!
//! ## Resolution order
//!
//! 1. A validated admin JWT `tnt` claim is authoritative.
//! 2. The `x-sauron-tenant-id` header may restate that claim but cannot
//!    override it; without a JWT it is only a routing signal.
//! 3. Fallback to `DEFAULT_TENANT` when neither signal exists.
//!
//! The resolved `TenantId` is inserted into the request `Extensions` so
//! downstream handlers can extract it via `Extension<TenantId>`.
//!
//! ## What is scoped vs global
//!
//! See `docs/multi-tenancy.md` for the full matrix. Summary:
//!
//! - **SCOPED** (data-isolated per tenant): `agents`, `policies`,
//!   `agent_action_receipts`, `agent_egress_log`, `consent_log`,
//!   `agent_payment_authorizations`, `credential_codes`, `user_credentials`,
//!   `user_registrations`, `merkle_leaves`, `risk_rate_counters`,
//!   `spend_ledger`, `spend_log`, `bitcoin_merkle_anchors`,
//!   `solana_merkle_anchors`, `agent_action_anchors`.
//! - **KEEP_GLOBAL** (cross-tenant reuse / aggregate): `users`, `clients`,
//!   `bank_kyc_links`, `bank_attestation_nonces`, `agent_pop_challenges`,
//!   `agent_call_nonces`, `ajwt_used_jtis`, `agent_action_nonces`,
//!   `agent_vcs`, `device_tokens`, `api_usage`, `requests_log`,
//!   `company_data`, `agent_checksum_inputs`, `agent_checksum_audit`,
//!   `payment_smt_leaves`, `user_compliance_screening`,
//!   `lightning_l402_invoices`.
//!
//! Rationale for KEEP_GLOBAL on session-scoped tables (`ajwt_used_jtis`,
//! `agent_call_nonces`, `agent_pop_challenges`): their primary keys carry
//! enough entropy (UUID-like + agent_id derived from SHA-256) to avoid
//! cross-tenant collisions, and every consumer already qualifies by
//! `agent_id`. Tenant isolation is inherited transitively from the
//! tenant-scoped `agents` table.
//!
//! `users` / `clients` stay global by design: SauronID's identity registry
//! is a single OPRF-derived directory; multi-tenant access control lives on
//! the *registration* (`user_registrations`) and *consent* (`consent_log`)
//! tables, both of which are tenant-scoped.

use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

pub mod billing;

/// Header used to convey the tenant id on every legacy HTTP call.
pub const TENANT_HEADER: &str = "x-sauron-tenant-id";

/// Fallback tenant id when no header / JWT claim is supplied. Every legacy
/// request, every existing test, every dashboard demo call lands here, so
/// backwards compatibility is preserved by construction.
pub const DEFAULT_TENANT: &str = "default";

/// Max accepted tenant-id length. Matches the conservative bound on
/// other tenant-style strings (consent token, agent id, policy id) so we
/// can't be embarrassed by an unbounded `Vec<u8>` payload.
pub const MAX_TENANT_ID_LEN: usize = 64;

/// Resolved tenant for the current request. Attached to the axum
/// `Extensions` map by [`extract_tenant`] middleware; handlers extract via
/// `Extension<TenantId>`. The single-field tuple is intentional — we want
/// `.0` access semantics and `Debug`/`Clone` for free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantId(pub String);

impl TenantId {
    /// Build a `TenantId` from an explicit string. Used by tests + handlers
    /// that derive the tenant from non-HTTP sources (background jobs,
    /// scheduled GC, anchor batcher).
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The default tenant — every legacy / unscoped request.
    pub fn default_tenant() -> Self {
        Self(DEFAULT_TENANT.to_string())
    }

    /// Borrow the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::default_tenant()
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Validate a tenant-id string is well-formed: 1..=64 chars, ASCII
/// alphanumeric + `-` + `_`. Anything else is rejected at the middleware
/// boundary as `400 Bad Request` to keep injection / smuggling at bay.
/// Public so admin provisioning (`/admin/keys/issue`) validates tenant
/// allowlists with the exact same rule the middleware enforces.
pub fn valid_tenant_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TENANT_ID_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Optional admin-JWT claim used to override the tenant header. Only `tnt`
/// is interpreted by this module; other claims are validated elsewhere.
#[derive(Debug, Deserialize)]
struct TenantClaims {
    #[serde(default)]
    tnt: Option<String>,
    /// Validated by `jsonwebtoken` exp handling. Not used here directly.
    #[allow(dead_code)]
    #[serde(default)]
    exp: Option<i64>,
}

/// Pull the `tnt` claim from a Bearer JWT, if present and the operator has
/// configured `SAURON_ADMIN_JWT_HS256_SECRET`. Returns `None` on any
/// failure — we never reject a request just because the JWT isn't usable
/// for tenant resolution (the admin auth middleware does that check
/// separately).
fn tenant_from_jwt(headers: &HeaderMap, secret: &[u8]) -> Option<String> {
    let auth = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        return None;
    }
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_exp = true;
    let data = decode::<TenantClaims>(token, &DecodingKey::from_secret(secret), &v).ok()?;
    data.claims.tnt.filter(|s| valid_tenant_id(s))
}

/// Outcome of reconciling an authenticated JWT tenant claim with a request
/// header. The JWT claim is AUTHENTICATED, so it is authoritative — a plain
/// header may restate it but must never override it.
#[derive(Debug, PartialEq)]
pub enum TenantResolution {
    /// Use this tenant id.
    Use(String),
    /// No signal — use the default tenant.
    Default,
    /// Header contradicts the authenticated tenant claim → reject the request.
    Conflict,
}

/// Pure reconciliation (unit-tested). Precedence: authenticated JWT tenant wins;
/// a header may only match it, never change it; absent JWT, the header is used;
/// absent both, the default.
pub fn resolve_tenant(
    jwt_tenant: Option<String>,
    header_tenant: Option<String>,
) -> TenantResolution {
    match (jwt_tenant, header_tenant) {
        (Some(jwt), Some(hdr)) if jwt != hdr => TenantResolution::Conflict,
        (Some(jwt), _) => TenantResolution::Use(jwt),
        (None, Some(hdr)) => TenantResolution::Use(hdr),
        (None, None) => TenantResolution::Default,
    }
}

/// Resolve the tenant id for an incoming request and stash it in
/// `request.extensions_mut()` so handlers can extract it with
/// `Extension<TenantId>`. A malformed `x-sauron-tenant-id` header is a
/// `400`; a header that contradicts an authenticated JWT tenant claim is a
/// `403` — the header can never override authenticated tenant identity.
pub async fn extract_tenant(mut request: Request, next: Next) -> Response {
    let header_tenant = match request
        .headers()
        .get(TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(raw) if !valid_tenant_id(&raw) => {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "invalid {TENANT_HEADER}: must match [A-Za-z0-9_-]{{1,{MAX_TENANT_ID_LEN}}}"
                ),
            )
                .into_response();
        }
        other => other,
    };

    // Authenticated tenant from a validated admin JWT (only if JWT auth is
    // configured). Authoritative over any header.
    let jwt_tenant = std::env::var("SAURON_ADMIN_JWT_HS256_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|secret| tenant_from_jwt(request.headers(), secret.as_bytes()));

    match resolve_tenant(jwt_tenant, header_tenant) {
        TenantResolution::Use(t) => {
            request.extensions_mut().insert(TenantId::new(t));
        }
        TenantResolution::Default => {
            request.extensions_mut().insert(TenantId::default_tenant());
        }
        TenantResolution::Conflict => {
            return (
                StatusCode::FORBIDDEN,
                format!("{TENANT_HEADER} does not match the authenticated tenant claim"),
            )
                .into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_default_is_default_const() {
        let t = TenantId::default_tenant();
        assert_eq!(t.as_str(), DEFAULT_TENANT);
        assert_eq!(t.0, "default");
    }

    #[test]
    fn authenticated_jwt_tenant_wins_over_header() {
        let j = |s: &str| Some(s.to_string());
        // Header cannot override an authenticated JWT tenant claim.
        assert_eq!(
            resolve_tenant(j("acme"), j("globex")),
            TenantResolution::Conflict
        );
        // Header may restate it.
        assert_eq!(
            resolve_tenant(j("acme"), j("acme")),
            TenantResolution::Use("acme".into())
        );
        // JWT alone is authoritative.
        assert_eq!(
            resolve_tenant(j("acme"), None),
            TenantResolution::Use("acme".into())
        );
        // No JWT → header is the (unauthenticated) signal.
        assert_eq!(
            resolve_tenant(None, j("globex")),
            TenantResolution::Use("globex".into())
        );
        // Neither → default.
        assert_eq!(resolve_tenant(None, None), TenantResolution::Default);
    }

    #[test]
    fn tenant_id_new_roundtrips() {
        let t = TenantId::new("acme_inc");
        assert_eq!(t.as_str(), "acme_inc");
        assert_eq!(format!("{t}"), "acme_inc");
    }

    #[test]
    fn valid_tenant_id_accepts_alnum_dash_underscore() {
        assert!(valid_tenant_id("default"));
        assert!(valid_tenant_id("acme-corp_42"));
        assert!(valid_tenant_id("a"));
        assert!(valid_tenant_id("0"));
    }

    #[test]
    fn valid_tenant_id_rejects_special_chars_and_empty() {
        assert!(!valid_tenant_id(""));
        assert!(!valid_tenant_id("../etc/passwd"));
        assert!(!valid_tenant_id("acme corp"));
        assert!(!valid_tenant_id("acme.corp"));
        assert!(!valid_tenant_id("tnt!"));
    }

    #[test]
    fn valid_tenant_id_enforces_length_cap() {
        let max = "a".repeat(MAX_TENANT_ID_LEN);
        assert!(valid_tenant_id(&max));
        let over = "a".repeat(MAX_TENANT_ID_LEN + 1);
        assert!(!valid_tenant_id(&over));
    }
}
