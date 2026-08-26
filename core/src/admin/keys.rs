//! Runtime issuance of scoped admin JWTs.

use super::*;
use axum::{http::StatusCode, response::Json};
use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

// ─────────────────────────────────────────────────────
//  POST /admin/keys/issue — runtime issuance of scoped admin JWTs
//
//  Static admin keys (`SAURON_ADMIN_KEY{,S}`) are loaded from env at boot and
//  cannot be created at runtime — they remain the break-glass path. Self-serve
//  provisioning instead mints tenant-locked HS256 admin JWTs signed with the
//  SAME secret `auth_middleware` already verifies
//  (`SAURON_ADMIN_JWT_HS256_SECRET`). The token is returned once and never
//  stored server-side; revocation = rotate the secret.
// ─────────────────────────────────────────────────────

/// TTL clamp for issued admin JWTs: 1 hour .. 90 days.
pub const MIN_ISSUED_KEY_TTL_SECS: i64 = 3600;
pub const MAX_ISSUED_KEY_TTL_SECS: i64 = 90 * 86_400;
pub const DEFAULT_ISSUED_KEY_TTL_SECS: i64 = 86_400;

#[derive(Deserialize)]
pub struct IssueAdminKeyRequest {
    /// Subset of {"admin:read", "admin:write"}. Super scopes are refused —
    /// runtime issuance must never escalate past the requester's own grant.
    pub scopes: Vec<String>,
    /// Tenant allowlist baked into the token (`tnt` claim). Non-empty:
    /// issued tokens are always tenant-locked.
    pub tenants: Vec<String>,
    /// Requested lifetime; clamped to [MIN, MAX].
    pub ttl_secs: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct IssueAdminKeyResponse {
    /// Shown once. Not persisted server-side.
    pub token: String,
    pub scopes: Vec<String>,
    pub tenants: Vec<String>,
    pub expires_at: i64,
}

/// Claims mirror [`AdminJwtClaims`] so `auth_middleware` verifies the token
/// unchanged, and `tenancy::extract_tenant` treats it like any admin JWT.
#[derive(Serialize)]
struct IssuedAdminClaims<'a> {
    scp: &'a [String],
    tnt: &'a [String],
    exp: i64,
}

/// Pure issuance logic (unit-tested without axum/OnceLock plumbing).
pub(crate) fn issue_admin_jwt(
    secret: Option<&[u8]>,
    requester_cross_tenant: bool,
    payload: &IssueAdminKeyRequest,
    now: i64,
) -> Result<IssueAdminKeyResponse, AppError> {
    // Only a super principal may mint admin credentials. `AdminAuthz` exposes
    // a single `cross_tenant` bool to handlers (true for `admin:super` JWTs,
    // and for static keys when SAURON_ADMIN_CROSS_TENANT=1) — that bool IS the
    // super signal available here, so it is what we require. Fail-closed.
    if !requester_cross_tenant {
        return Err(AppError::Unauthorized(
            "issuing admin keys requires a cross-tenant super-admin principal".into(),
        ));
    }
    let secret = secret.ok_or_else(|| {
        AppError::with_hint(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin_jwt_secret_unset",
            "runtime key issuance is disabled — no admin JWT secret is configured",
            "set SAURON_ADMIN_JWT_HS256_SECRET to enable runtime key issuance",
        )
    })?;

    if payload.scopes.is_empty() {
        return Err(AppError::BadRequest(
            "scopes must be non-empty (allowed: admin:read, admin:write)".into(),
        ));
    }
    let mut scopes: Vec<String> = Vec::new();
    for raw in &payload.scopes {
        let s = raw.trim().to_ascii_lowercase();
        match s.as_str() {
            "admin:read" | "admin:write" => {
                if !scopes.contains(&s) {
                    scopes.push(s);
                }
            }
            "admin:super" | "admin:full" | "*" => {
                return Err(AppError::BadRequest(format!(
                    "scope escalation refused: '{s}' cannot be issued at runtime; static env admin keys remain the break-glass path"
                )));
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "unknown scope '{other}' (allowed: admin:read, admin:write)"
                )));
            }
        }
    }

    // Issued tokens are ALWAYS tenant-locked. An empty `tnt` claim would fall
    // back to the legacy global-flag behaviour in `auth_middleware` — exactly
    // the cross-tenant reach this endpoint must never hand out.
    if payload.tenants.is_empty() {
        return Err(AppError::BadRequest(
            "tenants must be non-empty — issued keys are always tenant-locked".into(),
        ));
    }
    let mut tenants: Vec<String> = Vec::new();
    for raw in &payload.tenants {
        let t = raw.trim().to_string();
        if !crate::tenancy::valid_tenant_id(&t) {
            return Err(AppError::BadRequest(format!(
                "invalid tenant id '{t}': must match [A-Za-z0-9_-]{{1,64}}"
            )));
        }
        if !tenants.contains(&t) {
            tenants.push(t);
        }
    }

    let ttl = payload
        .ttl_secs
        .unwrap_or(DEFAULT_ISSUED_KEY_TTL_SECS)
        .clamp(MIN_ISSUED_KEY_TTL_SECS, MAX_ISSUED_KEY_TTL_SECS);
    let expires_at = now + ttl;

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(Algorithm::HS256),
        &IssuedAdminClaims {
            scp: &scopes,
            tnt: &tenants,
            exp: expires_at,
        },
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .map_err(|e| AppError::Internal(format!("jwt encode: {e}")))?;

    Ok(IssueAdminKeyResponse {
        token,
        scopes,
        tenants,
        expires_at,
    })
}

/// POST /admin/keys/issue — mint a scoped, tenant-locked admin JWT.
///
/// Super-admin only (see [`issue_admin_jwt`] for why the check is the
/// `cross_tenant` bool). 503 with a teaching envelope when
/// `SAURON_ADMIN_JWT_HS256_SECRET` is unset. Emits an `AdminKeyRotated`
/// audit event carrying a token fingerprint (never the token).
pub async fn issue_admin_key(
    authz: Option<axum::Extension<AdminAuthz>>,
    Json(payload): Json<IssueAdminKeyRequest>,
) -> Result<Json<IssueAdminKeyResponse>, AppError> {
    let cross = authz
        .map(|axum::Extension(a)| a.cross_tenant)
        .unwrap_or_else(cross_tenant_admin);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let resp = issue_admin_jwt(
        admin_cfg().jwt_hs256_secret.as_deref(),
        cross,
        &payload,
        now,
    )?;
    // Same audit family as an env-key rotation: first 12 hex chars of
    // SHA-256 over the issued token — correlatable, never the secret.
    use sha2::Digest;
    let fp_full = hex::encode(sha2::Sha256::digest(resp.token.as_bytes()));
    crate::middleware::audit_log::record(
        crate::middleware::audit_log::AuditEvent::AdminKeyRotated {
            key_fingerprint: fp_full[..12].to_string(),
        },
    );
    tracing::info!(
        target: "sauron::admin",
        scopes = ?resp.scopes,
        tenants = ?resp.tenants,
        expires_at = resp.expires_at,
        "scoped admin JWT issued"
    );
    Ok(Json(resp))
}

#[derive(Serialize, Default)]
pub struct AdminAnchorStatus {
    /// Configured provider: "opentimestamps", "mock", or "disabled". Callers MUST
    /// surface this: a mock anchor writes a synthetic txid that is not on any
    /// chain, and a UI that says "committed to Bitcoin" without it is lying.
    pub bitcoin_provider: String,
    pub bitcoin_network: String,
    /// Anchors recorded with `no_real_money = 1` — i.e. written by the mock
    /// provider and verifiable nowhere.
    pub bitcoin_synthetic: i64,
    pub bitcoin_total: i64,
    pub bitcoin_pending_upgrade: i64,
    pub bitcoin_upgraded: i64,
    pub solana_total: i64,
    pub solana_unconfirmed: i64,
    pub solana_confirmed: i64,
    pub agent_action_batches: i64,
    pub last_batch_at: i64,
    pub last_batch_n_actions: i64,
}
