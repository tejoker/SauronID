//! Admin authentication: multi-key rotation, optional HS256 JWT, and the
//! `auth_middleware` every /admin route goes through.

use super::*;
use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

use crate::runtime_mode::is_development_runtime;

// ─────────────────────────────────────────────────────
//  Admin authentication (multi-key rotation + optional HS256 JWT)
// ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AdminAuthConfig {
    /// Full-access static keys (`x-admin-key`).
    pub full_write_keys: Vec<Vec<u8>>,
    /// Read-only static keys — **GET/HEAD only**.
    pub read_only_keys: Vec<Vec<u8>>,
    /// When set, `Authorization: Bearer <jwt>` is accepted. JWT must include `scp`
    /// with `admin:read` (GET/HEAD), `admin:write` or `admin:full` (mutating), or `admin:super` / `*`.
    pub jwt_hs256_secret: Option<Vec<u8>>,
}

static ADMIN_AUTH: OnceLock<AdminAuthConfig> = OnceLock::new();

/// Call once at process startup after env is loaded.
pub fn init_admin_auth() -> Result<(), String> {
    let cfg = build_admin_auth_config()?;
    ADMIN_AUTH
        .set(cfg)
        .map_err(|_| "admin auth: init_admin_auth called twice".to_string())
}

pub(crate) fn admin_cfg() -> &'static AdminAuthConfig {
    ADMIN_AUTH
        .get()
        .expect("admin auth not initialized (call init_admin_auth at startup)")
}

fn build_admin_auth_config() -> Result<AdminAuthConfig, String> {
    let mut full_write_keys: Vec<Vec<u8>> = Vec::new();

    // Primary admin key: route through `secret_provider::resolve_secret` so a
    // `SAURON_ADMIN_KEY_WRAPPED` Vault Transit ciphertext is honored when
    // `SAURON_VAULT_TRANSIT_ENABLED=1`. Falls back to plaintext env otherwise.
    match crate::secret_provider::resolve_secret("SAURON_ADMIN_KEY") {
        Ok(b) if !b.is_empty() => full_write_keys.push(b),
        Ok(_) => {}
        Err(crate::secret_provider::ResolveError::NotFound(_)) => {}
        Err(e) => {
            return Err(format!("admin auth: SAURON_ADMIN_KEY resolver error: {e}"));
        }
    }

    // Multi-key list. Each comma-separated entry is treated as either a plain
    // key OR a `vault:v...` ciphertext when Vault Transit is enabled — the
    // latter is decrypted in place. Plain entries pass through unchanged.
    if let Ok(list) = std::env::var("SAURON_ADMIN_KEYS") {
        let vault_enabled = std::env::var("SAURON_VAULT_TRANSIT_ENABLED")
            .map(|v| {
                let lo = v.to_ascii_lowercase();
                v == "1" || lo == "true" || lo == "yes"
            })
            .unwrap_or(false);
        for (i, part) in list.split(',').enumerate() {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            if vault_enabled && t.starts_with("vault:v") {
                let client = match crate::secret_provider::VaultTransitClient::from_env() {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        return Err(format!(
                            "admin auth: SAURON_ADMIN_KEYS entry #{i} is a Vault ciphertext but Vault Transit is not enabled"
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "admin auth: cannot build Vault client for SAURON_ADMIN_KEYS entry #{i}: {e}"
                        ));
                    }
                };
                match client.decrypt_blocking(t) {
                    Ok(pt) => full_write_keys.push(pt),
                    Err(e) => {
                        return Err(format!(
                            "admin auth: failed to decrypt SAURON_ADMIN_KEYS entry #{i}: {e}"
                        ));
                    }
                }
            } else {
                full_write_keys.push(t.as_bytes().to_vec());
            }
        }
    }

    if full_write_keys.is_empty() {
        if let Some(b) = crate::state::development_fallback_admin_key_material() {
            tracing::warn!(
                target: "sauron::admin",
                "SAURON_ADMIN_KEY / SAURON_ADMIN_KEYS unset — using derived development admin key"
            );
            full_write_keys.push(b);
        }
    }

    let mut read_only_keys: Vec<Vec<u8>> = Vec::new();
    if let Ok(list) = std::env::var("SAURON_ADMIN_READ_ONLY_KEYS") {
        for part in list.split(',') {
            let t = part.trim();
            if !t.is_empty() {
                read_only_keys.push(t.as_bytes().to_vec());
            }
        }
    }

    // Route the admin JWT secret through the same secret resolver as the
    // other root secrets so a Vault/KMS-wrapped `..._WRAPPED` ciphertext is
    // decrypted at startup instead of forcing the highest-value admin secret
    // to sit in plaintext env. Falls back to plain `SAURON_ADMIN_JWT_HS256_SECRET`
    // when no backend is enabled. A configured-but-unreachable backend is
    // fatal (fail-closed), matching the SAURON_ADMIN_KEYS handling above.
    let jwt_hs256_secret =
        match crate::secret_provider::try_resolve_secret("SAURON_ADMIN_JWT_HS256_SECRET") {
            Ok(Some(bytes)) => {
                // Trim ASCII whitespace at the ends (parity with the previous
                // env-only path, which trimmed the string). Works on raw bytes so
                // a binary Vault plaintext is left intact in the middle.
                let start = bytes
                    .iter()
                    .position(|b| !b.is_ascii_whitespace())
                    .unwrap_or(bytes.len());
                let end = bytes
                    .iter()
                    .rposition(|b| !b.is_ascii_whitespace())
                    .map(|i| i + 1)
                    .unwrap_or(start);
                let trimmed = bytes[start..end].to_vec();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Ok(None) => None,
            Err(e) => {
                return Err(format!(
                    "admin auth: failed to resolve SAURON_ADMIN_JWT_HS256_SECRET: {e}"
                ))
            }
        };

    if !is_development_runtime() {
        if full_write_keys.is_empty() {
            return Err(
                "production requires SAURON_ADMIN_KEY and/or SAURON_ADMIN_KEYS (non-empty)".into(),
            );
        }
        for k in &full_write_keys {
            if k.len() < 32 {
                return Err("production: each full admin key must be >= 32 bytes".into());
            }
        }
        for k in &read_only_keys {
            if k.len() < 32 {
                return Err("production: each read-only admin key must be >= 32 bytes".into());
            }
        }
        if let Some(ref j) = jwt_hs256_secret {
            if j.len() < 32 {
                return Err("production: SAURON_ADMIN_JWT_HS256_SECRET must be >= 32 bytes".into());
            }
        }
    } else if full_write_keys.is_empty() && read_only_keys.is_empty() {
        return Err("development admin auth misconfigured (no keys)".into());
    } else {
        // Warn on the well-known defaults that ship in docs/seed scripts.
        // NOTE: the legacy seed token is included intentionally so deployments
        // that copied it from old docs trip this warning. Do not remove.
        const KNOWN_WEAK: &[&str] = &[
            "super_secret_hackathon_key",
            "changeme",
            "secret",
            "admin",
            "password",
        ];
        for k in &full_write_keys {
            if let Ok(s) = std::str::from_utf8(k) {
                if KNOWN_WEAK.contains(&s) {
                    tracing::warn!(
                        target: "sauron::admin",
                        key = %s,
                        "admin key is a known-weak default — set SAURON_ADMIN_KEY to a strong random secret before exposing this service"
                    );
                }
            }
        }
    }

    Ok(AdminAuthConfig {
        full_write_keys,
        read_only_keys,
        jwt_hs256_secret,
    })
}

#[derive(Debug, Deserialize)]
struct AdminJwtClaims {
    #[serde(default)]
    scp: Vec<String>,
    /// Optional tenant allowlist. When non-empty (and the token is not
    /// `admin:super`), this operator may ONLY act on these tenants — the core
    /// enforces it regardless of the global `SAURON_ADMIN_CROSS_TENANT` flag.
    /// Empty ⇒ legacy behaviour (global flag decides cross-tenant scope).
    #[serde(default)]
    tnt: Vec<String>,
    /// Handled by `jsonwebtoken` expiry validation.
    #[allow(dead_code)]
    exp: i64,
}

/// Per-request admin authorization context, inserted by [`auth_middleware`] and
/// consumed by [`admin_scope`]. Decides whether the principal may query across
/// all tenants (`*`) or is pinned to the request's tenant.
#[derive(Clone, Debug)]
pub struct AdminAuthz {
    pub cross_tenant: bool,
}

pub(crate) fn verify_admin_jwt(token: &str, secret: &[u8]) -> Option<(Vec<String>, Vec<String>)> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let data =
        decode::<AdminJwtClaims>(token, &DecodingKey::from_secret(secret), &validation).ok()?;
    Some((data.claims.scp, data.claims.tnt))
}

pub(crate) fn scopes_are_super(scopes: &[String]) -> bool {
    scopes
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .any(|s| s == "admin:super" || s == "*" || s == "admin:full")
}

/// Tenant on the incoming request (same header the tenancy middleware reads).
fn request_tenant(request: &Request) -> String {
    request
        .headers()
        .get(crate::tenancy::TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::tenancy::DEFAULT_TENANT.to_string())
}

fn jwt_auth_ok(scopes: &[String], method: &Method) -> bool {
    let scopes_l: Vec<String> = scopes.iter().map(|s| s.to_ascii_lowercase()).collect();
    if scopes_l
        .iter()
        .any(|s| s == "admin:super" || s == "*" || s == "admin:full")
    {
        return true;
    }
    let read_ok = method == Method::GET || method == Method::HEAD;
    if read_ok {
        scopes_l
            .iter()
            .any(|s| s == "admin:read" || s == "admin:write")
    } else {
        scopes_l.iter().any(|s| s == "admin:write")
    }
}

fn key_matches_any(candidate: &[u8], keys: &[Vec<u8>]) -> bool {
    keys.iter().any(|k| {
        if k.len() != candidate.len() {
            return false;
        }
        k.as_slice().ct_eq(candidate).into()
    })
}

fn extract_bearer_token(request: &Request) -> Option<String> {
    let h = request.headers().get(AUTHORIZATION)?.to_str().ok()?.trim();
    let rest = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?
        .trim();
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

fn extract_x_admin_key_bytes(request: &Request) -> Vec<u8> {
    request
        .headers()
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .as_bytes()
        .to_vec()
}

/// Principal kinds, for the audit trail. Never carries key material.
const PRINCIPAL_JWT: &str = "admin_jwt";
const PRINCIPAL_STATIC: &str = "static_key";

/// A static admin key is operator-global by construction: it carries no scopes
/// and no tenant allowlist, so the only thing deciding which tenant it reads is
/// the caller's own `x-sauron-tenant-id` header. That is fine for a single-tenant
/// or single-operator deployment and is NOT fine once the key is handed to
/// someone who administers one tenant among several — they read every other
/// tenant by editing a header.
///
/// So in production a static key may only target a non-default tenant when the
/// operator has explicitly declared the key operator-global with
/// `SAURON_ADMIN_CROSS_TENANT=1`. Without that declaration the request is a 403
/// and the operator is pointed at `/admin/keys/issue`, which mints a
/// tenant-locked JWT — the credential that actually carries a scope.
///
/// Development is unaffected: the seeded demo drives several tenants through one
/// key and blocking that would break every local walkthrough.
pub(crate) fn static_key_may_target(tenant: &str) -> bool {
    tenant == crate::tenancy::DEFAULT_TENANT
        || cross_tenant_admin()
        || crate::runtime_mode::is_development_runtime()
}

pub async fn auth_middleware(
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let cfg = admin_cfg();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let tenant = request_tenant(&request);

    // Run the handler, then record that an authenticated admin request
    // completed. Emitted here rather than in `audit_log_middleware` because
    // this is the only layer that knows HOW the caller authenticated and
    // whether it was allowed beyond its own tenant.
    async fn run_audited(
        request: Request,
        next: Next,
        principal: &'static str,
        cross_tenant: bool,
        tenant_id: String,
        method: Method,
        path: String,
    ) -> axum::response::Response {
        let response = next.run(request).await;
        crate::middleware::audit_log::record(
            crate::middleware::audit_log::AuditEvent::AdminAction {
                tenant_id,
                principal: principal.to_string(),
                cross_tenant,
                method: method.to_string(),
                path,
                status: response.status().as_u16(),
            },
        );
        response
    }

    // 1. Admin JWT (Bearer) — carries scopes (read/write/super) + optional
    //    tenant allowlist for per-operator least-privilege.
    if let Some(token) = extract_bearer_token(&request) {
        if let Some(ref sec) = cfg.jwt_hs256_secret {
            if let Some((scopes, tnt)) = verify_admin_jwt(&token, sec) {
                if !jwt_auth_ok(&scopes, &method) {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                let is_super = scopes_are_super(&scopes);
                let cross_tenant = if !is_super && !tnt.is_empty() {
                    // Tenant-locked operator: may act ONLY on an allowlisted
                    // tenant, regardless of the global cross-tenant flag.
                    if !tnt.iter().any(|t| t == &tenant) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    false
                } else {
                    // super ⇒ cross-tenant; otherwise the legacy global flag.
                    is_super || cross_tenant_admin()
                };
                request.extensions_mut().insert(AdminAuthz { cross_tenant });
                return Ok(run_audited(
                    request,
                    next,
                    PRINCIPAL_JWT,
                    cross_tenant,
                    tenant,
                    method,
                    path,
                )
                .await);
            }
        }
        // A Bearer token that is not a valid admin JWT is accepted as a static
        // admin key (constant-time compare, same rules as x-admin-key below).
        // The SDK enforcement layers send the static key as
        // `Authorization: Bearer <key>`; same secret, alternate transport.
        let bearer_bytes = token.trim().as_bytes().to_vec();
        if key_matches_any(&bearer_bytes, &cfg.full_write_keys)
            || key_matches_any(&bearer_bytes, &cfg.read_only_keys)
        {
            let read_only = !key_matches_any(&bearer_bytes, &cfg.full_write_keys);
            if read_only && method != Method::GET && method != Method::HEAD {
                return Err(StatusCode::FORBIDDEN);
            }
            if !static_key_may_target(&tenant) {
                return Err(StatusCode::FORBIDDEN);
            }
            let cross_tenant = cross_tenant_admin();
            request.extensions_mut().insert(AdminAuthz { cross_tenant });
            return Ok(run_audited(
                request,
                next,
                PRINCIPAL_STATIC,
                cross_tenant,
                tenant,
                method,
                path,
            )
            .await);
        }
        // Not a JWT, not a known static key: fall through to x-admin-key.
    }

    // 2. Static x-admin-key. Legacy scope: the global SAURON_ADMIN_CROSS_TENANT
    //    flag decides cross-tenant reach (per-operator scoping uses JWTs above).
    let key_bytes = extract_x_admin_key_bytes(&request);
    if key_bytes.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let full = key_matches_any(&key_bytes, &cfg.full_write_keys);
    let read = key_matches_any(&key_bytes, &cfg.read_only_keys);
    if !full && !read {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !full && method != Method::GET && method != Method::HEAD {
        return Err(StatusCode::FORBIDDEN);
    }
    if !static_key_may_target(&tenant) {
        return Err(StatusCode::FORBIDDEN);
    }
    let cross_tenant = cross_tenant_admin();
    request.extensions_mut().insert(AdminAuthz { cross_tenant });
    Ok(run_audited(
        request,
        next,
        PRINCIPAL_STATIC,
        cross_tenant,
        tenant,
        method,
        path,
    )
    .await)
}
