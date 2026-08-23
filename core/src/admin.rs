use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};
use curve25519_dalek::ristretto::CompressedRistretto;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock, RwLock};
use subtle::ConstantTimeEq;

use crate::any_db::AnyRowGet;
use crate::error::AppError;
use crate::identity::Identity;
use crate::risk;
use crate::runtime_mode::is_development_runtime;
use crate::sites::ClientType;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

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

fn admin_cfg() -> &'static AdminAuthConfig {
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

fn verify_admin_jwt(token: &str, secret: &[u8]) -> Option<(Vec<String>, Vec<String>)> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let data =
        decode::<AdminJwtClaims>(token, &DecodingKey::from_secret(secret), &validation).ok()?;
    Some((data.claims.scp, data.claims.tnt))
}

fn scopes_are_super(scopes: &[String]) -> bool {
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
fn static_key_may_target(tenant: &str) -> bool {
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

// ─────────────────────────────────────────────────────
//  POST /admin/clients — créer un nouveau site partenaire
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddClientRequest {
    pub name: String,
    pub client_type: ClientType,
    /// Production partners generate and retain their own ring key. The server
    /// receives only the public key and key image; it never stores custody.
    #[serde(default)]
    pub public_key_hex: Option<String>,
    #[serde(default)]
    pub key_image_hex: Option<String>,
}

#[derive(Serialize)]
pub struct AddClientResponse {
    pub name: String,
    pub public_key_hex: String,
    pub key_image_hex: String,
    pub client_type: String,
    /// Development-only one-time secret when the server generated the key.
    /// Never persisted, and forbidden by default in production.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex_once: Option<String>,
}

pub async fn add_client(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<crate::tenancy::TenantId>>,
    Json(payload): Json<AddClientRequest>,
) -> Result<Json<AddClientResponse>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let require_external = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_EXTERNAL_CLIENT_KEYS",
        /* dev_default */ false,
        /* prod_default */ true,
    );
    let (pub_hex, ki_hex, private_key_hex_once) = match (
        &payload.public_key_hex,
        &payload.key_image_hex,
    ) {
        (Some(pub_hex), Some(ki_hex)) => {
            use curve25519_dalek::ristretto::CompressedRistretto;
            use curve25519_dalek::traits::Identity as _;
            for (label, encoded) in [("public_key_hex", pub_hex), ("key_image_hex", ki_hex)] {
                let bytes = hex::decode(encoded)
                    .map_err(|_| (StatusCode::BAD_REQUEST, format!("{label} must be hex")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| (StatusCode::BAD_REQUEST, format!("{label} must be 32 bytes")))?;
                let point = CompressedRistretto(arr).decompress().ok_or((
                    StatusCode::BAD_REQUEST,
                    format!("{label} is not a valid Ristretto point"),
                ))?;
                if point == curve25519_dalek::RistrettoPoint::identity() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("{label} must not be the identity point"),
                    )
                        .into());
                }
            }
            (pub_hex.clone(), ki_hex.clone(), None)
        }
        (None, None) if !require_external => {
            let identity = Identity::random();
            (
                identity.public_hex(),
                identity.key_image_hex(),
                Some(identity.secret_hex()),
            )
        }
        (None, None) => {
            return Err((
                    StatusCode::BAD_REQUEST,
                    "production requires externally generated public_key_hex and key_image_hex; private partner keys must never enter SauronID custody".into(),
                ).into());
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "public_key_hex and key_image_hex must be supplied together".into(),
            )
                .into());
        }
    };
    let type_str = payload.client_type.as_db_str();

    // Persistance en DB.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        // Both rows or neither: a client without its tenant binding is
        // unreachable and would block the name from being re-registered.
        db.any_conn()
            .transaction(|tx| {
                tx.execute(
                    "INSERT INTO clients (name, public_key_hex, key_image_hex, client_type)
             VALUES (?1, ?2, ?3, ?4)",
                    sql_params![&payload.name, &pub_hex, &ki_hex, type_str],
                )?;
                tx.execute(
                    "INSERT INTO client_tenant_bindings (client_name, tenant_id) VALUES (?1, ?2)",
                    sql_params![&payload.name, &tenant_id],
                )?;
                Ok(())
            })
            .map_err(|e| {
                // A duplicate client name is a 409; losing the write lock is a
                // 503 the caller should retry; anything else is a 500. Each
                // backend spells the violation differently.
                let msg = e.to_lowercase();
                if msg.contains("unique") || msg.contains("duplicate key") {
                    (
                        StatusCode::CONFLICT,
                        format!("Client already exists or DB error: {e}"),
                    )
                } else if crate::error::is_db_contention(&e) {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("database busy, retry shortly: {e}"),
                    )
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, e)
                }
            })?;
    }

    // Ajouter la clé publique au groupe client en mémoire (pour vérifier les ring sigs Flux 1).
    {
        let mut st = state.write_or_recover();
        // pub_hex is server-generated via Identity::random() so decoding is
        // expected to succeed, but we defensively avoid panic on any future
        // refactor that pipes user-influenced hex through this path.
        let pub_bytes = hex::decode(&pub_hex).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("hex decode: {e}"),
            )
        })?;
        if let Some(pt) = CompressedRistretto::from_slice(&pub_bytes)
            .ok()
            .and_then(|c| c.decompress())
        {
            st.client_group.add_member(pt);
        }
        tracing::info!(
            target: "sauron::admin",
            client = %payload.name,
            client_type = %type_str,
            client_group_size = st.client_group.members.len(),
            "new client added"
        );
    }

    Ok(Json(AddClientResponse {
        name: payload.name,
        public_key_hex: pub_hex,
        key_image_hex: ki_hex,
        client_type: type_str.to_string(),
        private_key_hex_once,
    }))
}

// ─────────────────────────────────────────────────────
//  GET /admin/users
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminUserRecord {
    pub key_image_hex: String,
    pub first_name: String,
    pub last_name: String,
    pub nationality: String,
}

/// GET /admin/anchor/agent-actions/proof?receipt_id=<rcp_…>
/// Return the merkle inclusion proof for an agent action receipt within the
/// batch that anchored it on Bitcoin (OTS) and Solana (Memo).
#[derive(Deserialize)]
pub struct ActionAnchorProofQuery {
    pub receipt_id: String,
}

pub async fn get_action_anchor_proof(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<ActionAnchorProofQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    match crate::agent_action_anchor::proof_for_receipt_for_tenant(&state, &q.receipt_id, &scope) {
        Ok(Some(v)) => Ok(Json(v)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "receipt_id not yet anchored (next anchor batch will include it)".into(),
        )
            .into()),
        Err(e) => Err(AppError::Internal(e)),
    }
}

/// GET /admin/anchor/batches?limit=N — list recent anchor batches with the
/// per-chain three-state surface (ADR-001). Each row reports:
///
/// ```json
/// {
///   "anchor_id": "...",
///   "n_actions": 42,
///   "created_at": 1715800000,
///   "solana":  {"confirmed": true,  "slot": 12345, "sig": "..."},
///   "bitcoin": {"provider": "opentimestamps", "ots_upgraded": false, "block_height": null},
///   "anchored": false   // DEPRECATED — kept one minor version, see ADR-001
/// }
/// ```
///
/// The three UI states are computed client-side from the two booleans:
///   - "Pending"                          → !solana.confirmed
///   - "Solana-confirmed (BTC pending)"   →  solana.confirmed && !bitcoin.ots_upgraded
///   - "Dually anchored"                  →  solana.confirmed &&  bitcoin.ots_upgraded
#[derive(Deserialize)]
pub struct AnchorBatchesQuery {
    pub limit: Option<i64>,
}

pub async fn get_anchor_batches(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<AnchorBatchesQuery>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    match crate::agent_action_anchor::recent_batches_for_tenant(&state, limit, &scope) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(AppError::Internal(e)),
    }
}

// OpenTimestamps detached-file framing. We reconstruct a standards-compliant
// `.ots` around the stored calendar receipt so the artifact verifies with the
// stock `ots` tooling (`ots upgrade` / `ots info` / `ots verify`).
//
// The calendar `/digest` (and later `/timestamp/{root}`) endpoints return a
// serialized OTS *Timestamp* whose implicit message is the 32-byte merkle root
// we submitted (raw, no nonce — see bitcoin_anchor::publish_opentimestamps). A
// detached `.ots` file wraps that as:
//   HEADER_MAGIC ‖ varuint(MAJOR_VERSION=1) ‖ file_hash_op ‖ msg ‖ timestamp
// with file_hash_op = OpSHA256 (tag 0x08) and msg = the 32-byte root. The
// bytes below are verbatim from the OpenTimestamps spec
// (DetachedTimestampFile.HEADER_MAGIC).
const OTS_HEADER_MAGIC: [u8; 31] = [
    0x00, b'O', b'p', b'e', b'n', b'T', b'i', b'm', b'e', b's', b't', b'a', b'm', b'p', b's', 0x00,
    0x00, b'P', b'r', b'o', b'o', b'f', 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];
const OTS_MAJOR_VERSION: u8 = 0x01;
const OTS_OP_SHA256_TAG: u8 = 0x08;

/// Build the detached `.ots` byte stream from a 32-byte merkle root and the
/// stored calendar timestamp blob. Split out so it can be unit-tested for the
/// exact header/version/op framing the `ots` tooling expects.
fn build_ots_detached(root: &[u8; 32], timestamp_blob: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(OTS_HEADER_MAGIC.len() + 2 + root.len() + timestamp_blob.len());
    out.extend_from_slice(&OTS_HEADER_MAGIC);
    out.push(OTS_MAJOR_VERSION);
    out.push(OTS_OP_SHA256_TAG);
    out.extend_from_slice(root);
    out.extend_from_slice(timestamp_blob);
    out
}

/// GET /admin/anchor/ots/{anchor_id} — download the OpenTimestamps `.ots`
/// proof for a Bitcoin merkle anchor. `anchor_id` is the
/// `bitcoin_merkle_anchors.anchor_id` (i.e. the `btc_anchor_id` reported by
/// `/anchor/batches`). Returns the raw `.ots` bytes as an attachment so a
/// reviewer can verify the root is committed to Bitcoin with the stock tool.
pub async fn get_anchor_ots(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(anchor_id): Path<String>,
) -> axum::response::Response {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};

    let row: Option<(String, Vec<u8>)> = {
        let st = state.read_or_recover();
        let mut conn = match st.db.lock() {
            Ok(c) => c,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        conn.any_conn()
            .query_row(
                "SELECT merkle_root_hex, ots_receipt_blob
             FROM bitcoin_merkle_anchors
             WHERE anchor_id = ?1 AND provider = 'opentimestamps'
               AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![anchor_id, &scope],
                |r| Ok((r.get::<String>(0)?, r.get::<Vec<u8>>(1)?)),
            )
            .ok()
            .flatten()
    };

    let (root_hex, blob) = match row {
        Some(v) => v,
        None => return (
            StatusCode::NOT_FOUND,
            "no OpenTimestamps proof for this anchor (not Bitcoin-anchored, or unknown anchor_id)",
        )
            .into_response(),
    };
    if blob.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            "OpenTimestamps receipt not yet available — the calendar has not returned a proof for this root",
        )
            .into_response();
    }
    let root: [u8; 32] = match hex::decode(&root_hex) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored merkle root is not 32 bytes",
            )
                .into_response()
        }
    };

    let ots = build_ots_detached(&root, &blob);
    let short = &root_hex[..root_hex.len().min(16)];
    let filename = format!("sauronid-{short}.ots");
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        ots,
    )
        .into_response()
}

/// POST /admin/anchor/agent-actions/run
/// Force an immediate anchor batch instead of waiting for the periodic task.
/// Useful for tests and one-shot CI verification.
pub async fn force_action_anchor_run(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    // A cross-tenant operator may still trigger one batch per tenant; the
    // endpoint returns only the batch for the requested tenant unless the
    // caller explicitly requests a tenant through the normal tenant context.
    let target_tenant = if scope == "*" {
        tenant.as_str()
    } else {
        &scope
    };
    match crate::agent_action_anchor::anchor_pending_actions_for_tenant(&state, target_tenant).await
    {
        Ok(Some(anchor_id)) => Ok(Json(serde_json::json!({ "anchor_id": anchor_id }))),
        Ok(None) => Ok(Json(
            serde_json::json!({ "anchor_id": null, "reason": "no new receipts" }),
        )),
        Err(e) => Err(AppError::Internal(e)),
    }
}

/// GET /health (public) — minimal liveness probe.
///
/// Returns ONLY `{ok: bool}`. Does not leak runtime mode, feature flags,
/// anchor configuration, or DB backend — those would be reconnaissance
/// information for an attacker. The detailed structured report lives at
/// `/admin/health/detailed` behind admin auth.
pub async fn health_public(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<serde_json::Value> {
    // Keep this trivial. Just check the DB roundtrip.
    let ok = {
        let st = state.read_or_recover();
        match st.db.lock() {
            Ok(mut conn) => conn
                .any_conn()
                .query_row("SELECT 1", sql_params![], |r| r.get::<i64>(0))
                .is_ok(),
            Err(_) => false,
        }
    };
    Json(serde_json::json!({ "ok": ok }))
}

/// GET /readyz (public) — readiness probe: liveness plus a DB roundtrip.
///
/// 200 `{"ready":true}` when the database answers `SELECT 1`, otherwise
/// 503 `{"ready":false,"reason":...}`. Like `/health`, the reason is kept
/// generic — DB backend details are recon information; the full detail is
/// logged server-side and available at `/admin/health/detailed`.
pub async fn readyz(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_ok = {
        let st = state.read_or_recover();
        match st.db.lock() {
            Ok(mut conn) => match conn
                .any_conn()
                .query_row("SELECT 1", sql_params![], |r| r.get_i64(0))
            {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(target: "sauron::health", error = %e, "readyz DB probe failed");
                    false
                }
            },
            Err(e) => {
                tracing::error!(target: "sauron::health", error = %e, "readyz DB pool unavailable");
                false
            }
        }
    };
    if db_ok {
        (StatusCode::OK, Json(serde_json::json!({ "ready": true })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ready": false, "reason": "database unreachable" })),
        )
    }
}

/// GET /admin/health/detailed — structured health for operators.
///
/// Same shape as the previous public `/health`, but admin-gated so the
/// configuration surface isn't exposed to unauthenticated clients. Operators
/// scrape this from internal load balancers / monitoring agents.
#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub runtime: &'static str,
    pub call_sig_enforce: bool,
    pub require_agent_type: bool,
    pub require_hardware_attestation: bool,
    pub require_preregistered_measurement: bool,
    pub policy_require_binding: bool,
    pub egress_gateway_enabled: bool,
    pub global_max_action_usd: Option<f64>,
    /// Sprint 1: surfaces SAURON_POLICY_ENFORCEMENT_MODE so operators
    /// can confirm the server is fail-closed before traffic flips.
    pub policy_enforcement_mode: &'static str,
    pub bitcoin_anchor: HealthComponent,
    pub solana_anchor: HealthComponent,
    pub database: HealthComponent,
    /// Durability of the security-audit sinks. `ok=false` (and a warning) once
    /// any audit event failed to persist — regulated deployments alert on this.
    pub audit: HealthComponent,
    pub feature_flags: HealthFlags,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct HealthComponent {
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct HealthFlags {}

pub async fn health(State(state): State<Arc<RwLock<ServerState>>>) -> Json<HealthResponse> {
    let runtime = if crate::runtime_mode::is_development_runtime() {
        "development"
    } else {
        "production"
    };

    let flag = |name: &str| -> bool {
        match std::env::var(name).ok() {
            Some(v) => {
                let low = v.to_ascii_lowercase();
                v == "1" || low == "true" || low == "yes"
            }
            None => false,
        }
    };

    // Sprint 1: shared runtime_mode helper. Dev defaults advisory, prod enforce.
    let call_sig_enforce =
        crate::runtime_mode::require_or_default("SAURON_REQUIRE_CALL_SIG", false, true);
    let require_agent_type =
        crate::runtime_mode::require_or_default("SAURON_REQUIRE_AGENT_TYPE", false, true);
    let require_hardware_attestation = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_HARDWARE_ATTESTATION",
        false,
        false,
    );
    let require_preregistered_measurement = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_PREREGISTERED_MEASUREMENT",
        false,
        false,
    );
    let policy_require_binding = crate::runtime_mode::policy_require_binding();
    let egress_gateway_enabled = crate::egress_gateway::egress_gateway_enabled();
    let global_max_action_usd = crate::runtime_mode::global_max_action_usd();
    let policy_enforcement_mode = crate::runtime_mode::policy_enforcement_mode();

    let mut warnings: Vec<String> = Vec::new();

    // Bitcoin anchor health
    let bitcoin_anchor = match state.read_or_recover().bitcoin_anchor.as_ref() {
        Some(svc) if svc.provider() == crate::bitcoin_anchor::AnchorProvider::OpenTimestamps => {
            HealthComponent {
                ok: true,
                detail: "provider=OpenTimestamps".into(),
            }
        }
        Some(svc) => {
            if runtime == "production" {
                warnings.push(
                    "Production runtime uses a mock Bitcoin anchor; commitments are not externally verifiable"
                        .into(),
                );
            }
            HealthComponent {
                ok: runtime != "production",
                detail: format!("provider={:?} (development only)", svc.provider()),
            }
        }
        None => {
            warnings.push(
                "Bitcoin anchor disabled — audit log is not externally verifiable on BTC".into(),
            );
            HealthComponent {
                ok: false,
                detail: "disabled".into(),
            }
        }
    };
    let solana_anchor = match state.read_or_recover().solana_anchor.as_ref() {
        Some(svc) => HealthComponent {
            ok: true,
            detail: format!("signer={}", &svc.signer_pubkey_b58()[..20]),
        },
        None => {
            warnings.push(
                "Solana anchor disabled — audit log is not externally verifiable on Solana".into(),
            );
            HealthComponent {
                ok: false,
                detail: "disabled (set SAURON_SOLANA_ENABLED=1)".into(),
            }
        }
    };

    // DB roundtrip
    //
    // The label used to be the literal "sqlite" regardless of backend, so a
    // PostgreSQL deployment reported `"database": {"detail": "sqlite"}` while
    // `db.lock()` was correctly dispatching to Postgres — the check was right and
    // only its name was wrong. That matters twice over: an operator reads this to
    // confirm which tier they are on, and the benchmark harness reads it to record
    // which backend a result was measured against, where the two differ by more
    // than 10x on throughput.
    let database = {
        let st = state.read_or_recover();
        let backend = if st.db.is_postgres() {
            "postgres"
        } else {
            "sqlite"
        };
        match st.db.lock() {
            Ok(mut conn) => match conn
                .any_conn()
                .query_row("SELECT 1", sql_params![], |r| r.get_i64(0))
            {
                Ok(_) => HealthComponent {
                    ok: true,
                    detail: backend.into(),
                },
                Err(e) => HealthComponent {
                    ok: false,
                    detail: format!("{backend} query failed: {e}"),
                },
            },
            Err(e) => HealthComponent {
                ok: false,
                detail: format!("db lock: {e}"),
            },
        }
    };

    let feature_flags = HealthFlags {};

    if runtime == "production" && !call_sig_enforce {
        warnings.push("Production runtime but SAURON_REQUIRE_CALL_SIG is not enforced — per-call signature is advisory only".into());
    }
    if runtime == "production" && !require_agent_type {
        warnings.push("Production runtime but SAURON_REQUIRE_AGENT_TYPE is off — operators can supply unverified checksums".into());
    }
    if runtime == "production" && require_hardware_attestation && !require_preregistered_measurement
    {
        warnings.push(
            "Hardware assurance is enabled without authoritative pre-registered measurements"
                .into(),
        );
    }
    if runtime == "production" && !policy_require_binding {
        warnings.push("Production runtime permits protected agents without a bound policy".into());
    }
    if runtime == "production" && !egress_gateway_enabled {
        warnings.push("Production runtime has the enforcing egress gateway disabled".into());
    }
    if runtime == "production" && global_max_action_usd.is_none() {
        warnings
            .push("Production runtime has no SAURON_MAX_ACTION_USD blast-radius ceiling".into());
    }
    if runtime == "production"
        && matches!(
            policy_enforcement_mode,
            crate::runtime_mode::PolicyEnforcementMode::Advisory
                | crate::runtime_mode::PolicyEnforcementMode::Off
        )
    {
        warnings.push(format!(
            "Production runtime but SAURON_POLICY_ENFORCEMENT_MODE is '{}' — bound policy denies do not block action endpoints",
            policy_enforcement_mode.as_str()
        ));
    }
    if !flag("SAURON_VAULT_TRANSIT_ENABLED") && runtime == "production" {
        warnings.push(
            "Production runtime but Vault Transit is not enabled — root secrets in plain env"
                .into(),
        );
    }

    // Audit-sink durability: a non-zero failure count means at least one
    // security event may not have been durably recorded → health failure.
    let audit_failures = crate::middleware::audit_log::audit_sink_failure_count();
    let audit = if audit_failures == 0 {
        HealthComponent {
            ok: true,
            detail: "0 sink failures".into(),
        }
    } else {
        warnings.push(format!(
            "{audit_failures} security-audit sink write failure(s) — events may be missing from the tamper-evident log"
        ));
        HealthComponent {
            ok: false,
            detail: format!("{audit_failures} sink failures"),
        }
    };

    let ok = database.ok && audit.ok && warnings.is_empty();

    Json(HealthResponse {
        ok,
        runtime,
        call_sig_enforce,
        require_agent_type,
        require_hardware_attestation,
        require_preregistered_measurement,
        policy_require_binding,
        egress_gateway_enabled,
        global_max_action_usd,
        policy_enforcement_mode: policy_enforcement_mode.as_str(),
        bitcoin_anchor,
        solana_anchor,
        database,
        audit,
        feature_flags,
        warnings,
    })
}

// ─────────────────────────────────────────────────────
//  Live-data admin endpoints (Analytics 5/5)
//
//  Every dashboard number comes from a live SQL query against the SauronID core.
//  Replaces the pre-pivot parquet path (see the archive/banking-2025 git tag).
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminAgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub assurance_level: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub has_pop: bool,
    pub agent_type: String,
    /// The agent's declared mandate, verbatim as registered — scope, and any
    /// caps such as `maxAmount`/`currency`. Without it an operator console can
    /// only render "no intents declared" for every agent, which is the one thing
    /// about an agent a reviewer actually wants to see.
    pub intent_json: String,
    /// Attestation kind recorded at registration, normalised (`""` for none).
    pub attestation_kind: String,
    /// Whether that kind carries hardware-rooted evidence this build verifies.
    ///
    /// `SAURON_REQUIRE_HARDWARE_ATTESTATION` defaults OFF in production, so a
    /// default deployment accepts an unattested agent. Flipping that default
    /// would break every deployment not running on Nitro or TPM2, and it would
    /// not stop the escape it looks like it stops — a compromised agent inside
    /// an attested enclave still holds its owner's session. So the posture is
    /// surfaced instead of forced: an operator can see an unattested agent in
    /// the console rather than having to infer it from an absent field.
    pub hardware_attested: bool,
}

/// POST /admin/agents/{agent_id}/revoke — operator-side revocation (admin auth).
///
/// The public `DELETE /agent/{agent_id}` requires a user session header tied
/// to the human key image that owns the agent. The dashboard runs in an admin
/// context (no end-user session), so it uses this admin variant to revoke any
/// agent by id. Records an audit log entry under "AGENT_REVOKE_ADMIN".
/// Admin cross-tenant aggregate view. OFF by default (fail-closed: every admin
/// query is scoped to the request's resolved tenant). A single trusted
/// super-admin operator sets `SAURON_ADMIN_CROSS_TENANT=1` to see all tenants.
/// Multi-customer deployments MUST leave it off — this is the boundary that
/// prevents one tenant's admin from reading another's agents/receipts/PII.
fn cross_tenant_admin() -> bool {
    matches!(
        std::env::var("SAURON_ADMIN_CROSS_TENANT").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Scope token for admin queries: the request's tenant, or the `*` sentinel
/// (match-all — never a valid tenant id) when the authenticated principal is
/// allowed cross-tenant. Use in SQL as `(?N = '*' OR tenant_id = ?N)`.
///
/// The decision comes from the per-request [`AdminAuthz`] (set by
/// `auth_middleware` from the JWT scope/tenant-lock); when absent it falls back
/// to the legacy global `SAURON_ADMIN_CROSS_TENANT` flag.
fn admin_scope(authz: Option<&AdminAuthz>, tenant: &crate::tenancy::TenantId) -> String {
    let cross = authz
        .map(|a| a.cross_tenant)
        .unwrap_or_else(cross_tenant_admin);
    if cross {
        "*".to_string()
    } else {
        tenant.as_str().to_string()
    }
}

/// Deployment-global tables must never be returned to a tenant-locked admin.
/// These legacy tables do not carry tenant_id, so refusing the request is the
/// only safe behavior until they are migrated and backfilled.
fn require_cross_tenant_admin(authz: Option<&AdminAuthz>) -> Result<(), AppError> {
    let cross = authz
        .map(|a| a.cross_tenant)
        .unwrap_or_else(cross_tenant_admin);
    if cross {
        Ok(())
    } else {
        Err(AppError::Unauthorized(
            "this admin view is deployment-global; use a cross-tenant super-admin".into(),
        ))
    }
}

pub async fn revoke_agent_admin(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let rows = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "UPDATE agents SET revoked = 1 WHERE agent_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![&agent_id, &scope],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };
    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Agent not found".into()).into());
    }
    // M-3: prune the revoked agent's point from the in-memory ring.
    let pubkey: Option<String> = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .query_row(
                "SELECT public_key_hex FROM agents WHERE agent_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![&agent_id, &scope],
                |r| r.get(0),
            )
            .ok()
            .flatten()
    };
    if let Some(hex) = pubkey {
        state.write_or_recover().drop_ring_member(&hex);
    }
    {
        let st = state.read_or_recover();
        st.log("AGENT_REVOKE_ADMIN", "OK", &agent_id);
    }
    Ok(Json(
        serde_json::json!({ "revoked": true, "agent_id": agent_id }),
    ))
}

/// Is this owner within the calling admin's tenant scope?
///
/// `user_auth_credentials` carries no `tenant_id`, so the scope has to come from
/// `user_auth_tenant_bindings` — the same join the owner-mandate path uses.
/// `"*"` is the cross-tenant super-admin escape set by [`admin_scope`].
///
/// Separate from the handler so the scoping rule is testable without standing up
/// a `ServerState`: this is the check that stops a tenant-locked admin from
/// reaching an owner it cannot see, and it is worth a test of its own.
fn owner_visible_in_scope(
    conn: &mut crate::any_db::AnyConn<'_>,
    key_image: &str,
    scope: &str,
) -> bool {
    conn.scalar_or(
        "SELECT COUNT(*) FROM user_auth_credentials c
         JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
         WHERE c.key_image_hex = ?1 AND (?2 = '*' OR b.tenant_id = ?2)",
        sql_params![key_image, scope],
        |r| r.get_i64(0),
        0,
    ) > 0
}

/// POST /admin/users/{key_image}/revoke_sessions — cut an owner off.
///
/// The owner session authorises `POST /agent/register` and
/// `POST /agent/{id}/checksum/update`, so it MINTS agent authority: whoever
/// holds one can register a sibling agent with an intent it writes itself. It
/// is also a one-hour stateless bearer token, which used to mean a suspected
/// leak had no response — verification consulted no server state, so there was
/// nothing an operator could change.
///
/// Bumping the owner's `session_epoch` invalidates every session already issued
/// for it, because the epoch is inside the signed payload and
/// [`crate::user_session::key_image_from_headers`] compares it against the
/// stored one on every request. Existing agents keep working; they authenticate
/// with their own PoP keys, not with this. What stops is the ability to mint
/// new agent authority with the leaked token.
///
/// Tenant-scoped through `user_auth_tenant_bindings`, the same join the owner
/// mandate path uses — `user_auth_credentials` itself carries no `tenant_id`,
/// so a tenant-locked admin must not be able to bump an owner it cannot see.
pub async fn revoke_user_sessions(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(key_image): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "key_image must be 64 hex characters".into(),
        ));
    }
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);

    let st = state.read_or_recover();
    let epoch = {
        let mut db = st
            .db
            .lock()
            .map_err(|e| AppError::ServiceUnavailable(e.to_string()))?;
        let mut conn = db.any_conn();

        // Resolve inside the caller's scope first. Without this a tenant-locked
        // admin could bump any owner in the deployment by guessing a key image.
        if !owner_visible_in_scope(&mut conn, &key_image, &scope) {
            return Err(AppError::NotFound("owner not found".into()));
        }
        crate::user_session::revoke_all(&mut conn, &key_image).map_err(AppError::Internal)?
    };
    st.log("USER_SESSIONS_REVOKE_ADMIN", "OK", &key_image);

    Ok(Json(serde_json::json!({
        "revoked": true,
        "key_image": key_image,
        "session_epoch": epoch,
    })))
}

/// GET /admin/agents — list every registered agent + checksum + revocation status.
pub async fn get_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<Vec<AdminAgentRecord>>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminAgentRecord> = db
        .any_conn()
        .query_map(
            "SELECT a.agent_id, a.human_key_image, a.agent_checksum, a.assurance_level,
                    a.issued_at, a.expires_at, a.revoked,
                    IFNULL(LENGTH(a.pop_public_key_b64u), 0),
                    IFNULL(ci.agent_type, ''),
                    IFNULL(a.intent_json, ''),
                    IFNULL(a.attestation_kind, '')
             FROM agents a
             LEFT JOIN agent_checksum_inputs ci ON ci.agent_id = a.agent_id
             WHERE (?1 = '*' OR a.tenant_id = ?1)
             ORDER BY a.issued_at DESC",
            sql_params![&scope],
            |row| {
                let pop_len: i64 = row.get(7)?;
                Ok(AdminAgentRecord {
                    agent_id: row.get(0)?,
                    human_key_image: row.get(1)?,
                    agent_checksum: row.get(2)?,
                    assurance_level: row.get(3)?,
                    issued_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    revoked: row.get::<i64>(6)? != 0,
                    has_pop: pop_len > 0,
                    agent_type: row.get(8)?,
                    intent_json: row.get(9)?,
                    attestation_kind: {
                        let raw: String = row.get(10)?;
                        let kind = crate::attestation::AttestationKind::parse(&raw)
                            .unwrap_or(crate::attestation::AttestationKind::None);
                        kind.as_str().to_string()
                    },
                    hardware_attested: {
                        let raw: String = row.get(10)?;
                        crate::attestation::AttestationKind::parse(&raw)
                            .map(|k| k.is_hardware_backed())
                            .unwrap_or(false)
                    },
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

#[derive(Serialize)]
pub struct AdminActionReceiptRecord {
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub status: String,
    pub policy_version: String,
    pub created_at: i64,
}

/// GET /admin/agent_actions/recent?limit=N — last N agent action receipts.
pub async fn get_recent_actions(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminActionReceiptRecord>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminActionReceiptRecord> = db
        .any_conn()
        .query_map(
            "SELECT receipt_id, action_hash, agent_id, status, policy_version, created_at
             FROM agent_action_receipts
             WHERE (?1 = '*' OR tenant_id = ?1)
             ORDER BY created_at DESC
             LIMIT ?2",
            sql_params![&scope, limit],
            |row| {
                Ok(AdminActionReceiptRecord {
                    receipt_id: row.get(0)?,
                    action_hash: row.get(1)?,
                    agent_id: row.get(2)?,
                    status: row.get(3)?,
                    policy_version: row.get(4)?,
                    created_at: row.get(5)?,
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

/// Verdict surface for the dashboard "Try" page. Each scenario exercises a
/// REAL governance primitive (no mocks): `replay` runs the live single-use
/// nonce store, `scope`/`normal` run the live tool-allowlist invariant.
#[derive(Serialize)]
pub struct DemoScenarioOut {
    pub result: String, // "allowed" | "stopped"
    pub status_code: u16,
    pub detail: serde_json::Value,
}

#[derive(Deserialize)]
pub struct RecentLimitQuery {
    pub limit: Option<i64>,
}

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
fn issue_admin_jwt(
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

/// GET /admin/anchor/status — current state of the on-chain anchor pipeline.
// Clearer as default-then-assign-per-query than a struct literal with a dozen
// inline query_row calls.
#[allow(clippy::field_reassign_with_default)]
pub async fn get_anchor_status(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<AdminAnchorStatus>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let mut s = AdminAnchorStatus::default();
    s.bitcoin_provider = crate::bitcoin_anchor::configured_provider_label();
    s.bitcoin_network = crate::bitcoin_anchor::configured_network_label();
    s.bitcoin_synthetic = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors
             WHERE no_real_money = 1 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.bitcoin_total = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.bitcoin_pending_upgrade = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors
             WHERE provider = 'opentimestamps' AND ots_upgraded = 0
               AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.bitcoin_upgraded = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors
             WHERE ots_upgraded = 1 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.solana_total = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM solana_merkle_anchors WHERE (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.solana_unconfirmed = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM solana_merkle_anchors
             WHERE confirmed = 0 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.solana_confirmed = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM solana_merkle_anchors
             WHERE confirmed = 1 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.agent_action_batches = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM agent_action_anchors WHERE (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    if let Ok(Some(row)) = db.any_conn().query_row(
        "SELECT created_at, n_actions FROM agent_action_anchors
         WHERE (?1 = '*' OR tenant_id = ?1)
         ORDER BY created_at DESC LIMIT 1",
        sql_params![&scope],
        |r| Ok((r.get::<i64>(0)?, r.get::<i64>(1)?)),
    ) {
        s.last_batch_at = row.0;
        s.last_batch_n_actions = row.1;
    }
    Ok(Json(s))
}

#[derive(Serialize)]
pub struct AdminPerAgentMetric {
    pub agent_id: String,
    pub action_count: i64,
    pub egress_count: i64,
    pub last_action_at: i64,
}

/// GET /admin/per_agent_metrics?limit=N — per-agent action + egress counts, sorted by activity.
pub async fn get_per_agent_metrics(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminPerAgentMetric>>, AppError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminPerAgentMetric> = db.any_conn().query_map(
            "SELECT a.agent_id,
                    (SELECT COUNT(*) FROM agent_action_receipts r WHERE r.agent_id = a.agent_id) AS act_count,
                    (SELECT COUNT(*) FROM agent_egress_log e WHERE e.agent_id = a.agent_id)      AS egress_count,
                    (SELECT IFNULL(MAX(created_at),0) FROM agent_action_receipts r WHERE r.agent_id = a.agent_id) AS last_at
             FROM agents a
             WHERE (?1 = '*' OR a.tenant_id = ?1)
             ORDER BY act_count DESC, egress_count DESC
             LIMIT ?2",
            sql_params![&scope, limit],
            |row| {
            Ok(AdminPerAgentMetric {
                agent_id: row.get(0)?,
                action_count: row.get(1)?,
                egress_count: row.get(2)?,
                last_action_at: row.get(3)?,
            })
        }).map_err(AppError::internal)?;
    Ok(Json(records))
}

#[derive(Serialize)]
pub struct AdminEgressEntry {
    pub id: i64,
    pub agent_id: String,
    pub target_host: String,
    pub target_path: String,
    pub method: String,
    pub status_code: i64,
    pub ts: i64,
    pub allowed: bool,
}

/// GET /admin/egress/recent?limit=N — recent agent egress events.
pub async fn get_recent_egress(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminEgressEntry>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminEgressEntry> = db
        .any_conn()
        .query_map(
            "SELECT id, agent_id, target_host, target_path, method, status_code, ts, allowed
             FROM agent_egress_log
             WHERE (?1 = '*' OR tenant_id = ?1)
             ORDER BY ts DESC LIMIT ?2",
            sql_params![&scope, limit],
            |row| {
                Ok(AdminEgressEntry {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    target_host: row.get(2)?,
                    target_path: row.get(3)?,
                    method: row.get(4)?,
                    status_code: row.get(5)?,
                    ts: row.get(6)?,
                    allowed: row.get::<i64>(7)? != 0,
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

/// GET /admin/checksum/audit/{agent_id} — every checksum rotation for an agent.
#[derive(Serialize)]
pub struct AdminChecksumAudit {
    pub from_checksum: String,
    pub to_checksum: String,
    pub reason: String,
    pub actor: String,
    pub ts: i64,
}

pub async fn get_checksum_audit(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AdminChecksumAudit>>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminChecksumAudit> = db
        .any_conn()
        .query_map(
            "SELECT c.from_checksum, c.to_checksum, c.reason, c.actor, c.ts
             FROM agent_checksum_audit c
             JOIN agents a ON a.agent_id = c.agent_id
             WHERE c.agent_id = ?1 AND (?2 = '*' OR a.tenant_id = ?2)
             ORDER BY ts DESC",
            sql_params![agent_id, scope],
            |row| {
                Ok(AdminChecksumAudit {
                    from_checksum: row.get(0)?,
                    to_checksum: row.get(1)?,
                    reason: row.get(2)?,
                    actor: row.get(3)?,
                    ts: row.get(4)?,
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<Vec<AdminUserRecord>>, AppError> {
    // The `users` table (human identities + PII) is NOT tenant-scoped, so it
    // cannot be filtered per tenant. Listing it is therefore a cross-tenant
    // super-admin operation: refuse unless SAURON_ADMIN_CROSS_TENANT is set.
    require_cross_tenant_admin(authz.as_ref().map(|axum::Extension(a)| a))?;
    let repo = state.read_or_recover().repo.clone();
    let records: Vec<AdminUserRecord> = repo
        .list_users()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .into_iter()
        .map(
            |(key_image_hex, first_name, last_name, nationality)| AdminUserRecord {
                key_image_hex,
                first_name,
                last_name,
                nationality,
            },
        )
        .collect();
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/clients
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminClientRecord {
    pub name: String,
    pub public_key_hex: String,
    pub key_image_hex: String,
    pub tokens_b: i64,
    pub client_type: String,
}

pub async fn get_clients(
    State(state): State<Arc<RwLock<ServerState>>>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<Vec<AdminClientRecord>>, AppError> {
    require_cross_tenant_admin(authz.as_ref().map(|axum::Extension(a)| a))?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminClientRecord> = db.any_conn().query_map(
            "SELECT name, public_key_hex, key_image_hex, tokens_b, client_type FROM clients ORDER BY id",
            sql_params![],
            |row| {
            Ok(AdminClientRecord {
                name: row.get(0)?,
                public_key_hex: row.get(1)?,
                key_image_hex: row.get(2)?,
                tokens_b: row.get(3)?,
                client_type: row.get(4)?,
            })
        }).map_err(AppError::internal)?;
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/site/:name/users — rétrocompabilité
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SiteUserRecord {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub nationality: String,
    pub source: String,
    pub timestamp: i64,
}

// ─────────────────────────────────────────────────────
//  GET /admin/site/:name/zkp_proofs
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SiteZkpProofRecord {
    pub id: i64,
    pub timestamp: i64,
    pub ring_size: u64,
    pub proved_claims: Vec<String>,
    pub raw_detail: String,
}

// ─────────────────────────────────────────────────────
//  GET /admin/requests
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RequestLogRecord {
    pub id: i64,
    pub timestamp: i64,
    pub action_type: String,
    pub status: String,
    pub detail: String,
}

pub async fn get_requests(
    State(state): State<Arc<RwLock<ServerState>>>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<Vec<RequestLogRecord>>, AppError> {
    require_cross_tenant_admin(authz.as_ref().map(|axum::Extension(a)| a))?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<RequestLogRecord> = db.any_conn().query_map(
            "SELECT id, timestamp, action_type, status, detail FROM requests_log ORDER BY id DESC LIMIT 200",
            sql_params![],
            |row| {
            Ok(RequestLogRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action_type: row.get(2)?,
                status: row.get(3)?,
                detail: row.get(4)?,
            })
        }).map_err(AppError::internal)?;
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/stats
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_users: i64,
    pub total_clients: i64,
    pub total_api_calls: i64,
    pub total_kyc_retrievals: i64,
    pub total_agent_calls: i64,
    pub total_tokens_b_issued: i64,
    pub total_tokens_b_spent: i64,
    pub exchange_rate: i64,
    /// Operator-facing snapshot (no end-user PII): compliance, screening, issuer circuits, risk window.
    pub controls: serde_json::Value,
}

pub async fn get_stats(
    State(state): State<Arc<RwLock<ServerState>>>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<StatsResponse>, AppError> {
    require_cross_tenant_admin(authz.as_ref().map(|axum::Extension(a)| a))?;
    // `users` is read through the dual-backend repo; `clients`/`api_usage` come
    // off the raw handle, which dispatches too — so every count below reads the
    // configured backend rather than the sidecar.
    let repo = state.read_or_recover().repo.clone();
    let total_users: i64 = repo.count_users().await.unwrap_or(0);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();

    // `scalar_or` rather than `query_row(..).unwrap_or(0)`: query_row now
    // returns Ok(None) for "no rows" separately from Err, and a stats panel
    // wants 0 for both. Naming the swallow keeps it greppable.
    let mut count = |sql: &str| {
        db.any_conn()
            .scalar_or(sql, sql_params![], |r| r.get_i64(0), 0)
    };
    let total_clients: i64 = count("SELECT COUNT(*) FROM clients");
    let total_api_calls: i64 = count("SELECT COUNT(*) FROM api_usage");
    let total_kyc_retrievals: i64 =
        count("SELECT COUNT(*) FROM api_usage WHERE action = 'kyc_human'");
    let total_agent_calls: i64 = count("SELECT COUNT(*) FROM api_usage WHERE is_agent = 1");
    let total_tokens_b_spent: i64 = count(
        "SELECT COUNT(*) FROM api_usage WHERE action IN ('kyc_human','kyc_agent','zkp_login')",
    );
    let current_tokens_b: i64 = count("SELECT COALESCE(SUM(tokens_b), 0) FROM clients");
    let total_tokens_b_issued = current_tokens_b + total_tokens_b_spent;

    let controls = serde_json::json!({
        "risk": { "window_secs": risk::window_secs() },
    });

    Ok(Json(StatsResponse {
        total_users,
        total_clients,
        total_api_calls,
        total_kyc_retrievals,
        total_agent_calls,
        total_tokens_b_issued,
        total_tokens_b_spent,
        exchange_rate: 1,
        controls,
    }))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod owner_session_revocation_tests;
