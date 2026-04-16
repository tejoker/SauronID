use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};
use curve25519_dalek::ristretto::CompressedRistretto;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock, RwLock};
use subtle::ConstantTimeEq;

use crate::identity::Identity;
use crate::risk;
use crate::runtime_mode::is_development_runtime;
use crate::sites::ClientType;
use crate::state::ServerState;

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
    ADMIN_AUTH.get().expect("admin auth not initialized (call init_admin_auth at startup)")
}

fn build_admin_auth_config() -> Result<AdminAuthConfig, String> {
    let mut full_write_keys: Vec<Vec<u8>> = Vec::new();
    if let Ok(k) = std::env::var("SAURON_ADMIN_KEY") {
        let t = k.trim();
        if !t.is_empty() {
            full_write_keys.push(t.as_bytes().to_vec());
        }
    }
    if let Ok(list) = std::env::var("SAURON_ADMIN_KEYS") {
        for part in list.split(',') {
            let t = part.trim();
            if !t.is_empty() {
                full_write_keys.push(t.as_bytes().to_vec());
            }
        }
    }
    if full_write_keys.is_empty() {
        if let Some(b) = crate::state::development_fallback_admin_key_material() {
            eprintln!(
                "[WARN] SAURON_ADMIN_KEY / SAURON_ADMIN_KEYS unset — using derived **development** admin key."
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

    let jwt_hs256_secret = std::env::var("SAURON_ADMIN_JWT_HS256_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes());

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
    /// Handled by `jsonwebtoken` expiry validation.
    #[allow(dead_code)]
    exp: i64,
}

fn verify_admin_jwt(token: &str, secret: &[u8]) -> Option<Vec<String>> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let data = decode::<AdminJwtClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &validation,
    )
    .ok()?;
    Some(data.claims.scp)
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

pub async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let cfg = admin_cfg();
    let method = request.method().clone();

    if let Some(token) = extract_bearer_token(&request) {
        if let Some(ref sec) = cfg.jwt_hs256_secret {
            if let Some(scopes) = verify_admin_jwt(&token, sec) {
                if jwt_auth_ok(&scopes, &method) {
                    return Ok(next.run(request).await);
                }
                return Err(StatusCode::UNAUTHORIZED);
            }
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let key_bytes = extract_x_admin_key_bytes(&request);
    if key_bytes.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if key_matches_any(&key_bytes, &cfg.full_write_keys) {
        return Ok(next.run(request).await);
    }
    if key_matches_any(&key_bytes, &cfg.read_only_keys) {
        if method == Method::GET || method == Method::HEAD {
            return Ok(next.run(request).await);
        }
        return Err(StatusCode::FORBIDDEN);
    }

    Err(StatusCode::UNAUTHORIZED)
}

// ─────────────────────────────────────────────────────
//  POST /admin/clients — créer un nouveau site partenaire
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddClientRequest {
    pub name: String,
    pub client_type: ClientType,
}

#[derive(Serialize)]
pub struct AddClientResponse {
    pub name: String,
    pub public_key_hex: String,
    pub key_image_hex: String,
    pub client_type: String,
}

pub async fn add_client(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AddClientRequest>,
) -> Result<Json<AddClientResponse>, (StatusCode, String)> {
    // Génère une paire de clés Ristretto aléatoire pour ce site.
    let identity = Identity::random();
    let pub_hex   = identity.public_hex();
    let priv_hex  = identity.secret_hex();
    let ki_hex    = identity.key_image_hex();
    let type_str  = payload.client_type.as_db_str();

    // Persistance en DB.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT INTO clients (name, public_key_hex, private_key_hex, key_image_hex, client_type)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![payload.name, pub_hex, priv_hex, ki_hex, type_str],
        ).map_err(|e| (StatusCode::CONFLICT, format!("Client already exists or DB error: {e}")))?;
    }

    // Ajouter la clé publique au groupe client en mémoire (pour vérifier les ring sigs Flux 1).
    {
        let mut st = state.write().unwrap();
        if let Some(pt) = CompressedRistretto::from_slice(
            &hex::decode(&pub_hex).unwrap()
        ).ok().and_then(|c| c.decompress()) {
            st.client_group.add_member(pt);
        }
        println!("[ADMIN] New client '{}' ({}) added. client_group_size={}",
            payload.name, type_str, st.client_group.members.len());
    }

    Ok(Json(AddClientResponse {
        name: payload.name,
        public_key_hex: pub_hex,
        key_image_hex: ki_hex,
        client_type: type_str.to_string(),
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

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<AdminUserRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT key_image_hex, first_name, last_name, nationality FROM users"
    ).unwrap();
    let records: Vec<AdminUserRecord> = stmt.query_map([], |row| {
        Ok(AdminUserRecord {
            key_image_hex: row.get(0)?,
            first_name:    row.get(1)?,
            last_name:     row.get(2)?,
            nationality:   row.get(3)?,
        })
    }).unwrap().flatten().collect();
    Json(records)
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
) -> Json<Vec<AdminClientRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT name, public_key_hex, key_image_hex, tokens_b, client_type FROM clients ORDER BY id"
    ).unwrap();
    let records: Vec<AdminClientRecord> = stmt.query_map([], |row| {
        Ok(AdminClientRecord {
            name:           row.get(0)?,
            public_key_hex: row.get(1)?,
            key_image_hex:  row.get(2)?,
            tokens_b:       row.get(3)?,
            client_type:    row.get(4)?,
        })
    }).unwrap().flatten().collect();
    Json(records)
}

// ─────────────────────────────────────────────────────
//  GET /admin/site/:name/users — rétrocompabilité
// ─────────────────────────────────────────────────────

pub async fn get_site_users(
    State(_state): State<Arc<RwLock<ServerState>>>,
    Path(_name): Path<String>,
) -> Json<Vec<serde_json::Value>> {
    // Sauron ne stocke plus les associations site→utilisateur.
    // Le frontend gère cela en local.
    Json(vec![])
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

pub async fn get_site_zkp_proofs(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(name): Path<String>,
) -> Json<Vec<SiteZkpProofRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let pattern = format!("site={} %", name);
    let mut stmt = db.prepare(
        "SELECT id, timestamp, detail FROM requests_log \
         WHERE action_type = 'ZKP_VERIFY' AND status = 'OK' AND detail LIKE ?1 \
         ORDER BY id DESC LIMIT 200"
    ).unwrap();
    let records: Vec<SiteZkpProofRecord> = stmt.query_map(
        rusqlite::params![pattern],
        |row| {
            let id: i64 = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let detail: String = row.get(2)?;
            Ok((id, ts, detail))
        },
    ).unwrap().flatten()
    .map(|(id, timestamp, detail)| {
        // detail = "site=Discord ring=5 claims=age≥18,nationality:FRA"
        let mut ring_size: u64 = 0;
        let mut proved_claims: Vec<String> = vec![];
        for part in detail.split_whitespace() {
            if let Some(v) = part.strip_prefix("ring=") {
                ring_size = v.parse().unwrap_or(0);
            } else if let Some(v) = part.strip_prefix("claims=") {
                proved_claims = v.split(',').map(|s| s.to_string()).collect();
            }
        }
        if proved_claims.is_empty() { proved_claims.push("registered_user".to_string()); }
        SiteZkpProofRecord { id, timestamp, ring_size, proved_claims, raw_detail: detail }
    }).collect();
    Json(records)
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
) -> Json<Vec<RequestLogRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, timestamp, action_type, status, detail FROM requests_log ORDER BY id DESC LIMIT 200"
    ).unwrap();
    let records: Vec<RequestLogRecord> = stmt.query_map([], |row| {
        Ok(RequestLogRecord {
            id:          row.get(0)?,
            timestamp:   row.get(1)?,
            action_type: row.get(2)?,
            status:      row.get(3)?,
            detail:      row.get(4)?,
        })
    }).unwrap().flatten().collect();
    Json(records)
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
) -> Json<StatsResponse> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();

    let total_users: i64 = db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap_or(0);
    let total_clients: i64 = db.query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0)).unwrap_or(0);
    let total_api_calls: i64 = db.query_row("SELECT COUNT(*) FROM api_usage", [], |r| r.get(0)).unwrap_or(0);
    let total_kyc_retrievals: i64 = db.query_row(
        "SELECT COUNT(*) FROM api_usage WHERE action = 'kyc_human'", [], |r| r.get(0)
    ).unwrap_or(0);
    let total_agent_calls: i64 = db.query_row(
        "SELECT COUNT(*) FROM api_usage WHERE is_agent = 1", [], |r| r.get(0)
    ).unwrap_or(0);
    let total_tokens_b_spent: i64 = db.query_row(
        "SELECT COUNT(*) FROM api_usage WHERE action IN ('kyc_human','kyc_agent','zkp_login')",
        [],
        |r| r.get(0),
    ).unwrap_or(0);
    let current_tokens_b: i64 = db.query_row(
        "SELECT COALESCE(SUM(tokens_b), 0) FROM clients",
        [],
        |r| r.get(0),
    ).unwrap_or(0);
    let total_tokens_b_issued = current_tokens_b + total_tokens_b_spent;

    let controls = serde_json::json!({
        "compliance": st.compliance.admin_snapshot(),
        "screening": st.screening.admin_snapshot(),
        "issuer": st.issuer_runtime.circuit_snapshots_json(&st.issuer_urls),
        "risk": { "window_secs": risk::window_secs() },
    });

    Json(StatsResponse {
        total_users,
        total_clients,
        total_api_calls,
        total_kyc_retrievals,
        total_agent_calls,
        total_tokens_b_issued,
        total_tokens_b_spent,
        exchange_rate: 1,
        controls,
    })
}
