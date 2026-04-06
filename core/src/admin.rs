use axum::{
    extract::{State, Request, Path},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json},
};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use rusqlite::params;
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::state::ServerState;
use crate::identity::Identity;
use crate::sites::ClientType;

// ─────────────────────────────────────────────────────
//  Middleware d'authentification admin
// ─────────────────────────────────────────────────────

pub async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let key = request
        .headers()
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = std::env::var("SAURON_ADMIN_KEY")
        .unwrap_or_else(|_| "super_secret_hackathon_key".to_string());
    if key != expected.as_str() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
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
    pub client_type: String,
}

pub async fn get_clients(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<AdminClientRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT name, public_key_hex, key_image_hex, client_type FROM clients ORDER BY id"
    ).unwrap();
    let records: Vec<AdminClientRecord> = stmt.query_map([], |row| {
        Ok(AdminClientRecord {
            name:           row.get(0)?,
            public_key_hex: row.get(1)?,
            key_image_hex:  row.get(2)?,
            client_type:    row.get(3)?,
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

    Json(StatsResponse {
        total_users,
        total_clients,
        total_api_calls,
        total_kyc_retrievals,
        total_agent_calls,
    })
}
