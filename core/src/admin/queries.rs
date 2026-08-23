//! The remaining small read-only admin queries kept for dashboard
//! compatibility.

use super::*;
use axum::{extract::State, response::Json};
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::any_db::AnyRowGet;
use crate::error::AppError;
use crate::risk;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

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
