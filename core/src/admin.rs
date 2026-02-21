use axum::{
    extract::{State, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json},
};
use std::sync::{Arc, RwLock};
use serde::Serialize;
use crate::state::{ServerState, VerificationRecord};

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

    if key != "super_secret_hackathon_key" {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

// ─────────────────────────────────────────────────────
//  GET /admin/users
// ─────────────────────────────────────────────────────

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<String>> {
    let st = state.read().unwrap();
    let keys = st
        .user_group
        .members
        .iter()
        .map(|p| hex::encode(p.compress().as_bytes()))
        .collect();
    Json(keys)
}

// ─────────────────────────────────────────────────────
//  GET /admin/requests
// ─────────────────────────────────────────────────────

pub async fn get_requests(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<VerificationRecord>> {
    let st = state.read().unwrap();
    Json(st.request_history.clone())
}

// ─────────────────────────────────────────────────────
//  GET /admin/stats
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ClientBalance {
    pub name: String,
    pub purchased_tokens: i64,
    pub kyc_provided: usize,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_users: usize,
    pub total_tokens_a_issued: usize,
    pub total_tokens_a_burned: usize,
    pub total_tokens_b_issued: usize,
    pub total_tokens_b_burned: usize,
    pub exchange_rate: u32,
    pub client_balances: Vec<ClientBalance>,
}

pub async fn get_stats(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<StatsResponse> {
    let st = state.read().unwrap();

    let mut client_balances: Vec<ClientBalance> = st
        .client_accounts
        .iter()
        .map(|(name, acc)| ClientBalance {
            name: name.clone(),
            purchased_tokens: acc.purchased_tokens,
            kyc_provided: acc.kyc_provided,
        })
        .collect();
    client_balances.sort_by(|a, b| a.name.cmp(&b.name));

    Json(StatsResponse {
        total_users: st.user_group.members.len(),
        total_tokens_a_issued: st.total_tokens_a_issued,
        total_tokens_a_burned: st.total_tokens_a_burned,
        total_tokens_b_issued: st.total_tokens_b_issued,
        total_tokens_b_burned: st.total_tokens_b_burned,
        exchange_rate: st.token_a_to_b_rate,
        client_balances,
    })
}
