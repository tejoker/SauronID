use axum::{
    extract::{State, Request, Path},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json},
};
use std::sync::{Arc, RwLock};
use serde::Serialize;
use crate::state::{ServerState, VerificationRecord, SiteUser};

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

#[derive(Serialize)]
pub struct AdminUserRecord {
    pub key_image_hex: String,
    pub first_name: String,
    pub last_name: String,
    pub country: String,
}

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<AdminUserRecord>> {
    let st = state.read().unwrap();
    let records = st
        .user_profiles
        .iter()
        .map(|(hex_ki, profile)| AdminUserRecord {
            key_image_hex: hex_ki.clone(),
            first_name: profile.first_name.clone(),
            last_name: profile.last_name.clone(),
            country: profile.country.clone(),
        })
        .collect();
    Json(records)
}

// ─────────────────────────────────────────────────────
//  GET /admin/site/:name/users
// ─────────────────────────────────────────────────────

pub async fn get_site_users(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(name): Path<String>,
) -> Json<Vec<SiteUser>> {
    let st = state.read().unwrap();
    Json(
        st.client_accounts
            .get(&name)
            .map(|acct| acct.users.clone())
            .unwrap_or_default(),
    )
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
