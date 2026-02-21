use axum::{
    extract::{State, Request},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Json},
    middleware::Next,
};
use std::sync::{Arc, RwLock};
use serde::Serialize;
use curve25519_dalek::ristretto::RistrettoPoint;
use crate::state::{ServerState, VerificationRecord};

const ADMIN_API_KEY: &str = "super_secret_hackathon_key";

pub async fn auth_middleware(
    headers: HeaderMap, 
    request: Request, 
    next: Next
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(key) = headers.get("x-admin-key") {
        if key == ADMIN_API_KEY {
            return Ok(next.run(request).await);
        }
    }
    println!("[SECURITY] Blocked unauthorized admin access attempt");
    Err(StatusCode::UNAUTHORIZED)
}

#[derive(Serialize)]
pub struct UserRecord {
    pub public_key_hex: String,
}

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>
) -> Json<Vec<UserRecord>> {
    println!("[ADMIN] GET /admin/users");
    let st = state.read().unwrap();
    
    let users = st.adult_group.members.iter()
        .map(|p: &RistrettoPoint| UserRecord {
            public_key_hex: hex::encode(p.compress().as_bytes())
        })
        .collect();
        
    Json(users)
}

pub async fn get_requests(
    State(state): State<Arc<RwLock<ServerState>>>
) -> Json<Vec<VerificationRecord>> {
    println!("[ADMIN] GET /admin/requests");
    let st = state.read().unwrap();
    Json(st.request_history.clone())
}