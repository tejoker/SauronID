use axum::{
    routing::{get, post},
    extract::{State, Json},
    http::StatusCode,
    Router,
    middleware,
};
use std::sync::{Arc, RwLock};
use sauron_core::{oprf, ring, state::ServerState, admin, identity::UserData}; 
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let state = Arc::new(RwLock::new(ServerState::new()));

    // Admin routes protected by middleware
    let admin_routes = Router::new()
        .route("/users", get(admin::get_users))
        .route("/requests", get(admin::get_requests))
        .route_layer(middleware::from_fn(admin::auth_middleware));

    let app = Router::new()
        .route("/oprf", post(handle_oprf))
        .route("/register", post(handle_register))
        .route("/group", get(handle_get_group))
        .route("/verify", post(handle_verify))
        .nest("/admin", admin_routes)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    println!("[INFO] Sauron Server started");
    println!("[INFO] Listening on: {}", addr);
    println!("--------------------------------------------------");

    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct OprfRequest { blinded_point: Vec<u8> }

#[derive(Serialize)]
struct OprfResponse { evaluated_point: Vec<u8> }

async fn handle_oprf(
    State(state): State<Arc<RwLock<ServerState>>>, 
    Json(payload): Json<OprfRequest>
) -> Result<Json<OprfResponse>, StatusCode> {
    println!("[REQUEST] POST /oprf | Payload size: {} bytes", payload.blinded_point.len());
    
    let bytes: [u8; 32] = payload.blinded_point.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    let compressed = CompressedRistretto::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let point = compressed.decompress().ok_or(StatusCode::BAD_REQUEST)?;

    let st = state.read().unwrap();
    let evaluated = oprf::server_evaluate(point, st.k);
    
    Ok(Json(OprfResponse { evaluated_point: evaluated.compress().as_bytes().to_vec() }))
}

#[derive(Deserialize)]
struct RegisterRequest { 
    public_key: Vec<u8>,
    profile: UserData, // Ajout du profil transmis par le client
}

async fn handle_register(
    State(state): State<Arc<RwLock<ServerState>>>, 
    Json(payload): Json<RegisterRequest>
) -> Result<&'static str, StatusCode> {
    let bytes: [u8; 32] = payload.public_key.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    let compressed = CompressedRistretto::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let point = compressed.decompress().ok_or(StatusCode::BAD_REQUEST)?;

    // On convertit la clé en hexadécimal pour s'en servir de clé dans le HashMap
    let hex_key = hex::encode(point.compress().as_bytes());

    let mut st = state.write().unwrap();
    st.adult_group.add_member(point);
    st.user_profiles.insert(hex_key, payload.profile); // Mémorisation du profil
    
    println!("[REQUEST] POST /register | New member added. Total: {}", st.adult_group.members.len());
    Ok("Registered")
}

async fn handle_get_group(State(state): State<Arc<RwLock<ServerState>>>) -> Json<Vec<Vec<u8>>> {
    println!("[REQUEST] GET /group");
    let st = state.read().unwrap();
    let keys = st.adult_group.members.iter().map(|p| p.compress().as_bytes().to_vec()).collect();
    Json(keys)
}

#[derive(Deserialize)]
struct VerifyRequest {
    message: String,
    signature: ring::RingSignature,
}

async fn handle_verify(
    State(state): State<Arc<RwLock<ServerState>>>, 
    Json(payload): Json<VerifyRequest>
) -> Result<&'static str, StatusCode> {
    println!("[REQUEST] POST /verify | Message: '{}'", payload.message);
    
    let is_valid;
    let members_hex;
    
    {
        let st = state.read().unwrap();
        is_valid = st.adult_group.verify_proof(payload.message.as_bytes(), &payload.signature);
        members_hex = st.adult_group.members.iter()
            .map(|p| hex::encode(p.compress().as_bytes()))
            .collect::<Vec<String>>();
    }

    {
        let mut st = state.write().unwrap();
        st.add_record(payload.message.clone(), members_hex, is_valid);
    }

    if is_valid {
        println!("[SUCCESS] Signature verified successfully.");
        Ok("Valid")
    } else {
        println!("[ERROR] Invalid signature detected.");
        Err(StatusCode::UNAUTHORIZED)
    }
}