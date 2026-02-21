use axum::{
    routing::{get, post},
    extract::{State, Json},
    Router,
};
use std::sync::{Arc, RwLock};
use sauron_core::{oprf, ring}; 
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use serde::{Deserialize, Serialize};

struct ServerState {
    k: Scalar,
    adult_group: ring::AdultGroup,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(RwLock::new(ServerState {
        k: Scalar::from_bytes_mod_order([42u8; 32]),
        adult_group: ring::AdultGroup::new(),
    }));

    let app = Router::new()
        .route("/oprf", post(handle_oprf))
        .route("/register", post(handle_register))
        .route("/group", get(handle_get_group))
        .route("/verify", post(handle_verify))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    println!("[INFO] Sauron Server started");
    println!("[INFO] Listening on: {}", addr);
    println!("--------------------------------------------------");

    axum::serve(listener, app).await.unwrap();
}

// --- Endpoints OPRF & Register (Identiques, logs épurés) ---

#[derive(Deserialize)]
struct OprfRequest { blinded_point: Vec<u8> }
#[derive(Serialize)]
struct OprfResponse { evaluated_point: Vec<u8> }

async fn handle_oprf(State(state): State<Arc<RwLock<ServerState>>>, Json(payload): Json<OprfRequest>) -> Json<OprfResponse> {
    println!("[REQUEST] POST /oprf | Payload size: {} bytes", payload.blinded_point.len());
    let st = state.read().unwrap();
    let bytes: [u8; 32] = payload.blinded_point.try_into().unwrap();
    let point = CompressedRistretto::from_slice(&bytes).unwrap().decompress().unwrap();
    let evaluated = oprf::server_evaluate(point, st.k);
    Json(OprfResponse { evaluated_point: evaluated.compress().as_bytes().to_vec() })
}

#[derive(Deserialize)]
struct RegisterRequest { public_key: Vec<u8> }

async fn handle_register(State(state): State<Arc<RwLock<ServerState>>>, Json(payload): Json<RegisterRequest>) -> &'static str {
    let mut st = state.write().unwrap();
    let bytes: [u8; 32] = payload.public_key.try_into().unwrap();
    let point = CompressedRistretto::from_slice(&bytes).unwrap().decompress().unwrap();
    st.adult_group.add_member(point);
    println!("[REQUEST] POST /register | New member added. Total: {}", st.adult_group.members.len());
    "Registered"
}

async fn handle_get_group(State(state): State<Arc<RwLock<ServerState>>>) -> Json<Vec<Vec<u8>>> {
    println!("[REQUEST] GET /group");
    let st = state.read().unwrap();
    let keys = st.adult_group.members.iter().map(|p| p.compress().as_bytes().to_vec()).collect();
    Json(keys)
}

// --- Nouveau Endpoint: Vérification ---

#[derive(Deserialize)]
struct VerifyRequest {
    message: String,
    signature: ring::RingSignature,
}

async fn handle_verify(State(state): State<Arc<RwLock<ServerState>>>, Json(payload): Json<VerifyRequest>) -> &'static str {
    println!("[REQUEST] POST /verify | Message: '{}'", payload.message);
    let st = state.read().unwrap();
    
    let is_valid = st.adult_group.verify_proof(payload.message.as_bytes(), &payload.signature);
    
    if is_valid {
        println!("[SUCCESS] Signature verified successfully.");
        "Valid"
    } else {
        println!("[ERROR] Invalid signature detected.");
        "Invalid"
    }
}