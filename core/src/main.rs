use axum::{
    routing::{get, post},
    extract::{State, Json},
    http::StatusCode,
    Router,
    middleware,
};
use std::sync::{Arc, RwLock};
use sauron_core::{oprf, ring, state::{ServerState, sign_token, verify_token}, admin, billing, identity::UserData};
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let state = Arc::new(RwLock::new(ServerState::new()));

    let admin_routes = Router::new()
        .route("/users", get(admin::get_users))
        .route("/requests", get(admin::get_requests))
        .route("/stats", get(admin::get_stats))
        .route_layer(middleware::from_fn(admin::auth_middleware));

    let app = Router::new()
        // OPRF: derive user key
        .route("/oprf", post(handle_oprf))
        // Flux 1: Site deposits KYC, receives Token A
        .route("/register", post(handle_register))
        // Flux 2: Site exchanges N Token A for N*rate Token B
        .route("/exchange_tokens", post(handle_exchange_tokens))
        // Flux 3: Anonymous KYC retrieval with Token B + user ring sig
        .route("/get_kyc", post(handle_get_kyc))
        // Utility: list user group public keys
        .route("/group", get(handle_get_group))
        // Billing: site purchases Token B with fiat
        .route("/client/add_tokens", post(billing::add_tokens))
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

// ─────────────────────────────────────────────────────
//  OPRF
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OprfRequest { blinded_point: Vec<u8> }

#[derive(Serialize)]
struct OprfResponse { evaluated_point: Vec<u8> }

async fn handle_oprf(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<OprfRequest>,
) -> Result<Json<OprfResponse>, StatusCode> {
    let bytes: [u8; 32] = payload.blinded_point.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    let compressed = CompressedRistretto::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let point = compressed.decompress().ok_or(StatusCode::BAD_REQUEST)?;
    let st = state.read().unwrap();
    let evaluated = oprf::server_evaluate(point, st.k);
    Ok(Json(OprfResponse { evaluated_point: evaluated.compress().as_bytes().to_vec() }))
}

// ─────────────────────────────────────────────────────
//  Flux 1 : /register — Dépôt KYC → Token A
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    /// Clé publique OPRF de l'utilisateur (dérivée de email+password).
    public_key: Vec<u8>,
    /// key_image de l'utilisateur = secret * H(public). Permet la recherche en Flux 3.
    key_image: Vec<u8>,
    /// Données KYC de l'utilisateur.
    profile: UserData,
    /// Ring Signature du site partenaire sur le message = hex(public_key)||":"||(blinded_token_a).
    /// Prouve qu'un client légitime soumet ce KYC — mais lequel reste anonyme.
    client_signature: ring::RingSignature,
    /// Valeur aveugle choisie aléatoirement par le site (simulation blind token).
    blinded_token_a: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    /// Token A signé par le serveur : "blind_value:signature"
    /// Le site le stocke et l'utilisera lors de l'échange (Flux 2).
    signed_token_a: String,
}

async fn handle_register(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let pk_bytes: [u8; 32] = payload.public_key.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    let pk_compressed = CompressedRistretto::from_slice(&pk_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let pk_point = pk_compressed.decompress().ok_or(StatusCode::BAD_REQUEST)?;

    let ki_bytes: [u8; 32] = payload.key_image.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    let ki_compressed = CompressedRistretto::from_slice(&ki_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let _ki_point = ki_compressed.decompress().ok_or(StatusCode::BAD_REQUEST)?;

    // Message signé = hex(public_key) + ":" + blinded_token_a
    let hex_pk = hex::encode(&pk_bytes);
    let msg = format!("{}:{}", hex_pk, payload.blinded_token_a);

    // Vérifier que la signature provient d'un site partenaire légitime (anonyme).
    {
        let st = state.read().unwrap();
        if !st.client_group.verify_proof(msg.as_bytes(), &payload.client_signature) {
            println!("[SECURITY] POST /register | Invalid client signature. Registration rejected.");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Enregistrer l'utilisateur.
    let hex_ki = hex::encode(&ki_bytes);
    let signed_token_a;
    {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);
        st.user_profiles.insert(hex_ki.clone(), payload.profile);
        // Signer le token A (simulation blind signature).
        let sig = sign_token(&st.token_secret.clone(), "TOKEN_A", &payload.blinded_token_a);
        signed_token_a = format!("{}:{}", payload.blinded_token_a, sig);
        st.total_tokens_a_issued += 1;
        println!(
            "[FLUX 1] POST /register | User added. group_size={} | token_a_issued={}",
            st.user_group.members.len(),
            st.total_tokens_a_issued
        );
    }

    Ok(Json(RegisterResponse { signed_token_a }))
}

// ─────────────────────────────────────────────────────
//  Flux 2 : /exchange_tokens — N Token A → N*rate Token B
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ExchangeRequest {
    /// Liste des Tokens A en clair : ["blind_a:sig_a", ...].
    tokens_a: Vec<String>,
    /// Valeurs aveugles pour les Tokens B : autant que tokens_a * rate.
    blinded_tokens_b: Vec<String>,
}

#[derive(Serialize)]
struct ExchangeResponse {
    signed_tokens_b: Vec<String>,
    rate: u32,
    tokens_a_burned: usize,
    tokens_b_issued: usize,
}

async fn handle_exchange_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ExchangeRequest>,
) -> Result<Json<ExchangeResponse>, StatusCode> {
    if payload.tokens_a.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let rate;
    let token_secret;
    {
        let st = state.read().unwrap();
        rate = st.token_a_to_b_rate;
        token_secret = st.token_secret.clone();

        // Vérifier tous les Tokens A avant d'en brûler un seul.
        for token_a in &payload.tokens_a {
            if !verify_token(&token_secret, "TOKEN_A", token_a) {
                println!("[SECURITY] POST /exchange_tokens | Invalid Token A: {}", token_a);
                return Err(StatusCode::UNAUTHORIZED);
            }
            if st.spent_tokens_a.contains(token_a.as_str()) {
                println!("[SECURITY] POST /exchange_tokens | Double-spend Token A: {}", token_a);
                return Err(StatusCode::CONFLICT);
            }
        }
    }

    let expected_b_count = payload.tokens_a.len() * rate as usize;
    if payload.blinded_tokens_b.len() != expected_b_count {
        println!(
            "[ERROR] /exchange_tokens | Expected {} blinded_tokens_b, got {}",
            expected_b_count,
            payload.blinded_tokens_b.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut st = state.write().unwrap();
    // Brûler les Tokens A.
    for token_a in &payload.tokens_a {
        st.spent_tokens_a.insert(token_a.clone());
        st.total_tokens_a_burned += 1;
    }

    // Signer les Tokens B.
    let signed_tokens_b: Vec<String> = payload.blinded_tokens_b
        .iter()
        .map(|blind_b| {
            let sig = sign_token(&token_secret, "TOKEN_B", blind_b);
            format!("{}:{}", blind_b, sig)
        })
        .collect();

    st.total_tokens_b_issued += signed_tokens_b.len();

    println!(
        "[FLUX 2] POST /exchange_tokens | Burned {} Token A → Issued {} Token B (rate={})",
        payload.tokens_a.len(),
        signed_tokens_b.len(),
        rate
    );

    Ok(Json(ExchangeResponse {
        tokens_b_issued: signed_tokens_b.len(),
        signed_tokens_b,
        rate,
        tokens_a_burned: payload.tokens_a.len(),
    }))
}

// ─────────────────────────────────────────────────────
//  Flux 3 : /get_kyc — Token B + user ring sig → KYC
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GetKycRequest {
    /// Token B en clair : "blind_b:sig_b".
    token_b: String,
    /// Ring Signature de l'utilisateur sur le message "GET_KYC:{token_b}".
    /// Prouve le consentement de l'utilisateur. Son key_image identifie quel profil retourner.
    user_signature: ring::RingSignature,
}

#[derive(Serialize)]
struct GetKycResponse {
    profile: UserData,
}

async fn handle_get_kyc(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<GetKycRequest>,
) -> Result<Json<GetKycResponse>, StatusCode> {
    let token_secret;
    {
        let st = state.read().unwrap();
        token_secret = st.token_secret.clone();

        // Vérifier la signature du Token B.
        if !verify_token(&token_secret, "TOKEN_B", &payload.token_b) {
            println!("[SECURITY] POST /get_kyc | Invalid Token B.");
            return Err(StatusCode::UNAUTHORIZED);
        }

        // Anti-double-dépense.
        if st.spent_tokens_b.contains(&payload.token_b) {
            println!("[SECURITY] POST /get_kyc | Double-spend Token B: {}", payload.token_b);
            return Err(StatusCode::CONFLICT);
        }
    }

    // Vérifier la ring signature de l'utilisateur.
    // Message signé = "GET_KYC:{token_b}" pour lier le consentement à ce token précis.
    let msg = format!("GET_KYC:{}", payload.token_b);
    {
        let st = state.read().unwrap();
        if !st.user_group.verify_proof(msg.as_bytes(), &payload.user_signature) {
            println!("[SECURITY] POST /get_kyc | Invalid user ring signature.");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Retrouver le profil via le key_image de la signature (identifiant anonyme stable).
    let hex_ki = hex::encode(payload.user_signature.key_image.compress().as_bytes());

    let mut st = state.write().unwrap();
    let profile = st.user_profiles.get(&hex_ki).cloned().ok_or_else(|| {
        println!("[ERROR] POST /get_kyc | No profile found for key_image: {}", &hex_ki[..16]);
        StatusCode::NOT_FOUND
    })?;

    // Brûler le Token B.
    let ring_size = st.user_group.members.len();
    st.spent_tokens_b.insert(payload.token_b.clone());
    st.total_tokens_b_burned += 1;
    st.add_record(format!("GET_KYC:{}", &hex_ki[..16]), ring_size, true);

    println!(
        "[FLUX 3] POST /get_kyc | KYC delivered (anonymous). total_consumed={}",
        st.total_tokens_b_burned
    );

    Ok(Json(GetKycResponse { profile }))
}

// ─────────────────────────────────────────────────────
//  Utilitaire : liste des clés du groupe utilisateurs
// ─────────────────────────────────────────────────────

async fn handle_get_group(State(state): State<Arc<RwLock<ServerState>>>) -> Json<Vec<Vec<u8>>> {
    let st = state.read().unwrap();
    let keys = st.user_group.members.iter().map(|p| p.compress().as_bytes().to_vec()).collect();
    Json(keys)
}
