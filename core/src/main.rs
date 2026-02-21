use axum::{
    routing::{get, post},
    extract::{State, Json},
    http::StatusCode,
    Router,
    middleware,
};
use std::sync::{Arc, RwLock};
use sauron_core::{oprf, ring, state::{ServerState, sign_token, verify_token, SiteUser}, admin, billing, identity::UserData};
use sauron_core::{sites, identity::Identity};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use sha2::{Sha512, Digest};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let state = Arc::new(RwLock::new(ServerState::new()));

    let admin_routes = Router::new()
        .route("/users", get(admin::get_users))
        .route("/requests", get(admin::get_requests))
        .route("/stats", get(admin::get_stats))
        .route("/site/{name}/users", get(admin::get_site_users))
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
        // DEV endpoints (hackathon only — bypass crypto for frontend demo)
        .route("/dev/register_user", post(dev_register_user))
        .route("/dev/get_kyc", post(dev_get_kyc))
        .route("/dev/sites", get(dev_get_sites))
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
    /// Le site partenaire qui s'identifie pour l'échange (seul moment où Sauron connaît son identité).
    site_name: String,
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

    // C'est ICI, et uniquement ici, que Sauron apprend l'identité du site.
    // Sauron sait que Revolut a échangé N Tokens A, mais ne sait pas QUELS KYC il a fourni.
    if let Some(acct) = st.client_accounts.get_mut(&payload.site_name) {
        acct.kyc_provided += payload.tokens_a.len();
    }

    println!(
        "[FLUX 2] POST /exchange_tokens | {} burned {} Token A → {} Token B (rate={})",
        payload.site_name,
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

// ─────────────────────────────────────────────────────
//  DEV ENDPOINTS — hackathon only, exposes server crypto
//  so the frontend doesn't need to implement Ristretto255
// ─────────────────────────────────────────────────────

/// Recalcule le résultat OPRF sans le protocole blind.
/// Équivalent à client_unblind(server_evaluate(client_blind(e,p), k), r)
/// mais sans le masquage (k est connu, pour usage interne uniquement).
fn dev_oprf_eval(server_k: curve25519_dalek::scalar::Scalar, email: &str, password: &str) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(email.as_bytes());
    hasher.update(b"|SALT|");
    hasher.update(password.as_bytes());
    let base = RistrettoPoint::hash_from_bytes::<Sha512>(hasher.finalize().as_ref());
    server_k * base
}

#[derive(Deserialize)]
struct DevRegisterRequest {
    site_name: String,
    email: String,
    password: String,
    first_name: String,
    last_name: String,
    country: String,
}

#[derive(Serialize)]
struct DevRegisterResponse {
    signed_token_a: String,
    public_key_hex: String,
    message: String,
}

async fn dev_register_user(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevRegisterRequest>,
) -> Result<Json<DevRegisterResponse>, (StatusCode, String)> {
    // 1. Reconstruct user identity via internal OPRF (same result as full protocol)
    let oprf_result = {
        let st = state.read().unwrap();
        dev_oprf_eval(st.k, &payload.email, &payload.password)
    };
    let user_identity = Identity::from_oprf(oprf_result);
    let pk_bytes = user_identity.public.compress().as_bytes().to_vec();
    let ki_bytes = user_identity.key_image().compress().as_bytes().to_vec();
    let hex_pk = hex::encode(&pk_bytes);
    let hex_ki = hex::encode(&ki_bytes);

    // 2. Find the site that will sign the request
    let issuers = sites::hardcoded_issuers();
    let issuer_idx = issuers.iter().position(|i| i.name == payload.site_name)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("Unknown site: {}", payload.site_name)))?;

    // 3. Generate a random blind for Token A
    let random_bytes: [u8; 16] = rand::random();
    let blinded_token_a = hex::encode(random_bytes);

    // 4. Site ring-signs the message
    let ring_keys: Vec<RistrettoPoint> = issuers.iter().map(|i| i.identity.public).collect();
    let msg = format!("{}:{}", hex_pk, blinded_token_a);
    let client_signature = ring::sign(msg.as_bytes(), &ring_keys, &issuers[issuer_idx].identity, issuer_idx);

    // 5. Verify ring sig + register
    {
        let st = state.read().unwrap();
        if !st.client_group.verify_proof(msg.as_bytes(), &client_signature) {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Client ring signature check failed".into()));
        }
    }

    let profile = UserData::new(&payload.first_name, &payload.last_name, &payload.email, &payload.country);
    let pk_point = user_identity.public;

    let signed_token_a = {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);
        st.user_profiles.insert(hex_ki.clone(), profile);
        let sig = sign_token(&st.token_secret.clone(), "TOKEN_A", &blinded_token_a);
        let token_a = format!("{}:{}", blinded_token_a, sig);
        st.total_tokens_a_issued += 1;
        // NE PAS incrémenter kyc_provided ici — Sauron ne sait pas quel site a soumis ce KYC.
        // Le compteur sera mis à jour lors de l'échange (Flux 2), quand le site s'identifie explicitement.
        // En revanche, le site lui-même sait qu'il vient d'enregistrer cet utilisateur.
        if let Some(acct) = st.client_accounts.get_mut(&payload.site_name) {
            acct.users.push(SiteUser {
                first_name: payload.first_name.clone(),
                last_name: payload.last_name.clone(),
                email: payload.email.clone(),
                country: payload.country.clone(),
                source: "full_kyc".to_string(),
                acquired_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            });
        }
        println!("[FLUX 1] register_user | email={} | via Anonymous Partner (ring sig) | group_size={}",
            payload.email, st.user_group.members.len());
        token_a
    };

    Ok(Json(DevRegisterResponse {
        signed_token_a,
        public_key_hex: hex_pk,
        message: format!("{} registered via {}", payload.email, payload.site_name),
    }))
}

#[derive(Deserialize)]
struct DevGetKycRequest {
    site_name: String,
    email: String,
    password: String,
    token_b: String,
}

async fn dev_get_kyc(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevGetKycRequest>,
) -> Result<Json<GetKycResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Validate Token B
    {
        let st = state.read().unwrap();
        if !verify_token(&st.token_secret, "TOKEN_B", &payload.token_b) {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid Token B signature"}))));
        }
        if st.spent_tokens_b.contains(&payload.token_b) {
            return Err((StatusCode::CONFLICT, Json(serde_json::json!({"error": "Token B already spent"}))));
        }
    }

    // 2. Reconstruct user identity
    let oprf_result = {
        let st = state.read().unwrap();
        dev_oprf_eval(st.k, &payload.email, &payload.password)
    };
    let user_identity = Identity::from_oprf(oprf_result);

    // 3. Build user ring signature on GET_KYC:{token_b}
    let msg = format!("GET_KYC:{}", payload.token_b);
    let user_sig = {
        let st = state.read().unwrap();
        st.user_group.prove(&user_identity, msg.as_bytes())
            .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": format!("{} is not registered on Sauron. Register first.", payload.email)
            }))))?
    };

    // 4. Find profile by key_image + burn token
    let hex_ki = hex::encode(user_sig.key_image.compress().as_bytes());
    let mut st = state.write().unwrap();
    let profile = st.user_profiles.get(&hex_ki).cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Profile not found for this identity"}))))?;

    let ring_size = st.user_group.members.len();
    st.spent_tokens_b.insert(payload.token_b.clone());
    st.total_tokens_b_burned += 1;
    st.add_record(format!("GET_KYC:{}", &hex_ki[..16]), ring_size, true);
    // Le site qui a demandé le KYC connaît maintenant ce profil. Sauron lui indique le résultat,
    // mais ne sait pas lequel parmi tous les KYC de sa base a été demandé.
    if let Some(acct) = st.client_accounts.get_mut(&payload.site_name) {
        if !acct.users.iter().any(|u| u.email == profile.email) {
            acct.users.push(SiteUser {
                first_name: profile.first_name.clone(),
                last_name: profile.last_name.clone(),
                email: profile.email.clone(),
                country: profile.country.clone(),
                source: "fast_login".to_string(),
                acquired_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            });
        }
    }
    println!("[DEV/FLUX3] get_kyc | email={} | anonymous | total_consumed={}",
        payload.email, st.total_tokens_b_burned);

    Ok(Json(GetKycResponse { profile }))
}

async fn dev_get_sites() -> Json<Vec<&'static str>> {
    Json(sites::hardcoded_issuers().iter().map(|i| i.name).collect())
}
