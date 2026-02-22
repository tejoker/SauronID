use axum::{
    routing::{get, post},
    extract::{State, Json},
    http::StatusCode,
    Router,
    middleware,
};
use std::sync::{Arc, Mutex, RwLock};
use rusqlite::params;
use sauron_core::{oprf, ring, state::{ServerState, sign_token, verify_token, token_value}, admin, billing};
use sauron_core::{identity::{Identity, UserData}, db};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use sha2::{Sha512, Digest};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    // Initialise la base SQLite en mémoire.
    let conn = db::open_db();
    let db_arc = Arc::new(Mutex::new(conn));
    let state = Arc::new(RwLock::new(ServerState::new(Arc::clone(&db_arc))));

    let admin_routes = Router::new()
        .route("/users",             get(admin::get_users))
        .route("/clients",           get(admin::get_clients).post(admin::add_client))
        .route("/requests",          get(admin::get_requests))
        .route("/stats",             get(admin::get_stats))
        .route("/site/{name}/users",      get(admin::get_site_users))
        .route("/site/{name}/zkp_proofs", get(admin::get_site_zkp_proofs))
        .route_layer(middleware::from_fn(admin::auth_middleware));

    let app = Router::new()
        // OPRF
        .route("/oprf",              post(handle_oprf))
        // Flux 1: dépôt KYC → Token A
        .route("/register",          post(handle_register))
        // Flux 2: N Token A → N*rate Token B
        .route("/exchange_tokens",   post(handle_exchange_tokens))
        // Flux 3: Token B + ring sig → profil KYC
        .route("/get_kyc",           post(handle_get_kyc))
        // Utilitaire: clés publiques du groupe utilisateurs
        .route("/group",             get(handle_get_group))
        // Billing: émission de Token B
        .route("/client/add_tokens", post(billing::add_tokens))
        .nest("/admin", admin_routes)
        // DEV: endpoints sans crypto côté frontend
        .route("/dev/register_user", post(dev_register_user))
        .route("/dev/get_kyc",       post(dev_get_kyc))
        .route("/dev/sites",         get(dev_get_sites))
        .route("/dev/clients",       get(dev_get_clients))
        // ZKP
        .route("/zkp/build_ring",    post(handle_build_ring))
        .route("/zkp/verify_proof",  post(handle_verify_proof))
        .route("/zkp/client_ring",   get(handle_zkp_client_ring))
        // DEV ZKP (frontend-friendly — crypto côté serveur)
        .route("/dev/zkp_login",     post(dev_zkp_login))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

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
    let hex_pk = hex::encode(&pk_bytes);
    let hex_ki = hex::encode(&ki_bytes);
    let msg = format!("{}:{}", hex_pk, payload.blinded_token_a);

    // Vérifier que la ring sig provient d'un site partenaire légitime.
    {
        let st = state.read().unwrap();
        if !st.client_group.verify_proof(msg.as_bytes(), &payload.client_signature) {
            println!("[SECURITY] POST /register | Invalid client signature.");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Persister l'utilisateur dans la DB.
    let p = &payload.profile;
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO users
             (key_image_hex, public_key_hex, first_name, last_name, email, date_of_birth, nationality)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![hex_ki, hex_pk, p.first_name, p.last_name, p.email, p.date_of_birth, p.nationality],
        ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Mettre à jour le groupe en mémoire + signer Token A.
    let signed_token_a;
    {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);
        let sig = sign_token(&st.token_secret.clone(), "TOKEN_A", &payload.blinded_token_a);
        signed_token_a = format!("{}:{}", payload.blinded_token_a, sig);
        st.total_tokens_a_issued += 1;
        st.log("REGISTER", "OK", &hex_ki[..16]);
        println!("[FLUX 1] POST /register | group_size={} token_a_issued={}",
            st.user_group.members.len(), st.total_tokens_a_issued);
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
        let db = st.db.lock().unwrap();
        for token_a in &payload.tokens_a {
            if !verify_token(&token_secret, "TOKEN_A", token_a) {
                println!("[SECURITY] POST /exchange_tokens | Invalid Token A: {}", token_a);
                return Err(StatusCode::UNAUTHORIZED);
            }
            let tv = token_value(token_a);
            let exists: bool = db.query_row(
                "SELECT COUNT(*) FROM tokens_a_burned WHERE hash = ?1",
                params![tv], |r| r.get::<_, i64>(0),
            ).unwrap_or(0) > 0;
            if exists {
                println!("[SECURITY] POST /exchange_tokens | Double-spend Token A.");
                return Err(StatusCode::CONFLICT);
            }
        }
    }

    let expected_b_count = payload.tokens_a.len() * rate as usize;
    if payload.blinded_tokens_b.len() != expected_b_count {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Brûler les Tokens A en DB.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        for token_a in &payload.tokens_a {
            let tv = token_value(token_a);
            let _ = db.execute("INSERT OR IGNORE INTO tokens_a_burned (hash) VALUES (?1)", params![tv]);
        }
    }

    // Signer les Tokens B.
    let signed_tokens_b: Vec<String> = payload.blinded_tokens_b
        .iter()
        .map(|blind_b| {
            let sig = sign_token(&token_secret, "TOKEN_B", blind_b);
            format!("{}:{}", blind_b, sig)
        })
        .collect();

    {
        let mut st = state.write().unwrap();
        st.total_tokens_a_burned += payload.tokens_a.len();
        st.total_tokens_b_issued += signed_tokens_b.len();
        st.log("EXCHANGE", "OK", &format!("site={} burned_a={}", payload.site_name, payload.tokens_a.len()));
        println!("[FLUX 2] POST /exchange_tokens | {} burned {} Token A → {} Token B (rate={})",
            payload.site_name, payload.tokens_a.len(), signed_tokens_b.len(), rate);
    }

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
    let token_secret = state.read().unwrap().token_secret.clone();

    // Vérifier le Token B (HMAC).
    if !verify_token(&token_secret, "TOKEN_B", &payload.token_b) {
        println!("[SECURITY] POST /get_kyc | Invalid Token B.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Anti-double-dépense via DB.
    let tv = token_value(&payload.token_b).to_string();
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT COUNT(*) FROM tokens_b_spent WHERE hash = ?1",
            params![tv], |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if exists {
            println!("[SECURITY] POST /get_kyc | Double-spend Token B.");
            return Err(StatusCode::CONFLICT);
        }
    }

    // Vérifier la ring signature de l'utilisateur.
    let msg = format!("GET_KYC:{}", payload.token_b);
    {
        let st = state.read().unwrap();
        if !st.user_group.verify_proof(msg.as_bytes(), &payload.user_signature) {
            println!("[SECURITY] POST /get_kyc | Invalid user ring signature.");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Retrouver le profil via key_image depuis la DB.
    let hex_ki = hex::encode(payload.user_signature.key_image.compress().as_bytes());
    let profile: UserData = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT first_name, last_name, email, date_of_birth, nationality
             FROM users WHERE key_image_hex = ?1",
            params![hex_ki],
            |row| Ok(UserData {
                first_name:    row.get(0)?,
                last_name:     row.get(1)?,
                email:         row.get(2)?,
                date_of_birth: row.get(3)?,
                nationality:   row.get(4)?,
            }),
        ).map_err(|_| {
            println!("[ERROR] POST /get_kyc | Profile not found for key_image: {}", &hex_ki[..16]);
            StatusCode::NOT_FOUND
        })?
    };

    // Brûler le Token B.
    let ring_size;
    {
        let mut st = state.write().unwrap();
        ring_size = st.user_group.members.len();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute("INSERT OR IGNORE INTO tokens_b_spent (hash) VALUES (?1)", params![tv]);
        }
        st.total_tokens_b_burned += 1;
        st.log("GET_KYC", "OK", &hex_ki[..16]);
        println!("[FLUX 3] POST /get_kyc | KYC delivered anonymously. ring_size={} total_burned={}",
            ring_size, st.total_tokens_b_burned);
    }

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
    #[serde(default)]
    #[allow(dead_code)]
    site_name: String,   // accepté pour compatibilité, mais non utilisé côté server
    email: String,
    password: String,
    first_name: String,
    last_name: String,
    #[serde(default)]
    date_of_birth: String,
    #[serde(default)]
    nationality: String,
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
    // 1. Reconstruire l'identité via OPRF interne.
    let oprf_result = {
        let st = state.read().unwrap();
        dev_oprf_eval(st.k, &payload.email, &payload.password)
    };
    let user_identity = Identity::from_oprf(oprf_result);
    let pk_bytes = user_identity.public.compress().as_bytes().to_vec();
    let ki_bytes = user_identity.key_image().compress().as_bytes().to_vec();
    let hex_pk  = hex::encode(&pk_bytes);
    let hex_ki  = hex::encode(&ki_bytes);

    // 2. Simuler ring sig du site partenaire.
    let random_bytes: [u8; 16] = rand::random();
    let blinded_token_a = hex::encode(random_bytes);

    // 3. Persister dans la DB.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO users
             (key_image_hex, public_key_hex, first_name, last_name, email, date_of_birth, nationality)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![hex_ki, hex_pk,
                payload.first_name, payload.last_name, payload.email,
                payload.date_of_birth, payload.nationality],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // 4. Mettre à jour le groupe en mémoire.
    let pk_point = user_identity.public;
    let signed_token_a = {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);
        let sig = sign_token(&st.token_secret.clone(), "TOKEN_A", &blinded_token_a);
        let token_a = format!("{}:{}", blinded_token_a, sig);
        // NOTE: dev path — ne compte pas comme Token A réel (pas un vrai Flux 1)
        st.log("DEV_REGISTER", "OK", &hex_ki[..16]);
        println!("[FLUX 1][DEV] register_user | email={} | group_size={}",
            payload.email, st.user_group.members.len());
        token_a
    };

    Ok(Json(DevRegisterResponse {
        signed_token_a,
        public_key_hex: hex_pk,
        message: format!("{} registered (dev)", payload.email),
    }))
}

#[derive(Deserialize)]
struct DevGetKycRequest {
    #[serde(default)]
    #[allow(dead_code)]
    site_name: String,   // accepté pour compatibilité
    email: String,
    password: String,
    token_b: String,
}

async fn dev_get_kyc(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevGetKycRequest>,
) -> Result<Json<GetKycResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Valider Token B.
    {
        let st = state.read().unwrap();
        if !verify_token(&st.token_secret, "TOKEN_B", &payload.token_b) {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid Token B signature"}))));
        }
        let tv = token_value(&payload.token_b);
        let db = st.db.lock().unwrap();
        let exists: bool = db.query_row("SELECT COUNT(*) FROM tokens_b_spent WHERE hash = ?1",
            params![tv], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
        if exists {
            return Err((StatusCode::CONFLICT, Json(serde_json::json!({"error": "Token B already spent"}))));
        }
    }

    // 2. Reconstruire l'identité utilisateur.
    let oprf_result = {
        let st = state.read().unwrap();
        dev_oprf_eval(st.k, &payload.email, &payload.password)
    };
    let user_identity = Identity::from_oprf(oprf_result);
    let hex_ki = hex::encode(user_identity.key_image().compress().as_bytes());

    // 3. Vérifier que l'utilisateur est dans user_group.
    {
        let st = state.read().unwrap();
        if !st.user_group.members.contains(&user_identity.public) {
            return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": format!("{} is not registered on Sauron. Register first.", payload.email)
            }))));
        }
    }

    // 4. Lire le profil depuis la DB.
    let profile: UserData = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT first_name, last_name, email, date_of_birth, nationality FROM users WHERE key_image_hex = ?1",
            params![hex_ki],
            |row| Ok(UserData {
                first_name:    row.get(0)?,
                last_name:     row.get(1)?,
                email:         row.get(2)?,
                date_of_birth: row.get(3)?,
                nationality:   row.get(4)?,
            }),
        ).map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Profile not found"}))))?
    };

    // 5. Brûler le Token B.
    let tv = token_value(&payload.token_b).to_string();
    {
        let mut st = state.write().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute("INSERT OR IGNORE INTO tokens_b_spent (hash) VALUES (?1)", params![tv]);
        }
        st.total_tokens_b_burned += 1;
        st.log("DEV_GET_KYC", "OK", &payload.email);
        println!("[DEV/FLUX3] get_kyc | email={} | total_consumed={}", payload.email, st.total_tokens_b_burned);
    }

    Ok(Json(GetKycResponse { profile }))
}

async fn dev_get_sites() -> Json<Vec<serde_json::Value>> {
    Json(vec![])  // Désormais obsolète — utiliser GET /admin/clients ou GET /dev/clients
}

// ─────────────────────────────────────────────────────
//  GET /dev/clients — Retourne tous les sites avec clés publiques + privées
//  (hackathon only — permet au frontend de simuler les ring sigs côté client)
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct DevClientRecord {
    name:            String,
    public_key_hex:  String,
    private_key_hex: String,
    key_image_hex:   String,
    client_type:     String,
}

async fn dev_get_clients(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<DevClientRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT name, public_key_hex, private_key_hex, key_image_hex, client_type FROM clients ORDER BY id"
    ).unwrap();
    let records: Vec<DevClientRecord> = stmt.query_map([], |row| {
        Ok(DevClientRecord {
            name:            row.get(0)?,
            public_key_hex:  row.get(1)?,
            private_key_hex: row.get(2)?,
            key_image_hex:   row.get(3)?,
            client_type:     row.get(4)?,
        })
    }).unwrap().flatten().collect();
    Json(records)
}

// ─────────────────────────────────────────────────────
//  ZKP : construction d'anneau filtré et vérification de preuve
// ─────────────────────────────────────────────────────

/// Filtre un profil selon l'âge minimum et la nationalité requise.
fn user_passes_filters(profile: &UserData, min_age: Option<u8>, req_nat: Option<&str>) -> bool {
    if let Some(nat) = req_nat {
        if !nat.is_empty() && profile.nationality != nat {
            return false;
        }
    }
    if let Some(age) = min_age {
        if let Some(birth_year) = profile.date_of_birth.split('-').next()
            .and_then(|y| y.parse::<u32>().ok())
        {
            if 2026u32.saturating_sub(birth_year) < age as u32 {
                return false;
            }
        }
    }
    true
}

/// Paramètres de filtre pour la construction d'un anneau ZKP.
#[derive(Deserialize, Clone)]
struct ZkpRingRequest {
    min_age: Option<u8>,
    required_nationality: Option<String>,
}

/// POST /zkp/build_ring — retourne les clés publiques du sous-anneau filtré.
/// Le client peut ensuite utiliser ces clés pour construire une ring signature locale.
#[derive(Serialize)]
struct ZkpRingResponse {
    ring_pubkeys: Vec<String>,
    ring_size: usize,
}

async fn handle_build_ring(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ZkpRingRequest>,
) -> Json<ZkpRingResponse> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();

    // Lire tous les utilisateurs depuis la DB et filtrer.
    let mut stmt = db.prepare(
        "SELECT public_key_hex, date_of_birth, nationality FROM users"
    ).unwrap();

    let rows: Vec<(String, String, String)> = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }).unwrap().flatten().collect();

    let ring_pubkeys: Vec<String> = rows.into_iter()
        .filter(|(_, dob, nat)| {
            let profile = UserData {
                first_name:    String::new(),
                last_name:     String::new(),
                email:         String::new(),
                date_of_birth: dob.clone(),
                nationality:   nat.clone(),
            };
            user_passes_filters(&profile, payload.min_age, payload.required_nationality.as_deref())
        })
        .map(|(pk, _, _)| pk)
        .collect();

    let ring_size = ring_pubkeys.len();
    println!("[ZKP] POST /zkp/build_ring | filters=age≥{:?} nat={:?} | ring_size={}",
        payload.min_age, payload.required_nationality, ring_size);
    Json(ZkpRingResponse { ring_pubkeys, ring_size })
}

/// POST /zkp/verify_proof — vérifie une ring signature sur l'anneau filtré.
/// Brûle le Token B et retourne {verified, ring_size} sans révéler aucune donnée utilisateur.
#[derive(Deserialize)]
struct ZkpVerifyRequest {
    filters: ZkpRingRequest,
    /// Ring signature de l'utilisateur dans l'anneau filtré (prouve appartenance au groupe).
    user_signature: ring::RingSignature,
    /// Ring signature du client ZKP_ONLY dans l'anneau des clients ZKP (prouve que la demande vient d'un site autorisé).
    client_signature: ring::RingSignature,
    message: String,
    prepaid_token: String,
}

#[derive(Serialize)]
struct ZkpVerifyResponse {
    verified: bool,
    ring_size: usize,
}

async fn handle_verify_proof(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ZkpVerifyRequest>,
) -> Result<Json<ZkpVerifyResponse>, (StatusCode, String)> {
    // 1. Valider Token B.
    let tv = token_value(&payload.prepaid_token).to_string();
    {
        let st = state.read().unwrap();
        if !verify_token(&st.token_secret, "TOKEN_B", &payload.prepaid_token) {
            return Err((StatusCode::PAYMENT_REQUIRED, "Invalid Token B".into()));
        }
        let db = st.db.lock().unwrap();
        let exists: bool = db.query_row("SELECT COUNT(*) FROM tokens_b_spent WHERE hash = ?1",
            params![tv], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
        if exists {
            return Err((StatusCode::CONFLICT, "Token B already spent".into()));
        }
    }

    // 2. Vérifier la ring signature du client ZKP_ONLY.
    let client_ring_points: Vec<RistrettoPoint> = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT public_key_hex FROM clients WHERE client_type = 'ZKP_ONLY' ORDER BY id"
        ).unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap().flatten()
            .filter_map(|h| {
                let bytes = hex::decode(h).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                CompressedRistretto::from_slice(&arr).ok()?.decompress()
            })
            .collect()
    };
    if client_ring_points.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "No ZKP_ONLY clients registered".into()));
    }
    if !ring::verify(payload.message.as_bytes(), &client_ring_points, &payload.client_signature) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid client ring signature".into()));
    }

    // 3. Construire l'anneau utilisateur filtré depuis la DB.
    let ring_points: Vec<RistrettoPoint> = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT public_key_hex, date_of_birth, nationality FROM users"
        ).unwrap();
        stmt.query_map([], |row| Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))).unwrap().flatten()
        .filter(|(_, dob, nat)| {
            let profile = UserData {
                first_name: String::new(), last_name: String::new(), email: String::new(),
                date_of_birth: dob.clone(), nationality: nat.clone(),
            };
            user_passes_filters(&profile, payload.filters.min_age, payload.filters.required_nationality.as_deref())
        })
        .filter_map(|(pk_hex, _, _)| {
            let bytes = hex::decode(pk_hex).ok()?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            CompressedRistretto::from_slice(&arr).ok()?.decompress()
        })
        .collect()
    };

    if ring_points.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "No users match the filters".into()));
    }

    // 4. Vérifier la ring signature de l'utilisateur.
    let ring_size = ring_points.len();
    let verified  = ring::verify(payload.message.as_bytes(), &ring_points, &payload.user_signature);

    // 5. Brûler le Token B si valide.
    if verified {
        let mut st = state.write().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute("INSERT OR IGNORE INTO tokens_b_spent (hash) VALUES (?1)", params![tv]);
        }
        st.total_tokens_b_burned += 1;
        st.log("ZKP_VERIFY", "OK", &payload.message[..payload.message.len().min(20)]);
    }

    println!("[ZKP] POST /zkp/verify_proof | verified={} user_ring={} client_ring={}", verified, ring_size, client_ring_points.len());
    Ok(Json(ZkpVerifyResponse { verified, ring_size }))
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /zkp/client_ring  – renvoie les clés publiques de tous les clients ZKP_ONLY
// ──────────────────────────────────────────────────────────────────────────────
#[derive(Serialize)]
struct ZkpClientRingResponse {
    ring_pubkeys: Vec<String>,
    ring_size: usize,
}

async fn handle_zkp_client_ring(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<ZkpClientRingResponse> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT public_key_hex FROM clients WHERE client_type = 'ZKP_ONLY' ORDER BY id")
        .unwrap();
    let ring_pubkeys: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .flatten()
        .collect();
    let ring_size = ring_pubkeys.len();
    Json(ZkpClientRingResponse { ring_pubkeys, ring_size })
}

// ──────────────────────────────────────────────────────────────────────────────
// POST /dev/zkp_login  – flow ZKP complet côté serveur (pour le frontend JS)
// ──────────────────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct DevZkpLoginRequest {
    email: String,
    password: String,
    site_name: String,
    token_b: String,
    min_age: Option<u8>,
    required_nationality: Option<String>,
}

#[derive(Serialize)]
struct DevZkpLoginResponse {
    verified: bool,
    ring_size: usize,
    client_ring_size: usize,
    proved_claims: Vec<String>,
}

async fn dev_zkp_login(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevZkpLoginRequest>,
) -> Result<Json<DevZkpLoginResponse>, (StatusCode, String)> {
    // 1. Valider + anti-double-spend Token B
    let token_secret = state.read().unwrap().token_secret.clone();
    if !verify_token(&token_secret, "TOKEN_B", &payload.token_b) {
        return Err((StatusCode::PAYMENT_REQUIRED, "Invalid Token B".into()));
    }
    let tv = token_value(&payload.token_b).to_string();
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let exists: bool =
            db.query_row("SELECT COUNT(*) FROM tokens_b_spent WHERE hash = ?1",
                params![tv], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
        if exists {
            return Err((StatusCode::CONFLICT, "Token B already spent".into()));
        }
    }

    // 2. Reconstruire l'identité utilisateur depuis OPRF serveur
    let server_k = state.read().unwrap().k;
    let oprf_result = dev_oprf_eval(server_k, &payload.email, &payload.password);
    let user_identity = Identity::from_oprf(oprf_result);
    let user_pk_hex = user_identity.public_hex();

    // 3. Construire l'anneau utilisateur filtré
    let rows_users: Vec<(String, String, String)> = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT public_key_hex, date_of_birth, nationality FROM users")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap().flatten().collect()
    };
    let filtered_pks: Vec<String> = rows_users.iter()
        .filter(|(_, dob, nat)| {
            let profile = UserData {
                first_name: String::new(),
                last_name: String::new(),
                email: String::new(),
                date_of_birth: dob.clone(),
                nationality: nat.clone(),
            };
            user_passes_filters(&profile, payload.min_age, payload.required_nationality.as_deref())
        })
        .map(|(pk, _, _)| pk.clone())
        .collect();

    let user_signer_idx = filtered_pks.iter().position(|h| h == &user_pk_hex)
        .ok_or((StatusCode::FORBIDDEN, "User not in filtered ring".to_string()))?;

    let user_ring_points: Vec<RistrettoPoint> = filtered_pks.iter()
        .filter_map(|h| {
            let b = hex::decode(h).ok()?;
            let arr: [u8; 32] = b.try_into().ok()?;
            CompressedRistretto::from_slice(&arr).ok()?.decompress()
        })
        .collect();

    if user_ring_points.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "No users match the filters".into()));
    }

    // 4. Construire l'anneau client ZKP_ONLY + récupérer la clé privée du site
    let rows_clients: Vec<(String, String, String)> = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT name, public_key_hex, private_key_hex FROM clients WHERE client_type = 'ZKP_ONLY' ORDER BY id"
        ).unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap().flatten().collect()
    };
    if rows_clients.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "No ZKP_ONLY clients registered".into()));
    }
    let client_signer_idx = rows_clients.iter().position(|(name, _, _)| name == &payload.site_name)
        .ok_or((StatusCode::FORBIDDEN, format!("'{}' is not a registered ZKP_ONLY client", payload.site_name)))?;
    let site_identity = Identity::from_secret_hex(&rows_clients[client_signer_idx].2)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Invalid site private key".into()))?;
    let client_ring_points: Vec<RistrettoPoint> = rows_clients.iter()
        .filter_map(|(_, pub_hex, _)| {
            let b = hex::decode(pub_hex).ok()?;
            let arr: [u8; 32] = b.try_into().ok()?;
            CompressedRistretto::from_slice(&arr).ok()?.decompress()
        })
        .collect();

    // 5. Signer les deux anneaux
    let msg = format!("ZKP_PROOF:{}", payload.token_b);
    let user_sig   = ring::sign(msg.as_bytes(), &user_ring_points,   &user_identity,   user_signer_idx);
    let client_sig = ring::sign(msg.as_bytes(), &client_ring_points, &site_identity,   client_signer_idx);

    // 6. Vérification de cohérence
    if !ring::verify(msg.as_bytes(), &user_ring_points,   &user_sig)   ||
       !ring::verify(msg.as_bytes(), &client_ring_points, &client_sig) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal ring signature failure".into()));
    }

    // 7. Brûler Token B + journaliser
    let ring_size = user_ring_points.len();
    let client_ring_size = client_ring_points.len();
    {
        let mut st = state.write().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute("INSERT OR IGNORE INTO tokens_b_spent (hash) VALUES (?1)", params![tv]);
        }
        st.total_tokens_b_burned += 1;
        let log_claims: Vec<String> = {
            let mut c = vec![];
            if let Some(age) = payload.min_age { c.push(format!("age≥{}", age)); }
            if let Some(ref nat) = &payload.required_nationality { if !nat.is_empty() { c.push(format!("nationality:{}", nat)); } }
            if c.is_empty() { c.push("registered_user".to_string()); }
            c
        };
        st.log("ZKP_VERIFY", "OK", &format!("site={} ring={} claims={}",
            payload.site_name, ring_size, log_claims.join(",")));
        println!("[ZKP][DEV] /dev/zkp_login | site={} user_ring={} client_ring={}",
            payload.site_name, ring_size, client_ring_size);
    }

    let mut proved_claims: Vec<String> = vec![];
    if let Some(age) = payload.min_age {
        proved_claims.push(format!("age≥{}", age));
    }
    if let Some(ref nat) = payload.required_nationality {
        if !nat.is_empty() {
            proved_claims.push(format!("nationality:{}", nat));
        }
    }
    if proved_claims.is_empty() {
        proved_claims.push("registered_user".to_string());
    }

    Ok(Json(DevZkpLoginResponse { verified: true, ring_size, client_ring_size, proved_claims }))
}
