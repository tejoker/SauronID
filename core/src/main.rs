use axum::{
    routing::{get, post},
    extract::{State, Json, Path},
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
        .route("/dev/client/{name}",       get(dev_get_client_detail))
        .route("/dev/client/{name}/users", get(dev_get_client_users))
        .route("/dev/exchange",      post(dev_exchange))
        .route("/dev/buy_tokens",    post(dev_buy_tokens))
        // ZKP
        .route("/zkp/build_ring",    post(handle_build_ring))
        .route("/zkp/verify_proof",  post(handle_verify_proof))
        .route("/zkp/client_ring",   get(handle_zkp_client_ring))
        // DEV ZKP (frontend-friendly — crypto côté serveur)
        .route("/dev/zkp_login",     post(dev_zkp_login))
        // DATA: analytics pré-calculées (stats, forecast, fraud)
        .route("/data/{data_type}/{company_id}", get(data_get).post(data_put))
        .route("/data/companies",    get(data_companies))
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
    /// [MERKLE] Commitment cryptographique du client : SHA256(secret_client) encodé en hex.
    /// Le client conserve son secret ; Sauron s'engage sur le commitment dans l'arbre de Merkle.
    /// Champ optionnel — si absent, la réponse n'inclut pas de preuve Merkle.
    #[serde(default)]
    commitment: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    /// Statut de l'opération.
    status: String,
    /// Token A signé par le serveur : "blind_value:signature"
    /// Le site le stocke et l'utilisera lors de l'échange (Flux 2).
    signed_token_a: String,
    /// [MERKLE] Nouvelle racine de l'arbre de Merkle après insertion du commitment.
    /// Présent uniquement si un `commitment` a été envoyé dans la requête.
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_root: Option<String>,
    /// [MERKLE] Chemin de preuve : hashes frères de la feuille vers la racine (hex).
    /// Le client conserve ces données pour prouver que Sauron a ingéré son KYC.
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_proof: Option<Vec<String>>,
    /// [MERKLE] Index de la feuille dans l'arbre (0-based). Requis pour vérifier la preuve.
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_index: Option<usize>,
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

    // Mettre à jour le groupe en mémoire + signer Token A + insérer le commitment Merkle.
    let signed_token_a;
    let mut merkle_root_out: Option<String> = None;
    let mut merkle_proof_out: Option<Vec<String>> = None;
    let mut leaf_index_out: Option<usize> = None;
    {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);
        let sig = sign_token(&st.token_secret.clone(), "TOKEN_A", &payload.blinded_token_a);
        signed_token_a = format!("{}:{}", payload.blinded_token_a, sig);
        st.total_tokens_a_issued += 1;

        // ── Merkle Commitment Ledger ─────────────────────────────
        if let Some(ref commitment_hex) = payload.commitment {
            match st.merkle_ledger.add_commitment(commitment_hex) {
                Ok(receipt) => {
                    // Persister la feuille en DB pour reconstruction au redémarrage.
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    {
                        let db = st.db.lock().unwrap();
                        let _ = db.execute(
                            "INSERT OR IGNORE INTO merkle_leaves (commitment_hex, registered_at) VALUES (?1, ?2)",
                            params![commitment_hex, ts],
                        );
                    }
                    println!(
                        "[MERKLE] Feuille #{} insérée | root={} | preuves={}",
                        receipt.leaf_index, &receipt.merkle_root[..16], receipt.merkle_proof.len()
                    );
                    merkle_root_out  = Some(receipt.merkle_root);
                    merkle_proof_out = Some(receipt.merkle_proof);
                    leaf_index_out   = Some(receipt.leaf_index);
                }
                Err(e) => {
                    // Le commitment est invalide : on rejette la requête pour éviter
                    // d'accepter un KYC sans pouvoir émettre la preuve.
                    eprintln!("[MERKLE][ERREUR] commitment invalide : {}", e);
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
        // ────────────────────────────────────────────────────────

        st.log("REGISTER", "OK", &hex_ki[..16]);
        println!("[FLUX 1] POST /register | group_size={} token_a_issued={} merkle_leaves={}",
            st.user_group.members.len(), st.total_tokens_a_issued, st.merkle_ledger.len());
    }

    Ok(Json(RegisterResponse {
        status: "success".to_string(),
        signed_token_a,
        merkle_root: merkle_root_out,
        merkle_proof: merkle_proof_out,
        leaf_index: leaf_index_out,
    }))
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
    /// [MERKLE] Commitment optionnel (SHA256 hex). Si absent, le serveur en génère un
    /// automatiquement à partir du key_image (mode démo / seeder).
    #[serde(default)]
    commitment: Option<String>,
}

#[derive(Serialize)]
struct DevRegisterResponse {
    signed_token_a: String,
    public_key_hex: String,
    message: String,
    /// [MERKLE] Nouvelle racine Merkle après insertion du KYC (préparation Solana).
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_root: Option<String>,
    /// [MERKLE] Chemin de preuve Merkle pour ce commitment.
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_proof: Option<Vec<String>>,
    /// [MERKLE] Index de la feuille (0-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_index: Option<usize>,
    /// [MERKLE] Commitment utilisé (auto-généré si non fourni).
    commitment: String,
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

    // 4. Mettre à jour le groupe en mémoire + Merkle.
    let pk_point = user_identity.public;
    let mut merkle_root_out: Option<String> = None;
    let mut merkle_proof_out: Option<Vec<String>> = None;
    let mut leaf_index_out: Option<usize> = None;
    let commitment_used: String;
    let signed_token_a = {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);
        let sig = sign_token(&st.token_secret.clone(), "TOKEN_A", &blinded_token_a);
        let token_a = format!("{}:{}", blinded_token_a, sig);

        // ── Commitment Merkle (client-side simulation) ─────────────────
        // Si le client n'a pas fourni de commitment, on en génère un déterministe
        // à partir du key_image (simulation du comportement client).
        use sha2::{Sha256, Digest as _};
        let effective_commitment = payload.commitment.clone().unwrap_or_else(|| {
            let mut h = Sha256::new();
            h.update(b"DEV_AUTO_COMMITMENT:");
            h.update(hex_ki.as_bytes());
            hex::encode(h.finalize())
        });
        commitment_used = effective_commitment.clone();

        match st.merkle_ledger.add_commitment(&effective_commitment) {
            Ok(receipt) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                {
                    let db = st.db.lock().unwrap();
                    let _ = db.execute(
                        "INSERT OR IGNORE INTO merkle_leaves (commitment_hex, registered_at) VALUES (?1, ?2)",
                        params![effective_commitment, ts],
                    );
                }
                merkle_root_out  = Some(receipt.merkle_root);
                merkle_proof_out = Some(receipt.merkle_proof);
                leaf_index_out   = Some(receipt.leaf_index);
            }
            Err(e) => {
                eprintln!("[MERKLE][DEV][WARN] commitment invalide ou doublon : {}", e);
            }
        }
        // ──────────────────────────────────────────────────

        // 5. Incrémenter le solde Token A du client + enregistrer la relation.
        if !payload.site_name.is_empty() {
            {
                let db = st.db.lock().unwrap();
                let _ = db.execute(
                    "UPDATE clients SET tokens_a = tokens_a + 1 WHERE name = ?1",
                    params![payload.site_name],
                );
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                let _ = db.execute(
                    "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp)
                     VALUES (?1, ?2, 'register', ?3)",
                    params![payload.site_name, hex_ki, ts],
                );
            }
            st.total_tokens_a_issued += 1;
        }

        st.log("DEV_REGISTER", "OK", &hex_ki[..16]);
        println!("[FLUX 1][DEV] register_user | email={} | site={} | group_size={} | merkle_leaves={}",
            payload.email, payload.site_name, st.user_group.members.len(), st.merkle_ledger.len());
        token_a
    };

    Ok(Json(DevRegisterResponse {
        signed_token_a,
        public_key_hex: hex_pk,
        message: format!("{} registered (dev)", payload.email),
        merkle_root: merkle_root_out,
        merkle_proof: merkle_proof_out,
        leaf_index: leaf_index_out,
        commitment: commitment_used,
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

    // 5. Brûler le Token B + décrémenter solde du client.
    let tv = token_value(&payload.token_b).to_string();
    {
        let mut st = state.write().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute("INSERT OR IGNORE INTO tokens_b_spent (hash) VALUES (?1)", params![tv]);
            if !payload.site_name.is_empty() {
                let _ = db.execute(
                    "UPDATE clients SET tokens_b = MAX(0, tokens_b - 1) WHERE name = ?1",
                    params![payload.site_name],
                );
                // Enregistrer la relation user→client (kyc_retrieval)
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                let _ = db.execute(
                    "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp)
                     VALUES (?1, ?2, 'kyc_retrieval', ?3)",
                    params![payload.site_name, hex_ki, ts],
                );
            }
        }
        st.total_tokens_b_burned += 1;
        st.log("DEV_GET_KYC", "OK", &payload.email);
        println!("[DEV/FLUX3] get_kyc | site={} email={} | total_consumed={}",
            payload.site_name, payload.email, st.total_tokens_b_burned);
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
    tokens_a:        i64,
    tokens_b:        i64,
}

async fn dev_get_clients(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<DevClientRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT name, public_key_hex, private_key_hex, key_image_hex, client_type, tokens_a, tokens_b FROM clients ORDER BY id"
    ).unwrap();
    let records: Vec<DevClientRecord> = stmt.query_map([], |row| {
        Ok(DevClientRecord {
            name:            row.get(0)?,
            public_key_hex:  row.get(1)?,
            private_key_hex: row.get(2)?,
            key_image_hex:   row.get(3)?,
            client_type:     row.get(4)?,
            tokens_a:        row.get(5)?,
            tokens_b:        row.get(6)?,
        })
    }).unwrap().flatten().collect();
    Json(records)
}

// ─────────────────────────────────────────────────────
//  GET /dev/client/{name} — détails + soldes d'un client
// ─────────────────────────────────────────────────────

async fn dev_get_client_detail(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(name): Path<String>,
) -> Result<Json<DevClientRecord>, StatusCode> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    db.query_row(
        "SELECT name, public_key_hex, private_key_hex, key_image_hex, client_type, tokens_a, tokens_b
         FROM clients WHERE name = ?1",
        params![name],
        |row| Ok(DevClientRecord {
            name:            row.get(0)?,
            public_key_hex:  row.get(1)?,
            private_key_hex: row.get(2)?,
            key_image_hex:   row.get(3)?,
            client_type:     row.get(4)?,
            tokens_a:        row.get(5)?,
            tokens_b:        row.get(6)?,
        }),
    ).map(Json).map_err(|_| StatusCode::NOT_FOUND)
}

// ─────────────────────────────────────────────────────
//  GET /dev/client/{name}/users — utilisateurs associés à un client
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct ClientUserRecord {
    first_name: String,
    last_name:  String,
    email:      String,
    nationality: String,
    source:     String,
    timestamp:  i64,
}

async fn dev_get_client_users(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(name): Path<String>,
) -> Json<Vec<ClientUserRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT u.first_name, u.last_name, u.email, u.nationality, r.source, r.timestamp
         FROM user_registrations r
         JOIN users u ON u.key_image_hex = r.user_key_image_hex
         WHERE r.client_name = ?1
         ORDER BY r.timestamp DESC"
    ).unwrap();
    let records: Vec<ClientUserRecord> = stmt.query_map(params![name], |row| {
        Ok(ClientUserRecord {
            first_name:  row.get(0)?,
            last_name:   row.get(1)?,
            email:       row.get(2)?,
            nationality: row.get(3)?,
            source:      row.get(4)?,
            timestamp:   row.get(5)?,
        })
    }).unwrap().flatten().collect();
    Json(records)
}

// ─────────────────────────────────────────────────────
//  POST /dev/exchange — échange simplifié Token A → Token B (soldes DB)
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DevExchangeRequest {
    site_name: String,
    count: i64,
}

#[derive(Serialize)]
struct DevExchangeResponse {
    tokens_a_burned: i64,
    tokens_b_received: i64,
    new_tokens_a: i64,
    new_tokens_b: i64,
}

async fn dev_exchange(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevExchangeRequest>,
) -> Result<Json<DevExchangeResponse>, (StatusCode, String)> {
    if payload.count < 1 {
        return Err((StatusCode::BAD_REQUEST, "count must be >= 1".into()));
    }

    let rate;
    {
        let st = state.read().unwrap();
        rate = st.token_a_to_b_rate as i64;
    }
    let tokens_b_to_add = payload.count * rate;

    let mut st = state.write().unwrap();
    let db = st.db.lock().unwrap();

    // Vérifier le solde Token A du client
    let current_a: i64 = db.query_row(
        "SELECT tokens_a FROM clients WHERE name = ?1",
        params![payload.site_name],
        |row| row.get(0),
    ).map_err(|_| (StatusCode::NOT_FOUND, format!("Client '{}' not found", payload.site_name)))?;

    if current_a < payload.count {
        return Err((StatusCode::BAD_REQUEST,
            format!("Not enough Token A: have {}, need {}", current_a, payload.count)));
    }

    // Effectuer l'échange
    let _ = db.execute(
        "UPDATE clients SET tokens_a = tokens_a - ?1, tokens_b = tokens_b + ?2 WHERE name = ?3",
        params![payload.count, tokens_b_to_add, payload.site_name],
    );

    let (new_a, new_b): (i64, i64) = db.query_row(
        "SELECT tokens_a, tokens_b FROM clients WHERE name = ?1",
        params![payload.site_name],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();

    drop(db);
    st.total_tokens_a_burned += payload.count as usize;
    st.total_tokens_b_issued += tokens_b_to_add as usize;
    st.log("EXCHANGE", "OK", &format!("site={} burned={} received={}", payload.site_name, payload.count, tokens_b_to_add));
    println!("[FLUX 2][DEV] exchange | site={} | burned={}A → received={}B",
        payload.site_name, payload.count, tokens_b_to_add);

    Ok(Json(DevExchangeResponse {
        tokens_a_burned: payload.count,
        tokens_b_received: tokens_b_to_add,
        new_tokens_a: new_a,
        new_tokens_b: new_b,
    }))
}

// ─────────────────────────────────────────────────────
//  POST /dev/buy_tokens — achat direct de Token B (fiat simulé)
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DevBuyTokensRequest {
    site_name: String,
    amount: i64,
}

#[derive(Serialize)]
struct DevBuyTokensResponse {
    tokens_b_added: i64,
    new_tokens_b: i64,
}

async fn dev_buy_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevBuyTokensRequest>,
) -> Result<Json<DevBuyTokensResponse>, (StatusCode, String)> {
    if payload.amount < 1 || payload.amount > 10_000 {
        return Err((StatusCode::BAD_REQUEST, "amount must be 1..10000".into()));
    }

    let mut st = state.write().unwrap();
    let db = st.db.lock().unwrap();

    let _ = db.execute(
        "UPDATE clients SET tokens_b = tokens_b + ?1 WHERE name = ?2",
        params![payload.amount, payload.site_name],
    );

    let new_b: i64 = db.query_row(
        "SELECT tokens_b FROM clients WHERE name = ?1",
        params![payload.site_name],
        |row| row.get(0),
    ).map_err(|_| (StatusCode::NOT_FOUND, format!("Client '{}' not found", payload.site_name)))?;

    drop(db);
    st.total_tokens_b_issued += payload.amount as usize;
    st.log("BUY_TOKENS", "OK", &format!("site={} amount={}", payload.site_name, payload.amount));
    println!("[DEV] buy_tokens | site={} | amount={}", payload.site_name, payload.amount);

    Ok(Json(DevBuyTokensResponse {
        tokens_b_added: payload.amount,
        new_tokens_b: new_b,
    }))
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

    // 7. Brûler Token B + décrémenter solde client + journaliser
    let ring_size = user_ring_points.len();
    let client_ring_size = client_ring_points.len();
    {
        let mut st = state.write().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute("INSERT OR IGNORE INTO tokens_b_spent (hash) VALUES (?1)", params![tv]);
            let _ = db.execute(
                "UPDATE clients SET tokens_b = MAX(0, tokens_b - 1) WHERE name = ?1",
                params![payload.site_name],
            );
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

// ─────────────────────────────────────────────────────
//  DATA: Analytics pré-calculées (stats, forecast, fraud)
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DataPayload {
    data: serde_json::Value,
}

/// GET /data/{data_type}/{company_id} — renvoie le blob JSON stocké.
async fn data_get(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path((data_type, company_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let valid = ["stats", "forecast", "fraud_summary", "fraud_recent"];
    if !valid.contains(&data_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("data_type must be one of: {:?}", valid)));
    }
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let result: Result<String, _> = db.query_row(
        "SELECT data_json FROM company_data WHERE company_id = ?1 AND data_type = ?2",
        params![company_id, data_type],
        |row| row.get(0),
    );
    match result {
        Ok(json_str) => {
            let val: serde_json::Value = serde_json::from_str(&json_str)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Bad JSON in DB: {e}")))?;
            Ok(Json(val))
        }
        Err(_) => Err((StatusCode::NOT_FOUND, format!("No {data_type} data for company {company_id}"))),
    }
}

/// POST /data/{data_type}/{company_id} — stocke un blob JSON (pour le seed).
async fn data_put(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path((data_type, company_id)): Path<(String, i64)>,
    Json(payload): Json<DataPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let valid = ["stats", "forecast", "fraud_summary", "fraud_recent"];
    if !valid.contains(&data_type.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("data_type must be one of: {:?}", valid)));
    }
    let json_str = serde_json::to_string(&payload.data)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}")))?;
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    db.execute(
        "INSERT OR REPLACE INTO company_data (company_id, data_type, data_json) VALUES (?1, ?2, ?3)",
        params![company_id, data_type, json_str],
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(Json(serde_json::json!({"ok": true, "company_id": company_id, "data_type": data_type})))
}

/// GET /data/companies — liste tous les company_id qui ont des données.
async fn data_companies(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT DISTINCT company_id FROM company_data ORDER BY company_id"
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let ids: Vec<i64> = stmt.query_map([], |row| row.get(0))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(Json(serde_json::json!({"company_ids": ids})))
}