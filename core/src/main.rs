use axum::{
    body::{to_bytes, Body},
    routing::{get, post, delete},
    extract::{Request, State, Json, Path},
    http::{StatusCode, HeaderMap},
    Router,
    middleware,
};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use rusqlite::params;
use sauron_core::{oprf, ring, state::{ServerState, verify_token, token_value, sign_token}, admin};
use sauron_core::{identity::{Identity, UserData}, db, agent};
use sauron_core::policy::{self, AssuranceLevel};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use sha2::{Sha256, Sha512, Digest};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

type HmacSha256 = Hmac<Sha256>;

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
        // Flux 1: dépôt KYC
        .route("/register",          post(handle_register))
        .route("/bank/register",     post(bank_register_user))
        .route("/register/bank",     post(bank_register_user))
        // Utilitaire: clés publiques du groupe utilisateurs
        .route("/group",             get(handle_get_group))
        .nest("/admin", admin_routes)
        // DEV: endpoints sans crypto côté frontend
        .route("/dev/register_user", post(dev_register_user))
        .route("/dev/sites",         get(dev_get_sites))
        .route("/dev/clients",       get(dev_get_clients))
        .route("/dev/client/{name}",       get(dev_get_client_detail))
        .route("/dev/client/{name}/users", get(dev_get_client_users))
        .route("/dev/buy_tokens",    post(dev_buy_tokens))
        // ZKP
        .route("/zkp/build_ring",    post(handle_build_ring))
        .route("/zkp/verify_proof",  post(handle_verify_proof))
        .route("/zkp/proof_material", post(handle_zkp_proof_material))
        .route("/zkp/client_ring",   get(handle_zkp_client_ring))
        // DEV ZKP (frontend-friendly — crypto côté serveur)
        .route("/dev/zkp_login",     post(dev_zkp_login))
        // A-JWT Agentic Layer
        .route("/agent/register",                        post(agent::register_agent))
        .route("/agent/verify",                          post(agent::verify_agent_token))
        .route("/policy/authorize",                      post(policy_authorize))
        .route("/agent/list/{human_key_image}",          get(agent::list_agents))
        .route("/agent/{agent_id}",                      get(agent::get_agent).delete(agent::revoke_agent))
        // User consent flow (KYC retrieval with explicit user consent)
        .route("/kyc/request",                           post(kyc_request))
        .route("/kyc/consent",                           post(kyc_consent))
        .route("/kyc/consent_info/{request_id}",         get(kyc_consent_info))
        .route(
            "/kyc/retrieve",
            post(kyc_retrieve).route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                delegated_agent_binding_middleware,
            )),
        )
        // Trusted device (silent re-auth)
        .route("/auth/device/issue",  post(device_issue))
        .route("/auth/device/check",  post(device_check))
        // User self-service (manage own consents + agents)
        .route("/user/auth",          post(user_auth))
        .route("/user/consents",      get(user_consents))
        .route("/user/profile",       get(user_profile))
        .route("/user/credential",    get(user_get_credential))
        .route("/user/consent/{request_id}", delete(user_revoke_consent))
        // Agent KYC consent flow (agent acts on behalf of human)
        .route("/agent/kyc/consent",  post(agent_kyc_consent))
        // Self-sovereign agent VC (KYA without banks)
        .route("/agent/vc/issue",     post(agent_vc_issue))
        // DATA: analytics pré-calculées (stats, forecast, fraud)
        .route("/data/{data_type}/{company_id}", get(data_get).post(data_put))
        .route("/data/companies",    get(data_companies))
        .layer({
            let allowed_origins: Vec<axum::http::HeaderValue> = std::env::var("SAURON_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:3001".to_string())
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if allowed_origins.is_empty() {
                CorsLayer::permissive()
            } else {
                CorsLayer::new()
                    .allow_origin(allowed_origins)
                    .allow_methods(tower_http::cors::Any)
                    .allow_headers(tower_http::cors::Any)
            }
        })
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
    /// Ring Signature du site partenaire sur le message = hex(public_key).
    /// Prouve qu'un client légitime soumet ce KYC — mais lequel reste anonyme.
    client_signature: ring::RingSignature,
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

#[derive(Deserialize)]
struct BankRegisterRequest {
    /// Registered BANK client name (must exist in clients table).
    bank_client_name: String,
    /// Optional bank-side customer identifier.
    #[serde(default)]
    bank_customer_id: Option<String>,
    /// User Ristretto public key (compressed hex).
    public_key_hex: String,
    /// User key image (compressed hex) used as stable identity handle.
    key_image_hex: String,
    first_name: String,
    last_name: String,
    email: String,
    date_of_birth: String,
    nationality: String,
    /// HMAC-SHA256 signature over canonical payload.
    attestation_signature: String,
    /// Unix timestamp issued by bank.
    attestation_issued_at: i64,
    /// Replay-protection nonce.
    attestation_nonce: String,
}

#[derive(Serialize)]
struct BankRegisterResponse {
    status: String,
    bank_client_name: String,
    key_image_hex: String,
    user_preexisting: bool,
}

fn bank_provider_secret(bank_client_name: &str) -> Option<String> {
    let raw = std::env::var("BANK_PROVIDER_SECRETS_JSON").ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed
        .get(bank_client_name)
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn bank_attestation_payload(req: &BankRegisterRequest) -> String {
    [
        req.bank_client_name.clone(),
        req.bank_customer_id.clone().unwrap_or_default(),
        req.key_image_hex.clone(),
        req.public_key_hex.clone(),
        req.first_name.clone(),
        req.last_name.clone(),
        req.email.clone(),
        req.date_of_birth.clone(),
        req.nationality.to_uppercase(),
        req.attestation_issued_at.to_string(),
        req.attestation_nonce.clone(),
    ]
    .join("|")
}

fn verify_bank_attestation(req: &BankRegisterRequest) -> Result<(), (StatusCode, String)> {
    if req.attestation_signature.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "attestation_signature required".into()));
    }
    if req.attestation_nonce.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "attestation_nonce required".into()));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    if (now - req.attestation_issued_at).abs() > 300 {
        return Err((StatusCode::UNAUTHORIZED, "attestation_issued_at outside 5-minute skew".into()));
    }

    let secret = bank_provider_secret(&req.bank_client_name)
        .ok_or((StatusCode::UNAUTHORIZED, "unknown bank_client_name in BANK_PROVIDER_SECRETS_JSON".into()))?;

    let sig = hex::decode(req.attestation_signature.trim())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "attestation_signature must be hex-encoded HMAC".into()))?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "failed to initialize HMAC".into()))?;
    mac.update(bank_attestation_payload(req).as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid bank attestation signature".into()))
}

async fn bank_register_user(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<BankRegisterRequest>,
) -> Result<Json<BankRegisterResponse>, (StatusCode, String)> {
    if payload.bank_client_name.is_empty()
        || payload.public_key_hex.is_empty()
        || payload.key_image_hex.is_empty()
    {
        return Err((StatusCode::BAD_REQUEST, "bank_client_name, public_key_hex and key_image_hex are required".into()));
    }

    let pk_bytes = hex::decode(&payload.public_key_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "public_key_hex must be valid hex".into()))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "public_key_hex must be 32-byte compressed Ristretto point".into()))?;
    let pk_point = CompressedRistretto(pk_arr)
        .decompress()
        .ok_or((StatusCode::BAD_REQUEST, "public_key_hex is not a valid Ristretto point".into()))?;

    let ki_bytes = hex::decode(&payload.key_image_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "key_image_hex must be valid hex".into()))?;
    if ki_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "key_image_hex must be 32 bytes".into()));
    }

    // Verify caller is known BANK client.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let bank_exists: bool = db
            .query_row(
                "SELECT COUNT(*) FROM clients WHERE name = ?1 AND client_type = 'BANK'",
                params![payload.bank_client_name],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if !bank_exists {
            return Err((StatusCode::FORBIDDEN, "bank_client_name is not a registered BANK client".into()));
        }
    }

    verify_bank_attestation(&payload)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let nationality = payload.nationality.to_uppercase();
    let user_preexisting = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();

        let exists: bool = db
            .query_row(
                "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
                params![payload.key_image_hex],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        let nonce_used: bool = db
            .query_row(
                "SELECT COUNT(*) FROM bank_attestation_nonces WHERE provider_id = ?1 AND nonce = ?2",
                params![payload.bank_client_name, payload.attestation_nonce],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if nonce_used {
            return Err((StatusCode::CONFLICT, "Replay detected for bank attestation nonce".into()));
        }

        db.execute(
            "INSERT INTO bank_attestation_nonces (provider_id, nonce, issued_at) VALUES (?1, ?2, ?3)",
            params![payload.bank_client_name, payload.attestation_nonce, payload.attestation_issued_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        db.execute(
            "INSERT INTO users (key_image_hex, public_key_hex, first_name, last_name, email, date_of_birth, nationality)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(key_image_hex) DO UPDATE SET
                 public_key_hex = excluded.public_key_hex,
                 first_name = excluded.first_name,
                 last_name = excluded.last_name,
                 email = excluded.email,
                 date_of_birth = excluded.date_of_birth,
                 nationality = excluded.nationality",
            params![
                payload.key_image_hex,
                payload.public_key_hex,
                payload.first_name,
                payload.last_name,
                payload.email,
                payload.date_of_birth,
                nationality,
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if let Some(bank_customer_id) = payload
            .bank_customer_id
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            let metadata = serde_json::json!({
                "source": "bank_webhook",
                "bank_client_name": payload.bank_client_name,
                "attestation_nonce": payload.attestation_nonce,
            })
            .to_string();
            db.execute(
                "INSERT OR REPLACE INTO bank_kyc_links (bank_customer_id, user_key_image, updated_at, metadata_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![bank_customer_id, payload.key_image_hex, now, metadata],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        let _ = db.execute(
            "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp)
             VALUES (?1, ?2, 'bank_webhook', ?3)",
            params![payload.bank_client_name, payload.key_image_hex, now],
        );

        exists
    };

    {
        let mut st = state.write().unwrap();
        if !st.user_group.members.contains(&pk_point) {
            st.user_group.members.push(pk_point);
        }
    }

    {
        let st = state.read().unwrap();
        let short_ki: String = payload.key_image_hex.chars().take(16).collect();
        st.log(
            "BANK_REGISTER",
            "OK",
            &format!("bank={} user={}", payload.bank_client_name, short_ki),
        );
    }

    Ok(Json(BankRegisterResponse {
        status: "success".to_string(),
        bank_client_name: payload.bank_client_name,
        key_image_hex: payload.key_image_hex,
        user_preexisting,
    }))
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
    let msg = hex_pk.clone();

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

    // Mettre à jour le groupe en mémoire + insérer le commitment Merkle.
    let mut merkle_root_out: Option<String> = None;
    let mut merkle_proof_out: Option<Vec<String>> = None;
    let mut leaf_index_out: Option<usize> = None;
    {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);

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
        println!("[FLUX 1] POST /register | group_size={} merkle_leaves={}",
            st.user_group.members.len(), st.merkle_ledger.len());
    }

    // ── Ancrage Solana (non-bloquant) ─────────────────────────────────────
    // Si une nouvelle root Merkle a été calculée ET que le service Solana est
    // configuré, on publie la root on-chain dans un task séparé (fire & forget).
    // Une erreur réseau Solana ne doit jamais faire échouer l'API KYC.
    if let Some(ref root_hex) = merkle_root_out {
        if let Ok(root_bytes) = hex::decode(root_hex) {
            if root_bytes.len() == 32 {
                let root_arr: [u8; 32] = root_bytes.try_into().unwrap();
                let st = state.read().unwrap();
                if let Some(ref svc) = st.solana_service {
                    let svc = svc.clone();
                    tokio::spawn(async move {
                        match svc.publish_new_root(root_arr).await {
                            Ok(sig) => println!(
                                "[SOLANA] ✓ Root anchée on-chain | tx={}",
                                &sig[..20]
                            ),
                            Err(e) => eprintln!(
                                "[SOLANA] ⚠ publish_new_root échoué (non-fatal) : {}", e
                            ),
                        }
                    });
                }
            }
        }
    }
    // ─────────────────────────────────────────────────────────────────────

    Ok(Json(RegisterResponse {
        status: "success".to_string(),
        merkle_root: merkle_root_out,
        merkle_proof: merkle_proof_out,
        leaf_index: leaf_index_out,
    }))
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

    // 2. Persister dans la DB.
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

    // 3. Mettre à jour le groupe en mémoire + Merkle.
    let pk_point = user_identity.public;
    let mut merkle_root_out: Option<String> = None;
    let mut merkle_proof_out: Option<Vec<String>> = None;
    let mut leaf_index_out: Option<usize> = None;
    let commitment_used: String;
    {
        let mut st = state.write().unwrap();
        st.user_group.add_member(pk_point);

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

        // 4. Enregistrer la relation client→utilisateur.
        if !payload.site_name.is_empty() {
            {
                let db = st.db.lock().unwrap();
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                let _ = db.execute(
                    "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp)
                     VALUES (?1, ?2, 'register', ?3)",
                    params![payload.site_name, hex_ki, ts],
                );
            }
        }

        st.log("DEV_REGISTER", "OK", &hex_ki[..16]);
        println!("[FLUX 1][DEV] register_user | email={} | site={} | group_size={} | merkle_leaves={}",
            payload.email, payload.site_name, st.user_group.members.len(), st.merkle_ledger.len());
    }

    // ── Ancrage Solana (non-bloquant) ─────────────────────────────────────
    if let Some(ref root_hex) = merkle_root_out {
        if let Ok(root_bytes) = hex::decode(root_hex) {
            if root_bytes.len() == 32 {
                let root_arr: [u8; 32] = root_bytes.try_into().unwrap();
                let st = state.read().unwrap();
                if let Some(ref svc) = st.solana_service {
                    let svc = svc.clone();
                    tokio::spawn(async move {
                        match svc.publish_new_root(root_arr).await {
                            Ok(sig) => println!(
                                "[SOLANA][DEV] ✓ Root anchée | tx={}",
                                &sig[..20]
                            ),
                            Err(e) => eprintln!(
                                "[SOLANA][DEV] ⚠ publish échoué (non-fatal) : {}", e
                            ),
                        }
                    });
                }
            }
        }
    }

    // ── ZKP Credential Issuance (non-bloquant) ───────────────────────────────
    // Appel asynchrone au service issuer pour pré-autoriser l'émission d'un
    // credential BabyJubJub signé. L'utilisateur pourra ensuite récupérer son
    // credential et générer des preuves Groth16 côté client.
    // Une erreur du service issuer n'empêche pas l'enregistrement.
    {
        let issuer_url = state.read().unwrap().issuer_url.clone();
        let subject_did = format!("did:sauron:user:{}", &hex_ki[..16]);
        let dob = payload.date_of_birth.clone();
        let nat = payload.nationality.clone();
        let state2 = Arc::clone(&state);
        let hex_ki2 = hex_ki.clone();
        tokio::spawn(async move {
            let body = serde_json::json!({
                "subjectDid": subject_did,
                "claims": {
                    "date_of_birth": dob,
                    "nationality": nat,
                    "document_number": "000000",
                    "expiry_date": "2030-12-31",
                }
            });
            match reqwest::Client::new()
                .post(&format!("{}/register-credential", issuer_url))
                .json(&body)
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    if let Ok(data) = r.json::<serde_json::Value>().await {
                        if let Some(code) = data.get("pre-authorized_code").and_then(|v| v.as_str()) {
                            // Store code in DB so /user/credential can claim it later.
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                            if let Ok(db) = state2.read().unwrap().db.lock() {
                                let _ = db.execute(
                                    "INSERT OR REPLACE INTO credential_codes
                                     (key_image_hex, pre_auth_code, subject_did, issued_at, claimed)
                                     VALUES (?1,?2,?3,?4,0)",
                                    params![hex_ki2, code, subject_did, ts],
                                );
                            }
                            println!("[ZKP] Credential pre-auth stored for {} | code={}",
                                &subject_did, &code[..8]);
                        }
                    }
                }
                Ok(r) => eprintln!("[ZKP][WARN] /register-credential returned {} (non-fatal)", r.status()),
                Err(e) => eprintln!("[ZKP][WARN] Issuer unreachable (non-fatal): {}", e),
            }
        });
    }
    // ─────────────────────────────────────────────────────────────────────────

    Ok(Json(DevRegisterResponse {
        public_key_hex: hex_pk,
        message: format!("{} registered", payload.email),
        merkle_root: merkle_root_out,
        merkle_proof: merkle_proof_out,
        leaf_index: leaf_index_out,
        commitment: commitment_used,
    }))
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
    name:           String,
    public_key_hex: String,
    key_image_hex:  String,
    tokens_b:       i64,
    client_type:    String,
}

async fn dev_get_clients(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Vec<DevClientRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT name, public_key_hex, key_image_hex, tokens_b, client_type FROM clients ORDER BY id"
    ).unwrap();
    let records: Vec<DevClientRecord> = stmt.query_map([], |row| {
        Ok(DevClientRecord {
            name:           row.get(0)?,
            public_key_hex: row.get(1)?,
            key_image_hex:  row.get(2)?,
            tokens_b:       row.get(3)?,
            client_type:    row.get(4)?,
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
        "SELECT name, public_key_hex, key_image_hex, tokens_b, client_type
         FROM clients WHERE name = ?1",
        params![name],
        |row| Ok(DevClientRecord {
            name:           row.get(0)?,
            public_key_hex: row.get(1)?,
            key_image_hex:  row.get(2)?,
            tokens_b:       row.get(3)?,
            client_type:    row.get(4)?,
        }),
    ).map(Json).map_err(|_| StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct DevBuyTokensBody {
    site_name: String,
    amount: i64,
}

async fn dev_buy_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevBuyTokensBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.site_name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "site_name required".into()));
    }
    if payload.amount <= 0 {
        return Err((StatusCode::BAD_REQUEST, "amount must be > 0".into()));
    }

    let (rows, new_tokens_b) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let rows = db
            .execute(
                "UPDATE clients SET tokens_b = tokens_b + ?1 WHERE name = ?2",
                params![payload.amount, payload.site_name],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let balance: i64 = db
            .query_row(
                "SELECT tokens_b FROM clients WHERE name = ?1",
                params![payload.site_name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (rows, balance)
    };

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "client not found".into()));
    }

    {
        let st = state.read().unwrap();
        st.log(
            "BUY_TOKENS",
            "OK",
            &format!("site={} amount={}", payload.site_name, payload.amount),
        );
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "site_name": payload.site_name,
        "amount": payload.amount,
        "new_tokens_b": new_tokens_b,
    })))
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
    #[allow(dead_code)]
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
    // 1. Vérifier la ring signature du client ZKP_ONLY.
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

    if verified {
        let st = state.read().unwrap();
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        if let Ok(db) = st.db.lock() {
            let _ = db.execute(
                "INSERT INTO api_usage (client_name, action, is_agent, timestamp) VALUES ('_zkp','zkp_login',0,?1)",
                params![ts],
            );
        }
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

#[derive(Deserialize)]
struct ZkpProofMaterialRequest {
    #[serde(default)]
    credential_hash: Option<String>,
    #[serde(default)]
    leaf_index: Option<usize>,
}

async fn handle_zkp_proof_material(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ZkpProofMaterialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let issuer_url = state.read().unwrap().issuer_url.clone();
    let body = serde_json::json!({
        "credentialHash": payload.credential_hash,
        "leafIndex": payload.leaf_index,
    });
    let response = reqwest::Client::new()
        .post(format!("{issuer_url}/proof-material"))
        .json(&body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer unreachable: {e}")))?;

    if !response.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Issuer proof-material failed: {}",
                response.text().await.unwrap_or_default()
            ),
        ));
    }

    let data = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer payload parse error: {e}")))?;
    Ok(Json(data))
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
    // 1. Reconstruire l'identité utilisateur depuis OPRF serveur
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

    // 6. Journaliser
    let ring_size = user_ring_points.len();
    let client_ring_size = client_ring_points.len();
    {
        let st = state.read().unwrap();
        let log_claims: Vec<String> = {
            let mut c = vec![];
            if let Some(age) = payload.min_age { c.push(format!("age≥{}", age)); }
            if let Some(ref nat) = &payload.required_nationality { if !nat.is_empty() { c.push(format!("nationality:{}", nat)); } }
            if c.is_empty() { c.push("registered_user".to_string()); }
            c
        };
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        if let Ok(db) = st.db.lock() {
            let _ = db.execute(
                "INSERT INTO api_usage (client_name, action, is_agent, timestamp) VALUES (?1,'zkp_login',0,?2)",
                params![payload.site_name, ts],
            );
        }
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

// ─────────────────────────────────────────────────────
//  Phase 2: User Consent Flow
//
//  OAuth-style popup: retail site requests consent, user approves in a Sauron
//  popup, site retrieves KYC using a one-time consent_token.
//
//  POST /kyc/request       — site asks for user consent (returns request_id + popup URL)
//  GET  /kyc/consent_info  — consent page fetches request info (site name, claims)
//  POST /kyc/consent       — user approves (email+password, dev mode)
//  POST /kyc/retrieve      — site retrieves KYC using the consent_token
// ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct DelegatedAgentBinding {
    agent_id: String,
    human_key_image: String,
}

async fn delegated_agent_binding_middleware(
    State(state): State<Arc<RwLock<ServerState>>>,
    request: Request,
    next: middleware::Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Unable to read request body".to_string()))?;

    let payload: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid JSON body".to_string()))?;

    let consent_token = payload
        .get("consent_token")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "consent_token is required".to_string()))?
        .to_string();

    let (user_key_image, issuing_agent_id) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT user_key_image, issuing_agent_id FROM consent_log WHERE consent_token = ?1 AND revoked = 0",
            params![consent_token],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or revoked consent token".to_string()))?
    };

    let mut request = Request::from_parts(parts, Body::from(body_bytes));

    if let Some(expected_agent_id) = issuing_agent_id {
        let ajwt = request
            .headers()
            .get("x-agent-ajwt")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "x-agent-ajwt header required for delegated consent".to_string()))?;

        let jwt_secret = state.read().unwrap().jwt_secret.clone();
        let claims = agent::verify_ajwt(&jwt_secret, ajwt)
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".to_string()))?;

        let claim_agent_id = claims
            .get("agent_id")
            .and_then(|v| v.as_str())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".to_string()))?
            .to_string();
        let claim_human_key_image = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".to_string()))?
            .to_string();

        if claim_agent_id != expected_agent_id {
            return Err((
                StatusCode::UNAUTHORIZED,
                "A-JWT agent_id does not match delegated consent issuer".to_string(),
            ));
        }

        if claim_human_key_image != user_key_image {
            return Err((
                StatusCode::UNAUTHORIZED,
                "A-JWT subject does not match consent owner".to_string(),
            ));
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let (db_human, revoked, expires_at, agent_pub_hex): (String, i64, i64, String) = {
            let st = state.read().unwrap();
            let db = st.db.lock().unwrap();
            db.query_row(
                "SELECT human_key_image, revoked, expires_at, public_key_hex FROM agents WHERE agent_id = ?1",
                params![claim_agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Agent not found".to_string()))?
        };

        if revoked != 0 || expires_at < now || db_human != claim_human_key_image {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (revoked, expired, or owner mismatch)".to_string(),
            ));
        }

        if agent_pub_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (agent missing ring public key)".to_string(),
            ));
        }

        let agent_in_ring = {
            let st = state.read().unwrap();
            let bytes = hex::decode(&agent_pub_hex)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Delegated agent binding failed (invalid public key encoding)".to_string()))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Delegated agent binding failed (invalid public key length)".to_string()))?;
            let pt = CompressedRistretto(arr)
                .decompress()
                .ok_or((StatusCode::UNAUTHORIZED, "Delegated agent binding failed (invalid public key point)".to_string()))?;
            st.agent_group.members.contains(&pt)
        };

        if !agent_in_ring {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (agent not in delegated ring)".to_string(),
            ));
        }

        request.extensions_mut().insert(DelegatedAgentBinding {
            agent_id: claim_agent_id,
            human_key_image: claim_human_key_image,
        });
    }

    Ok(next.run(request).await)
}

#[derive(Deserialize)]
struct KycRequestBody {
    /// Name of the site requesting consent.
    site_name: String,
    /// ZKP claim assertions the site wants to receive.
    #[serde(default)]
    requested_claims: Vec<String>,
    /// Optional redirect URL to postMessage the consent_token back to.
    #[serde(default)]
    #[allow(dead_code)]
    redirect_origin: String,
}

#[derive(Serialize)]
struct KycRequestResponse {
    request_id: String,
    consent_url: String,
    expires_at: i64,
}

fn is_supported_zkp_claim(claim: &str) -> bool {
    matches!(
        claim,
        "age_over_threshold"
            | "age_threshold"
            | "credential_valid"
            | "nationality_match"
            | "merkle_inclusion"
    )
}

fn normalize_requested_claims(mut claims: Vec<String>) -> Result<Vec<String>, Vec<String>> {
    if claims.is_empty() {
        claims = vec!["age_over_threshold".to_string(), "age_threshold".to_string()];
    }
    let unsupported: Vec<String> = claims
        .iter()
        .filter(|claim| !is_supported_zkp_claim(claim))
        .cloned()
        .collect();
    if !unsupported.is_empty() {
        return Err(unsupported);
    }
    Ok(claims)
}

async fn kyc_request(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<KycRequestBody>,
) -> Result<Json<KycRequestResponse>, (StatusCode, String)> {
    if payload.site_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "site_name required".into()));
    }

    let requested_claims = normalize_requested_claims(payload.requested_claims).map_err(|unsupported| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "requested_claims must be ZKP assertions only. Unsupported: {:?}",
                unsupported
            ),
        )
    })?;

    // Mandatory ZKP-only mode: only ZKP_ONLY relying parties may open consent requests.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT COUNT(*) FROM clients WHERE name = ?1 AND client_type = 'ZKP_ONLY'",
            params![payload.site_name],
            |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if !exists {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Site '{}' must be registered as ZKP_ONLY for consent retrieval",
                    payload.site_name
                ),
            ));
        }
    }

    // Generate request_id
    use sha2::{Sha256, Digest as _};
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut h = Sha256::new();
    h.update(payload.site_name.as_bytes());
    h.update(&ts.to_le_bytes());
    let request_id = hex::encode(&h.finalize()[..16]);

    let claims_json = serde_json::to_string(&requested_claims).unwrap_or_else(|_| "[]".into());
    let expires_at = ts + 600; // 10 minutes

    // Store pending consent request in canonical consent_log (user_key_image stays empty until consent).
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT INTO consent_log (request_id, user_key_image, site_name, requested_claims_json, granted_at, token_used, revoked)
             VALUES (?1, '', ?2, ?3, 0, 0, 0)",
            params![request_id, payload.site_name, claims_json],
        )
        .map_err(|e| (StatusCode::CONFLICT, format!("Unable to create consent request: {e}")))?;

        let _ = db.execute(
            "INSERT INTO requests_log (timestamp, action_type, status, detail) VALUES (?1,'KYC_REQUEST','PENDING',?2)",
            params![ts, format!("site={} request_id={}", payload.site_name, request_id)],
        );
    }

    let consent_url = format!(
        "{}/consent?request_id={}&site={}&claims={}",
        std::env::var("NEXT_PUBLIC_API_URL").unwrap_or_else(|_| "http://localhost:3000".into()),
        request_id,
        urlencoding_simple(&payload.site_name),
        urlencoding_simple(&claims_json),
    );

    Ok(Json(KycRequestResponse { request_id, consent_url, expires_at }))
}

fn urlencoding_simple(s: &str) -> String {
    s.chars().map(|c| {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c.to_string() }
        else { format!("%{:02X}", c as u32) }
    }).collect()
}

#[derive(Serialize)]
struct KycConsentInfo {
    request_id: String,
    site_name: String,
    requested_claims: Vec<String>,
    status: String,
}

async fn kyc_consent_info(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Result<Json<KycConsentInfo>, (StatusCode, String)> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();

    let (site_name, claims_json, consent_token): (String, String, Option<String>) = db
        .query_row(
            "SELECT site_name, requested_claims_json, consent_token FROM consent_log WHERE request_id = ?1",
            params![request_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Consent request not found or expired".into()))?;

    let requested_claims: Vec<String> = serde_json::from_str(&claims_json).unwrap_or_default();
    let status = if consent_token.is_some() { "granted" } else { "pending" };

    Ok(Json(KycConsentInfo {
        request_id,
        site_name,
        requested_claims,
        status: status.into(),
    }))
}

#[derive(Deserialize)]
struct KycConsentBody {
    request_id: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct KycConsentResponse {
    consent_token: String,
    expires_at: i64,
}

async fn kyc_consent(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<KycConsentBody>,
) -> Result<Json<KycConsentResponse>, (StatusCode, String)> {
    // Validate the consent request exists and is pending
    let site_name = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT site_name FROM consent_log WHERE request_id = ?1 AND revoked = 0 AND token_used = 0",
            params![payload.request_id],
            |r| r.get::<_, String>(0),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Consent request not found or expired".into()))?
    };

    // Authenticate the user (dev mode: OPRF server-side)
    let server_k = state.read().unwrap().k;
    let oprf_result = dev_oprf_eval(server_k, &payload.email, &payload.password);
    let user_identity = Identity::from_oprf(oprf_result);
    let hex_ki = hex::encode(user_identity.key_image().compress().as_bytes());

    // Verify user exists
    {
        let st = state.read().unwrap();
        if !st.user_group.members.contains(&user_identity.public) {
            return Err((StatusCode::NOT_FOUND, format!("{} is not registered on Sauron", payload.email)));
        }
    }

    // Generate consent_token
    use sha2::{Sha256, Digest as _};
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut h = Sha256::new();
    h.update(payload.request_id.as_bytes());
    h.update(hex_ki.as_bytes());
    h.update(&ts.to_le_bytes());
    let consent_token = hex::encode(&h.finalize()[..]);
    let expires_at = ts + 300; // 5 minutes to use the token

    // Update pending consent row atomically
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let rows = db
            .execute(
                "UPDATE consent_log
                 SET user_key_image = ?1, granted_at = ?2, consent_token = ?3
                 WHERE request_id = ?4 AND consent_token IS NULL AND revoked = 0 AND token_used = 0",
                params![hex_ki, ts, consent_token, payload.request_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if rows == 0 {
            return Err((StatusCode::CONFLICT, "Consent already granted for this request".into()));
        }

        // Also log the consent in requests_log
        let _ = db.execute(
            "INSERT INTO requests_log (timestamp, action_type, status, detail) VALUES (?1,'KYC_CONSENT','OK',?2)",
            params![ts, format!("site={} user={}", site_name, &hex_ki[..16])],
        );
    }

    println!("[CONSENT] User {} consented for site {} | request_id={}", payload.email, site_name, payload.request_id);

    Ok(Json(KycConsentResponse { consent_token, expires_at }))
}

#[derive(Deserialize)]
struct KycRetrieveBody {
    /// The consent_token returned to the site after user approval.
    consent_token: String,
    /// Site name (for balance decrement).
    site_name: String,
    /// Optional Groth16 ZKP proof submitted by the client.
    #[serde(default)]
    zkp_proof: Option<serde_json::Value>,
    /// Circuit name for the ZKP proof (e.g. "AgeVerification").
    #[serde(default)]
    zkp_circuit: Option<String>,
    /// Public signals for the ZKP proof.
    #[serde(default)]
    zkp_public_signals: Option<Vec<String>>,
    /// Optional action to authorize through assurance-level policy engine.
    #[serde(default)]
    required_action: Option<String>,
}

async fn kyc_retrieve(
    agent_binding: Option<axum::extract::Extension<DelegatedAgentBinding>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<KycRetrieveBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (user_ki, stored_site, token_used, issuing_agent_id, requested_claims_json) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT user_key_image, site_name, token_used, issuing_agent_id, requested_claims_json FROM consent_log WHERE consent_token = ?1",
            params![payload.consent_token],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
            )),
        ).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired consent token".into()))?
    };

    if token_used != 0 {
        return Err((StatusCode::CONFLICT, "Consent token already used".into()));
    }

    if stored_site != payload.site_name {
        return Err((StatusCode::UNAUTHORIZED, "Consent token was not issued for this site".into()));
    }

    if let Some(expected_agent_id) = issuing_agent_id.clone() {
        let binding = agent_binding
            .ok_or((StatusCode::UNAUTHORIZED, "Delegated agent binding missing".into()))?
            .0;
        if binding.agent_id != expected_agent_id || binding.human_key_image != user_ki {
            return Err((StatusCode::UNAUTHORIZED, "Delegated agent binding mismatch".into()));
        }
    }

    // ZKP-only identity disclosure is mandatory.
    let proof = payload
        .zkp_proof
        .clone()
        .ok_or((StatusCode::BAD_REQUEST, "zkp_proof is required".into()))?;
    let public_signals = payload
        .zkp_public_signals
        .clone()
        .ok_or((StatusCode::BAD_REQUEST, "zkp_public_signals are required".into()))?;
    if public_signals.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "zkp_public_signals must not be empty".into()));
    }
    let circuit = payload
        .zkp_circuit
        .clone()
        .unwrap_or_else(|| "CredentialVerification".to_string());

    let issuer_url = state.read().unwrap().issuer_url.clone();
    let allow_dev_mock = std::env::var("SAURON_ALLOW_DEV_MOCK_PROOF")
        .map(|v| {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        })
        .unwrap_or(false);

    let proof_verified = if allow_dev_mock
        && proof
            .get("dev_mock")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        true
    } else {
        let verify_body = serde_json::json!({
            "circuit": circuit,
            "proof": proof,
            "public_signals": public_signals,
            "publicSignals": public_signals
        });
        match reqwest::Client::new()
            .post(format!("{issuer_url}/verify-proof"))
            .json(&verify_body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let resp: serde_json::Value = r.json().await.unwrap_or_default();
                resp.get("verified")
                    .or_else(|| resp.get("valid"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            }
            _ => false,
        }
    };

    if !proof_verified {
        return Err((StatusCode::UNAUTHORIZED, "ZKP proof verification failed".into()));
    }

    let assertions = build_zkp_assertions(&circuit, &public_signals);
    let requested_claims: Vec<String> = serde_json::from_str(&requested_claims_json).unwrap_or_default();
    let disclosed_claims = select_disclosed_claims(&assertions, &requested_claims)
        .map_err(|unsupported| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "Unsupported claim request for zkp-only disclosure: {:?}",
                    unsupported
                ),
            )
        })?;

    // Mark token as used + charge one connection credit + record api_usage
    let billing = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();

        let charged = db
            .execute(
                "UPDATE clients SET tokens_b = tokens_b - 1 WHERE name = ?1 AND tokens_b > 0",
                params![payload.site_name],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if charged == 0 {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                format!(
                    "Client '{}' has no credits. Buy credits before retrieval.",
                    payload.site_name
                ),
            ));
        }

        let tokens_b_remaining: i64 = db
            .query_row(
                "SELECT tokens_b FROM clients WHERE name = ?1",
                params![payload.site_name],
                |r| r.get(0),
            )
            .unwrap_or(0);

        serde_json::json!({
            "charged": true,
            "unit": "connection",
            "amount": 1,
            "tokens_b_remaining": tokens_b_remaining,
        })
    };

    // Mark token as used + record api_usage
    {
        let st = state.read().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute(
                "UPDATE consent_log SET token_used = 1 WHERE consent_token = ?1",
                params![payload.consent_token],
            );
            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let is_agent_int = if issuing_agent_id.is_some() { 1i64 } else { 0i64 };
            let action = if issuing_agent_id.is_some() { "kyc_agent" } else { "kyc_human" };
            let _ = db.execute(
                "INSERT INTO api_usage (client_name, action, is_agent, timestamp) VALUES (?1,?2,?3,?4)",
                params![payload.site_name, action, is_agent_int, ts],
            );
            let _ = db.execute(
                "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp)
                 VALUES (?1, ?2, 'kyc_retrieval', ?3)",
                params![payload.site_name, user_ki, ts],
            );
        }
        st.log("KYC_RETRIEVE", "OK", &format!("site={} user={}", payload.site_name, &user_ki[..16]));
    }

    // ── Ring membership verification ─────────────────────────────────────────
    // Verify human is in user_group ring.
    // If consent was issued by an agent, also verify agent is in agent_group ring.
    // Agent inherits human's ring membership — site sees BOTH proofs.
    let (human_in_user_ring, agent_in_agent_ring, agent_pub_key_hex, agent_assurance_level) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();

        // Resolve human public key from DB
        let human_pub_hex: Option<String> = db.query_row(
            "SELECT public_key_hex FROM users WHERE key_image_hex = ?1",
            params![user_ki],
            |r| r.get(0),
        ).ok();

        let human_in_ring = if let Some(ref hex) = human_pub_hex {
            if let Ok(bytes) = hex::decode(hex) {
                if let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> {
                    if let Some(pt) = CompressedRistretto(arr).decompress() {
                        st.user_group.members.contains(&pt)
                    } else { false }
                } else { false }
            } else { false }
        } else { false };

        // If agent-issued consent, verify agent ring membership
        let (agent_in_ring, agent_hex, agent_assurance) = if let Some(ref aid) = issuing_agent_id {
            let agent_row: Option<(String, String)> = db.query_row(
                "SELECT public_key_hex, assurance_level FROM agents WHERE agent_id = ?1 AND revoked = 0",
                params![aid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).ok();
            let in_ring = if let Some((ref hex, _)) = agent_row {
                if !hex.is_empty() {
                    if let Ok(bytes) = hex::decode(hex) {
                        if let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> {
                            if let Some(pt) = CompressedRistretto(arr).decompress() {
                                st.agent_group.members.contains(&pt)
                            } else { false }
                        } else { false }
                    } else { false }
                } else { false }
            } else { false };
            let agent_hex = agent_row.as_ref().map(|r| r.0.clone());
            let agent_assurance = agent_row.as_ref().map(|r| r.1.clone());
            (in_ring, agent_hex, agent_assurance)
        } else {
            (false, None, None)
        };

        (human_in_ring, agent_in_ring, agent_hex, agent_assurance)
    };

    let is_agent = issuing_agent_id.is_some();
    let trust_verified = human_in_user_ring && (!is_agent || agent_in_agent_ring);

    if !trust_verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Ring trust verification failed for consent owner or delegated agent".into(),
        ));
    }

    if is_agent
        && payload
            .required_action
            .as_deref()
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "required_action is mandatory for agent-mediated retrieval".into(),
        ));
    }

    let action_policy = if is_agent {
        let action = payload.required_action.as_deref().unwrap_or_default();
        let assurance_str = agent_assurance_level
            .clone()
            .unwrap_or_else(|| "delegated_nonbank".to_string());
        let decision = policy::authorize_action(AssuranceLevel::from_db(&assurance_str), action);
        if !decision.allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Policy denied action '{}': {}", action, decision.reason),
            ));
        }
        Some(serde_json::json!({
            "action": action,
            "allowed": true,
            "reason": decision.reason,
            "assurance_level": assurance_str,
        }))
    } else {
        None
    };

    println!("[CONSENT] KYC retrieved by site {} | is_agent={} user_ring={} agent_ring={}",
        payload.site_name, is_agent, human_in_user_ring, agent_in_agent_ring);

    let resp = serde_json::json!({
        "disclosure_mode": "zkp_only",
        "proof": {
            "verified": true,
            "circuit": circuit,
            "public_signals": public_signals,
        },
        "billing": billing,
        "claims": disclosed_claims,
        "identity": {
            "is_agent": is_agent,
            "agent_id": issuing_agent_id,
            "agent_pub_key_hex": agent_pub_key_hex,
            "agent_assurance_level": agent_assurance_level,
            "human_in_user_ring": human_in_user_ring,
            "agent_in_agent_ring": if is_agent { Some(agent_in_agent_ring) } else { None },
            "trust_verified": trust_verified,
            "policy": action_policy,
        }
    });

    Ok(Json(resp))
}

fn build_zkp_assertions(
    circuit: &str,
    public_signals: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    let mut assertions = serde_json::Map::new();
    assertions.insert("proof_verified".to_string(), serde_json::Value::Bool(true));
    assertions.insert("circuit".to_string(), serde_json::Value::String(circuit.to_string()));

    match circuit {
        "AgeVerification" => {
            let (age_ok, threshold) = if public_signals.len() >= 5 {
                // Real Groth16 output layout: [ageThreshold, currentDate, issuerAx, issuerAy, valid]
                let age_ok = public_signals
                    .last()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let threshold = public_signals
                    .first()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                (age_ok, threshold)
            } else {
                // Backward-compatible mock layout: [age_ok, threshold]
                let age_ok = public_signals
                    .first()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let threshold = public_signals
                    .get(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                (age_ok, threshold)
            };
            assertions.insert("age_over_threshold".to_string(), serde_json::Value::Bool(age_ok));
            assertions.insert(
                "age_threshold".to_string(),
                serde_json::Value::Number(serde_json::Number::from(threshold)),
            );
        }
        "CredentialVerification" => {
            let (age_ok, nationality_ok, credential_ok, threshold) = if public_signals.len() >= 9 {
                // Real Groth16 output layout:
                // [currentDate, ageThreshold, requiredNationality, merkleRoot, issuerAx, issuerAy, ageVerified, nationalityMatched, credentialValid]
                let n = public_signals.len();
                let age_ok = public_signals
                    .get(n - 3)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let nationality_ok = public_signals
                    .get(n - 2)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let credential_ok = public_signals
                    .get(n - 1)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let threshold = public_signals
                    .get(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                (age_ok, nationality_ok, credential_ok, threshold)
            } else {
                // Backward-compatible mock layout: [age_ok, nationality_ok, credential_ok]
                let age_ok = public_signals
                    .first()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let nationality_ok = public_signals
                    .get(1)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                let credential_ok = public_signals
                    .get(2)
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1;
                (age_ok, nationality_ok, credential_ok, 0)
            };
            assertions.insert("age_over_threshold".to_string(), serde_json::Value::Bool(age_ok));
            assertions.insert(
                "age_threshold".to_string(),
                serde_json::Value::Number(serde_json::Number::from(threshold)),
            );
            assertions.insert("nationality_match".to_string(), serde_json::Value::Bool(nationality_ok));
            assertions.insert("credential_valid".to_string(), serde_json::Value::Bool(credential_ok));
        }
        "MerkleInclusion" => {
            let inclusion_ok = if public_signals.len() >= 4 {
                public_signals
                    .last()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1
            } else {
                public_signals
                    .first()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1
            };
            assertions.insert("merkle_inclusion".to_string(), serde_json::Value::Bool(inclusion_ok));
        }
        _ => {}
    }

    assertions
}

fn select_disclosed_claims(
    assertions: &serde_json::Map<String, serde_json::Value>,
    requested_claims: &[String],
) -> Result<serde_json::Map<String, serde_json::Value>, Vec<String>> {
    let unsupported: Vec<String> = requested_claims
        .iter()
        .filter(|claim| !assertions.contains_key(*claim))
        .cloned()
        .collect();
    if !unsupported.is_empty() {
        return Err(unsupported);
    }

    if requested_claims.is_empty() {
        return Ok(assertions.clone());
    }

    let mut disclosed = serde_json::Map::new();
    for claim in requested_claims {
        if let Some(value) = assertions.get(claim) {
            disclosed.insert(claim.clone(), value.clone());
        }
    }
    Ok(disclosed)
}

#[cfg(test)]
mod tests {
    use super::{build_zkp_assertions, select_disclosed_claims};

    #[test]
    fn age_verification_assertions_are_parsed() {
        let signals = vec!["1".to_string(), "21".to_string()];
        let assertions = build_zkp_assertions("AgeVerification", &signals);

        assert_eq!(assertions.get("proof_verified").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(assertions.get("age_over_threshold").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(assertions.get("age_threshold").and_then(|v| v.as_u64()), Some(21));
    }

    #[test]
    fn credential_verification_assertions_are_parsed() {
        let signals = vec!["1".to_string(), "0".to_string(), "1".to_string()];
        let assertions = build_zkp_assertions("CredentialVerification", &signals);

        assert_eq!(assertions.get("age_over_threshold").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(assertions.get("nationality_match").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(assertions.get("credential_valid").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn requested_claims_reject_unsupported_keys() {
        let signals = vec!["1".to_string(), "18".to_string()];
        let assertions = build_zkp_assertions("AgeVerification", &signals);
        let requested = vec!["age_over_threshold".to_string(), "email".to_string()];

        let unsupported = select_disclosed_claims(&assertions, &requested).unwrap_err();
        assert_eq!(unsupported, vec!["email".to_string()]);
    }

    #[test]
    fn empty_requested_claims_returns_all_assertions() {
        let signals = vec!["1".to_string(), "18".to_string()];
        let assertions = build_zkp_assertions("AgeVerification", &signals);

        let disclosed = select_disclosed_claims(&assertions, &[]).unwrap();
        assert_eq!(disclosed, assertions);
    }
}

#[derive(Deserialize)]
struct PolicyAuthorizeBody {
    agent_id: String,
    action: String,
}

async fn policy_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<PolicyAuthorizeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.agent_id.is_empty() || payload.action.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id and action are required".into()));
    }

    let (assurance_level, revoked, expires_at): (String, i64, i64) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT assurance_level, revoked, expires_at FROM agents WHERE agent_id = ?1",
            params![payload.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".into()))?
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    if revoked != 0 || expires_at < now {
        return Err((StatusCode::UNAUTHORIZED, "Agent is revoked or expired".into()));
    }

    let decision = policy::authorize_action(AssuranceLevel::from_db(&assurance_level), &payload.action);
    Ok(Json(serde_json::json!({
        "agent_id": payload.agent_id,
        "action": payload.action,
        "assurance_level": assurance_level,
        "allowed": decision.allowed,
        "reason": decision.reason,
    })))
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
// ─────────────────────────────────────────────────────
//  Helpers: user session (stateless HMAC, 1h TTL)
// ─────────────────────────────────────────────────────

fn issue_user_session(jwt_secret: &[u8], key_image: &str) -> (String, i64) {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 + 3600;
    let payload = format!("{}|{}", key_image, expires_at);
    let mut h = Sha256::new();
    h.update(jwt_secret);
    h.update(b"|SESSION|");
    h.update(payload.as_bytes());
    let sig = hex::encode(h.finalize());
    (format!("{}|{}", payload, sig), expires_at)
}

fn verify_user_session(jwt_secret: &[u8], session: &str) -> Option<String> {
    let pos = session.rfind('|')?;
    let payload = &session[..pos];
    let sig = &session[pos + 1..];
    let mut h = Sha256::new();
    h.update(jwt_secret);
    h.update(b"|SESSION|");
    h.update(payload.as_bytes());
    if hex::encode(h.finalize()) != sig { return None; }
    let pos2 = payload.rfind('|')?;
    let expires_at: i64 = payload[pos2 + 1..].parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    if expires_at < now { return None; }
    Some(payload[..pos2].to_string())
}

fn session_key_image(headers: &HeaderMap, jwt_secret: &[u8]) -> Option<String> {
    let val = headers.get("x-sauron-session")?.to_str().ok()?;
    verify_user_session(jwt_secret, val)
}

// ─────────────────────────────────────────────────────
//  POST /user/auth — email+password → session token
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct UserAuthBody { email: String, password: String }

async fn user_auth(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<UserAuthBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (server_k, jwt_secret) = {
        let st = state.read().unwrap();
        (st.k, st.jwt_secret.clone())
    };
    let oprf_result = dev_oprf_eval(server_k, &payload.email, &payload.password);
    let identity = Identity::from_oprf(oprf_result);
    {
        let st = state.read().unwrap();
        if !st.user_group.members.contains(&identity.public) {
            return Err((StatusCode::UNAUTHORIZED, "User not registered".into()));
        }
    }
    let key_image = hex::encode(identity.key_image().compress().as_bytes());
    let profile: Option<(String, String)> = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT first_name, last_name FROM users WHERE key_image_hex = ?1",
            params![key_image],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ).ok()
    };
    let (session, expires_at) = issue_user_session(&jwt_secret, &key_image);
    Ok(Json(serde_json::json!({
        "session": session,
        "key_image": key_image,
        "expires_at": expires_at,
        "first_name": profile.as_ref().map(|p| &p.0).unwrap_or(&String::new()),
        "last_name":  profile.as_ref().map(|p| &p.1).unwrap_or(&String::new()),
    })))
}

// ─────────────────────────────────────────────────────
//  GET /user/profile
// ─────────────────────────────────────────────────────

async fn user_profile(
    headers: HeaderMap,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired session".into()))?;
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let profile: UserData = db.query_row(
        "SELECT first_name, last_name, email, date_of_birth, nationality FROM users WHERE key_image_hex = ?1",
        params![key_image],
        |r| Ok(UserData { first_name: r.get(0)?, last_name: r.get(1)?, email: r.get(2)?, date_of_birth: r.get(3)?, nationality: r.get(4)? }),
    ).map_err(|_| (StatusCode::NOT_FOUND, "Profile not found".into()))?;
    Ok(Json(serde_json::json!({
        "key_image": key_image,
        "first_name": profile.first_name,
        "last_name": profile.last_name,
        "email": profile.email,
        "date_of_birth": profile.date_of_birth,
        "nationality": profile.nationality,
    })))
}

// ─────────────────────────────────────────────────────
//  GET /user/consents — list all consents for user
// ─────────────────────────────────────────────────────

async fn user_consents(
    headers: HeaderMap,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired session".into()))?;
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT request_id, site_name, granted_at, token_used, revoked FROM consent_log
         WHERE user_key_image = ?1 ORDER BY granted_at DESC LIMIT 100"
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rows: Vec<serde_json::Value> = stmt.query_map(params![key_image], |r| {
        Ok(serde_json::json!({
            "request_id":  r.get::<_, String>(0)?,
            "site_name":   r.get::<_, String>(1)?,
            "granted_at":  r.get::<_, i64>(2)?,
            "used":        r.get::<_, i64>(3)? != 0,
            "revoked":     r.get::<_, i64>(4)? != 0,
        }))
    }).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .filter_map(|r| r.ok()).collect();
    Ok(Json(serde_json::json!({ "consents": rows })))
}

// ─────────────────────────────────────────────────────
//  DELETE /user/consent/{request_id} — revoke a consent
// ─────────────────────────────────────────────────────

async fn user_revoke_consent(
    headers: HeaderMap,
    Path(request_id): Path<String>,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired session".into()))?;
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let n = db.execute(
        "UPDATE consent_log SET revoked = 1 WHERE request_id = ?1 AND user_key_image = ?2",
        params![request_id, key_image],
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if n == 0 {
        return Err((StatusCode::NOT_FOUND, "Consent not found or not yours".into()));
    }
    Ok(Json(serde_json::json!({ "revoked": true })))
}

// ─────────────────────────────────────────────────────
//  POST /auth/device/issue — issue trusted device token
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeviceIssueBody {
    consent_token: String,
    fingerprint: String,
    site_name: String,
}

async fn device_issue(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DeviceIssueBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Verify consent_token exists (used or unused both ok — user just proved they own it)
    let user_ki = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT user_key_image FROM consent_log WHERE consent_token = ?1 AND site_name = ?2 AND revoked = 0",
            params![payload.consent_token, payload.site_name],
            |r| r.get::<_, String>(0),
        ).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid consent token or site mismatch".into()))?
    };

    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires_at = now as i64 + 30 * 24 * 3600;

    // Random-ish token_id (sha256 of nonce + user + site)
    let token_id = {
        let mut h = Sha256::new();
        h.update(now.to_le_bytes());
        h.update(payload.fingerprint.as_bytes());
        h.update(user_ki.as_bytes());
        h.update(payload.site_name.as_bytes());
        hex::encode(h.finalize())
    };
    let device_token = format!("{}:{}", token_id, sign_token(&jwt_secret, "DEVICE", &token_id));

    let token_hash = hex::encode(Sha256::digest(token_id.as_bytes()));
    let fp_hash = hex::encode(Sha256::digest(payload.fingerprint.as_bytes()));

    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT OR REPLACE INTO device_tokens (token_hash, user_key_image, site_name, fingerprint_hash, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![token_hash, user_ki, payload.site_name, fp_hash, now as i64, expires_at],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(serde_json::json!({ "device_token": device_token, "expires_at": expires_at })))
}

// ─────────────────────────────────────────────────────
//  POST /auth/device/check — silent re-auth via device token
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeviceCheckBody {
    device_token: String,
    site_name: String,
    fingerprint: String,
}

async fn device_check(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DeviceCheckBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();

    if !verify_token(&jwt_secret, "DEVICE", &payload.device_token) {
        return Ok(Json(serde_json::json!({ "valid": false, "reason": "bad_signature" })));
    }

    let token_id = token_value(&payload.device_token);
    let token_hash = hex::encode(Sha256::digest(token_id.as_bytes()));
    let fp_hash = hex::encode(Sha256::digest(payload.fingerprint.as_bytes()));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

    let row: Option<(String, String, String, i64, i64)> = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT user_key_image, site_name, fingerprint_hash, expires_at, revoked FROM device_tokens WHERE token_hash = ?1",
            params![token_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).ok()
    };

    let (user_ki, stored_site, stored_fp, expires_at, revoked) = match row {
        None => return Ok(Json(serde_json::json!({ "valid": false, "reason": "not_found" }))),
        Some(r) => r,
    };

    if revoked != 0 || expires_at < now || stored_site != payload.site_name || stored_fp != fp_hash {
        return Ok(Json(serde_json::json!({ "valid": false, "reason": "expired_or_mismatch" })));
    }

    // Issue a fresh silent consent_token
    let nonce = now.to_string();
    let consent_token = hex::encode(Sha256::digest(
        format!("{}:{}:{}:{}", jwt_secret.len(), token_id, payload.site_name, nonce).as_bytes()
    ));
    let request_id = format!("device-{}-{}", &token_id[..12], nonce);

    {
        let st = state.write().unwrap();
        {
            let db = st.db.lock().unwrap();
            let _ = db.execute(
                "INSERT OR IGNORE INTO consent_log (request_id, user_key_image, site_name, granted_at, consent_token, token_used)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![request_id, user_ki, payload.site_name, now, consent_token],
            );
        }
        st.log("DEVICE_SILENT", "OK", &format!("site={}", payload.site_name));
    }

    let (user_session, session_expires_at) = issue_user_session(&jwt_secret, &user_ki);

    Ok(Json(serde_json::json!({
        "valid": true,
        "consent_token": consent_token,
        "user_session": user_session,
        "session_expires_at": session_expires_at,
    })))
}

// ─────────────────────────────────────────────────────
//  GET /user/credential — fetch BabyJubJub VC for ZKP proofs (frictionless)
//
//  Called automatically by the consent popup after the user authenticates.
//  No extra user action needed — credential retrieved in background.
// ─────────────────────────────────────────────────────

async fn user_get_credential(
    headers: HeaderMap,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired session".into()))?;

    // Look up pre-auth code
    let (pre_auth_code, subject_did, claimed) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT pre_auth_code, subject_did, claimed FROM credential_codes WHERE key_image_hex = ?1",
            params![key_image],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)),
        ).map_err(|_| (StatusCode::NOT_FOUND, "No credential registered. Register via a bank or enroll first.".into()))?
    };

    if claimed != 0 {
        // Already claimed — return cached VC from user_credentials table
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        if let Ok(vc_json) = db.query_row(
            "SELECT credential_json FROM user_credentials WHERE key_image_hex = ?1",
            params![key_image],
            |r| r.get::<_, String>(0),
        ) {
            let vc: serde_json::Value = serde_json::from_str(&vc_json)
                .unwrap_or(serde_json::json!({ "raw": vc_json }));
            return Ok(Json(serde_json::json!({ "credential": vc, "cached": true })));
        }
    }

    // Claim from issuer
    let issuer_url = state.read().unwrap().issuer_url.clone();
    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
        "subject_did": subject_did,
    });

    let resp = reqwest::Client::new()
        .post(format!("{issuer_url}/credential"))
        .json(&body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer unreachable: {e}")))?;

    if !resp.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, "Issuer returned error during credential claim".into()));
    }

    let vc: serde_json::Value = resp.json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer response parse error: {e}")))?;

    // Cache credential + mark code as claimed
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let _ = db.execute(
            "INSERT OR REPLACE INTO user_credentials (key_image_hex, credential_json, issued_at) VALUES (?1,?2,?3)",
            params![key_image, vc.to_string(), ts],
        );
        let _ = db.execute(
            "UPDATE credential_codes SET claimed = 1 WHERE key_image_hex = ?1",
            params![key_image],
        );
    }

    Ok(Json(serde_json::json!({ "credential": vc, "cached": false })))
}

// ─────────────────────────────────────────────────────
//  POST /agent/kyc/consent — agent acts on behalf of human
//
//  Agent presents A-JWT → server validates → issues consent_token
//  in the human owner's name → site can call /kyc/retrieve normally.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentKycConsentBody {
    /// A-JWT issued to the agent by SauronID.
    ajwt: String,
    /// Site requesting KYC.
    site_name: String,
    /// Consent request ID (from /kyc/request).
    request_id: String,
}

async fn agent_kyc_consent(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentKycConsentBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // 1. Verify A-JWT
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let claims = agent::verify_ajwt(&jwt_secret, &payload.ajwt)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;

    let human_key_image = claims.get("sub").and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub claim".into()))?
        .to_string();
    let agent_id = claims.get("agent_id").and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?
        .to_string();

    // 2. Verify agent status + mandatory delegated-ring membership
    let assurance_level = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, agent_pub_hex, assurance): (i64, i64, String, String, String) = db.query_row(
            "SELECT revoked, expires_at, human_key_image, public_key_hex, assurance_level FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).unwrap_or((1, 0, String::new(), String::new(), "delegated_nonbank".to_string()));
        if revoked != 0 {
            return Err((StatusCode::UNAUTHORIZED, "Agent has been revoked".into()));
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        if expires_at < now {
            return Err((StatusCode::UNAUTHORIZED, "Agent has expired".into()));
        }
        if db_human != human_key_image {
            return Err((StatusCode::UNAUTHORIZED, "Agent owner mismatch".into()));
        }
        if agent_pub_hex.is_empty() {
            return Err((StatusCode::UNAUTHORIZED, "Delegated agent missing ring public key".into()));
        }
        let bytes = hex::decode(&agent_pub_hex)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Agent public key encoding invalid".into()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Agent public key length invalid".into()))?;
        let pt = CompressedRistretto(arr)
            .decompress()
            .ok_or((StatusCode::UNAUTHORIZED, "Agent public key point invalid".into()))?;
        if !st.agent_group.members.contains(&pt) {
            return Err((StatusCode::UNAUTHORIZED, "Agent not in delegated ring".into()));
        }
        assurance
    };

    // 3. Verify consent request exists + is for this site + not yet claimed
    let stored_site: String = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT site_name FROM consent_log WHERE request_id = ?1 AND token_used = 0 AND revoked = 0 AND consent_token IS NULL",
            params![payload.request_id],
            |r| r.get(0),
        ).map_err(|_| (StatusCode::NOT_FOUND, "Consent request not found, already claimed, or already used".into()))?
    };
    if stored_site != payload.site_name {
        return Err((StatusCode::UNAUTHORIZED, "Request ID does not match site_name".into()));
    }

    // 4. Issue consent_token for the human
    let consent_token = {
        let mut h = Sha256::new();
        h.update(jwt_secret.as_slice());
        h.update(b"|AGENT_CONSENT|");
        h.update(payload.request_id.as_bytes());
        h.update(human_key_image.as_bytes());
        h.update(agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let expires_at = now + 300;

    {
        let st = state.read().unwrap();
        // Atomic: only update if consent_token is still NULL (race-safe)
        let rows = {
            let db = st.db.lock().unwrap();
            db.execute(
                "UPDATE consent_log SET consent_token = ?1, user_key_image = ?2, granted_at = ?3, issuing_agent_id = ?4 WHERE request_id = ?5 AND consent_token IS NULL",
                params![consent_token, human_key_image, now, agent_id, payload.request_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        };
        if rows == 0 {
            return Err((StatusCode::CONFLICT, "Consent already claimed by another agent".into()));
        }
        st.log("AGENT_KYC_CONSENT", "OK",
            &format!("agent={} site={} human={}", &agent_id[..16], payload.site_name, &human_key_image[..16]));
    }

    println!("[AGENT] KYC consent issued | agent={} site={}", &agent_id[..16], payload.site_name);

    Ok(Json(serde_json::json!({
        "consent_token": consent_token,
        "expires_at": expires_at,
        "on_behalf_of": human_key_image,
        "agent_id": agent_id,
        "assurance_level": assurance_level,
    })))
}

// ─────────────────────────────────────────────────────
//  POST /agent/vc/issue — self-sovereign agent VC (KYA without banks)
//
//  Protocol:
//    1. Human proves liveness (passed as liveness_proof).
//       In prod: OPRF key_image proves uniqueness, liveness_confidence proves humanness.
//       In dev: accepted if confidence ≥ 0.7 (mock provider).
//    2. Sauron verifies the human is unique (key_image must not have issued >N VCs).
//    3. Sauron issues a signed Agent VC:
//         - agent_id, agent_checksum, human_key_image
//         - scope (what the agent may do)
//         - timestamp + expiry
//         - Merkle-committed (tamper-evident log)
//       Signed with server JWT secret (same trust anchor as A-JWT).
//    4. VC stored in agent_vcs table.
//    5. Optional: agent_checksum anchored to on-chain AgentDelegationRegistry
//       (existing Solana/EVM contracts).
//
//  Trust chain: SauronID server key → VC → agent_id
//  Verification by retail site: POST /agent/verify with A-JWT → server returns VC proof.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentVcIssueBody {
    /// Human owner's key_image (legacy optional hint; server trusts authenticated session).
    #[serde(default)]
    human_key_image: String,
    /// SHA-256 of agent's behavioral config (tamper detection).
    agent_checksum: String,
    /// Human-readable description of agent's purpose.
    description: String,
    /// JSON array of allowed actions, e.g. ["read:profile", "prove:age", "prove:nationality"].
    scope: Vec<String>,
    /// Lifetime hours (default 24, max 720).
    #[serde(default = "default_vc_ttl")]
    ttl_hours: i64,
}

fn default_vc_ttl() -> i64 { 24 }

async fn agent_vc_issue(
    headers: HeaderMap,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentVcIssueBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()));
    }

    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let human_key_image = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Valid x-sauron-session header required".into()))?;
    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((StatusCode::UNAUTHORIZED, "human_key_image payload does not match authenticated session".into()));
    }

    // 1. Verify authenticated human exists and is present in user ring.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let human_pub_hex: String = db
            .query_row(
                "SELECT public_key_hex FROM users WHERE key_image_hex = ?1",
                params![human_key_image],
                |r| r.get(0),
            )
            .map_err(|_| {
                (
                    StatusCode::NOT_FOUND,
                    "Human user not found — must be registered via bank KYC first".into(),
                )
            })?;

        let bytes = hex::decode(&human_pub_hex)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Human user public key encoding invalid".into()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Human user public key length invalid".into()))?;
        let pt = CompressedRistretto(arr)
            .decompress()
            .ok_or((StatusCode::UNAUTHORIZED, "Human user public key point invalid".into()))?;
        if !st.user_group.members.contains(&pt) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Human user is not in trusted user ring".into(),
            ));
        }
    }

    // 2. Uniqueness check — each human may issue at most 10 active VCs
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let active_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM agent_vcs
             WHERE agent_id IN (SELECT agent_id FROM agents WHERE human_key_image = ?1)
             AND revoked = 0 AND expires_at > ?2",
            params![human_key_image, now],
            |r| r.get(0),
        ).unwrap_or(0);
        if active_count >= 10 {
            return Err((StatusCode::TOO_MANY_REQUESTS,
                "Maximum 10 active agent VCs per human. Revoke some first.".into()));
        }
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let ttl_secs = payload.ttl_hours.clamp(1, 720) * 3600;
    let expires_at = now + ttl_secs;

    // 3. Derive agent_id
    let agent_id = {
        let mut h = Sha256::new();
        h.update(payload.agent_checksum.as_bytes());
        h.update(human_key_image.as_bytes());
        h.update(&now.to_le_bytes());
        format!("agt_{}", &hex::encode(h.finalize())[..24])
    };

    // 4. Build VC (self-sovereign, Sauron as issuer)
    let vc = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://sauronid.io/credentials/agent/v1"
        ],
        "id": format!("urn:sauronid:agent-vc:{}", agent_id),
        "type": ["VerifiableCredential", "SauronAgentCredential"],
        "issuer": "did:sauron:idp",
        "issuanceDate": now,
        "expirationDate": expires_at,
        "credentialSubject": {
            "id": format!("did:sauron:agent:{}", agent_id),
            "agentId": agent_id,
            "agentChecksum": payload.agent_checksum,
            "humanOwner": format!("did:sauron:user:{}", &human_key_image[..16]),
            "description": payload.description,
            "scope": payload.scope,
            // Trust derives from human's bank-verified KYC — no separate liveness needed
            "rootOfTrust": "did:sauron:idp"
        },
    });

    // 5. Sign VC (HMAC-SHA256 over canonical JSON — same trust anchor as A-JWT)
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let vc_canonical = vc.to_string();
    let mut h = Sha256::new();
    h.update(&jwt_secret);
    h.update(b"|VC|");
    h.update(vc_canonical.as_bytes());
    let vc_hash = hex::encode(h.finalize());

    // 6. Persist in agents + agent_vcs tables
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        // Register in agents table (so A-JWT flow works normally)
        db.execute(
            "INSERT OR REPLACE INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, issued_at, expires_at, revoked)
             VALUES (?1,?2,?3,?4,'autonomous_web3','',?5,?6,0)",
            params![
                agent_id,
                human_key_image,
                payload.agent_checksum,
                serde_json::json!({ "description": payload.description, "scope": payload.scope }).to_string(),
                now, expires_at,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Persist VC
        db.execute(
            "INSERT OR REPLACE INTO agent_vcs (agent_id, vc_json, vc_hash, issued_at, expires_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![agent_id, vc_canonical, vc_hash, now, expires_at],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Push a server-generated Ristretto point to agent_group ring so ring checks work
    {
        use sha2::Digest as _;
        let mut h = Sha256::new();
        h.update(b"AGENT_RING_KEY:");
        h.update(agent_id.as_bytes());
        let seed_bytes: [u8; 32] = h.finalize().into();
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(seed_bytes);
        let pt = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * scalar;
        let pub_hex = hex::encode(pt.compress().as_bytes());
        {
            let mut st = state.write().unwrap();
            if !st.agent_group.members.contains(&pt) {
                st.agent_group.members.push(pt);
            }
            let db = st.db.lock().unwrap();
            let _ = db.execute(
                "UPDATE agents SET public_key_hex = ?1 WHERE agent_id = ?2",
                params![pub_hex, agent_id],
            );
        }
    }

    // 7. Forge A-JWT so agent can start using it immediately
    let ajwt = agent::forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &serde_json::json!({ "description": payload.description, "scope": payload.scope }).to_string(),
        ttl_secs,
    );

    {
        let st = state.read().unwrap();
        st.log("AGENT_VC_ISSUE", "OK",
            &format!("agent={} human={}", &agent_id[..16], &human_key_image[..16]));
    }

    println!("[KYA] Self-sovereign VC issued | agent={} scope={:?}", &agent_id[..16], payload.scope);

    Ok(Json(serde_json::json!({
        "agent_id": agent_id,
        "assurance_level": "autonomous_web3",
        "vc": vc,
        "vc_hash": vc_hash,
        "ajwt": ajwt,
        "expires_at": expires_at,
        "trust_chain": "SauronID self-sovereign (bank KYC as root of trust)",
    })))
}
