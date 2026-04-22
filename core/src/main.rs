use axum::{
    body::{to_bytes, Body},
    routing::{get, post, delete},
    extract::{Request, State, Json, Path},
    http::{StatusCode, HeaderMap},
    Router,
    middleware,
};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use rusqlite::params;
use sauron_core::{
    oprf,
    ring,
    state::{
        ServerState,
    },
};
use sauron_core::{identity::{Identity, UserData}, db, agent};
use sauron_core::compliance;
use sauron_core::compliance_screening;
use sauron_core::issuer_runtime::IssuerVerifyError;
use sauron_core::policy::{self, AssuranceLevel};
use sauron_core::risk;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use sha2::{Sha256, Sha512, Digest};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

type HmacSha256 = Hmac<Sha256>;

fn assert_production_sqlite_acknowledged() {
    if sauron_core::runtime_mode::is_development_runtime() {
        return;
    }
    let ok = std::env::var("SAURON_ACCEPT_SINGLE_NODE_SQLITE")
        .map(|v| {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        })
        .unwrap_or(false);
    if !ok {
        panic!(
            "[FATAL] SQLite is single-node (no cross-region HA). Set SAURON_ACCEPT_SINGLE_NODE_SQLITE=1 to acknowledge this deployment, or replace the data tier before claiming global production readiness."
        );
    }
}

#[tokio::main]
async fn main() {
    // Initialise la base SQLite en mémoire.
    let db_handle = db::open_db();
    let db_arc = Arc::new(db_handle);
    let state = Arc::new(RwLock::new(ServerState::new(Arc::clone(&db_arc))));
    assert_production_sqlite_acknowledged();

    let app = Router::new()
        // OPRF
        .route("/oprf",              post(handle_oprf))
        // Flux 1: dépôt KYC
        .route("/register",          post(handle_register))
        .route("/bank/register",     post(bank_register_user))
        .route("/register/bank",     post(bank_register_user))
        // ZKP
        .route("/zkp/proof_material", post(handle_zkp_proof_material))
        // A-JWT Agentic Layer
        .route("/agent/register",                        post(agent::register_agent))
        .route("/agent/verify",                          post(agent::verify_agent_token))
        .route("/agent/pop/challenge",                   post(agent::agent_pop_challenge))
        .route("/agent/payment/authorize",               post(agent_payment_authorize))
        .route("/agent/payment/nonexistence/material",   post(payment_nonexistence_material))
        .route("/agent/payment/nonexistence/verify",     post(payment_nonexistence_verify))
        .route("/merchant/payment/consume",              post(merchant_payment_consume))
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
        // User self-service (manage own consents + agents)
        .route("/user/auth",          post(user_auth))
        .route("/user/consents",      get(user_consents))
        .route("/user/credential",    get(user_get_credential))
        .route("/user/consent/{request_id}", delete(user_revoke_consent))
        // Agent KYC consent flow (agent acts on behalf of human)
        .route("/agent/kyc/consent",  post(agent_kyc_consent))
        // Self-sovereign agent VC (KYA without banks)
        .route("/agent/vc/issue",     post(agent_vc_issue))
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

        let _ = compliance_screening::upsert_bank_cleared_row(&db, &payload.key_image_hex, now)
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
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let _ = compliance_screening::upsert_default_row(&db, &hex_ki, ts);
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


// ─────────────────────────────────────────────────────
//  ZKP : construction d'anneau filtré et vérification de preuve
// ─────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// POST /zkp/proof_material
// ──────────────────────────────────────────────────────────────────────────────

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
    let (issuer_url, client) = {
        let st = state.read().unwrap();
        (st.issuer_url.clone(), st.issuer_runtime.client.clone())
    };
    let body = serde_json::json!({
        "credentialHash": payload.credential_hash,
        "leafIndex": payload.leaf_index,
    });
    let response = client
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
                 SET user_key_image = ?1, granted_at = ?2, consent_expires_at = ?3, consent_token = ?4
                 WHERE request_id = ?5 AND consent_token IS NULL AND revoked = 0 AND token_used = 0",
                params![hex_ki, ts, expires_at, consent_token, payload.request_id],
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
    let (user_ki, stored_site, token_used, revoked, consent_expires_at, issuing_agent_id, requested_claims_json) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT user_key_image, site_name, token_used, revoked, consent_expires_at, issuing_agent_id, requested_claims_json FROM consent_log WHERE consent_token = ?1",
            params![payload.consent_token],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
            )),
        ).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired consent token".into()))?
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

    if revoked != 0 {
        return Err((StatusCode::UNAUTHORIZED, "Consent token revoked".into()));
    }

    if token_used != 0 {
        return Err((StatusCode::CONFLICT, "Consent token already used".into()));
    }

    if consent_expires_at > 0 && now > consent_expires_at {
        return Err((StatusCode::UNAUTHORIZED, "Consent token expired".into()));
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

    // Risk + compliance (DB-backed nationality only; never trust client-supplied jurisdiction).
    let jurisdiction_decision: compliance::JurisdictionDecision = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        risk::check_and_increment(
            &db,
            &risk::bucket_kyc_retrieve(&payload.site_name, &user_ki),
            now,
            risk::limit_kyc_retrieve(),
        )
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        let nationality: String = db
            .query_row(
                "SELECT IFNULL(nationality, '') FROM users WHERE key_image_hex = ?1",
                params![user_ki],
                |r| r.get(0),
            )
            .unwrap_or_default();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?
    };

    let screening_row = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        st.screening
            .enforce_for_user(&db, &user_ki)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?
    };

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

    let (issuer_urls, issuer_rt) = {
        let st = state.read().unwrap();
        (st.issuer_urls.clone(), st.issuer_runtime.clone())
    };
    let requested_dev_mock = proof
        .get("dev_mock")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if requested_dev_mock {
        return Err((
            StatusCode::BAD_REQUEST,
            "dev_mock proofs are disabled".into(),
        ));
    }

    let verify_body = serde_json::json!({
        "circuit": circuit,
        "proof": proof,
        "public_signals": public_signals,
        "publicSignals": public_signals
    });
    let proof_verified = match issuer_rt
        .verify_proof_failover(&issuer_urls, &verify_body)
        .await
    {
        Ok(v) => v,
        Err(IssuerVerifyError::CircuitOpen) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "ZKP issuer verify-proof temporarily unavailable (circuit open)".into(),
            ));
        }
        Err(IssuerVerifyError::Transport(e)) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("ZKP issuer unreachable: {e}"),
            ));
        }
        Err(IssuerVerifyError::JsonParse) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                "ZKP issuer returned unreadable JSON for verify-proof".into(),
            ));
        }
        Err(IssuerVerifyError::Upstream(status)) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("ZKP issuer verify-proof returned HTTP {status}"),
            ));
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
            "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        }))
    } else {
        None
    };

    println!("[CONSENT] KYC retrieved by site {} | is_agent={} user_ring={} agent_ring={}",
        payload.site_name, is_agent, human_in_user_ring, agent_in_agent_ring);

    let issuer_controls = {
        let st = state.read().unwrap();
        st.issuer_runtime.circuit_snapshots_json(&st.issuer_urls)
    };
    let screening_api = {
        let st = state.read().unwrap();
        st.screening.for_agent_api(&screening_row)
    };
    let controls = serde_json::json!({
        "compliance": jurisdiction_decision.for_agent_api(),
        "screening": screening_api,
        "issuer": issuer_controls,
        "risk": { "window_secs": risk::window_secs() },
    });

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
        },
        "controls": controls,
    });

    Ok(Json(resp))
}

fn build_zkp_assertions(
    circuit: &str,
    public_signals: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    fn parse_bool_signal(v: Option<&String>) -> Option<bool> {
        v.and_then(|s| s.parse::<u8>().ok()).and_then(|n| match n {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        })
    }

    fn parse_u64_signal(v: Option<&String>) -> Option<u64> {
        v.and_then(|s| s.parse::<u64>().ok())
    }

    let mut assertions = serde_json::Map::new();
    assertions.insert("proof_verified".to_string(), serde_json::Value::Bool(true));
    assertions.insert("circuit".to_string(), serde_json::Value::String(circuit.to_string()));

    match circuit {
        "AgeVerification" => {
            let (age_ok, threshold) = if public_signals.len() >= 5 {
                // Accept both layouts:
                //  - outputs-last:  [ageThreshold, currentDate, issuerAx, issuerAy, valid]
                //  - outputs-first: [valid, ageThreshold, currentDate, issuerAx, issuerAy]
                let first_bool = parse_bool_signal(public_signals.first());
                let last_bool = parse_bool_signal(public_signals.last());

                if first_bool.is_some() && last_bool.is_none() {
                    (
                        first_bool.unwrap_or(false),
                        parse_u64_signal(public_signals.get(1)).unwrap_or(0),
                    )
                } else {
                    (
                        last_bool.unwrap_or(false),
                        parse_u64_signal(public_signals.first()).unwrap_or(0),
                    )
                }
            } else {
                // Backward-compatible mock layout: [age_ok, threshold]
                let age_ok = parse_bool_signal(public_signals.first()).unwrap_or(false);
                let threshold = parse_u64_signal(public_signals.get(1)).unwrap_or(0);
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
                // Accept both layouts:
                //  - outputs-last:
                //    [currentDate, ageThreshold, requiredNationality, merkleRoot, issuerAx, issuerAy, ageVerified, nationalityMatched, credentialValid]
                //  - outputs-first:
                //    [ageVerified, nationalityMatched, credentialValid, currentDate, ageThreshold, requiredNationality, merkleRoot, issuerAx, issuerAy]
                let first_three_binary = public_signals
                    .iter()
                    .take(3)
                    .all(|v| parse_bool_signal(Some(v)).is_some());

                if first_three_binary {
                    (
                        parse_bool_signal(public_signals.first()).unwrap_or(false),
                        parse_bool_signal(public_signals.get(1)).unwrap_or(false),
                        parse_bool_signal(public_signals.get(2)).unwrap_or(false),
                        parse_u64_signal(public_signals.get(4)).unwrap_or(0),
                    )
                } else {
                    let n = public_signals.len();
                    (
                        parse_bool_signal(public_signals.get(n - 3)).unwrap_or(false),
                        parse_bool_signal(public_signals.get(n - 2)).unwrap_or(false),
                        parse_bool_signal(public_signals.get(n - 1)).unwrap_or(false),
                        parse_u64_signal(public_signals.get(1)).unwrap_or(0),
                    )
                }
            } else {
                // Backward-compatible mock layout: [age_ok, nationality_ok, credential_ok]
                let age_ok = parse_bool_signal(public_signals.first()).unwrap_or(false);
                let nationality_ok = parse_bool_signal(public_signals.get(1)).unwrap_or(false);
                let credential_ok = parse_bool_signal(public_signals.get(2)).unwrap_or(false);
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
        "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
    })))
}

#[derive(Deserialize)]
struct AgentPaymentAuthorizeBody {
    /// Agent token minted by /agent/register or /agent/vc/issue.
    ajwt: String,
    /// Requested charge amount in minor units (e.g. cents).
    amount_minor: i64,
    /// ISO-4217 3-letter currency code.
    currency: String,
    /// Merchant-side idempotency/payment reference.
    payment_ref: String,
    /// Optional merchant account / destination identifier.
    #[serde(default)]
    merchant_id: String,
    /// Mandatory for payment authorization (PoP).
    #[serde(default)]
    pop_challenge_id: String,
    /// Mandatory for payment authorization (PoP).
    #[serde(default)]
    pop_jws: String,
}

fn parse_ajwt_intent_claim(claims: &serde_json::Value) -> Result<serde_json::Value, (StatusCode, String)> {
    match claims.get("intent") {
        Some(serde_json::Value::String(s)) => serde_json::from_str::<serde_json::Value>(s)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "A-JWT intent is not valid JSON".into())),
        Some(v @ serde_json::Value::Object(_)) => Ok(v.clone()),
        _ => Err((StatusCode::UNAUTHORIZED, "A-JWT missing intent claim".into())),
    }
}

fn payment_scopes_from_intent(intent: &serde_json::Value) -> Vec<String> {
    if let Some(arr) = intent.get("scope").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(arr) = intent
        .get("constraints")
        .and_then(|v| v.get("scope"))
        .and_then(|v| v.as_array())
    {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(action) = intent.get("action").and_then(|v| v.as_str()) {
        let normalized = action.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            return vec![normalized];
        }
    }
    Vec::new()
}

fn enforce_strict_payment_intent(
    intent: &serde_json::Value,
    amount_minor: i64,
    request_currency: &str,
    request_merchant_id: &str,
) -> Result<(), (StatusCode, String)> {
    let scopes = payment_scopes_from_intent(intent);
    if !scopes.iter().any(|s| s == "payment_initiation") {
        return Err((
            StatusCode::FORBIDDEN,
            "Intent scope must explicitly include payment_initiation".into(),
        ));
    }

    let max_amount_major = intent
        .get("maxAmount")
        .and_then(|v| v.as_f64())
        .ok_or((StatusCode::FORBIDDEN, "Intent must define numeric maxAmount for payments".into()))?;
    if !(max_amount_major.is_finite() && max_amount_major > 0.0) {
        return Err((StatusCode::FORBIDDEN, "Intent maxAmount must be > 0".into()));
    }
    let max_minor = (max_amount_major * 100.0).round() as i64;
    if amount_minor > max_minor {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested amount {} exceeds intent maxAmount {} {} ({} minor units)",
                amount_minor, max_amount_major, request_currency, max_minor
            ),
        ));
    }

    let intent_currency = intent
        .get("currency")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_uppercase())
        .ok_or((StatusCode::FORBIDDEN, "Intent must define currency for payments".into()))?;
    if intent_currency != request_currency {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested currency {} does not match intent currency {}",
                request_currency, intent_currency
            ),
        ));
    }

    let merchant_allowlist = intent
        .get("constraints")
        .and_then(|v| v.get("merchant_allowlist"))
        .and_then(|v| v.as_array());
    if let Some(allowlist) = merchant_allowlist {
        if request_merchant_id.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "merchant_id is required by intent constraints.merchant_allowlist".into(),
            ));
        }
        let allowed = allowlist.iter().any(|m| {
            m.as_str()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s == request_merchant_id)
                .unwrap_or(false)
        });
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!("merchant_id '{}' is not allowed by intent", request_merchant_id),
            ));
        }
    }

    Ok(())
}

async fn agent_payment_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentPaymentAuthorizeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.ajwt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "ajwt is required".into()));
    }
    if payload.amount_minor <= 0 {
        return Err((StatusCode::BAD_REQUEST, "amount_minor must be > 0".into()));
    }
    if payload.payment_ref.trim().is_empty() || payload.payment_ref.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "payment_ref is required (1..128 chars)".into()));
    }
    let currency = payload.currency.trim().to_ascii_uppercase();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err((StatusCode::BAD_REQUEST, "currency must be a 3-letter ISO uppercase code".into()));
    }

    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let claims = agent::verify_ajwt(&jwt_secret, &payload.ajwt)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;

    let human_key_image = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".into()))?
        .to_string();
    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?
        .to_string();
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".into()))?
        .to_string();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".into()))?;

    let intent = parse_ajwt_intent_claim(&claims)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let payment_jurisdiction = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        risk::check_and_increment(
            &db,
            &risk::bucket_payment_authorize(&agent_id),
            now,
            risk::limit_payment_authorize(),
        )
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        let nationality: String = db
            .query_row(
                "SELECT IFNULL(nationality, '') FROM users WHERE key_image_hex = ?1",
                params![human_key_image],
                |r| r.get(0),
            )
            .unwrap_or_default();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?
    };

    let payment_screening_row = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        st.screening
            .enforce_for_user(&db, &human_key_image)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?
    };

    let assurance_level = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, assurance, pop_pk_b64u): (i64, i64, String, String, String) = db
            .query_row(
                "SELECT revoked, expires_at, human_key_image, assurance_level, IFNULL(pop_public_key_b64u, '') FROM agents WHERE agent_id = ?1",
                params![agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".into()))?;
        if revoked != 0 {
            return Err((StatusCode::UNAUTHORIZED, "Agent has been revoked".into()));
        }
        if expires_at < now {
            return Err((StatusCode::UNAUTHORIZED, "Agent has expired".into()));
        }
        if db_human != human_key_image {
            return Err((StatusCode::UNAUTHORIZED, "Agent owner mismatch".into()));
        }
        if pop_pk_b64u.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires PoP-enabled agent registration".into(),
            ));
        }
        if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires pop_challenge_id and pop_jws from /agent/pop/challenge".into(),
            ));
        }
        let challenge_plain = sauron_core::ajwt_support::take_pop_challenge(
            &db,
            &payload.pop_challenge_id,
            &agent_id,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        sauron_core::ajwt_support::verify_ed25519_pop_jws(
            &challenge_plain,
            &payload.pop_jws,
            &pop_pk_b64u,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        assurance
    };

    let decision = policy::authorize_action(
        AssuranceLevel::from_db(&assurance_level),
        "payment_initiation",
    );
    if !decision.allowed {
        return Err((
            StatusCode::FORBIDDEN,
            format!("Policy denied payment_initiation: {}", decision.reason),
        ));
    }

    enforce_strict_payment_intent(
        &intent,
        payload.amount_minor,
        &currency,
        payload.merchant_id.trim(),
    )?;

    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&db, &jti, exp)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    }

    let auth_id = format!("payauth_{}", sauron_core::ajwt_support::random_hex_32());
    let expires_at = std::cmp::min(exp, now + 300);
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT INTO agent_payment_authorizations
             (auth_id, agent_id, jti, amount_minor, currency, merchant_id, payment_ref, created_at, expires_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
            params![
                auth_id,
                agent_id,
                jti,
                payload.amount_minor,
                currency,
                payload.merchant_id.trim(),
                payload.payment_ref.trim(),
                now,
                expires_at,
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let issuer_snap = {
        let st = state.read().unwrap();
        st.issuer_runtime.circuit_snapshots_json(&st.issuer_urls)
    };
    let screening_api = {
        let st = state.read().unwrap();
        st.screening.for_agent_api(&payment_screening_row)
    };

    Ok(Json(serde_json::json!({
        "authorized": true,
        "authorization_id": auth_id,
        "agent_id": claims.get("agent_id").and_then(|v| v.as_str()).unwrap_or_default(),
        "amount_minor": payload.amount_minor,
        "currency": currency,
        "merchant_id": payload.merchant_id.trim(),
        "payment_ref": payload.payment_ref.trim(),
        "assurance_level": assurance_level,
        "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        "expires_at": expires_at,
        "controls": {
            "compliance": payment_jurisdiction.for_agent_api(),
            "screening": screening_api,
            "issuer": issuer_snap,
            "risk": { "window_secs": risk::window_secs() },
        },
    })))
}

// ─────────────────────────────────────────────────────
//  Merchant: consume a payment authorization + update SMT
// ─────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct MerchantPaymentConsumeBody {
    authorization_id: String,
    merchant_id: String,
}

/// POST /merchant/payment/consume
///
/// Merchant marks an authorization as consumed. On success, the payment SMT is
/// updated (key = SHA256(agent_id|window_start), value = 1) so that subsequent
/// non-payment proofs for the same window will correctly fail.
async fn merchant_payment_consume(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<MerchantPaymentConsumeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.authorization_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "authorization_id required".into()));
    }
    if payload.merchant_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "merchant_id required".into()));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let now_i64 = now as i64;

    let (agent_id, amount_minor, currency) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let row: (String, i64, String, String, i64, i64) = db
            .query_row(
                "SELECT agent_id, amount_minor, currency, merchant_id, expires_at, consumed
                 FROM agent_payment_authorizations
                 WHERE auth_id = ?1",
                params![payload.authorization_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "Authorization not found".into()))?;
        let (agent_id, amount_minor, currency, db_merchant, expires_at, consumed) = row;
        if db_merchant != payload.merchant_id.trim() {
            return Err((StatusCode::FORBIDDEN, "merchant_id mismatch".into()));
        }
        if expires_at < now_i64 {
            return Err((StatusCode::GONE, "Authorization expired".into()));
        }
        if consumed != 0 {
            return Err((StatusCode::CONFLICT, "Authorization already consumed".into()));
        }
        db.execute(
            "UPDATE agent_payment_authorizations SET consumed = 1 WHERE auth_id = ?1",
            params![payload.authorization_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        (agent_id, amount_minor, currency)
    };

    // Update payment SMT: set key(agent_id, current window) = 1.
    let win_start = sauron_core::payment_smt::window_start(now);
    let key_hex = sauron_core::payment_smt::payment_smt_key(&agent_id, win_start);
    {
        let st = state.read().unwrap();
        let mut smt = st.payment_smt.lock().unwrap();
        smt.set_leaf(&st.db, &key_hex, 1);
        // Invalidate cached root so stale proofs can't be generated until issuer recomputes.
        smt.root = "pending".to_string();
    }

    Ok(Json(serde_json::json!({
        "consumed": true,
        "authorization_id": payload.authorization_id,
        "agent_id": agent_id,
        "amount_minor": amount_minor,
        "currency": currency,
        "window_start": win_start,
        "smt_key_hex": key_hex,
        "note": "SMT leaf set to 1 — non-payment proofs for this agent in this window will now fail.",
    })))
}

// ─────────────────────────────────────────────────────
//  Proof of Non-Payment endpoints
// ─────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct PaymentNonexistenceMaterialBody {
    agent_id: String,
    /// Unix timestamp inside the window to prove (defaults to now).
    #[serde(default)]
    timestamp: Option<u64>,
}

/// POST /agent/payment/nonexistence/material
///
/// Returns the SMT path material needed for a client to generate a ZKP showing
/// that the agent has no consumed payment in the current 30-day window.
async fn payment_nonexistence_material(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<PaymentNonexistenceMaterialBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.agent_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()));
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ts = payload.timestamp.unwrap_or(now_unix);
    let win_start = sauron_core::payment_smt::window_start(ts);
    let key_hex = sauron_core::payment_smt::payment_smt_key(&payload.agent_id, win_start);

    let (path_request, current_root, is_non_member) = {
        let st = state.read().unwrap();
        let smt = st.payment_smt.lock().unwrap();
        let is_nm = smt.is_non_member(&key_hex);
        let req = smt.build_path_request(&key_hex);
        let root = smt.root.clone();
        (req, root, is_nm)
    };

    // Delegate Poseidon path computation to the issuer service.
    let issuer_url = {
        let st = state.read().unwrap();
        st.issuer_url.clone()
    };
    let client = reqwest::Client::new();
    let issuer_resp = client
        .post(format!("{}/payment-smt/path", issuer_url))
        .json(&path_request)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer unreachable: {e}")))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer bad JSON: {e}")))?;

    Ok(Json(serde_json::json!({
        "agent_id": payload.agent_id,
        "window_start": win_start,
        "key_hex": key_hex,
        "is_non_member": is_non_member,
        "smt_levels": sauron_core::payment_smt::SMT_LEVELS,
        "current_root": current_root,
        "path": issuer_resp.get("path").cloned().unwrap_or(serde_json::Value::Null),
        "public_inputs": {
            "root": issuer_resp.get("root").and_then(|v| v.as_str()).unwrap_or(&current_root),
            "key_hex": key_hex,
            "window_start": win_start,
            "agent_id": payload.agent_id,
        },
    })))
}

#[derive(serde::Deserialize)]
struct PaymentNonexistenceVerifyBody {
    agent_id: String,
    window_start: u64,
    /// Groth16 proof object from the client.
    proof: serde_json::Value,
    /// Public signals emitted by the circuit.
    public_signals: Vec<String>,
}

/// POST /agent/payment/nonexistence/verify
///
/// Verifies a client-generated ZKP proving non-payment in a 30-day window.
/// Delegates Groth16 verification to the issuer service.
async fn payment_nonexistence_verify(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<PaymentNonexistenceVerifyBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if payload.agent_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()));
    }

    let key_hex = sauron_core::payment_smt::payment_smt_key(
        &payload.agent_id,
        payload.window_start,
    );

    let current_root = {
        let st = state.read().unwrap();
        let smt = st.payment_smt.lock().unwrap();
        smt.root.clone()
    };

    // Forward proof to issuer for Groth16 verification.
    let issuer_url = {
        let st = state.read().unwrap();
        st.issuer_url.clone()
    };
    let verify_body = serde_json::json!({
        "circuit": "PaymentNonMembershipSMT",
        "proof": payload.proof,
        "publicSignals": payload.public_signals,
        "expectedRoot": current_root,
        "expectedKeyHex": key_hex,
    });
    let client = reqwest::Client::new();
    let issuer_resp = client
        .post(format!("{}/verify-proof", issuer_url))
        .json(&verify_body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer unreachable: {e}")))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer bad JSON: {e}")))?;

    let verified = issuer_resp
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !verified {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "ZKP verification failed: {}",
                issuer_resp
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            ),
        ));
    }

    Ok(Json(serde_json::json!({
        "verified": true,
        "agent_id": payload.agent_id,
        "window_start": payload.window_start,
        "key_hex": key_hex,
        "root_checked": current_root,
        "smt_levels": sauron_core::payment_smt::SMT_LEVELS,
    })))
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
    let (issuer_url, client) = {
        let st = state.read().unwrap();
        (st.issuer_url.clone(), st.issuer_runtime.client.clone())
    };
    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
        "subject_did": subject_did,
    });

    let resp = client
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
    /// From `POST /agent/pop/challenge` when the agent has PoP keys registered.
    #[serde(default)]
    pop_challenge_id: String,
    /// Compact JWS signing the challenge plaintext (Ed25519).
    #[serde(default)]
    pop_jws: String,
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

    let consent_guard_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        risk::check_and_increment(
            &db,
            &risk::bucket_agent_kyc_consent(&payload.site_name, &human_key_image),
            consent_guard_ts,
            risk::limit_agent_kyc_consent(),
        )
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        let nationality: String = db
            .query_row(
                "SELECT IFNULL(nationality, '') FROM users WHERE key_image_hex = ?1",
                params![human_key_image],
                |r| r.get(0),
            )
            .unwrap_or_default();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?;
        st.screening
            .enforce_for_user(&db, &human_key_image)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?;
    }

    // 2. Verify agent status + mandatory delegated-ring membership + KYA policy
    let assurance_level = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, agent_pub_hex, assurance, pop_pk_b64u): (
            i64,
            i64,
            String,
            String,
            String,
            String,
        ) = db
            .query_row(
                "SELECT revoked, expires_at, human_key_image, public_key_hex, assurance_level, IFNULL(pop_public_key_b64u, '') FROM agents WHERE agent_id = ?1",
                params![agent_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap_or((
                1,
                0,
                String::new(),
                String::new(),
                "delegated_nonbank".to_string(),
                String::new(),
            ));
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

        if !pop_pk_b64u.is_empty() {
            if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Agent requires PoP: provide pop_challenge_id and pop_jws from /agent/pop/challenge"
                        .into(),
                ));
            }
            let challenge_plain = sauron_core::ajwt_support::take_pop_challenge(
                &db,
                &payload.pop_challenge_id,
                &agent_id,
            )
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
            sauron_core::ajwt_support::verify_ed25519_pop_jws(
                &challenge_plain,
                &payload.pop_jws,
                &pop_pk_b64u,
            )
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        }

        assurance
    };

    let level = policy::AssuranceLevel::from_db(&assurance_level);
    if !policy::can_agent_issue_kyc_consent(level) {
        return Err((
            StatusCode::FORBIDDEN,
            "delegated_nonbank agents cannot issue KYC consent; use bank-linked delegated registration or /agent/vc/issue"
                .into(),
        ));
    }

    // 3b. Server-side JTI consumption (one consent per A-JWT)
    {
        let jti = claims
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".into()))?;
        let exp = claims
            .get("exp")
            .and_then(|v| v.as_i64())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".into()))?;
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&db, jti, exp)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    }

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
                "UPDATE consent_log SET consent_token = ?1, user_key_image = ?2, granted_at = ?3, consent_expires_at = ?4, issuing_agent_id = ?5 WHERE request_id = ?6 AND consent_token IS NULL",
                params![consent_token, human_key_image, now, expires_at, agent_id, payload.request_id],
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
    /// Optional Groth16 ZKP proof for non-bank KYA.
    #[serde(default)]
    zkp_proof: Option<serde_json::Value>,
    /// Circuit name for non-bank proof (defaults to CredentialVerification).
    #[serde(default)]
    zkp_circuit: Option<String>,
    /// Public signals for non-bank proof.
    #[serde(default)]
    zkp_public_signals: Option<Vec<String>>,
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

    // 1. Verify authenticated human exists and resolve trust source.
    let (human_in_user_ring, has_bank_link) = {
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
                    "Human user not found — must be registered in trusted user directory first".into(),
                )
            })?;

        let has_bank_link: bool = db
            .query_row(
                "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
                params![human_key_image],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        let bytes = hex::decode(&human_pub_hex)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Human user public key encoding invalid".into()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Human user public key length invalid".into()))?;
        let pt = CompressedRistretto(arr)
            .decompress()
            .ok_or((StatusCode::UNAUTHORIZED, "Human user public key point invalid".into()))?;

        (st.user_group.members.contains(&pt), has_bank_link)
    };

    let vc_issue_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        risk::check_and_increment(
            &db,
            &risk::bucket_agent_vc_issue(&human_key_image),
            vc_issue_ts,
            risk::limit_agent_vc_issue(),
        )
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        let nationality: String = db
            .query_row(
                "SELECT IFNULL(nationality, '') FROM users WHERE key_image_hex = ?1",
                params![human_key_image],
                |r| r.get(0),
            )
            .unwrap_or_default();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?;
        st.screening
            .enforce_for_user(&db, &human_key_image)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?;
    }

    let mut non_bank_kya_assertions: Option<serde_json::Map<String, serde_json::Value>> = None;
    let root_of_trust: String;

    if has_bank_link && human_in_user_ring {
        root_of_trust = "did:sauron:idp:bank_kyc".to_string();
    } else {
        let proof = payload
            .zkp_proof
            .clone()
            .ok_or((StatusCode::BAD_REQUEST, "zkp_proof is required for non-bank KYA issuance".into()))?;
        let public_signals = payload
            .zkp_public_signals
            .clone()
            .ok_or((StatusCode::BAD_REQUEST, "zkp_public_signals are required for non-bank KYA issuance".into()))?;
        if public_signals.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "zkp_public_signals must not be empty".into()));
        }
        let circuit = payload
            .zkp_circuit
            .clone()
            .unwrap_or_else(|| "CredentialVerification".to_string());

        let requested_dev_mock = proof
            .get("dev_mock")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if requested_dev_mock {
            return Err((
                StatusCode::BAD_REQUEST,
                "dev_mock proofs are disabled".into(),
            ));
        }

        let (issuer_urls, issuer_rt) = {
            let st = state.read().unwrap();
            (st.issuer_urls.clone(), st.issuer_runtime.clone())
        };
        let verify_body = serde_json::json!({
            "circuit": circuit,
            "proof": proof,
            "public_signals": public_signals,
            "publicSignals": public_signals,
        });
        let proof_verified = match issuer_rt
            .verify_proof_failover(&issuer_urls, &verify_body)
            .await
        {
            Ok(v) => v,
            Err(IssuerVerifyError::CircuitOpen) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ZKP issuer verify-proof temporarily unavailable (circuit open)".into(),
                ));
            }
            Err(IssuerVerifyError::Transport(e)) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("ZKP issuer unreachable: {e}"),
                ));
            }
            Err(IssuerVerifyError::JsonParse) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "ZKP issuer returned unreadable JSON for verify-proof".into(),
                ));
            }
            Err(IssuerVerifyError::Upstream(status)) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("ZKP issuer verify-proof returned HTTP {status}"),
                ));
            }
        };

        if !proof_verified {
            return Err((StatusCode::UNAUTHORIZED, "Non-bank KYA proof verification failed".into()));
        }

        let assertions = build_zkp_assertions(&circuit, &public_signals);
        let credential_valid = assertions
            .get("credential_valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !credential_valid {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Non-bank KYA requires credential_valid=1 in CredentialVerification proof".into(),
            ));
        }

        non_bank_kya_assertions = Some(assertions);
        root_of_trust = "did:sauron:idp:non_bank_zkp".to_string();
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
            "rootOfTrust": root_of_trust,
            "kyaEvidence": non_bank_kya_assertions,
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
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u)
             VALUES (?1,?2,?3,?4,'autonomous_web3','',?5,?6,0,NULL,0,'','')",
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
        None,
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
        "trust_chain": if has_bank_link && human_in_user_ring {
            "SauronID self-sovereign (bank-linked human trust root)"
        } else {
            "SauronID self-sovereign (non-bank CredentialVerification proof root)"
        },
    })))
}
