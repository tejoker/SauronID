// ─────────────────────────────────────────────────────────────────────────────
//  A-JWT Agentic Layer
//
//  An A-JWT (Agentic JSON Web Token) allows an AI agent to call the Sauron API
//  on behalf of a human user.  The token proves:
//    - Which human authorised the agent  (sub = human key_image_hex)
//    - What the agent is allowed to do   (intent JSON)
//    - The agent hasn't been tampered    (agent_checksum = SHA-256 of agent config)
//
//  Token format (EdDSA/Ed25519, base64url-encoded JSON parts):
//    header.payload.signature   (dot-separated, all base64url-no-padding)
//
//  Signing keys are derived per-agent from server secret + agent identity
//  material, so each agent has a distinct effective signing key.
// ─────────────────────────────────────────────────────────────────────────────

use axum::{
    extract::{State, Path, Json},
    http::{StatusCode, HeaderMap},
};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use rusqlite::params;
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::state::ServerState;

// ─── Token helpers ───────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn verify_user_session(jwt_secret: &[u8], session: &str) -> Option<String> {
    let pos = session.rfind('|')?;
    let payload = &session[..pos];
    let sig = &session[pos + 1..];
    let mut h = Sha256::new();
    h.update(jwt_secret);
    h.update(b"|SESSION|");
    h.update(payload.as_bytes());
    if hex::encode(h.finalize()) != sig {
        return None;
    }
    let pos2 = payload.rfind('|')?;
    let expires_at: i64 = payload[pos2 + 1..].parse().ok()?;
    if now_secs() > expires_at {
        return None;
    }
    Some(payload[..pos2].to_string())
}

fn session_key_image(headers: &HeaderMap, jwt_secret: &[u8]) -> Option<String> {
    let session = headers.get("x-sauron-session")?.to_str().ok()?;
    verify_user_session(jwt_secret, session)
}

/// Encode a JSON value as base64url (no padding).
fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

fn derive_agent_signing_key(
    jwt_secret: &[u8],
    agent_id: &str,
    human_key_image: &str,
    agent_checksum: &str,
) -> SigningKey {
    let mut h = Sha256::new();
    h.update(jwt_secret);
    h.update(b"|AJWT_ED25519|\n");
    h.update(agent_id.as_bytes());
    h.update(b"|");
    h.update(human_key_image.as_bytes());
    h.update(b"|");
    h.update(agent_checksum.as_bytes());
    let seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Forge an A-JWT signed with per-agent Ed25519 key material.
pub fn forge_ajwt(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    ttl_secs: i64,
) -> String {
    let header_obj = serde_json::json!({
        "alg": "EdDSA",
        "typ": "ajwt+jwt",
        "kid": agent_id,
    });
    let header = b64url(header_obj.to_string().as_bytes());
    let now = now_secs();
    let payload_obj = serde_json::json!({
        "iss": "did:sauron:idp",
        "sub": human_key_image,
        "agent_id": agent_id,
        "agent_checksum": agent_checksum,
        "intent": intent_json,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": uuid_v4(),
    });
    let payload = b64url(payload_obj.to_string().as_bytes());
    let signing_input = format!("{}.{}", header, payload);

    let signing_key = derive_agent_signing_key(
        jwt_secret,
        agent_id,
        human_key_image,
        agent_checksum,
    );
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig = b64url(&signature.to_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

/// Verify an A-JWT.  Returns the decoded payload if valid.
pub fn verify_ajwt(
    jwt_secret: &[u8],
    token: &str,
) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 { return None; }

    let header_bytes = b64url_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    if header.get("alg")?.as_str()? != "EdDSA" {
        return None;
    }

    let payload_bytes = b64url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    let agent_id = payload.get("agent_id")?.as_str()?;
    let human_key_image = payload.get("sub")?.as_str()?;
    let agent_checksum = payload.get("agent_checksum")?.as_str()?;

    let signing_key = derive_agent_signing_key(
        jwt_secret,
        agent_id,
        human_key_image,
        agent_checksum,
    );
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let sig_bytes = b64url_decode(parts[2])?;
    let signature = Signature::from_slice(&sig_bytes).ok()?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .ok()?;

    // Check expiry
    let exp = payload.get("exp")?.as_i64()?;
    if now_secs() > exp { return None; }

    Some(payload)
}

fn uuid_v4() -> String {
    use sha2::Sha256;
    let mut h = Sha256::new();
    h.update(&now_secs().to_le_bytes());
    h.update(b"uuid_salt");
    let d = h.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d[0],d[1],d[2],d[3],d[4],d[5],d[6]&0x0f,d[7],
        (d[8]&0x3f)|0x80,d[9],d[10],d[11],d[12],d[13],d[14],d[15]
    )
}

// ─── Request / Response types ────────────────────────────────────────────────

/// POST /agent/register
#[derive(Deserialize)]
pub struct RegisterAgentRequest {
    /// key_image_hex of the human owner (optional legacy field; server trusts session).
    #[serde(default)]
    pub human_key_image: String,
    /// SHA-256 hex of the agent's config (proves the agent is what it claims to be).
    pub agent_checksum: String,
    /// JSON describing what the agent is allowed to do.
    #[serde(default = "default_intent")]
    pub intent_json: String,
    /// Agent public key (Ristretto compressed hex). Mandatory for ring membership.
    pub public_key_hex: String,
    /// Lifetime in seconds (default 3600, max 86400).
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
}

fn default_intent() -> String { "{}".to_string() }
fn default_ttl() -> i64 { 3600 }

#[derive(Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: String,
    pub ajwt: String,
    pub expires_at: i64,
    pub assurance_level: String,
}

/// GET /agent/{agent_id}
#[derive(Serialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub intent_json: String,
    pub assurance_level: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// POST /agent/verify  (used by external callers to validate an A-JWT)
#[derive(Deserialize)]
pub struct VerifyAjwtRequest {
    pub ajwt: String,
}

#[derive(Serialize)]
pub struct VerifyAjwtResponse {
    pub valid: bool,
    pub agent_id: Option<String>,
    pub human_key_image: Option<String>,
    pub intent_json: Option<String>,
    pub assurance_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn has_bank_kyc_link(db: &rusqlite::Connection, human_key_image: &str) -> bool {
    db.query_row(
        "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
        params![human_key_image],
        |r| r.get::<_, i64>(0),
    )
    .ok()
    .unwrap_or(0)
        > 0
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /agent/register — authenticated user registers an agent bound to their session.
pub async fn register_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()));
    }
    if payload.public_key_hex.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "public_key_hex is required for delegated-agent ring binding".into()));
    }

    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let human_key_image = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Valid x-sauron-session header required".into()))?;

    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((StatusCode::UNAUTHORIZED, "human_key_image payload does not match authenticated session".into()));
    }

    let agent_point = {
        let bytes = hex::decode(&payload.public_key_hex)
            .map_err(|_| (StatusCode::BAD_REQUEST, "public_key_hex must be valid hex".into()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| (StatusCode::BAD_REQUEST, "public_key_hex must be 32-byte compressed Ristretto point".into()))?;
        curve25519_dalek::ristretto::CompressedRistretto(arr)
            .decompress()
            .ok_or((StatusCode::BAD_REQUEST, "public_key_hex is not a valid Ristretto point".into()))?
    };

    // Ensure no active agent already uses this pubkey.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let in_use: bool = db.query_row(
            "SELECT COUNT(*) FROM agents WHERE public_key_hex = ?1 AND revoked = 0",
            params![payload.public_key_hex],
            |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if in_use {
            return Err((StatusCode::CONFLICT, "public_key_hex already registered to an active agent".into()));
        }
    }

    // Validate human exists in DB
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
            params![human_key_image],
            |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if !exists {
            return Err((StatusCode::NOT_FOUND, "Human user not found — register the user first".into()));
        }
    }

    let has_bank_link = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        has_bank_kyc_link(&db, &human_key_image)
    };

    if !has_bank_link {
        return Err((
            StatusCode::FORBIDDEN,
            "Delegated registration requires bank-verified KYC link. Use /agent/vc/issue for non-bank agents.".into(),
        ));
    };

    let assurance_level = "delegated_bank".to_string();

    let ttl = payload.ttl_secs.clamp(60, 86400);
    let now = now_secs();
    let expires_at = now + ttl;

    // Generate a deterministic-ish agent_id from checksum + timestamp
    let mut h = Sha256::new();
    h.update(payload.agent_checksum.as_bytes());
    h.update(human_key_image.as_bytes());
    h.update(&now.to_le_bytes());
    let agent_id = format!("agt_{}", &hex::encode(h.finalize())[..24]);

    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &payload.intent_json,
        ttl,
    );

    // Persist agent in DB
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT OR REPLACE INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, issued_at, expires_at, revoked)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0)",
            params![
                agent_id, human_key_image, payload.agent_checksum,
                payload.intent_json, assurance_level, payload.public_key_hex, now, expires_at,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Mandatory ring membership for delegated agents.
    {
        let mut st = state.write().unwrap();
        if !st.agent_group.members.contains(&agent_point) {
            st.agent_group.members.push(agent_point);
        }
    }

    {
        let st = state.read().unwrap();
        st.log("AGENT_REGISTER", "OK", &agent_id);
    }
    println!("[AGENT] Registered agent_id={} human={}", agent_id, &human_key_image[..16]);

    Ok(Json(RegisterAgentResponse { agent_id, ajwt, expires_at, assurance_level }))
}

/// GET /agent/{agent_id} — retrieve agent info.
pub async fn get_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentRecord>, StatusCode> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    db.query_row(
        "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, issued_at, expires_at, revoked
         FROM agents WHERE agent_id = ?1",
        params![agent_id],
        |row| Ok(AgentRecord {
            agent_id:        row.get(0)?,
            human_key_image: row.get(1)?,
            agent_checksum:  row.get(2)?,
            intent_json:     row.get(3)?,
            assurance_level: row.get(4)?,
            issued_at:       row.get(5)?,
            expires_at:      row.get(6)?,
            revoked:         row.get::<_, i64>(7)? != 0,
        }),
    ).map(Json).map_err(|_| StatusCode::NOT_FOUND)
}

/// DELETE /agent/{agent_id} — revoke an agent owned by authenticated user.
pub async fn revoke_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let human_ki = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Valid x-sauron-session header required".into()))?;

    let rows = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "UPDATE agents SET revoked = 1 WHERE agent_id = ?1 AND human_key_image = ?2",
            params![agent_id, human_ki],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Agent not found or not owned by this user".into()));
    }

    {
        let st = state.read().unwrap();
        st.log("AGENT_REVOKE", "OK", &agent_id);
    }
    println!("[AGENT] Revoked agent_id={}", agent_id);

    Ok(Json(serde_json::json!({ "revoked": true, "agent_id": agent_id })))
}

/// POST /agent/verify — validate an A-JWT token.
pub async fn verify_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<VerifyAjwtRequest>,
) -> Json<VerifyAjwtResponse> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();

    let claims = match verify_ajwt(&jwt_secret, &payload.ajwt) {
        None => return Json(VerifyAjwtResponse {
            valid: false,
            agent_id: None,
            human_key_image: None,
            intent_json: None,
            assurance_level: None,
            error: Some("Invalid or expired A-JWT".into()),
        }),
        Some(c) => c,
    };

    let agent_id = claims.get("agent_id").and_then(|v| v.as_str()).map(String::from);
    let human_ki = claims.get("sub").and_then(|v| v.as_str()).map(String::from);
    let intent   = claims.get("intent").and_then(|v| v.as_str()).map(String::from);

    // Cross-check with DB: agent must not be revoked
    let mut assurance_level: Option<String> = None;

    if let Some(ref aid) = agent_id {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let (revoked, db_assurance): (i64, String) = db.query_row(
            "SELECT revoked, assurance_level FROM agents WHERE agent_id = ?1",
            params![aid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap_or((1, "delegated_nonbank".to_string())); // if not found, treat as revoked
        assurance_level = Some(db_assurance);
        if revoked != 0 {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id: agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level,
                error: Some("Agent has been revoked".into()),
            });
        }
    }

    Json(VerifyAjwtResponse {
        valid: true,
        agent_id,
        human_key_image: human_ki,
        intent_json: intent,
        assurance_level,
        error: None,
    })
}

/// GET /agent/list/{human_key_image} — list agents for authenticated human only.
pub async fn list_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Path(human_ki): Path<String>,
) -> Result<Json<Vec<AgentRecord>>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let session_human = session_key_image(&headers, &jwt_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "Valid x-sauron-session header required".into()))?;
    if session_human != human_ki {
        return Err((StatusCode::UNAUTHORIZED, "Cannot list agents for another user".into()));
    }

    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, issued_at, expires_at, revoked
         FROM agents WHERE human_key_image = ?1 ORDER BY issued_at DESC"
    ).unwrap();
    let records: Vec<AgentRecord> = stmt.query_map(params![human_ki], |row| {
        Ok(AgentRecord {
            agent_id:        row.get(0)?,
            human_key_image: row.get(1)?,
            agent_checksum:  row.get(2)?,
            intent_json:     row.get(3)?,
            assurance_level: row.get(4)?,
            issued_at:       row.get(5)?,
            expires_at:      row.get(6)?,
            revoked:         row.get::<_, i64>(7)? != 0,
        })
    }).unwrap().flatten().collect();
    Ok(Json(records))
}
