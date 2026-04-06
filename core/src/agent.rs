// ─────────────────────────────────────────────────────────────────────────────
//  A-JWT Agentic Layer
//
//  An A-JWT (Agentic JSON Web Token) allows an AI agent to call the Sauron API
//  on behalf of a human user.  The token proves:
//    - Which human authorised the agent  (sub = human key_image_hex)
//    - What the agent is allowed to do   (intent JSON)
//    - The agent hasn't been tampered    (agent_checksum = SHA-256 of agent config)
//
//  Token format (HMAC-SHA256, base64url-encoded JSON parts):
//    header.payload.signature   (dot-separated, all base64url-no-padding)
//
//  This is a simplified implementation using HMAC-SHA256 instead of Ed25519
//  so that no extra key-management infrastructure is needed at the Rust layer.
//  The `agentic/src/` TypeScript library provides the full Ed25519/jose flavour
//  for external integrations.
// ─────────────────────────────────────────────────────────────────────────────

use axum::{
    extract::{State, Path, Json},
    http::{StatusCode, HeaderMap},
};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use rusqlite::params;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::state::ServerState;

type HmacSha256 = Hmac<Sha256>;

// ─── Token helpers ───────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Encode a JSON value as base64url (no padding).
fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Forge an A-JWT signed with the server's HMAC-SHA256 jwt_secret.
pub fn forge_ajwt(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    ttl_secs: i64,
) -> String {
    let header = b64url(b"{\"alg\":\"HS256\",\"typ\":\"ajwt+jwt\"}");
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
    let mut mac = HmacSha256::new_from_slice(jwt_secret).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = b64url(&mac.finalize().into_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

/// Verify an A-JWT.  Returns the decoded payload if valid.
pub fn verify_ajwt(
    jwt_secret: &[u8],
    token: &str,
) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 { return None; }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(jwt_secret).unwrap();
    mac.update(signing_input.as_bytes());
    let expected_sig = b64url(&mac.finalize().into_bytes());
    if expected_sig != parts[2] { return None; }

    let payload_bytes = b64url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

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
    /// key_image_hex of the human owner.
    pub human_key_image: String,
    /// SHA-256 hex of the agent's config (proves the agent is what it claims to be).
    pub agent_checksum: String,
    /// JSON describing what the agent is allowed to do.
    #[serde(default = "default_intent")]
    pub intent_json: String,
    /// Ed25519 public key of the agent (hex), for future PoP binding.
    #[serde(default)]
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
}

/// GET /agent/{agent_id}
#[derive(Serialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub intent_json: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /agent/register — any caller with a valid human_key_image can register an agent.
pub async fn register_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    if payload.human_key_image.is_empty() || payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "human_key_image and agent_checksum required".into()));
    }

    // Validate human exists in DB
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
            params![payload.human_key_image],
            |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if !exists {
            return Err((StatusCode::NOT_FOUND, "Human user not found — register the user first".into()));
        }
    }

    let ttl = payload.ttl_secs.clamp(60, 86400);
    let now = now_secs();
    let expires_at = now + ttl;

    // Generate a deterministic-ish agent_id from checksum + timestamp
    let mut h = Sha256::new();
    h.update(payload.agent_checksum.as_bytes());
    h.update(payload.human_key_image.as_bytes());
    h.update(&now.to_le_bytes());
    let agent_id = format!("agt_{}", &hex::encode(h.finalize())[..24]);

    let (jwt_secret, issuer_url) = {
        let st = state.read().unwrap();
        (st.jwt_secret.clone(), st.issuer_url.clone())
    };
    let _ = issuer_url; // not needed here, kept for symmetry

    let ajwt = forge_ajwt(
        &jwt_secret,
        &payload.human_key_image,
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
             (agent_id, human_key_image, agent_checksum, intent_json, public_key_hex, issued_at, expires_at, revoked)
             VALUES (?1,?2,?3,?4,?5,?6,?7,0)",
            params![
                agent_id, payload.human_key_image, payload.agent_checksum,
                payload.intent_json, payload.public_key_hex, now, expires_at,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Push agent public key into in-memory ring group so it's immediately usable.
    if !payload.public_key_hex.is_empty() {
        if let Ok(bytes) = hex::decode(&payload.public_key_hex) {
            if let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> {
                if let Some(pt) = curve25519_dalek::ristretto::CompressedRistretto(arr).decompress() {
                    let mut st = state.write().unwrap();
                    if !st.agent_group.members.contains(&pt) {
                        st.agent_group.members.push(pt);
                    }
                }
            }
        }
    }

    {
        let st = state.read().unwrap();
        st.log("AGENT_REGISTER", "OK", &agent_id);
    }
    println!("[AGENT] Registered agent_id={} human={}", agent_id, &payload.human_key_image[..16]);

    Ok(Json(RegisterAgentResponse { agent_id, ajwt, expires_at }))
}

/// GET /agent/{agent_id} — retrieve agent info.
pub async fn get_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentRecord>, StatusCode> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    db.query_row(
        "SELECT agent_id, human_key_image, agent_checksum, intent_json, issued_at, expires_at, revoked
         FROM agents WHERE agent_id = ?1",
        params![agent_id],
        |row| Ok(AgentRecord {
            agent_id:        row.get(0)?,
            human_key_image: row.get(1)?,
            agent_checksum:  row.get(2)?,
            intent_json:     row.get(3)?,
            issued_at:       row.get(4)?,
            expires_at:      row.get(5)?,
            revoked:         row.get::<_, i64>(6)? != 0,
        }),
    ).map(Json).map_err(|_| StatusCode::NOT_FOUND)
}

/// DELETE /agent/{agent_id} — revoke an agent.
/// Caller must provide the agent's human_key_image in the x-human-key-image header.
pub async fn revoke_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let human_ki = headers
        .get("x-human-key-image")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if human_ki.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "x-human-key-image header required".into()));
    }

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
            error: Some("Invalid or expired A-JWT".into()),
        }),
        Some(c) => c,
    };

    let agent_id = claims.get("agent_id").and_then(|v| v.as_str()).map(String::from);
    let human_ki = claims.get("sub").and_then(|v| v.as_str()).map(String::from);
    let intent   = claims.get("intent").and_then(|v| v.as_str()).map(String::from);

    // Cross-check with DB: agent must not be revoked
    if let Some(ref aid) = agent_id {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let revoked: i64 = db.query_row(
            "SELECT revoked FROM agents WHERE agent_id = ?1",
            params![aid],
            |r| r.get(0),
        ).unwrap_or(1); // if not found, treat as revoked
        if revoked != 0 {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id: agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                error: Some("Agent has been revoked".into()),
            });
        }
    }

    Json(VerifyAjwtResponse {
        valid: true,
        agent_id,
        human_key_image: human_ki,
        intent_json: intent,
        error: None,
    })
}

/// GET /agent/list/{human_key_image} — list all agents for a human.
pub async fn list_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(human_ki): Path<String>,
) -> Json<Vec<AgentRecord>> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT agent_id, human_key_image, agent_checksum, intent_json, issued_at, expires_at, revoked
         FROM agents WHERE human_key_image = ?1 ORDER BY issued_at DESC"
    ).unwrap();
    let records: Vec<AgentRecord> = stmt.query_map(params![human_ki], |row| {
        Ok(AgentRecord {
            agent_id:        row.get(0)?,
            human_key_image: row.get(1)?,
            agent_checksum:  row.get(2)?,
            intent_json:     row.get(3)?,
            issued_at:       row.get(4)?,
            expires_at:      row.get(5)?,
            revoked:         row.get::<_, i64>(6)? != 0,
        })
    }).unwrap().flatten().collect();
    Json(records)
}
