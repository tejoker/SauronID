//! Shared A-JWT / KYA helpers: intent scopes, JTI replay store, PoP JWS verification.

use rusqlite::{params, Connection};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Effective delegable scopes from agent `intent_json` (subset checks for child registration).
pub fn scopes_from_intent_json(intent_json: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(intent_json).unwrap_or(Value::Null);
    if let Some(arr) = v.get("scope").and_then(|x| x.as_array()) {
        return arr
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    if let Some(arr) = v
        .get("constraints")
        .and_then(|c| c.get("scope"))
        .and_then(|x| x.as_array())
    {
        return arr
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    if let Some(s) = v.get("action").and_then(|x| x.as_str()) {
        if !s.is_empty() {
            return vec![s.to_string()];
        }
    }
    Vec::new()
}

/// Every child scope string must appear in parent scopes (set equality / subset).
pub fn assert_child_scopes_subset_of_parent(
    parent_intent_json: &str,
    child_intent_json: &str,
) -> Result<(), String> {
    let parent: std::collections::HashSet<String> =
        scopes_from_intent_json(parent_intent_json).into_iter().collect();
    if parent.is_empty() {
        return Err("parent agent intent defines no delegable scopes (add scope[] or action)".into());
    }
    let child = scopes_from_intent_json(child_intent_json);
    if child.is_empty() {
        return Err("child agent intent must declare scope[] (or action) for delegated registration"
            .into());
    }
    for s in &child {
        if !parent.contains(s) {
            return Err(format!(
                "delegation scope {:?} not allowed by parent intent",
                s
            ));
        }
    }
    Ok(())
}

/// Delete expired JTIs, then insert this one. Fails if `jti` already present.
pub fn consume_ajwt_jti(db: &Connection, jti: &str, exp: i64) -> Result<(), String> {
    if jti.is_empty() {
        return Err("missing jti".into());
    }
    let now = now_secs();
    db.execute("DELETE FROM ajwt_used_jtis WHERE exp < ?", params![now])
        .map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO ajwt_used_jtis (jti, exp) VALUES (?1, ?2)",
        params![jti, exp],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            "A-JWT jti replay (token already used)".to_string()
        } else {
            e.to_string()
        }
    })?;
    Ok(())
}

/// Verify compact JWS: EdDSA over `header.payload`, payload decodes to UTF-8 `challenge`.
pub fn verify_ed25519_pop_jws(challenge: &str, jws: &str, public_key_b64url: &str) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pk_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64url.trim())
        .map_err(|_| "pop_public_key_b64u invalid base64url".to_string())?;
    if pk_bytes.len() != 32 {
        return Err("pop public key must decode to 32 bytes".into());
    }
    let vk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "pop key length".to_string())?,
    )
    .map_err(|_| "invalid Ed25519 public key".to_string())?;

    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("pop JWS must have 3 segments".into());
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| "pop JWS payload b64 invalid".to_string())?;
    let payload_str = String::from_utf8(payload_bytes)
        .map_err(|_| "pop JWS payload not UTF-8".to_string())?;
    if payload_str != challenge {
        return Err("pop JWS payload does not match challenge".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "pop JWS sig b64 invalid".to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "invalid Ed25519 signature".to_string())?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| "PoP signature verification failed".to_string())
}

pub fn random_hex_32() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

pub fn random_challenge_id() -> String {
    format!("pch_{}", hex::encode(rand::random::<[u8; 16]>()))
}

/// Store one-time PoP challenge for an agent.
pub fn insert_pop_challenge(
    db: &Connection,
    id: &str,
    agent_id: &str,
    challenge: &str,
    ttl_secs: i64,
) -> Result<i64, String> {
    let now = now_secs();
    let exp = now + ttl_secs;
    db.execute(
        "DELETE FROM agent_pop_challenges WHERE exp < ?",
        params![now],
    )
    .map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO agent_pop_challenges (id, agent_id, challenge, exp) VALUES (?1, ?2, ?3, ?4)",
        params![id, agent_id, challenge, exp],
    )
    .map_err(|e| e.to_string())?;
    Ok(exp)
}

/// Load and delete challenge (one-time use).
pub fn take_pop_challenge(
    db: &Connection,
    challenge_id: &str,
    expected_agent_id: &str,
) -> Result<String, String> {
    let now = now_secs();
    let (challenge, agent_id, exp): (String, String, i64) = db
        .query_row(
            "SELECT challenge, agent_id, exp FROM agent_pop_challenges WHERE id = ?1",
            params![challenge_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| "unknown or expired pop_challenge_id".to_string())?;
    if agent_id != expected_agent_id {
        return Err("pop challenge does not match agent".into());
    }
    if exp < now {
        let _ = db.execute(
            "DELETE FROM agent_pop_challenges WHERE id = ?1",
            params![challenge_id],
        );
        return Err("pop challenge expired".into());
    }
    db.execute(
        "DELETE FROM agent_pop_challenges WHERE id = ?1",
        params![challenge_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(challenge)
}
