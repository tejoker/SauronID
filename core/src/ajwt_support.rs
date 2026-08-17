//! Shared A-JWT / KYA helpers: intent scopes, JTI replay store, PoP JWS verification.

use crate::any_db::{AnyConn, AnyRowGet};
use crate::sql_params;
use rand::rngs::OsRng;
use rand::RngCore;
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
    let parent: std::collections::HashSet<String> = scopes_from_intent_json(parent_intent_json)
        .into_iter()
        .collect();
    if parent.is_empty() {
        return Err(
            "parent agent intent defines no delegable scopes (add scope[] or action)".into(),
        );
    }
    let child = scopes_from_intent_json(child_intent_json);
    if child.is_empty() {
        return Err(
            "child agent intent must declare scope[] (or action) for delegated registration".into(),
        );
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
///
/// Wrapped in `BEGIN IMMEDIATE TRANSACTION` to acquire the SQLite writer lock
/// for the duration of the delete+insert pair. Combined with `journal_mode =
/// WAL` + `busy_timeout` this gives single-writer serialisable semantics.
/// On Postgres the transaction is a plain `BEGIN` — READ COMMITTED, not
/// SERIALIZABLE. That is sufficient here because replay detection is the
/// PRIMARY KEY on `jti`, not anything this transaction reads: two concurrent
/// consumes of the same jti both attempt the INSERT and exactly one survives.
/// `Repo::consume_ajwt_jti` upgrades the isolation for callers that already
/// hold an async context.
pub fn consume_ajwt_jti(db: &mut AnyConn<'_>, jti: &str, exp: i64) -> Result<(), String> {
    if jti.is_empty() {
        return Err("missing jti".into());
    }
    if jti.len() > 256 {
        return Err("jti too long (max 256 chars)".into());
    }
    let now = now_secs();
    db.transaction(|tx| {
        tx.execute(
            "DELETE FROM ajwt_used_jtis WHERE exp < ?1",
            sql_params![&now],
        )?;
        tx.execute(
            "INSERT INTO ajwt_used_jtis (jti, exp) VALUES (?1, ?2)",
            sql_params![&jti, &exp],
        )
        .map_err(|e| {
            // Each backend spells the unique violation differently; matching
            // only SQLite's wording would turn a replay into a 500 on Postgres.
            let msg = e.to_lowercase();
            if msg.contains("unique") || msg.contains("duplicate key") {
                "A-JWT jti replay (token already used)".to_string()
            } else {
                e
            }
        })?;
        Ok(())
    })
}

/// Atomic single-use nonce consume for the DPoP-style per-call signature.
/// Returns Err if (agent_id, nonce) already inserted (replay), or db error.
///
/// Legacy direct-DB path. Prefer `Repo::consume_call_nonce` (in
/// `repository.rs`) which runs under `BEGIN IMMEDIATE` on SQLite and
/// `ISOLATION LEVEL SERIALIZABLE` (with retry) on Postgres.
pub fn consume_call_nonce(
    db: &mut AnyConn<'_>,
    agent_id: &str,
    nonce: &str,
    exp: i64,
) -> Result<(), String> {
    if nonce.is_empty() {
        return Err("missing call nonce".into());
    }
    if nonce.len() > 128 {
        return Err("call nonce too long (max 128 chars)".into());
    }
    // No transaction: one statement, and the replay check is the uniqueness of
    // (agent_id, nonce). Wrapping it added nothing on SQLite and would be a
    // READ COMMITTED transaction on Postgres, which is weaker than the
    // constraint doing the work.
    match db.execute(
        "INSERT INTO agent_call_nonces (agent_id, nonce, exp) VALUES (?1, ?2, ?3)",
        sql_params![&agent_id, &nonce, &exp],
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_lowercase();
            if msg.contains("unique")
                || msg.contains("primary key")
                || msg.contains("duplicate key")
            {
                Err("call nonce replay (already used)".to_string())
            } else {
                Err(e)
            }
        }
    }
}

/// Verify compact JWS: EdDSA over `header.payload`, payload decodes to UTF-8 `challenge`.
pub fn verify_ed25519_pop_jws(
    challenge: &str,
    jws: &str,
    public_key_b64url: &str,
) -> Result<(), String> {
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
    let payload_str =
        String::from_utf8(payload_bytes).map_err(|_| "pop JWS payload not UTF-8".to_string())?;
    if payload_str != challenge {
        return Err("pop JWS payload does not match challenge".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "pop JWS sig b64 invalid".to_string())?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|_| "invalid Ed25519 signature".to_string())?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| "PoP signature verification failed".to_string())
}

pub fn random_hex_32() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn random_challenge_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("pch_{}", hex::encode(bytes))
}

/// Store one-time PoP challenge for an agent.
pub fn insert_pop_challenge(
    db: &mut AnyConn<'_>,
    id: &str,
    agent_id: &str,
    challenge: &str,
    ttl_secs: i64,
) -> Result<i64, String> {
    let now = now_secs();
    let exp = now + ttl_secs;
    db.execute(
        "DELETE FROM agent_pop_challenges WHERE exp < ?1",
        sql_params![&now],
    )?;
    db.execute(
        "INSERT INTO agent_pop_challenges (id, agent_id, challenge, exp) VALUES (?1, ?2, ?3, ?4)",
        sql_params![&id, &agent_id, &challenge, &exp],
    )?;
    Ok(exp)
}

/// Load and delete challenge (one-time use).
///
/// The DELETE, not the SELECT, is what makes it one-time. The read validates
/// the agent binding and expiry so the caller gets a specific error, but two
/// concurrent takes can both pass that read — on SQLite as much as on Postgres,
/// since this pair was never wrapped in a transaction. Only the caller whose
/// DELETE reports a row removed may use the challenge; the loser is told it was
/// already consumed rather than being handed a second copy.
pub fn take_pop_challenge(
    db: &mut AnyConn<'_>,
    challenge_id: &str,
    expected_agent_id: &str,
) -> Result<String, String> {
    let now = now_secs();
    let (challenge, agent_id, exp): (String, String, i64) = db.require(
        "SELECT challenge, agent_id, exp FROM agent_pop_challenges WHERE id = ?1",
        sql_params![challenge_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        || "unknown or expired pop_challenge_id".to_string(),
    )?;
    if agent_id != expected_agent_id {
        return Err("pop challenge does not match agent".into());
    }
    if exp < now {
        let _ = db.execute(
            "DELETE FROM agent_pop_challenges WHERE id = ?1",
            sql_params![&challenge_id],
        );
        return Err("pop challenge expired".into());
    }
    let consumed = db.execute(
        "DELETE FROM agent_pop_challenges WHERE id = ?1",
        sql_params![&challenge_id],
    )?;
    if consumed != 1 {
        return Err("pop challenge already used".into());
    }
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_32_returns_32_hex_chars() {
        let r = random_hex_32();
        assert_eq!(r.len(), 32);
        assert!(r.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_hex_32_returns_distinct_values_across_calls() {
        let a = random_hex_32();
        let b = random_hex_32();
        assert_ne!(a, b);
    }
}
