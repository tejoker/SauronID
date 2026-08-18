//! Owner session: a stateless HMAC bearer token, now revocable.
//!
//! This is the credential that authorises `POST /agent/register` and
//! `POST /agent/{id}/checksum/update` — it MINTS agent authority. An attacker
//! holding one registers a sibling agent with an `intent_json` it writes itself,
//! including a fresh egress allowlist and a PoP keypair it controls.
//!
//! It used to be unrevocable. Verification consulted no server state, so there
//! was nothing an operator could change in response to a leak: the token stayed
//! valid for its full hour regardless. `session_epoch` on
//! `user_auth_credentials` fixes that. The epoch is inside the signed payload,
//! so incrementing it makes every session previously issued for that owner fail
//! on its next use.
//!
//! Per-owner, not per-session: the response to a suspected leak is "cut this
//! owner off", and a per-session table would need a row per login to revoke a
//! capability that expires within the hour anyway. One integer, read from a row
//! the session path already has to touch.
//!
//! ## Format
//!
//! `v3|<tenant_id>|<key_image_hex>|<epoch>|<expires_at>|<hex hmac>`
//!
//! HMAC-SHA256 over `"|SESSION|" ‖ payload` under a subkey derived from
//! `jwt_secret`, NOT naked `SHA256(secret ‖ msg)`: the naked construction is
//! length-extendable, so anyone with one valid (payload, sig) could append
//! controlled bytes and forge another without the secret.
//!
//! `v2` (no epoch) is deliberately NOT accepted. Honouring it would leave every
//! pre-existing token unrevocable, which is the hole this closes. Deploying this
//! invalidates sessions in flight; they last an hour, so the cost is that
//! everyone signs in again once.

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

use crate::any_db::AnyConn;
use crate::sql_params;

type HmacSha256 = Hmac<Sha256>;

/// Session lifetime. Short on purpose — the epoch bounds a leak from above, but
/// expiry is what bounds it without operator action.
pub const SESSION_TTL_SECS: i64 = 3600;

/// Header carrying the session token.
pub const SESSION_HEADER: &str = "x-sauron-session";

/// A verified session: the owner it names and the epoch it was minted under.
///
/// Holding one means the HMAC checked out and the token has not expired. It does
/// NOT mean the epoch is still current — that requires a database read, which is
/// [`key_image_from_headers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSession {
    pub key_image: String,
    pub epoch: i64,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sign(jwt_secret: &[u8], payload: &str) -> String {
    let key = crate::crypto_protocol::derive_subkey(jwt_secret, "session-hmac-v1");
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
    mac.update(b"|SESSION|");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Mint a session for `key_image` under `epoch`. Returns the token and its
/// expiry. `epoch` must be the owner's CURRENT `session_epoch` — see
/// [`current_epoch`] — or the token is dead on arrival.
pub fn issue(jwt_secret: &[u8], tenant_id: &str, key_image: &str, epoch: i64) -> (String, i64) {
    let expires_at = now_secs() + SESSION_TTL_SECS;
    let payload = format!("v3|{tenant_id}|{key_image}|{epoch}|{expires_at}");
    let sig = sign(jwt_secret, &payload);
    (format!("{payload}|{sig}"), expires_at)
}

/// Verify the signature, tenant binding and expiry. Does no I/O, so the epoch it
/// returns is what the token CLAIMS, not what the server currently accepts.
pub fn verify(
    jwt_secret: &[u8],
    session: &str,
    expected_tenant_id: &str,
) -> Option<VerifiedSession> {
    let pos = session.rfind('|')?;
    let (payload, sig) = (&session[..pos], &session[pos + 1..]);
    let computed = sign(jwt_secret, payload);
    if computed.as_bytes().ct_eq(sig.as_bytes()).unwrap_u8() == 0 {
        return None;
    }
    let fields: Vec<&str> = payload.split('|').collect();
    // v2 tokens have 4 fields and no epoch. Rejected, not upgraded.
    if fields.len() != 5 || fields[0] != "v3" || fields[1] != expected_tenant_id {
        return None;
    }
    let key_image = fields[2];
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let epoch: i64 = fields[3].parse().ok()?;
    let expires_at: i64 = fields[4].parse().ok()?;
    if now_secs() > expires_at {
        return None;
    }
    Some(VerifiedSession {
        key_image: key_image.to_string(),
        epoch,
    })
}

/// The owner's current epoch. A missing credential row reads as 0, which is the
/// same value a freshly-created row carries, so an unknown owner cannot be
/// authenticated by this alone — the caller still needs a token signed for it.
pub fn current_epoch(db: &mut AnyConn<'_>, key_image: &str) -> i64 {
    db.scalar_or(
        "SELECT COALESCE(session_epoch, 0) FROM user_auth_credentials WHERE key_image_hex = ?1",
        sql_params![key_image],
        |r| r.get_i64(0),
        0,
    )
}

/// Invalidate every session issued for `key_image` by advancing its epoch.
/// Returns the new epoch. Idempotent in effect, not in value: each call bumps.
pub fn revoke_all(db: &mut AnyConn<'_>, key_image: &str) -> Result<i64, String> {
    db.execute(
        "UPDATE user_auth_credentials SET session_epoch = COALESCE(session_epoch, 0) + 1
         WHERE key_image_hex = ?1",
        sql_params![key_image],
    )
    .map_err(|e| format!("bump session_epoch: {e}"))?;
    Ok(current_epoch(db, key_image))
}

/// The full check every session-authenticated handler wants: signature, tenant,
/// expiry, AND that the epoch has not been revoked. `None` means "not
/// authenticated" for any of those reasons; the caller returns 401 either way.
pub fn key_image_from_headers(
    headers: &HeaderMap,
    jwt_secret: &[u8],
    expected_tenant_id: &str,
    db: &mut AnyConn<'_>,
) -> Option<String> {
    let raw = headers.get(SESSION_HEADER)?.to_str().ok()?;
    let verified = verify(jwt_secret, raw, expected_tenant_id)?;
    if current_epoch(db, &verified.key_image) != verified.epoch {
        return None;
    }
    Some(verified.key_image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_db::AsAnyConn;

    fn db_with_owner(key_image: &str) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn);
        conn.execute(
            "INSERT INTO user_auth_credentials (key_image_hex, ed25519_public_key_b64u, created_at)
             VALUES (?1, ?2, 1)",
            rusqlite::params![key_image, format!("pk-{key_image}")],
        )
        .unwrap();
        conn
    }

    fn headers_with(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(SESSION_HEADER, token.parse().unwrap());
        h
    }

    #[test]
    fn a_session_round_trips_and_is_bound_to_its_tenant() {
        let secret = [7u8; 32];
        let ki = "ab".repeat(32);
        let (token, exp) = issue(&secret, "tenant-a", &ki, 0);
        assert!(exp > now_secs());
        let v = verify(&secret, &token, "tenant-a").expect("verifies");
        assert_eq!(v.key_image, ki);
        assert_eq!(v.epoch, 0);
        // Replaying it against another tenant fails — the tenant is signed.
        assert!(verify(&secret, &token, "tenant-b").is_none());
        // So does a different secret.
        assert!(verify(&[9u8; 32], &token, "tenant-a").is_none());
    }

    /// The property this module exists for: after a revoke, a token that still
    /// verifies cryptographically and has NOT expired is no longer accepted.
    #[test]
    fn revoking_kills_a_still_valid_token() {
        let secret = [7u8; 32];
        let ki = "cd".repeat(32);
        let db = db_with_owner(&ki);
        let mut conn = db.any_conn();

        let epoch = current_epoch(&mut conn, &ki);
        let (token, _) = issue(&secret, "default", &ki, epoch);
        let headers = headers_with(&token);
        assert_eq!(
            key_image_from_headers(&headers, &secret, "default", &mut conn),
            Some(ki.clone()),
            "a fresh session authenticates"
        );

        let new_epoch = revoke_all(&mut conn, &ki).expect("revoke");
        assert_eq!(new_epoch, epoch + 1);

        // The signature is still good and the clock has not moved, yet the
        // session is refused. That is the whole point.
        assert!(
            verify(&secret, &token, "default").is_some(),
            "still cryptographically valid"
        );
        assert_eq!(
            key_image_from_headers(&headers, &secret, "default", &mut conn),
            None,
            "revoked session must not authenticate"
        );

        // A session minted after the bump works again.
        let (fresh, _) = issue(&secret, "default", &ki, new_epoch);
        assert_eq!(
            key_image_from_headers(&headers_with(&fresh), &secret, "default", &mut conn),
            Some(ki)
        );
    }

    /// v2 tokens carried no epoch, so honouring them would leave every
    /// pre-existing session permanently unrevocable.
    #[test]
    fn legacy_v2_tokens_are_refused_not_upgraded() {
        let secret = [7u8; 32];
        let ki = "ef".repeat(32);
        let expires_at = now_secs() + 600;
        let payload = format!("v2|default|{ki}|{expires_at}");
        let legacy = format!("{payload}|{}", sign(&secret, &payload));
        assert!(
            verify(&secret, &legacy, "default").is_none(),
            "a correctly signed v2 token must still be rejected"
        );
    }

    #[test]
    fn a_tampered_or_truncated_token_is_refused() {
        let secret = [7u8; 32];
        let ki = "11".repeat(32);
        let (token, _) = issue(&secret, "default", &ki, 0);
        for bad in [
            token.replace("v3", "v4"),
            token.replacen(&ki, &"22".repeat(32), 1),
            token[..token.len() - 4].to_string(),
            "garbage".to_string(),
            String::new(),
        ] {
            assert!(verify(&secret, &bad, "default").is_none(), "{bad}");
        }
    }

    /// An expired token is refused without any database read.
    #[test]
    fn an_expired_token_is_refused() {
        let secret = [7u8; 32];
        let ki = "33".repeat(32);
        let expires_at = now_secs() - 1;
        let payload = format!("v3|default|{ki}|0|{expires_at}");
        let expired = format!("{payload}|{}", sign(&secret, &payload));
        assert!(verify(&secret, &expired, "default").is_none());
    }
}
