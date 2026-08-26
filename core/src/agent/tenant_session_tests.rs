//! Extracted verbatim from the inline `mod tenant_session_tests` that `agent.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;
use crate::any_db::AsAnyConn;
use crate::crypto_protocol;
use crate::user_session;
use axum::http::HeaderMap;
use sha2::Sha256;

/// Forge a legacy `v2` session — correctly signed, but carrying no epoch.
///
/// This is the shape the binary used to mint. It exists here so the routes
/// that consume sessions own a test proving they refuse it: a v2 token is
/// unrevocable by construction, and honouring one would reopen the hole the
/// epoch closes.
fn legacy_v2(secret: &[u8], tenant: &str, key_image: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let payload = format!("v2|{tenant}|{key_image}|{}", now_secs() + 60);
    let key = crypto_protocol::derive_subkey(secret, "session-hmac-v1");
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(b"|SESSION|");
    mac.update(payload.as_bytes());
    format!("{}|{}", payload, hex::encode(mac.finalize().into_bytes()))
}

fn headers_with(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(user_session::SESSION_HEADER, token.parse().unwrap());
    h
}

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

#[test]
fn agent_routes_reject_cross_tenant_human_sessions() {
    let secret = [3u8; 32];
    let ki = "ab".repeat(32);
    let (token, _) = user_session::issue(&secret, "tenant-a", &ki, 0);
    assert_eq!(
        user_session::verify(&secret, &token, "tenant-a").map(|v| v.key_image),
        Some(ki)
    );
    assert!(user_session::verify(&secret, &token, "tenant-b").is_none());
}

/// The regression that made this suite fail to compile: the binary minted
/// `v2` while these routes had already moved to `v3`, so every registration
/// authenticated with a freshly issued session was refused. Minting and
/// verification now share one implementation; this pins the version the
/// routes accept so they cannot drift apart again.
#[test]
fn agent_routes_refuse_the_legacy_unrevocable_session() {
    let secret = [3u8; 32];
    let ki = "cd".repeat(32);
    let conn = db_with_owner(&ki);
    let mut any = conn.any_conn();

    let legacy = legacy_v2(&secret, "default", &ki);
    assert!(
        user_session::key_image_from_headers(&headers_with(&legacy), &secret, "default", &mut any,)
            .is_none(),
        "a correctly signed v2 token carries no epoch and must be refused"
    );

    let epoch = user_session::current_epoch(&mut any, &ki);
    let (current, _) = user_session::issue(&secret, "default", &ki, epoch);
    assert_eq!(
        user_session::key_image_from_headers(&headers_with(&current), &secret, "default", &mut any,),
        Some(ki),
        "a session minted the way the binary mints one must authenticate"
    );
}
