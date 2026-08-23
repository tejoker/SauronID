//! Extracted verbatim from the inline `mod owner_session_revocation_tests` that `admin.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;
use crate::any_db::AsAnyConn;

/// Two owners in two tenants, so "scoped" and "unscoped" can be told apart.
fn db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    crate::db::init_schema(&conn);
    for (ki, tenant) in [("aa".repeat(32), "tenant-a"), ("bb".repeat(32), "tenant-b")] {
        conn.execute(
            "INSERT INTO user_auth_credentials (key_image_hex, ed25519_public_key_b64u, created_at)
                 VALUES (?1, ?2, 1)",
            rusqlite::params![&ki, format!("pk-{ki}")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_auth_tenant_bindings (tenant_id, key_image_hex, created_at)
                 VALUES (?1, ?2, 1)",
            rusqlite::params![tenant, &ki],
        )
        .unwrap();
    }
    conn
}

/// The property the endpoint exists to not violate: a tenant-locked admin
/// must not be able to bump an owner belonging to another tenant, even
/// though `user_auth_credentials` has no `tenant_id` of its own.
#[test]
fn a_tenant_locked_admin_cannot_see_another_tenants_owner() {
    let conn = db();
    let mut c = conn.any_conn();
    let (a, b) = ("aa".repeat(32), "bb".repeat(32));

    assert!(owner_visible_in_scope(&mut c, &a, "tenant-a"));
    assert!(
        !owner_visible_in_scope(&mut c, &b, "tenant-a"),
        "tenant-a must not reach tenant-b's owner"
    );
    assert!(
        !owner_visible_in_scope(&mut c, &"cc".repeat(32), "*"),
        "an owner that does not exist is not visible to anyone"
    );
}

/// The cross-tenant super-admin escape still works — otherwise the endpoint
/// would be unusable in the single-tenant default deployment.
#[test]
fn a_cross_tenant_admin_sees_every_owner() {
    let conn = db();
    let mut c = conn.any_conn();
    assert!(owner_visible_in_scope(&mut c, &"aa".repeat(32), "*"));
    assert!(owner_visible_in_scope(&mut c, &"bb".repeat(32), "*"));
}

/// End to end at the storage level: bumping the epoch is what makes a
/// still-unexpired session stop authenticating.
#[test]
fn revoking_advances_the_epoch_and_kills_live_sessions() {
    let conn = db();
    let mut c = conn.any_conn();
    let ki = "aa".repeat(32);
    let secret = [5u8; 32];

    let epoch = crate::user_session::current_epoch(&mut c, &ki);
    let (token, _) = crate::user_session::issue(&secret, "tenant-a", &ki, epoch);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(crate::user_session::SESSION_HEADER, token.parse().unwrap());
    assert_eq!(
        crate::user_session::key_image_from_headers(&headers, &secret, "tenant-a", &mut c),
        Some(ki.clone())
    );

    let bumped = crate::user_session::revoke_all(&mut c, &ki).unwrap();
    assert_eq!(bumped, epoch + 1);
    assert_eq!(
        crate::user_session::key_image_from_headers(&headers, &secret, "tenant-a", &mut c),
        None,
        "the leaked session must stop working the moment the epoch moves"
    );
}

/// Revoking one owner must not touch another's sessions.
#[test]
fn revocation_is_scoped_to_one_owner() {
    let conn = db();
    let mut c = conn.any_conn();
    let (a, b) = ("aa".repeat(32), "bb".repeat(32));
    crate::user_session::revoke_all(&mut c, &a).unwrap();
    assert_eq!(crate::user_session::current_epoch(&mut c, &a), 1);
    assert_eq!(
        crate::user_session::current_epoch(&mut c, &b),
        0,
        "the other owner's sessions must survive"
    );
}
