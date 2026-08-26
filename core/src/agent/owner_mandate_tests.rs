//! Extracted verbatim from the inline `mod owner_mandate_tests` that `agent.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::verify_owner_mandate;
use crate::any_db::AsAnyConn;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// An owner key bound to a key image, exactly as partner registration binds it.
fn db_with_owner(key_image: &str, owner_pub: &[u8; 32]) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    crate::db::init_schema(&conn);
    conn.execute(
        "INSERT INTO user_auth_credentials (key_image_hex, ed25519_public_key_b64u, created_at)
             VALUES (?1, ?2, 1)",
        rusqlite::params![key_image, b64u(owner_pub)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_auth_tenant_bindings (key_image_hex, tenant_id, created_at)
             VALUES (?1, 'default', 1)",
        rusqlite::params![key_image],
    )
    .unwrap();
    conn
}

fn mandate_sig(
    key: &SigningKey,
    key_image: &str,
    agent_pk: &str,
    pop: &str,
    intent: &str,
    ttl: i64,
) -> String {
    let ttl_s = ttl.to_string();
    let payload =
        crate::crypto_protocol::owner_mandate_payload(&crate::crypto_protocol::OwnerMandateInput {
            tenant_id: "default",
            human_key_image: key_image,
            agent_public_key_hex: agent_pk,
            pop_public_key_b64u: pop,
            intent_json: intent,
            ttl_secs: &ttl_s,
        });
    b64u(&key.sign(&payload).to_bytes())
}

#[test]
fn owner_signature_authorizes_the_exact_grant() {
    let owner = SigningKey::from_bytes(&[7u8; 32]);
    let ki = "aa".repeat(32);
    let db = db_with_owner(&ki, &owner.verifying_key().to_bytes());
    let intent = r#"{"scope":["payment_initiation"],"maxAmount":5,"currency":"EUR"}"#;
    let sig = mandate_sig(&owner, &ki, "pk_hex", "pop_b64u", intent, 3600);

    let hash = verify_owner_mandate(
        &mut db.any_conn(),
        "default",
        &ki,
        "pk_hex",
        "pop_b64u",
        intent,
        3600,
        &sig,
    )
    .expect("owner-signed mandate verifies");
    assert_eq!(hash.len(), 64, "mandate hash is sha256 hex");
}

/// The property: the operator holds the database and the session, but not the
/// owner's key, so it cannot mint authority.
#[test]
fn operator_cannot_forge_a_mandate() {
    let owner = SigningKey::from_bytes(&[7u8; 32]);
    let operator = SigningKey::from_bytes(&[9u8; 32]);
    let ki = "bb".repeat(32);
    let db = db_with_owner(&ki, &owner.verifying_key().to_bytes());
    let intent = r#"{"scope":["payment_initiation"]}"#;

    let forged = mandate_sig(&operator, &ki, "pk_hex", "pop_b64u", intent, 3600);
    let err = verify_owner_mandate(
        &mut db.any_conn(),
        "default",
        &ki,
        "pk_hex",
        "pop_b64u",
        intent,
        3600,
        &forged,
    )
    .unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
}

/// A mandate signed for one grant cannot be replayed onto a wider one.
#[test]
fn widening_the_intent_invalidates_the_mandate() {
    let owner = SigningKey::from_bytes(&[7u8; 32]);
    let ki = "cc".repeat(32);
    let db = db_with_owner(&ki, &owner.verifying_key().to_bytes());
    let signed_intent = r#"{"scope":["prove_age"],"maxAmount":5,"currency":"EUR"}"#;
    let sig = mandate_sig(&owner, &ki, "pk_hex", "pop_b64u", signed_intent, 3600);

    let widened = r#"{"scope":["payment_initiation"],"maxAmount":100000,"currency":"EUR"}"#;
    let err = verify_owner_mandate(
        &mut db.any_conn(),
        "default",
        &ki,
        "pk_hex",
        "pop_b64u",
        widened,
        3600,
        &sig,
    )
    .unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);

    // Same for swapping in a different agent key or stretching the TTL.
    let err = verify_owner_mandate(
        &mut db.any_conn(),
        "default",
        &ki,
        "other_pk",
        "pop_b64u",
        signed_intent,
        3600,
        &sig,
    )
    .unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
    let err = verify_owner_mandate(
        &mut db.any_conn(),
        "default",
        &ki,
        "pk_hex",
        "pop_b64u",
        signed_intent,
        86_400,
        &sig,
    )
    .unwrap_err();
    assert_eq!(err.status(), axum::http::StatusCode::UNAUTHORIZED);
}
