//! Demo-lane helpers: validate and store a user auth public key.

use super::*;
use axum::http::StatusCode;
use sauron_core::any_db::AnyRowGet;
use sauron_core::error::AppError;
use sauron_core::sql_params;

// ─────────────────────────────────────────────────────
//  OPRF
// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
//  Flux 1 : /register — Dépôt KYC → Token A
// ─────────────────────────────────────────────────────

#[cfg(feature = "demo")]
pub(crate) fn validate_user_auth_public_key(value: &str) -> Result<(), AppError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "auth_public_key_b64u must be unpadded base64url".into(),
            )
        })?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "auth_public_key_b64u must decode to 32 bytes".into(),
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "auth_public_key_b64u is not a valid Ed25519 public key".into(),
        )
    })?;
    Ok(())
}

#[cfg(feature = "demo")]
pub(crate) fn store_user_auth_credential(
    state: &Arc<RwLock<ServerState>>,
    tenant_id: &str,
    key_image_hex: &str,
    public_key_b64u: &str,
    now: i64,
) -> Result<(), AppError> {
    validate_user_auth_public_key(public_key_b64u)?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    db.any_conn()
        .execute(
            "INSERT OR IGNORE INTO user_auth_credentials
         (key_image_hex, ed25519_public_key_b64u, created_at) VALUES (?1, ?2, ?3)",
            sql_params![&key_image_hex, &public_key_b64u, &now],
        )
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                format!("authentication credential conflict: {e}"),
            )
        })?;
    let stored: String = db.any_conn().require(
        "SELECT ed25519_public_key_b64u FROM user_auth_credentials WHERE key_image_hex = ?1",
        sql_params![&key_image_hex],
        |r| r.get(0),
        || {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored credential unreadable".to_string(),
            )
        },
    )?;
    if stored != public_key_b64u {
        return Err((
            StatusCode::CONFLICT,
            "user already has a different authentication key; authenticated rotation is required"
                .into(),
        )
            .into());
    }
    db.any_conn()
        .execute(
            "INSERT OR IGNORE INTO user_auth_tenant_bindings
         (tenant_id, key_image_hex, created_at) VALUES (?1, ?2, ?3)",
            sql_params![&tenant_id, &key_image_hex, &now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}
