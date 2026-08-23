//! User session issuance: the challenge, the finish step, and the password
//! path. Minting and verification live in `sauron_core::user_session`.

use super::*;
use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use sauron_core::any_db::AnyRowGet;
use sauron_core::error::AppError;
use sauron_core::identity::Identity;
use sauron_core::sql_params;
use sauron_core::state::ServerState;
use sauron_core::tenancy as sauron_tenancy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────
//  Helpers: user session
// ─────────────────────────────────────────────────────
//
// Minting and verification live in `sauron_core::user_session`. They used to be
// duplicated here, which is how the binary ended up issuing `v2` tokens that the
// agent routes — already ported to the module — refused on arrival. One
// implementation, one token version.

/// Mint a session bound to the owner's CURRENT epoch.
///
/// Reading the epoch at mint time is what keeps `issue` and `verify` agreeing:
/// a token minted under a stale epoch is dead the moment it is used.
fn issue_session_for(
    state: &Arc<RwLock<ServerState>>,
    jwt_secret: &[u8],
    tenant_id: &str,
    key_image: &str,
) -> Result<(String, i64), AppError> {
    let epoch = {
        let st = state.read_or_recover();
        let mut db = st
            .db
            .lock()
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
        sauron_core::user_session::current_epoch(&mut db.any_conn(), key_image)
    };
    Ok(sauron_core::user_session::issue(
        jwt_secret, tenant_id, key_image, epoch,
    ))
}

// ─────────────────────────────────────────────────────
//  POST /user/auth — email+password → session token
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserAuthChallengeBody {
    key_image_hex: String,
}

#[derive(Serialize)]
pub(crate) struct UserAuthChallengeResponse {
    challenge_id: String,
    nonce: String,
    expires_at: i64,
    signing_payload_b64u: String,
}

pub(crate) async fn user_auth_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<UserAuthChallengeBody>,
) -> Result<Json<UserAuthChallengeResponse>, AppError> {
    use base64::Engine as _;

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let key_image = payload.key_image_hex.trim().to_ascii_lowercase();
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "key_image_hex must be 32-byte hex".into(),
        )
            .into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let expires_at = now + 120;
    let challenge_id = format!("uac_{}", sauron_core::ajwt_support::random_hex_32());
    let nonce = sauron_core::ajwt_support::random_hex_32();
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let _ = db.any_conn().execute(
            "DELETE FROM user_auth_challenges WHERE expires_at < ?1 OR used_at > 0",
            sql_params![now - 300],
        );
        let total: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM user_auth_challenges",
            sql_params![],
            |r| r.get_i64(0),
            0,
        );
        let active_for_subject: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM user_auth_challenges
                 WHERE tenant_id = ?1 AND key_image_hex = ?2 AND used_at = 0 AND expires_at >= ?3",
            sql_params![&tenant_id, &key_image, now],
            |r| r.get_i64(0),
            0,
        );
        if total >= 100_000 || active_for_subject >= 5 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "authentication challenge capacity exceeded".into(),
            )
                .into());
        }
        // Insert even for an unknown key image so the response shape and timing
        // do not become a reliable account-enumeration oracle.
        db.any_conn()
            .execute(
                "INSERT INTO user_auth_challenges
             (challenge_id, tenant_id, key_image_hex, nonce, expires_at, used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                sql_params![&challenge_id, &tenant_id, &key_image, &nonce, expires_at],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    let signing_payload = sauron_core::crypto_protocol::user_auth_challenge_payload(
        &challenge_id,
        &tenant_id,
        &key_image,
        &nonce,
        expires_at,
    );
    Ok(Json(UserAuthChallengeResponse {
        challenge_id,
        nonce,
        expires_at,
        signing_payload_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_payload),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserAuthFinishBody {
    challenge_id: String,
    key_image_hex: String,
    signature_b64u: String,
}

pub(crate) async fn user_auth_finish(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<UserAuthFinishBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    use base64::Engine as _;

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let key_image = payload.key_image_hex.trim().to_ascii_lowercase();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (nonce, expires_at, public_key_b64u, jwt_secret) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let challenge: (String, i64) = db.any_conn().require(
            "SELECT nonce, expires_at FROM user_auth_challenges
                 WHERE challenge_id = ?1 AND tenant_id = ?2 AND key_image_hex = ?3
                   AND used_at = 0 AND expires_at >= ?4",
            sql_params![&payload.challenge_id, &tenant_id, &key_image, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
            || {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authentication proof".to_string(),
                )
            },
        )?;
        let public_key: String = db.any_conn().require(
            "SELECT c.ed25519_public_key_b64u
                 FROM user_auth_credentials c
                 JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
                 WHERE c.key_image_hex = ?1 AND b.tenant_id = ?2",
            sql_params![&key_image, &tenant_id],
            |r| r.get_string(0),
            || {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authentication proof".to_string(),
                )
            },
        )?;
        (challenge.0, challenge.1, public_key, st.jwt_secret.clone())
    };
    let public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&public_key_b64u)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid authentication proof".into(),
        ))?;
    let signature: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.signature_b64u.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid authentication proof".into(),
        ))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid authentication proof".into(),
        )
    })?;
    let signed = sauron_core::crypto_protocol::user_auth_challenge_payload(
        &payload.challenge_id,
        &tenant_id,
        &key_image,
        &nonce,
        expires_at,
    );
    verifying_key
        .verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid authentication proof".into(),
            )
        })?;

    // Consume only after a valid signature. The conditional write is the
    // replay arbiter if two valid finishes race; exactly one receives a session.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let consumed = db
            .any_conn()
            .execute(
                "UPDATE user_auth_challenges SET used_at = ?1
                 WHERE challenge_id = ?2 AND tenant_id = ?3 AND key_image_hex = ?4
                   AND used_at = 0 AND expires_at >= ?1",
                sql_params![now, &payload.challenge_id, &tenant_id, &key_image],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if consumed != 1 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "invalid authentication proof".into(),
            )
                .into());
        }
    }
    let (session, session_expires_at) =
        issue_session_for(&state, &jwt_secret, &tenant_id, &key_image)?;
    Ok(Json(serde_json::json!({
        "session": session,
        "key_image": key_image,
        "expires_at": session_expires_at,
        "authentication": "ed25519_challenge_v1"
    })))
}

#[derive(Deserialize)]
pub(crate) struct UserAuthBody {
    email: String,
    password: String,
}

pub(crate) async fn user_auth(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<UserAuthBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let enabled = sauron_core::runtime_mode::require_or_default(
        "SAURON_ENABLE_LEGACY_OPRF_AUTH",
        /* dev_default */ true,
        /* prod_default */ false,
    );
    if !enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "password-derived legacy identity authentication is disabled in production; use /user/auth/challenge and /user/auth/finish".into(),
        ).into());
    }
    let (server_k, jwt_secret) = {
        let st = state.read_or_recover();
        (st.k, st.jwt_secret.clone())
    };
    let oprf_result =
        sauron_core::oprf::evaluate_unblinded(server_k, &payload.email, &payload.password);
    let identity = Identity::from_oprf(oprf_result);
    {
        let st = state.read_or_recover();
        if !st.user_group.members.contains(&identity.public) {
            return Err((StatusCode::UNAUTHORIZED, "User not registered".into()).into());
        }
    }
    let key_image = hex::encode(identity.key_image().compress().as_bytes());
    let profile: Option<(String, String)> = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_user(&key_image)
            .await
            .ok()
            .flatten()
            .map(|u| (u.first_name, u.last_name))
    };
    let (session, expires_at) = issue_session_for(&state, &jwt_secret, &tenant_id, &key_image)?;
    Ok(Json(serde_json::json!({
        "session": session,
        "key_image": key_image,
        "expires_at": expires_at,
        "first_name": profile.as_ref().map(|p| &p.0).unwrap_or(&String::new()),
        "last_name":  profile.as_ref().map(|p| &p.1).unwrap_or(&String::new()),
    })))
}
