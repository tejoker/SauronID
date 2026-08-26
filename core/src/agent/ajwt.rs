//! A-JWT forging and verification, plus the per-agent signing-key derivation.

use crate::ajwt_support;
use crate::crypto_protocol::{self};
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::Sha256;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

// ─── Token helpers ───────────────────────────────────────────────────────────

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Owner-session authentication, including the revocation check.
///
/// Thin wrapper over [`crate::user_session::key_image_from_headers`] so the ~7
/// call sites in this file keep their shape. The `state` argument is what the
/// epoch read needs; before sessions were revocable this took no database at
/// all, which is precisely why a leaked session could not be cut off.
/// Resolve the authenticated human behind `x-sauron-session`.
///
/// `pub` because `main.rs` is a separate crate and had a byte-for-byte copy of
/// this. Two copies of a session-authentication helper is the kind of
/// duplication that goes wrong quietly: a fix to one leaves the other
/// authenticating by the old rules.
pub fn session_key_image(
    state: &Arc<RwLock<ServerState>>,
    headers: &HeaderMap,
    jwt_secret: &[u8],
    expected_tenant_id: &str,
) -> Option<String> {
    let st = state.read_or_recover();
    let mut db = st.db.lock().ok()?;
    crate::user_session::key_image_from_headers(
        headers,
        jwt_secret,
        expected_tenant_id,
        &mut db.any_conn(),
    )
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
    let root = crypto_protocol::derive_subkey(jwt_secret, "ajwt-ed25519-root-v2");
    let info = crypto_protocol::canonical_fields(
        "sauron.ajwt.agent-key.v2",
        &[
            ("agent_id", agent_id),
            ("human_key_image", human_key_image),
            ("agent_checksum", agent_checksum),
        ],
    );
    let hk = hkdf::Hkdf::<Sha256>::from_prk(&root).expect("HKDF PRK is 32 bytes");
    let mut seed = [0u8; 32];
    hk.expand(&info, &mut seed)
        .expect("32-byte HKDF expansion cannot exceed RFC 5869 limit");
    SigningKey::from_bytes(&seed)
}

/// Optional claims aligned with `@sauronid/agentic` (cnf, workflow, delegation_chain).
#[derive(Clone, Default, Debug)]
pub struct AjwtExtraClaims {
    pub cnf_jkt: Option<String>,
    pub workflow_id: Option<String>,
    pub delegation_chain: Option<serde_json::Value>,
}

/// Forge an A-JWT signed with per-agent Ed25519 key material.
///
/// `intent` claim is always a **JSON string** (wire format). Optional `extra` adds
/// `cnf`, `workflow_id`, `delegation_chain` for client/server contract parity.
pub fn forge_ajwt(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    tenant_id: &str,
    ttl_secs: i64,
    extra: Option<&AjwtExtraClaims>,
) -> String {
    let header_obj = serde_json::json!({
        "alg": "EdDSA",
        "typ": "ajwt+jwt",
        "kid": agent_id,
    });
    let header = b64url(header_obj.to_string().as_bytes());
    let now = now_secs();
    let audience = ajwt_audience();
    let mut payload_obj = serde_json::json!({
        "iss": "did:sauron:idp",
        "aud": audience,
        "tenant_id": tenant_id,
        "sub": human_key_image,
        "agent_id": agent_id,
        "agent_checksum": agent_checksum,
        "intent": intent_json,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": ajwt_support::random_hex_32(),
    });
    if let Some(ex) = extra {
        if let Some(ref jkt) = ex.cnf_jkt {
            if !jkt.is_empty() {
                payload_obj["cnf"] = serde_json::json!({ "jkt": jkt });
            }
        }
        if let Some(ref wf) = ex.workflow_id {
            if !wf.is_empty() {
                payload_obj["workflow_id"] = serde_json::json!(wf);
            }
        }
        if let Some(ref dc) = ex.delegation_chain {
            payload_obj["delegation_chain"] = dc.clone();
        }
    }
    let payload = b64url(payload_obj.to_string().as_bytes());
    let signing_input = format!("{}.{}", header, payload);

    let signing_key =
        derive_agent_signing_key(jwt_secret, agent_id, human_key_image, agent_checksum);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig = b64url(&signature.to_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

/// Verify an A-JWT.  Returns the decoded payload if valid.
pub fn verify_ajwt(jwt_secret: &[u8], token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_bytes = b64url_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    if header.get("alg")?.as_str()? != "EdDSA" {
        return None;
    }
    // Bind the token TYPE so an EdDSA JWT of a different kind (signed by a
    // colliding key) cannot be replayed as an A-JWT.
    if header.get("typ").and_then(|v| v.as_str()) != Some("ajwt+jwt") {
        return None;
    }

    let payload_bytes = b64url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    let agent_id = payload.get("agent_id")?.as_str()?;
    let human_key_image = payload.get("sub")?.as_str()?;
    let agent_checksum = payload.get("agent_checksum")?.as_str()?;

    // `kid` must name the same agent whose key derives the signature — binds the
    // header to the claim set.
    if header.get("kid").and_then(|v| v.as_str()) != Some(agent_id) {
        return None;
    }
    // Issuer binding — reject tokens minted by any other authority.
    if payload.get("iss").and_then(|v| v.as_str()) != Some("did:sauron:idp") {
        return None;
    }
    if payload.get("aud").and_then(|v| v.as_str()) != Some(ajwt_audience().as_str()) {
        return None;
    }
    payload
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())?;

    let signing_key =
        derive_agent_signing_key(jwt_secret, agent_id, human_key_image, agent_checksum);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let sig_bytes = b64url_decode(parts[2])?;
    let signature = Signature::from_slice(&sig_bytes).ok()?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .ok()?;

    // Temporal validity: expiry, not-before, no future-dating, and a hard
    // maximum lifetime so a forged token cannot grant an unbounded window
    // (the minter clamps ttl to <= 24h; reject anything beyond it).
    const MAX_AJWT_LIFETIME_SECS: i64 = 86_400;
    const CLOCK_SKEW_SECS: i64 = 300;
    let now = now_secs();
    let exp = payload.get("exp")?.as_i64()?;
    if now > exp {
        return None;
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if now + CLOCK_SKEW_SECS < nbf {
            return None;
        }
    }
    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        if iat > now + CLOCK_SKEW_SECS {
            return None; // future-dated
        }
        if exp.saturating_sub(iat) > MAX_AJWT_LIFETIME_SECS {
            return None; // lifetime exceeds the policy ceiling
        }
    }

    Some(payload)
}

fn ajwt_audience() -> String {
    std::env::var("SAURON_AJWT_AUDIENCE").unwrap_or_else(|_| "sauron-core".into())
}

/// Verify the cryptographic token and bind it to the request-scoped tenant.
pub fn verify_ajwt_for_tenant(
    jwt_secret: &[u8],
    token: &str,
    expected_tenant_id: &str,
) -> Option<serde_json::Value> {
    let claims = verify_ajwt(jwt_secret, token)?;
    let got = claims.get("tenant_id")?.as_str()?;
    if got
        .as_bytes()
        .ct_eq(expected_tenant_id.as_bytes())
        .unwrap_u8()
        == 0
    {
        return None;
    }
    Some(claims)
}
