//! Opt-in RFC 9449 (DPoP) compatibility surface for the call-signature
//! middleware.
//!
//! When `SAURON_ACCEPT_DPOP=1`, `require_call_signature` additionally accepts
//! a `DPoP: <proof JWS>` header as an alternative to the `x-sauron-call-sig`
//! header set. The proof is a compact JWS with header
//! `{typ:"dpop+jwt", alg:"EdDSA", jwk:<Ed25519 OKP public JWK>}` and claims
//! `{htm, htu, iat, jti}` plus optional `ath` (base64url SHA-256 of the
//! Authorization bearer token). Verification maps onto the existing call-sig
//! machinery:
//!
//!   - the `jwk.x` must equal the agent's registered `pop_public_key_b64u`
//!     (agent identity still comes from `x-sauron-agent-id`);
//!   - `htm`/`htu` must match the request method and URI;
//!   - `iat` must be within the same `SAURON_CALL_SIG_SKEW_MS` window;
//!   - `jti` is consumed through the same single-use `agent_call_nonces`
//!     table, prefixed with `dpop:` to avoid cross-scheme collisions.
//!
//! SECURITY — explicitly weaker than call-sig v2. A DPoP proof binds method +
//! URI + time + jti only. It does NOT bind the request body (no `body_sha256`)
//! or the agent config digest, so within the skew window a captured proof
//! allows body substitution, and config drift goes undetected on this path.
//! Hence: default OFF, and in production the flag is ignored (fail-closed,
//! mirroring the `SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD` pattern in
//! `runtime_mode.rs`) unless `SAURON_ACCEPT_DPOP_IN_PROD=1` explicitly
//! acknowledges the weakened binding.
//!
//! No new dependencies: hand-rolled compact-JWS parse over the existing
//! `ed25519-dalek` + `base64` + `serde_json` stack.

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use crate::agent::{call_sig_skew_ms, VerifiedCallSig};
use crate::error::AppError;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;
use crate::tenancy::TenantId;
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Nonce-table prefix keeping DPoP `jti` values disjoint from call-sig v2
/// nonces (both live in `agent_call_nonces`).
const JTI_PREFIX: &str = "dpop:";

/// Max accepted `jti` length; `dpop:` + jti must fit the 128-char nonce cap.
const JTI_MAX_LEN: usize = 120;

const MALFORMED_FIX: &str = "send DPoP as a compact JWS base64url(header).base64url(claims).base64url(signature) with header {typ:\"dpop+jwt\", alg:\"EdDSA\", jwk:<Ed25519 OKP JWK>} and claims {htm, htu, iat, jti}";

/// Whether the DPoP surface is enabled for this process. Default off.
/// Production additionally requires `SAURON_ACCEPT_DPOP_IN_PROD=1`
/// acknowledging the missing body/config binding; without it the flag is
/// ignored (fail-closed) and an error is logged.
pub fn accept_dpop() -> bool {
    let enabled = std::env::var("SAURON_ACCEPT_DPOP")
        .ok()
        .and_then(|v| crate::runtime_mode::parse_truthy(&v))
        .unwrap_or(false);
    if !enabled {
        return false;
    }
    if crate::runtime_mode::is_development_runtime() {
        return true;
    }
    let acknowledged = std::env::var("SAURON_ACCEPT_DPOP_IN_PROD")
        .ok()
        .and_then(|v| crate::runtime_mode::parse_truthy(&v))
        .unwrap_or(false);
    if !acknowledged {
        tracing::error!(
            target: "sauron::dpop",
            "SAURON_ACCEPT_DPOP=1 ignored in production runtime — DPoP proofs do not bind \
             body or config digest; set SAURON_ACCEPT_DPOP_IN_PROD=1 to explicitly accept this"
        );
        return false;
    }
    true
}

/// Parsed, signature-verified DPoP proof claims (context not yet checked).
#[derive(Debug)]
pub struct DpopProof {
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub jti: String,
    pub ath: Option<String>,
}

fn malformed(msg: &'static str) -> AppError {
    AppError::with_hint(
        StatusCode::UNAUTHORIZED,
        "dpop_malformed_proof",
        msg,
        MALFORMED_FIX,
    )
}

fn decode_json_part(part: &str, what: &'static str) -> Result<serde_json::Value, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| malformed("DPoP proof part is not valid base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| malformed(what))
}

/// Parse a compact-JWS DPoP proof and verify its EdDSA signature against the
/// agent's registered PoP public key. The embedded `jwk` MUST carry the same
/// key — a proof signed by any other key is rejected. Pure (no I/O), so unit
/// tests can drive every rejection path.
pub fn verify_proof(proof: &str, registered_pop_pk_b64u: &str) -> Result<DpopProof, AppError> {
    let mut parts = proof.trim().splitn(3, '.');
    let (Some(h_b64), Some(c_b64), Some(s_b64)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(malformed("DPoP proof must have three dot-separated parts"));
    };

    let header = decode_json_part(h_b64, "DPoP proof header is not valid JSON")?;
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(malformed("DPoP proof typ must be dpop+jwt"));
    }
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err(malformed("DPoP proof alg must be EdDSA"));
    }
    let jwk = header
        .get("jwk")
        .ok_or_else(|| malformed("DPoP proof header missing jwk"))?;
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("OKP")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("Ed25519")
    {
        return Err(malformed("DPoP jwk must be kty OKP / crv Ed25519"));
    }
    let jwk_x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| malformed("DPoP jwk missing x"))?;

    // The proof key must be the agent's registered PoP key. Compare decoded
    // bytes (constant-time, encoding-insensitive) and verify with the
    // registered key — the server-side key is authoritative, never the jwk.
    let registered = URL_SAFE_NO_PAD
        .decode(registered_pop_pk_b64u.trim())
        .map_err(|_| {
            AppError::with_hint(
                StatusCode::UNAUTHORIZED,
                "call_sig_bad_pop_key",
                "agent pop key invalid base64url",
                "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
            )
        })?;
    let claimed = URL_SAFE_NO_PAD
        .decode(jwk_x.trim())
        .map_err(|_| malformed("DPoP jwk x is not valid base64url"))?;
    if claimed.ct_eq(&registered).unwrap_u8() == 0 {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "dpop_wrong_key",
            "DPoP proof jwk does not match the agent's registered PoP key",
            "the DPoP jwk must be the agent's registered Ed25519 PoP public key (OKP/Ed25519, x = base64url(no-pad) of 32 bytes)",
        ));
    }
    let pk_arr: [u8; 32] = registered.as_slice().try_into().map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_pop_key",
            "agent pop key wrong length",
            "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
        )
    })?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_pop_key",
            "agent pop key not a valid Ed25519 point",
            "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
        )
    })?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s_b64)
        .map_err(|_| malformed("DPoP proof signature is not valid base64url"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| malformed("DPoP proof signature wrong size"))?;
    let signing_input = format!("{h_b64}.{c_b64}");
    vk.verify(signing_input.as_bytes(), &sig).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "dpop_invalid_signature",
            "DPoP proof signature verification failed",
            "sign base64url(header).base64url(claims) with the registered Ed25519 PoP key",
        )
    })?;

    let claims = decode_json_part(c_b64, "DPoP proof claims are not valid JSON")?;
    let str_claim = |k: &str, msg: &'static str| -> Result<String, AppError> {
        claims
            .get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| malformed(msg))
    };
    let htm = str_claim("htm", "DPoP proof missing htm claim")?;
    let htu = str_claim("htu", "DPoP proof missing htu claim")?;
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| malformed("DPoP proof missing numeric iat claim"))?;
    let jti = str_claim("jti", "DPoP proof missing jti claim")?;
    if jti.is_empty() || jti.len() > JTI_MAX_LEN {
        return Err(malformed("DPoP jti must be 1..=120 chars"));
    }
    let ath = claims
        .get("ath")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(DpopProof {
        htm,
        htu,
        iat,
        jti,
        ath,
    })
}

/// Check the proof claims against the actual request: method, URI, and clock
/// skew. `request_host` is the `Host` header when present; the `htu`
/// authority is only compared when both sides are known.
pub fn check_context(
    proof: &DpopProof,
    method: &str,
    request_path: &str,
    request_host: Option<&str>,
    now_ms: i64,
    skew_ms: i64,
) -> Result<(), AppError> {
    if !proof.htm.eq_ignore_ascii_case(method) {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "dpop_htm_mismatch",
            "DPoP htm does not match the request method",
            "set the htm claim to the exact HTTP method of the request",
        ));
    }
    let htu_mismatch = || {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "dpop_htu_mismatch",
            "DPoP htu does not match the request URI",
            "set the htu claim to the full request URI (scheme://host/path, no query or fragment)",
        )
    };
    let htu: axum::http::Uri = proof.htu.parse().map_err(|_| htu_mismatch())?;
    if htu.scheme().is_none() || htu.authority().is_none() || htu.query().is_some() {
        return Err(htu_mismatch());
    }
    if htu.path() != request_path {
        return Err(htu_mismatch());
    }
    if let (Some(host), Some(authority)) = (request_host, htu.authority()) {
        if !authority.as_str().eq_ignore_ascii_case(host.trim()) {
            return Err(htu_mismatch());
        }
    }
    if (now_ms - proof.iat.saturating_mul(1000)).abs() > skew_ms {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "dpop_stale_iat",
            "DPoP iat outside acceptable skew window",
            "set iat to current unix seconds and sync the client clock (NTP); the server accepts +/- SAURON_CALL_SIG_SKEW_MS (default 60000 ms)",
        ));
    }
    Ok(())
}

/// If the proof carries `ath`, it must be base64url(no-pad) of the SHA-256 of
/// the Authorization bearer token on the same request.
pub fn check_ath(proof: &DpopProof, bearer: Option<&str>) -> Result<(), AppError> {
    let Some(ath) = proof.ath.as_deref() else {
        return Ok(());
    };
    let mismatch = || {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "dpop_ath_mismatch",
            "DPoP ath does not match the Authorization bearer token",
            "set ath to base64url(no-pad) of the SHA-256 of the exact Authorization bearer token bytes",
        )
    };
    let token = bearer.ok_or_else(mismatch)?;
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    if ath.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
        return Err(mismatch());
    }
    Ok(())
}

/// Consume a DPoP `jti` through the same single-use nonce table as call-sig
/// v2 nonces, namespaced with the `dpop:` prefix.
pub async fn consume_jti(
    repo: &crate::repository::Repo,
    agent_id: &str,
    jti: &str,
    exp: i64,
) -> Result<(), AppError> {
    repo.consume_call_nonce(agent_id, &format!("{JTI_PREFIX}{jti}"), exp)
        .await
        .map_err(|e| match e {
            crate::repository::RepoError::Replay(_) => AppError::with_hint(
                StatusCode::CONFLICT,
                "dpop_jti_reused",
                "DPoP jti replay (already used)",
                "generate a fresh random jti per proof",
            ),
            crate::repository::RepoError::Backend(s) => AppError::Internal(s),
        })
}

/// Full request-level DPoP verification, called from
/// `agent::require_call_signature` when [`accept_dpop`] is on and the request
/// carries a `DPoP` header instead of `x-sauron-call-sig`.
pub async fn verify_dpop_request(
    state: &Arc<RwLock<ServerState>>,
    parts: &axum::http::request::Parts,
) -> Result<VerifiedCallSig, AppError> {
    let agent_id = parts
        .headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-agent-id header required",
            "send x-sauron-agent-id alongside the DPoP proof; agent identity is never taken from the proof jwk",
        ))?;
    let proof_str = parts
        .headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| malformed("DPoP header is not valid ascii"))?;

    let tenant_id = parts
        .extensions
        .get::<TenantId>()
        .cloned()
        .unwrap_or_default()
        .0;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Same lookup + expiry/revocation gate as call-sig v2. The registered
    // checksum is intentionally NOT enforced here — DPoP proofs carry no
    // config digest (see module doc for why this surface is opt-in).
    let pop_pk_b64u: String = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn().require(
            "SELECT IFNULL(pop_public_key_b64u, '')
             FROM agents WHERE agent_id = ?1 AND revoked = 0 AND tenant_id = ?2 AND expires_at > ?3",
            sql_params![&agent_id, &tenant_id, &now],
            |r| r.get::<String>(0),
            || AppError::with_hint(
                StatusCode::UNAUTHORIZED,
                "call_sig_unknown_agent",
                "unknown, revoked, or expired agent",
                "register the agent (or re-register after expiry/revocation) and send its exact agent_id and tenant in x-sauron-agent-id / x-sauron-tenant-id",
            ),
        )?
    };
    if pop_pk_b64u.is_empty() {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_no_pop_key",
            "agent has no pop_public_key_b64u registered (per-call signature requires PoP-bound agent)",
            "register the agent with an Ed25519 PoP public key before using per-call signatures",
        ));
    }

    let proof = verify_proof(proof_str, &pop_pk_b64u)?;

    let skew_ms = call_sig_skew_ms();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let host = parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    check_context(
        &proof,
        parts.method.as_str(),
        parts.uri.path(),
        host,
        now_ms,
        skew_ms,
    )?;
    let bearer = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    check_ath(&proof, bearer)?;

    // Same replay window arithmetic as call-sig v2 (iat is already seconds).
    let jti_exp = proof.iat + skew_ms / 1000 + 60;
    let repo = state.read_or_recover().repo.clone();
    consume_jti(&repo, &agent_id, &proof.jti, jti_exp).await?;

    Ok(VerifiedCallSig { agent_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_b64u = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        (sk, pk_b64u)
    }

    fn make_proof(
        sk: &SigningKey,
        htm: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        ath: Option<&str>,
    ) -> String {
        let jwk_x = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": jwk_x },
        });
        let mut claims = serde_json::json!({
            "htm": htm, "htu": htu, "iat": iat, "jti": jti,
        });
        if let Some(ath) = ath {
            claims["ath"] = serde_json::Value::String(ath.to_string());
        }
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = sk.sign(format!("{h}.{c}").as_bytes());
        format!("{h}.{c}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn code_of(err: &AppError) -> &'static str {
        match err {
            AppError::Detailed { code, .. } => code,
            other => panic!("expected Detailed error, got {other}"),
        }
    }

    const NOW_MS: i64 = 1_750_000_000_000;
    const SKEW_MS: i64 = 60_000;

    #[test]
    fn valid_proof_accepted() {
        let (sk, pk) = keypair();
        let iat = NOW_MS / 1000;
        let proof = make_proof(
            &sk,
            "POST",
            "https://api.example.com/agent/vc/issue",
            iat,
            "jti-1",
            None,
        );
        let parsed = verify_proof(&proof, &pk).expect("proof verifies");
        check_context(
            &parsed,
            "POST",
            "/agent/vc/issue",
            Some("api.example.com"),
            NOW_MS,
            SKEW_MS,
        )
        .expect("context matches");
        check_ath(&parsed, None).expect("no ath claim → ok");
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _) = keypair();
        let other_pk = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let proof = make_proof(
            &sk,
            "POST",
            "https://api.example.com/x",
            NOW_MS / 1000,
            "jti-2",
            None,
        );
        let err = verify_proof(&proof, &other_pk).unwrap_err();
        assert_eq!(code_of(&err), "dpop_wrong_key");
    }

    #[test]
    fn stale_iat_rejected() {
        let (sk, pk) = keypair();
        let stale = NOW_MS / 1000 - 3600;
        let proof = make_proof(
            &sk,
            "POST",
            "https://api.example.com/x",
            stale,
            "jti-3",
            None,
        );
        let parsed = verify_proof(&proof, &pk).unwrap();
        let err = check_context(&parsed, "POST", "/x", None, NOW_MS, SKEW_MS).unwrap_err();
        assert_eq!(code_of(&err), "dpop_stale_iat");
    }

    #[test]
    fn htu_mismatch_rejected() {
        let (sk, pk) = keypair();
        let iat = NOW_MS / 1000;
        let proof = make_proof(
            &sk,
            "POST",
            "https://api.example.com/other/path",
            iat,
            "jti-4",
            None,
        );
        let parsed = verify_proof(&proof, &pk).unwrap();
        let err =
            check_context(&parsed, "POST", "/agent/vc/issue", None, NOW_MS, SKEW_MS).unwrap_err();
        assert_eq!(code_of(&err), "dpop_htu_mismatch");
        // Host mismatch also rejects even when the path matches.
        let err = check_context(
            &parsed,
            "POST",
            "/other/path",
            Some("evil.example.net"),
            NOW_MS,
            SKEW_MS,
        )
        .unwrap_err();
        assert_eq!(code_of(&err), "dpop_htu_mismatch");
    }

    #[tokio::test]
    async fn replayed_jti_rejected() {
        // In-memory single-connection pool; schema init creates agent_call_nonces.
        let db = crate::db::open_db_at(":memory:", 1);
        let repo = crate::repository::Repo::Sqlite(std::sync::Arc::new(db));
        consume_jti(&repo, "agent-1", "jti-5", i64::MAX - 1)
            .await
            .expect("first use accepted");
        let err = consume_jti(&repo, "agent-1", "jti-5", i64::MAX - 1)
            .await
            .unwrap_err();
        assert_eq!(code_of(&err), "dpop_jti_reused");
        // Different agent, same jti — independent namespace, accepted.
        consume_jti(&repo, "agent-2", "jti-5", i64::MAX - 1)
            .await
            .expect("jti is per-agent");
    }
}
