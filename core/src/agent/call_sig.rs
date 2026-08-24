//! Per-call signature middleware: DPoP-style request binding that closes the
//! replayed-A-JWT hole.

use super::*;
use crate::crypto_protocol::{self, CallSignatureInput};
use crate::error::AppError;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;
use crate::tenancy::TenantId;
use axum::{
    extract::State,
    http::{Method, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
//  Per-call signature middleware (DPoP-style request binding)
//
//  Closes the "captured A-JWT replayed against a different endpoint or with
//  mutated body" gap that PoP-on-challenge does not cover. Every protected call
//  carries an Ed25519 signature over:
//
//  Version 2 uses the length-prefixed canonical encoding in
//  `crypto_protocol::call_signature_payload`. It binds identity, tenant,
//  audience, full path+query, content type, body, config, timestamp, and nonce.
//
//  signed by the agent's registered `pop_public_key_b64u`. Nonce is single-use
//  (consumed atomically in `agent_call_nonces`); timestamp must be within
//  ±SAURON_CALL_SIG_SKEW_MS (default 60s) of server time.
//
//  Headers expected:
//    x-sauron-agent-id   : agent_id whose pop key is used
//    x-sauron-call-ts    : unix milliseconds, ascii-decimal
//    x-sauron-call-nonce : opaque nonce (≤128 chars), single-use
//    x-sauron-call-sig   : base64url(no-pad) Ed25519 signature
//    x-sauron-call-audience : configured service audience
//    x-sauron-protocol-version : "2"
// ─────────────────────────────────────────────────────────────────────────────

/// Verified per-call signature context. Attached to request extensions on success.
#[derive(Clone, Debug)]
pub struct VerifiedCallSig {
    pub agent_id: String,
}

const CALL_SIG_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// One-line remediation hint listing every header a signed call must carry.
pub(crate) const CALL_SIG_HEADERS_FIX: &str = "include x-sauron-agent-id, x-sauron-call-ts, \
    x-sauron-call-nonce, x-sauron-call-sig, x-sauron-call-audience, \
    x-sauron-protocol-version, and x-sauron-agent-config-digest on every signed call; \
    see docs/integration/sdk-integration.md";

/// Resolve the accepted clock-skew window (SAURON_CALL_SIG_SKEW_MS, default
/// 60s, clamped to 1s..10min). Shared by call-sig v2 and the DPoP surface.
pub(crate) fn call_sig_skew_ms() -> i64 {
    std::env::var("SAURON_CALL_SIG_SKEW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000)
        .clamp(1_000, 600_000)
}

/// Try to verify the call signature given the parts and buffered body.
/// Returns the verified context on success, or a typed error on failure.
async fn try_verify_call_sig(
    state: &Arc<RwLock<ServerState>>,
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
) -> Result<VerifiedCallSig, AppError> {
    // Opt-in RFC 9449 surface: a DPoP proof header may replace the
    // x-sauron-call-sig header set (see core/src/dpop.rs for the flag gating
    // and the documented body/config-binding weakness).
    if parts.headers.contains_key("dpop")
        && !parts.headers.contains_key("x-sauron-call-sig")
        && crate::dpop::accept_dpop()
    {
        return crate::dpop::verify_dpop_request(state, parts).await;
    }

    let agent_id = parts
        .headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-agent-id header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let call_ts_str = parts
        .headers
        .get("x-sauron-call-ts")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-ts header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let call_ts: i64 = call_ts_str.parse().map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_timestamp",
            "x-sauron-call-ts must be unix milliseconds",
            "send x-sauron-call-ts as ascii-decimal unix milliseconds",
        )
    })?;
    let nonce = parts
        .headers
        .get("x-sauron-call-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-nonce header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let sig_b64 = parts
        .headers
        .get("x-sauron-call-sig")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-sig header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let protocol_version = parts
        .headers
        .get("x-sauron-protocol-version")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UPGRADE_REQUIRED,
            "call_sig_protocol_version",
            "x-sauron-protocol-version: 2 required",
            "set x-sauron-protocol-version: 2 and use the call-sig v2 canonical payload",
        ))?;
    if protocol_version != crypto_protocol::CALL_SIGNATURE_VERSION {
        return Err(AppError::with_hint(
            StatusCode::UPGRADE_REQUIRED,
            "call_sig_protocol_version",
            format!(
                "unsupported call-signature protocol version {protocol_version}; expected {}",
                crypto_protocol::CALL_SIGNATURE_VERSION
            ),
            "set x-sauron-protocol-version: 2 and use the call-sig v2 canonical payload",
        ));
    }
    let claimed_audience = parts
        .headers
        .get("x-sauron-call-audience")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-call-audience header required",
            CALL_SIG_HEADERS_FIX,
        ))?;
    let expected_audience =
        std::env::var("SAURON_CALL_AUDIENCE").unwrap_or_else(|_| "sauron-core".to_string());
    if claimed_audience != expected_audience {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_audience_mismatch",
            "call signature audience mismatch",
            "set x-sauron-call-audience to the server's configured audience (SAURON_CALL_AUDIENCE, default sauron-core)",
        ));
    }

    let skew_ms = call_sig_skew_ms();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if (now_ms - call_ts).abs() > skew_ms {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_timestamp_skew",
            "x-sauron-call-ts outside acceptable skew window",
            "sync the client clock (NTP) and retry; the server accepts +/- SAURON_CALL_SIG_SKEW_MS (default 60000 ms) around its own time",
        ));
    }

    let body_hash_hex = hex::encode(Sha256::digest(body_bytes));

    // S11.5: pull the tenant from request extensions populated by the
    // global `extract_tenant` middleware. Falls back to the default tenant
    // when callers haven't set the header — keeps legacy A12 redteam +
    // existing integration tests on the same row they wrote at register.
    let tenant_id = parts
        .extensions
        .get::<TenantId>()
        .cloned()
        .unwrap_or_default()
        .0;

    // Pull both the PoP key and the registered checksum in one shot. Also
    // enforce expiry here: an expired agent must not be able to sign calls
    // (revocation was already checked; expiration was not — an expired lease is
    // no longer a valid delegation).
    let now = now_secs();
    let (pop_pk_b64u, registered_checksum): (String, String) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn().require(
            "SELECT IFNULL(pop_public_key_b64u, ''), agent_checksum
             FROM agents WHERE agent_id = ?1 AND revoked = 0 AND tenant_id = ?2 AND expires_at > ?3",
            sql_params![&agent_id, &tenant_id, now],
            |r| Ok((r.get_string(0)?, r.get_string(1)?)),
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

    // Gap 4c — config-digest enforcement.
    //
    // Every protected request MUST include `x-sauron-agent-config-digest` matching the
    // server-stored `agents.agent_checksum`. If the agent's runtime flipped its system
    // prompt / tool list / model without first calling /agent/<id>/checksum/update,
    // the digest its runtime computes diverges from what SauronID has on file and
    // every call rejects with 401. The leash cannot be silently bypassed by mutating
    // agent config; either you update SauronID first, or you stop being able to act.
    //
    // Honesty assumption: the runtime computes its own digest from its actual config.
    // A compromised host can lie — that's gap 3, mitigated by hardware attestation.
    let claimed_digest = parts
        .headers
        .get("x-sauron-agent-config-digest")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_missing_header",
            "x-sauron-agent-config-digest header required (Gap 4 enforcement)",
            CALL_SIG_HEADERS_FIX,
        ))?;
    use subtle::ConstantTimeEq;
    if claimed_digest
        .as_bytes()
        .ct_eq(registered_checksum.as_bytes())
        .unwrap_u8()
        == 0
    {
        return Err(AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_config_digest_mismatch",
            "agent runtime config digest does not match registered checksum (config drift; call /agent/<id>/checksum/update to rotate)",
            "runtime config drifted from registered checksum; call POST /agent/{agent_id}/checksum/update with the new digest",
        ));
    }

    let target_uri = parts
        .uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let method = parts.method.as_str().to_ascii_uppercase();
    let signing_payload = crypto_protocol::call_signature_payload(&CallSignatureInput {
        agent_id: &agent_id,
        tenant_id: &tenant_id,
        audience: &expected_audience,
        method: &method,
        target_uri,
        content_type: &content_type,
        body_sha256_hex: &body_hash_hex,
        config_digest: claimed_digest,
        timestamp_ms: call_ts_str,
        nonce: &nonce,
    });

    let pk_bytes = URL_SAFE_NO_PAD.decode(pop_pk_b64u.trim()).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_pop_key",
            "agent pop key invalid base64url",
            "re-register the agent PoP key as base64url(no-pad) of the 32-byte Ed25519 public key",
        )
    })?;
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
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
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_signature_encoding",
            "x-sauron-call-sig invalid base64url",
            "send x-sauron-call-sig as base64url(no-pad) of the 64-byte Ed25519 signature",
        )
    })?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_bad_signature_encoding",
            "x-sauron-call-sig wrong size",
            "send x-sauron-call-sig as base64url(no-pad) of the 64-byte Ed25519 signature",
        )
    })?;
    vk.verify(&signing_payload, &sig).map_err(|_| {
        AppError::with_hint(
            StatusCode::UNAUTHORIZED,
            "call_sig_invalid",
            "call signature verification failed",
            "sign the sauron.call.v2 canonical payload with the registered Ed25519 PoP key; \
             verify body_sha256 matches the exact bytes sent. If the client is correct and \
             this started when you put the core behind a reverse proxy, the proxy is almost \
             certainly rewriting the request line: target_uri is signed byte-for-byte, so \
             collapsing //, decoding %2F, or reordering the query invalidates it: \
             configure the proxy to pass the request target through verbatim",
        )
    })?;

    // Atomic single-use nonce consume — replay protection.
    // Routed through the dual-backend `repo` abstraction (Phase 3 template):
    // SQLite default keeps the existing rusqlite path; Postgres path activates
    // when `SAURON_DB_BACKEND=postgres` + `DATABASE_URL` are set.
    let nonce_exp = call_ts / 1000 + skew_ms / 1000 + 60;
    let repo = state.read_or_recover().repo.clone();
    repo.consume_call_nonce(&agent_id, &nonce, nonce_exp)
        .await
        .map_err(|e| match e {
            crate::repository::RepoError::Replay(s) => AppError::with_hint(
                StatusCode::CONFLICT,
                "call_sig_nonce_reused",
                s,
                "generate a fresh random nonce per call",
            ),
            crate::repository::RepoError::Backend(s) => AppError::Internal(s),
        })?;

    Ok(VerifiedCallSig { agent_id })
}

fn enforce_signed_agent_body_binding(
    verified: &VerifiedCallSig,
    body_bytes: &[u8],
) -> Result<(), AppError> {
    if body_bytes.is_empty() {
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
        return Ok(()); // content hash still binds non-JSON bodies byte-for-byte
    };
    if let Some(body_agent_id) = value.get("agent_id").and_then(|v| v.as_str()) {
        if body_agent_id != verified.agent_id {
            return Err(AppError::with_hint(
                StatusCode::UNAUTHORIZED,
                "call_sig_agent_id_mismatch",
                "signed agent_id does not match request body agent_id",
                "set the body agent_id to the same agent that signs the call (x-sauron-agent-id)",
            ));
        }
    }
    Ok(())
}

/// Best-effort: persist a *denied* agent egress attempt into `agent_egress_log`
/// with `allowed = 0`, so a blocked call (replayed nonce / tampered body /
/// revoked agent) is visible in the audit feed (the dashboard Activity → Stopped
/// view), not silently dropped. A real audit records denials, not just
/// successes — otherwise a blocked attack leaves no trace after the fact.
///
/// Scoped to the `/agent/egress/log` route: denials on other signed routes are
/// not "egress" events and would mislabel the feed. Never fails the request —
/// any storage error is swallowed, the original 4xx still stands.
fn log_denied_egress(
    state: &Arc<RwLock<ServerState>>,
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
    status: StatusCode,
) {
    if parts.uri.path() != "/agent/egress/log" {
        return;
    }
    let v: serde_json::Value =
        serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null);
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    let agent_id = match field("agent_id") {
        Some(a) if !a.is_empty() => a,
        _ => return, // can't attribute the attempt → don't pollute the feed
    };
    let target_host = field("target_host").unwrap_or_default();
    let target_path = field("target_path").unwrap_or_default();
    let method = field("method").unwrap_or_else(|| parts.method.as_str().to_string());
    let body_hash_hex = field("body_hash_hex").unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(st) = state.read() {
        if let Ok(mut db) = st.db.lock() {
            let _ = db.any_conn().execute(
                "INSERT INTO agent_egress_log
                 (agent_id, target_host, target_path, method, body_hash_hex, status_code, ts, allowed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                sql_params![
                    &agent_id,
                    &target_host,
                    &target_path,
                    &method,
                    &body_hash_hex,
                    status.as_u16() as i64,
                    now,
                ],
            );
        }
    }
}

/// Paths under the agent surface that deliberately carry NO per-call signature,
/// because at that point in the flow no agent key exists yet or the route is
/// public by design. Everything else on that surface is signed.
///
/// This is the whole point of the default-deny layer: the exempt set is written
/// down and reviewable, so adding a route cannot silently ship it unprotected.
/// A new route is refused until someone consciously adds it here — a one-line
/// diff a reviewer can see, instead of a missing line nobody notices.
pub const CALL_SIG_EXEMPT_PATHS: &[&str] = &[
    // Registration is where an agent's keys come into existence.
    "/agent/register",
    // Bootstrap: the agent has keys but no A-JWT yet.
    "/agent/token",
    // Challenge issuance — the client cannot sign before it has the challenge.
    "/agent/attestation/challenge",
    "/agent/pop/challenge",
    // Public verification surfaces: they reveal nothing an unauthenticated
    // caller could not already compute, and third parties must be able to call
    // them without agent credentials.
    "/agent/verify",
    "/agent/action/receipt/verify",
    // Anonymous ring-policy surface. A per-call signature carries the
    // `x-sauron-agent-id` of the signer, which is precisely the identity the
    // ring signature exists to withhold — requiring both would deanonymise the
    // path it protects. Authentication is not skipped here, it is different:
    // both handlers verify a linkable ring signature over a canonical envelope
    // and consume a single-use nonce, and both are inert unless
    // SAURON_ANON_RINGS is on.
    "/agent/action/anon",
    "/agent/usage",
];

/// True when a request on the agent surface must carry a call signature.
///
/// The method matters. The single-segment carve-out below exists for
/// `GET /agent/{id}`, a read of a record the caller already holds; applied to
/// every verb it would silently exempt any future one-word route
/// (`POST /agent/spend`, `DELETE /agent/keys`, …). Those are exactly the routes
/// that carry authority, and nothing fails when a check is merely absent — so
/// the carve-out is pinned to the verb it was written for.
pub(crate) fn call_sig_required_for(method: &Method, path: &str) -> bool {
    if !path.starts_with("/agent/") {
        return false;
    }
    if CALL_SIG_EXEMPT_PATHS.contains(&path) {
        return false;
    }
    let rest = &path["/agent/".len()..];

    // GET /agent/rings/{id}/members — the signing set for an anonymous ring.
    //
    // Matched by shape rather than added to CALL_SIG_EXEMPT_PATHS because the
    // path carries an id and that list is exact-match. Deliberately narrow: the
    // verb is pinned and both literal segments are checked, so a future
    // `POST /agent/rings/{id}/subscribe` is still protected. A bare
    // `starts_with("/agent/rings/")` would have exempted the whole subtree —
    // the same blunt-prefix mistake the single-segment rule below once made.
    if method == Method::GET {
        let segs: Vec<&str> = rest.split('/').collect();
        if segs.len() == 3 && segs[0] == "rings" && segs[2] == "members" && !segs[1].is_empty() {
            return false;
        }
    }

    let single_segment = !rest.is_empty() && !rest.contains('/');
    if single_segment && (method == Method::GET || method == Method::HEAD) {
        return false;
    }
    true
}

/// Default-deny wrapper: applies [`require_call_signature`] to every route on
/// the agent surface except [`CALL_SIG_EXEMPT_PATHS`].
///
/// Replaces per-route opt-in. Under opt-in the protected set was whatever
/// someone remembered to annotate, so a new route shipped unprotected and every
/// test still passed — nothing fails when a check is simply absent.
pub async fn require_call_signature_default_deny(
    state: State<Arc<RwLock<ServerState>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    if !call_sig_required_for(req.method(), req.uri().path()) {
        return Ok(next.run(req).await);
    }
    require_call_signature(state, req, next).await
}

pub async fn require_call_signature(
    State(state): State<Arc<RwLock<ServerState>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    // Sprint 1: defer to runtime_mode helper so dev/prod defaults are
    // shared. Dev: advisory (log + pass-through); Prod: enforce (401 on miss).
    let enforce = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_CALL_SIG",
        /* dev_default */ false,
        /* prod_default */ true,
    );

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, CALL_SIG_BODY_LIMIT)
        .await
        .map_err(|_| {
            AppError::with_hint(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body too large",
                "the call-signature middleware buffers at most 4 MiB of body; send a smaller request",
            )
        })?;

    match try_verify_call_sig(&state, &parts, &body_bytes).await {
        Ok(verified) => {
            enforce_signed_agent_body_binding(&verified, &body_bytes)?;
            let mut req =
                axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
            req.extensions_mut().insert(verified);
            Ok(next.run(req).await)
        }
        Err(err) => {
            if enforce {
                // Record the blocked attempt so the rejection is auditable
                // (Activity → Stopped) instead of vanishing.
                log_denied_egress(&state, &parts, &body_bytes, err.status());
                Err(err)
            } else {
                tracing::warn!(
                    target: "sauron::call_sig",
                    enforce = false,
                    status = err.status().as_u16(),
                    msg = %err,
                    "call signature verification skipped (advisory mode)"
                );
                let req =
                    axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
                Ok(next.run(req).await)
            }
        }
    }
}
