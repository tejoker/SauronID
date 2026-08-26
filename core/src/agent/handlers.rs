//! HTTP handlers for the agent routes: register, token issue, checksum
//! rotation, read, revoke, verify, list, and the attestation/PoP challenges.

use super::*;
use crate::ajwt_support;
use crate::any_db::AnyConn;
use crate::crypto_protocol::{self};
use crate::error::AppError;
use crate::policy;
use crate::risk;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;
use crate::tenancy::TenantId;
use axum::{
    extract::{Extension, Json, Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use curve25519_dalek::traits::Identity as _;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /agent/register — authenticated user registers an agent bound to their session.
///
/// S11.5: each row stamps `tenant_id` from the request-scoped
/// `Extension<TenantId>` (header `x-sauron-tenant-id`, admin-JWT `tnt` claim,
/// or the `"default"` fallback). Uniqueness checks (`public_key_hex`,
/// `ring_key_image_hex`), parent-agent lookups, and the persisted INSERT all
/// filter / write within that tenant so cross-tenant rows are invisible.
/// Verify the owner's signature over the registration mandate.
///
/// Returns the mandate hash to persist. The owner's Ed25519 public key is the
/// one bound to `human_key_image` at partner registration — the same key
/// `user_auth_with_key` proves possession of — so the operator cannot produce
/// this signature, only relay it.
pub(crate) fn verify_owner_mandate(
    db: &mut AnyConn<'_>,
    tenant_id: &str,
    human_key_image: &str,
    agent_public_key_hex: &str,
    pop_public_key_b64u: &str,
    intent_json: &str,
    ttl_secs: i64,
    signature_b64u: &str,
) -> Result<String, AppError> {
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let missing_owner_key = || {
        (
            StatusCode::BAD_REQUEST,
            "owner mandate requires an owner key bound to human_key_image; register the owner with a client-generated Ed25519 key first".to_string(),
        )
    };
    let owner_pk_b64u: String = db.require(
        "SELECT c.ed25519_public_key_b64u
             FROM user_auth_credentials c
             JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
             WHERE c.key_image_hex = ?1 AND b.tenant_id = ?2",
        sql_params![human_key_image, tenant_id],
        |r| r.get_string(0),
        missing_owner_key,
    )?;

    let owner_pk: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(owner_pk_b64u.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored owner public key is not 32-byte base64url".to_string(),
            )
        })?;
    let vk = VerifyingKey::from_bytes(&owner_pk).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored owner public key is not a valid Ed25519 key".to_string(),
        )
    })?;

    let sig_bytes: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64u.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "owner_mandate_sig_b64u must be 64-byte base64url".to_string(),
            )
        })?;

    let ttl = ttl_secs.to_string();
    let input = crate::crypto_protocol::OwnerMandateInput {
        tenant_id,
        human_key_image,
        agent_public_key_hex,
        pop_public_key_b64u,
        intent_json,
        ttl_secs: &ttl,
    };
    let payload = crate::crypto_protocol::owner_mandate_payload(&input);
    vk.verify(&payload, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "owner mandate signature does not verify against the owner key bound to human_key_image".to_string(),
            )
        })?;
    Ok(crate::crypto_protocol::owner_mandate_hash(&input))
}

pub async fn register_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(mut payload): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human_key_image = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "human_key_image payload does not match authenticated session".into(),
        )
            .into());
    }

    if payload.pop_jkt.trim().is_empty() || payload.pop_public_key_b64u.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP is mandatory: pop_jkt and pop_public_key_b64u are required".into(),
        )
            .into());
    }
    let computed_pop_jkt = crypto_protocol::ed25519_jwk_thumbprint(&payload.pop_public_key_b64u)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if computed_pop_jkt
        .as_bytes()
        .ct_eq(payload.pop_jkt.trim().as_bytes())
        .unwrap_u8()
        == 0
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "pop_jkt must be the RFC 7638 thumbprint of pop_public_key_b64u".into(),
        )
            .into());
    }
    let pop_raw = URL_SAFE_NO_PAD
        .decode(payload.pop_public_key_b64u.trim())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("PoP public key base64url: {e}"),
            )
        })?;
    let pop_arr: [u8; 32] = pop_raw.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "PoP public key must be exactly 32 bytes".into(),
        )
    })?;
    let pop_vk = VerifyingKey::from_bytes(&pop_arr)
        .map_err(|_| (StatusCode::BAD_REQUEST, "PoP public key is invalid".into()))?;
    if pop_vk.is_weak() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP public key is a weak/small-order Ed25519 key".into(),
        )
            .into());
    }

    let parsed_intent: serde_json::Value =
        serde_json::from_str(&payload.intent_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("intent_json is invalid JSON: {e}"),
            )
        })?;
    if !crate::runtime_mode::is_development_runtime() {
        crate::egress_gateway::validate_production_egress_policy(&parsed_intent)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    }

    // Owner mandate: the grant must come from the owner's key, not the
    // operator's word. Opt-in for now because no released SDK signs it yet;
    // turning SAURON_REQUIRE_OWNER_MANDATE on makes an unsigned registration a
    // hard failure, which is the state a deployment wants once its clients are
    // updated.
    // Production requires the owner's signature; development does not, so the
    // demo stays a two-command story while a real deployment refuses any agent
    // whose authority is only the operator's word. Same shape as
    // SAURON_REQUIRE_CALL_SIG, and overridable in both directions.
    let require_owner_mandate = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_OWNER_MANDATE",
        /* dev_default */ false,
        /* prod_default */ true,
    );
    let owner_mandate_sig = payload.owner_mandate_sig_b64u.trim().to_string();
    let owner_mandate_hash = if owner_mandate_sig.is_empty() {
        if require_owner_mandate {
            return Err((
                StatusCode::UNAUTHORIZED,
                "owner_mandate_sig_b64u is required: this deployment refuses agents whose authority is not signed by their owner".into(),
            ).into());
        }
        String::new()
    } else {
        let st = state.read_or_recover();
        let mut db = st
            .db
            .lock()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        verify_owner_mandate(
            &mut db.any_conn(),
            &tenant_id,
            &payload.human_key_image,
            &payload.public_key_hex,
            &payload.pop_public_key_b64u,
            &payload.intent_json,
            payload.ttl_secs,
            &owner_mandate_sig,
        )?
    };

    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let now = crate::ajwt_support::now_secs();
        risk::check_and_increment(
            &mut db.any_conn(),
            &risk::bucket_agent_register(&tenant_id, &human_key_image),
            now,
            risk::limit_agent_register(),
        )
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Agent registration rate limit exceeded".into(),
            )
        })?;
    }

    // A kind this build cannot verify is a 400, not a silent fall-back to
    // `None` — see AttestationKind::parse for why the old fallback was a
    // security hole rather than leniency.
    let kind_parsed = crate::attestation::AttestationKind::parse(&payload.attestation_kind)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let needs_attestation_challenge = !matches!(
        kind_parsed,
        crate::attestation::AttestationKind::None
            | crate::attestation::AttestationKind::ServerDerived
    );
    let attestation_nonce = if needs_attestation_challenge {
        if payload.attestation_challenge_id.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "attestation_challenge_id is required for attested registration; request one from POST /agent/attestation/challenge".into(),
            ).into());
        }
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let now = now_secs();
        let no_challenge = || {
            (
                StatusCode::UNAUTHORIZED,
                "attestation challenge not found or not bound to this PoP key".to_string(),
            )
        };
        let (challenge_tenant, challenge_human, nonce, expires_at, used_at) =
            db.any_conn()
                .require(
                    "SELECT tenant_id, human_key_image, nonce, expires_at, used_at FROM agent_attestation_challenges WHERE id = ?1 AND pop_public_key_b64u = ?2",
                    sql_params![&payload.attestation_challenge_id, &payload.pop_public_key_b64u],
                    |r| {
                        Ok((
                            r.get_string(0)?,
                            r.get_string(1)?,
                            r.get_string(2)?,
                            r.get_i64(3)?,
                            // NULL until the challenge is spent, so this must
                            // stay optional rather than coalescing to 0 — a
                            // zero timestamp would read as "already used".
                            r.get_opt_i64(4)?,
                        ))
                    },
                no_challenge)?;
        if challenge_tenant != tenant_id || challenge_human != human_key_image {
            return Err((
                StatusCode::FORBIDDEN,
                "attestation challenge belongs to a different tenant or session".into(),
            )
                .into());
        }
        if used_at.is_some() || expires_at < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                "attestation challenge is expired or already used".into(),
            )
                .into());
        }
        Some(nonce)
    } else {
        None
    };

    // ── Server-side checksum (Gap 4 fix) ──────────────────────────────────
    //
    // If the caller supplies typed `agent_type` + `checksum_inputs`, we
    // canonicalise + hash on the server. The resulting digest OVERRIDES any
    // operator-supplied `agent_checksum`. If the operator also passed a value
    // and it doesn't match, the registration is rejected — so a malicious
    // operator can't claim a different checksum than what the inputs hash to.
    //
    // Legacy path (no `agent_type`): operator-supplied `agent_checksum` accepted,
    // but a warning is logged. Existing tests pass through this path; new
    // deployments should always use typed inputs.
    // Determine whether legacy operator-supplied checksum is allowed.
    //
    // Rule: legacy mode is REJECTED in production-like runtimes by default.
    // Operators who need the legacy path during a migration can set
    // SAURON_REQUIRE_AGENT_TYPE=0 explicitly. In dev mode (ENV=development),
    // legacy mode is allowed with a warning so existing test scenarios keep
    // working without modification.
    // Sprint 1: defer to runtime_mode helper so dev/prod defaults are
    // shared with the other SAURON_REQUIRE_* gates. Dev: advisory; Prod: enforce.
    let require_agent_type = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_AGENT_TYPE",
        /* dev_default */ false,
        /* prod_default */ true,
    );

    // Gap #3 hardening: the `custom` agent_type carries an EMPTY required-fields
    // contract (`AgentType::required_fields`), so an operator can register it
    // with arbitrary or empty `checksum_inputs` — binding nothing the runtime
    // can drift from, which silently defeats the config-digest leash. Refuse
    // `custom` in production-like runtimes unless explicitly opted in, matching
    // the `SAURON_REQUIRE_*` gate convention (dev: allow; prod: deny).
    if matches!(
        crate::agent_checksum::AgentType::parse(&payload.agent_type),
        Some(crate::agent_checksum::AgentType::Custom)
    ) {
        let allow_custom = crate::runtime_mode::require_or_default(
            "SAURON_ALLOW_CUSTOM_CHECKSUM",
            /* dev_default */ true,
            /* prod_default */ false,
        );
        if !allow_custom {
            return Err((
                StatusCode::BAD_REQUEST,
                "agent_type='custom' has no required-field contract and binds nothing the \
                 runtime can drift from; refused in production. Use a typed agent_type \
                 (llm/mcp_server/rule_bot/browser/openai_assistant/framework) or set \
                 SAURON_ALLOW_CUSTOM_CHECKSUM=1 to opt in."
                    .into(),
            )
                .into());
        }
    }

    let computed_checksum_pair: Option<(String, String, String)> = if !payload.agent_type.is_empty()
    {
        let inputs = payload.checksum_inputs.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "checksum_inputs required when agent_type is set".into(),
        ))?;
        let (canonical, computed) =
            crate::agent_checksum::compute_checksum(&payload.agent_type, inputs)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        if !payload.agent_checksum.is_empty() && payload.agent_checksum != computed {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "operator-supplied agent_checksum does not match server-computed value (expected {}, got {})",
                    computed, payload.agent_checksum
                ),
            ).into());
        }
        payload.agent_checksum = computed.clone();
        Some((payload.agent_type.clone(), canonical, computed))
    } else if require_agent_type {
        // Escape hatch fix: in production-like runtimes, refuse legacy operator-
        // supplied checksum. Forces operators to opt into the typed-input path
        // where the system prompt / model / tool list are server-bound.
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_type + checksum_inputs are required (set SAURON_REQUIRE_AGENT_TYPE=0 to allow legacy operator-supplied agent_checksum, but be aware this disables runtime drift detection)".into(),
        ).into());
    } else {
        tracing::warn!(
            target: "sauron::agent_checksum",
            "agent registration with legacy operator-supplied checksum (no agent_type / checksum_inputs); recommend specifying agent_type for server-computed integrity"
        );
        None
    };

    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()).into());
    }
    if payload.public_key_hex.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_hex is required for delegated-agent ring binding".into(),
        )
            .into());
    }
    if !payload
        .ring_key_image_hex
        .chars()
        .all(|c| c.is_ascii_hexdigit())
        || payload.ring_key_image_hex.len() != 64
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "ring_key_image_hex is required and must be 32-byte hex".into(),
        )
            .into());
    }
    // ServerDerived PoP: refuse in production unless explicitly opted in.
    // Operators must set SAURON_ALLOW_SERVER_DERIVED_POP=1 or run with
    // ENV=development. Previously the server silently derived a PoP key from
    // `jwt_secret`, making operator compromise equal full agent impersonation.
    // The TPM2-rooted alternative that used to follow this gate was cancelled
    // with the hardware-attestation track in 2026-08; refusing the kind in
    // production is the mitigation. See archive/removed-2026-08/hardware-attestation/.
    if matches!(
        kind_parsed,
        crate::attestation::AttestationKind::ServerDerived
    ) {
        crate::attestation::check_server_derived_allowed()
            .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    }
    // ── Gap #4: enforce attestation AT REGISTRATION ─────────────────────────
    //
    // The verifiers (ed25519_self / tpm2 / nitro) existed but were only
    // reachable via the standalone /v1/attestation route — the blob was
    // previously persisted verbatim without verification. Resolve the blob per
    // and run the hybrid (pre-registered / TOFU) measurement gate.
    let attest_blob: Vec<u8> = payload.attestation_blob.clone().into_bytes();
    let attest_trusted_pubkey = payload.attestation_pubkey_b64u.as_deref().unwrap_or("");
    let attest_expected_measurement = payload.expected_measurement_hex.as_deref().unwrap_or("");
    let registration_attestation = crate::attestation::enforce_registration_attestation_bound(
        kind_parsed,
        &attest_blob,
        attest_trusted_pubkey,
        attest_expected_measurement,
        attestation_nonce.as_deref().unwrap_or(""),
        &payload.pop_public_key_b64u,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("attestation rejected: {e}"),
        )
    })?;

    if needs_attestation_challenge {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let now = now_secs();
        // Single-use claim: the `used_at IS NULL` predicate is what makes this
        // atomic, so the row count is the TOCTOU verdict. Preserved exactly.
        let changed = db.any_conn()
            .execute(
                "UPDATE agent_attestation_challenges SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL AND expires_at >= ?1",
                sql_params![now, &payload.attestation_challenge_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if changed != 1 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "attestation challenge was consumed concurrently or expired".into(),
            )
                .into());
        }
    }

    let agent_point = {
        let bytes = hex::decode(&payload.public_key_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be valid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be 32-byte compressed Ristretto point".into(),
            )
        })?;
        let point = curve25519_dalek::ristretto::CompressedRistretto(arr)
            .decompress()
            .ok_or((
                StatusCode::BAD_REQUEST,
                "public_key_hex is not a valid Ristretto point".into(),
            ))?;
        if point == curve25519_dalek::RistrettoPoint::identity() {
            return Err((
                StatusCode::BAD_REQUEST,
                "public_key_hex must not be the identity point".into(),
            )
                .into());
        }
        point
    };

    let _ring_key_image_point = {
        let bytes = hex::decode(&payload.ring_key_image_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex must be valid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex must be a 32-byte compressed Ristretto point".into(),
            )
        })?;
        let point = curve25519_dalek::ristretto::CompressedRistretto(arr)
            .decompress()
            .ok_or((
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex is not a valid Ristretto point".into(),
            ))?;
        if point == curve25519_dalek::RistrettoPoint::identity() {
            return Err((
                StatusCode::BAD_REQUEST,
                "ring_key_image_hex must not be the identity point".into(),
            )
                .into());
        }
        point
    };

    // Ensure no active agent already uses this pubkey.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let in_use: bool = db.any_conn()
            .scalar_or(
                "SELECT COUNT(*) FROM agents WHERE public_key_hex = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&payload.public_key_hex, &tenant_id],
                |r| r.get_i64(0),
                0)
            > 0;
        if in_use {
            return Err((
                StatusCode::CONFLICT,
                "public_key_hex already registered to an active agent".into(),
            )
                .into());
        }
        let key_image_in_use: bool = db.any_conn()
            .scalar_or(
                "SELECT COUNT(*) FROM agents WHERE ring_key_image_hex = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&payload.ring_key_image_hex, &tenant_id],
                |r| r.get_i64(0),
                0)
            > 0;
        if key_image_in_use {
            return Err((
                StatusCode::CONFLICT,
                "ring_key_image_hex already registered to an active agent".into(),
            )
                .into());
        }
        let pop_key_in_use: bool = db.any_conn()
            .scalar_or(
                "SELECT COUNT(*) FROM agents WHERE pop_public_key_b64u = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&payload.pop_public_key_b64u, &tenant_id],
                |r| r.get_i64(0),
                0)
            > 0;
        if pop_key_in_use {
            return Err((
                StatusCode::CONFLICT,
                "pop_public_key_b64u already registered to an active agent; PoP keys must be agent-unique"
                    .into(),
            ).into());
        }
    }

    // Validate human exists in DB (dual-backend repo)
    {
        let repo = state.read_or_recover().repo.clone();
        let exists = repo
            .user_exists(&human_key_image)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !exists {
            return Err((
                StatusCode::NOT_FOUND,
                "Human user not found — register the user first".into(),
            )
                .into());
        }
    }

    let has_bank_link = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        has_bank_kyc_link(&mut db.any_conn(), &human_key_image)
    };

    if !has_bank_link {
        return Err((
            StatusCode::FORBIDDEN,
            "Delegated registration requires bank-verified KYC link. Use /agent/vc/issue for non-bank agents.".into(),
        ).into());
    };

    let assurance_level = "delegated_bank".to_string();

    let (parent_opt, delegation_depth) = if payload.parent_agent_id.is_empty() {
        (None::<String>, 0i64)
    } else {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let no_parent = || {
            (
                StatusCode::BAD_REQUEST,
                "parent_agent_id not found".to_string(),
            )
        };
        let (p_intent, p_human, p_depth, p_rev) = db.any_conn()
            .require(
                "SELECT intent_json, human_key_image, COALESCE(delegation_depth, 0), revoked FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![&payload.parent_agent_id, &tenant_id],
                |r| {
                    Ok((
                        r.get_string(0)?,
                        r.get_string(1)?,
                        r.get_i64(2)?,
                        r.get_i64(3)?,
                    ))
                },
                no_parent)?;
        if p_rev != 0 {
            return Err((StatusCode::BAD_REQUEST, "parent agent is revoked".into()).into());
        }
        if p_human != human_key_image {
            return Err((
                StatusCode::FORBIDDEN,
                "parent agent belongs to another user".into(),
            )
                .into());
        }
        ajwt_support::assert_child_scopes_subset_of_parent(&p_intent, &payload.intent_json)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let d = p_depth + 1;
        if d > policy::MAX_DELEGATION_DEPTH as i64 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "delegation depth exceeds max {}",
                    policy::MAX_DELEGATION_DEPTH
                ),
            )
                .into());
        }
        (Some(payload.parent_agent_id.clone()), d)
    };

    let ttl = payload.ttl_secs.clamp(60, 86400);
    let now = now_secs();
    let expires_at = now + ttl;

    // Opaque 128-bit identifier. Security attributes are database fields, not
    // encoded into an identifier whose collision semantics could overwrite
    // another lease.
    let agent_id = format!("agt_{}", ajwt_support::random_hex_32());

    let delegation_chain: Option<serde_json::Value> =
        if payload.delegation_chain_json.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&payload.delegation_chain_json).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("delegation_chain_json invalid JSON: {e}"),
                    )
                })?,
            )
        };

    let extra = AjwtExtraClaims {
        cnf_jkt: if payload.pop_jkt.is_empty() {
            None
        } else {
            Some(payload.pop_jkt.clone())
        },
        workflow_id: if payload.workflow_id.is_empty() {
            None
        } else {
            Some(payload.workflow_id.clone())
        },
        delegation_chain,
    };

    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &payload.intent_json,
        &tenant_id,
        ttl,
        Some(&extra),
    );

    // Persist agent in DB
    {
        let st = state.read_or_recover();
        // Deliberately NOT st.db.conn(). The `agents` table is touched from 40
        // places, all still on the SQLite connection — including the
        // call-signature lookup in try_verify_call_sig. Dispatching this write
        // alone put registrations in Postgres while every later lookup read
        // SQLite, so under SAURON_DB_BACKEND=postgres an agent registered
        // successfully and then failed every signed call with 401
        // call_sig_unknown_agent. `agents` converts as one unit — writes and
        // reads together — or not at all.
        let mut db = st.db.lock().unwrap();
        // The operator-signed key the ed25519_self gate verified against, and
        // the measurement it pinned. The TPM2 columns that used to be fed from
        // request input are gone with the verifier; both stay NULL.
        let attestation_pubkey_b64u = payload
            .attestation_pubkey_b64u
            .as_deref()
            .filter(|s| !s.is_empty());
        let attestation_pcr_set = registration_attestation.pinned_measurement_hex.as_deref();
        let attestation_ek_cert_chain_pem: Option<&str> = None;
        db.any_conn()
            .execute(
            // Plain INSERT (not OR REPLACE): agent_id is unique per registration,
            // so a conflict is a real error to surface, never a silent overwrite
            // of an existing agent's state.
            "INSERT INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, attestation_blob, attestation_kind, attestation_pubkey_b64u, attestation_pcr_set, attestation_ek_cert_chain_pem, tenant_id,
              owner_mandate_sig_b64u, owner_mandate_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
                sql_params![
                    &agent_id,
                    &human_key_image,
                    &payload.agent_checksum,
                    &payload.intent_json,
                    &assurance_level,
                    &payload.public_key_hex,
                    &payload.ring_key_image_hex,
                    now,
                    expires_at,
                    // Nullable columns stay nullable: SqlValue::from(Option<T>)
                    // maps None to SQL NULL, so an absent parent or attestation
                    // field is not silently stored as an empty string.
                    parent_opt.as_deref(),
                    delegation_depth,
                    &payload.pop_jkt,
                    &payload.pop_public_key_b64u,
                    if payload.attestation_blob.is_empty() { None } else { Some(&payload.attestation_blob) },
                    &payload.attestation_kind,
                    attestation_pubkey_b64u,
                    attestation_pcr_set,
                    attestation_ek_cert_chain_pem,
                    &tenant_id,
                    &owner_mandate_sig,
                    &owner_mandate_hash,
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        // Server-computed checksum: persist the structured inputs so future
        // /agent/{id}/checksum/update calls can audit the prior version.
        // `storage_payload` honours SAURON_CHECKSUM_INPUTS_STORAGE — in
        // hash_only mode the raw system prompt / tools never hit the DB.
        if let Some((kind, canonical, _)) = computed_checksum_pair.as_ref() {
            let stored = crate::agent_checksum::storage_payload(canonical, &payload.agent_checksum);
            crate::agent_checksum::persist_inputs(
                &mut db.any_conn(),
                &agent_id,
                kind,
                &stored,
                &payload.agent_checksum,
                now,
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
    }

    // Mandatory ring membership for delegated agents.
    {
        let mut st = state.write_or_recover();
        if !st.agent_group.members.contains(&agent_point) {
            st.agent_group.members.push(agent_point);
        }
    }

    {
        let st = state.read_or_recover();
        st.log("AGENT_REGISTER", "OK", &agent_id);
    }
    tracing::info!(
        target: "sauron::agent",
        %agent_id,
        human = &human_key_image[..16],
        "agent registered"
    );

    Ok(Json(RegisterAgentResponse {
        agent_id,
        ajwt,
        expires_at,
        assurance_level,
    }))
}

/// POST /agent/token — mint a fresh one-use A-JWT for an existing active agent.
///
/// Action endpoints consume A-JWT `jti`s. Multi-step demos and integrations
/// should call this endpoint before each independent agent action instead of
/// replaying the token returned by `/agent/register`.
pub async fn issue_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<IssueAgentTokenRequest>,
) -> Result<Json<IssueAgentTokenResponse>, AppError> {
    if payload.agent_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()).into());
    }
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let session_human = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let now = now_secs();
    let (human_key_image, agent_checksum, intent_json, revoked, agent_expires_at, pop_jkt): (
        String,
        String,
        String,
        i64,
        i64,
        String,
    ) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .require(
                "SELECT human_key_image, agent_checksum, intent_json, revoked, expires_at, IFNULL(pop_jkt, '')
             FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![&payload.agent_id, &tenant_id],
                |r| {
                    Ok((
                        r.get_string(0)?,
                        r.get_string(1)?,
                        r.get_string(2)?,
                        r.get_i64(3)?,
                        r.get_i64(4)?,
                        r.get_string(5)?,
                    ))
                },
                || (StatusCode::NOT_FOUND, "Agent not found".to_string()))?
    };

    if human_key_image != session_human {
        return Err((
            StatusCode::FORBIDDEN,
            "agent not owned by authenticated session".into(),
        )
            .into());
    }
    if revoked != 0 || agent_expires_at <= now {
        return Err((StatusCode::UNAUTHORIZED, "Agent revoked or expired".into()).into());
    }

    let max_ttl = (agent_expires_at - now).max(1);
    let ttl = payload.ttl_secs.clamp(15, 3600).min(max_ttl);
    let extra = AjwtExtraClaims {
        cnf_jkt: if pop_jkt.is_empty() {
            None
        } else {
            Some(pop_jkt)
        },
        workflow_id: None,
        delegation_chain: None,
    };
    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &payload.agent_id,
        &agent_checksum,
        &intent_json,
        &tenant_id,
        ttl,
        Some(&extra),
    );

    Ok(Json(IssueAgentTokenResponse {
        agent_id: payload.agent_id,
        ajwt,
        expires_at: now + ttl,
    }))
}

/// POST /agent/{agent_id}/checksum/update — rotate the registered config.
///
/// Operator updates the agent's typed config (e.g. new system prompt, added tool).
/// Server recomputes the canonical SHA, updates `agent_checksum`, and appends to
/// `agent_checksum_audit`. After this call, the agent runtime must use the matching
/// `x-sauron-agent-config-digest` header on subsequent calls.
///
/// Authentication: requires the same human session that originally registered the agent.
#[derive(Deserialize)]
pub struct ChecksumUpdateRequest {
    pub agent_type: String,
    pub checksum_inputs: serde_json::Value,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
pub struct ChecksumUpdateResponse {
    pub agent_id: String,
    pub from_checksum: String,
    pub to_checksum: String,
    pub version: i64,
}

pub async fn update_agent_checksum(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ChecksumUpdateRequest>,
) -> Result<Json<ChecksumUpdateResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let actor_human_ki = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let (canonical, new_checksum) =
        crate::agent_checksum::compute_checksum(&payload.agent_type, &payload.checksum_inputs)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Verify the caller owns the agent (same human as registration).
    let owner_ki: String = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .query_row(
                "SELECT human_key_image FROM agents WHERE agent_id = ?1 AND revoked = 0 AND tenant_id = ?2",
                sql_params![&agent_id, &tenant_id],
                |r| r.get_string(0),
            )
            .map_err(|_| {
                (
                    StatusCode::NOT_FOUND,
                    "agent not found or revoked".to_string(),
                )
            })?
            .ok_or((
                StatusCode::NOT_FOUND,
                "agent not found or revoked".to_string(),
            ))?
    };
    if owner_ki != actor_human_ki {
        return Err((
            StatusCode::FORBIDDEN,
            "only the registering human can rotate this agent's checksum".into(),
        )
            .into());
    }

    let prev_checksum: String = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn().scalar_or(
            "SELECT agent_checksum FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&agent_id, &tenant_id],
            |r| r.get_string(0),
            String::new(),
        )
    };

    let now = ajwt_support::now_secs();
    let new_version = {
        let st = state.read_or_recover();
        // Same reason as agent registration above: rotate_inputs also runs
        // `UPDATE agents SET agent_checksum`, and `agents` is not converted.
        let mut db = st.db.lock().unwrap();
        // Honour the storage-privacy mode on rotation too, otherwise hash_only
        // would leak the plaintext config via a later checksum update.
        let stored = crate::agent_checksum::storage_payload(&canonical, &new_checksum);
        crate::agent_checksum::rotate_inputs(
            &mut db.any_conn(),
            &agent_id,
            &payload.agent_type,
            &stored,
            &new_checksum,
            &payload.reason,
            &actor_human_ki,
            now,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    tracing::info!(
        target: "sauron::agent_checksum",
        agent_id = %agent_id,
        from = %prev_checksum,
        to = %new_checksum,
        version = new_version,
        "agent checksum rotated"
    );

    Ok(Json(ChecksumUpdateResponse {
        agent_id,
        from_checksum: prev_checksum,
        to_checksum: new_checksum,
        version: new_version,
    }))
}

/// GET /agent/{agent_id} — retrieve agent info.
pub async fn get_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentRecord>, StatusCode> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    db.any_conn()
        .query_row(
            "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, IFNULL(ring_key_image_hex, ''), issued_at, expires_at, revoked
         FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&agent_id, &tenant_id],
            |row| {
                Ok(AgentRecord {
                    agent_id: row.get_string(0)?,
                    human_key_image: row.get_string(1)?,
                    agent_checksum: row.get_string(2)?,
                    intent_json: row.get_string(3)?,
                    assurance_level: row.get_string(4)?,
                    ring_key_image_hex: row.get_string(5)?,
                    issued_at: row.get_i64(6)?,
                    expires_at: row.get_i64(7)?,
                    revoked: row.get_i64(8)? != 0,
                })
            },
        )
        .map_err(|_| StatusCode::NOT_FOUND)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// DELETE /agent/{agent_id} — revoke an agent owned by authenticated user.
pub async fn revoke_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human_ki = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let rows = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "UPDATE agents SET revoked = 1 WHERE agent_id = ?1 AND human_key_image = ?2 AND tenant_id = ?3",
                sql_params![&agent_id, &human_ki, &tenant_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    if rows == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Agent not found or not owned by this user".into(),
        )
            .into());
    }

    // M-3: prune the revoked agent's point from the in-memory ring.
    let pubkey: Option<String> = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .query_row(
                "SELECT public_key_hex FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                sql_params![&tenant_id, &agent_id],
                |r| r.get_string(0),
            )
            .ok()
            .flatten()
    };
    if let Some(hex) = pubkey {
        state.write_or_recover().drop_ring_member(&hex);
    }
    {
        let st = state.read_or_recover();
        st.log("AGENT_REVOKE", "OK", &agent_id);
    }
    tracing::info!(target: "sauron::agent", %agent_id, "agent revoked");

    Ok(Json(
        serde_json::json!({ "revoked": true, "agent_id": agent_id }),
    ))
}

/// POST /agent/verify — validate an A-JWT token.
pub async fn verify_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Json(payload): Json<VerifyAjwtRequest>,
) -> Json<VerifyAjwtResponse> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();

    let claims = match verify_ajwt_for_tenant(&jwt_secret, &payload.ajwt, &tenant_id) {
        None => {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id: None,
                human_key_image: None,
                intent_json: None,
                assurance_level: None,
                error: Some("Invalid or expired A-JWT".into()),
            })
        }
        Some(c) => c,
    };

    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let human_ki = claims.get("sub").and_then(|v| v.as_str()).map(String::from);
    let intent = match claims.get("intent") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(v) => serde_json::to_string(v).ok(),
        None => None,
    };

    // Rate-limit per agent_id to prevent token enumeration / replay amplification.
    if let Some(ref aid) = agent_id {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let now = crate::ajwt_support::now_secs();
        if risk::check_and_increment(
            &mut db.any_conn(),
            &risk::bucket_agent_verify(&tenant_id, aid),
            now,
            risk::limit_agent_verify(),
        )
        .is_err()
        {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level: None,
                error: Some("Rate limit exceeded for agent verification".into()),
            });
        }
    }

    // Cross-check with DB: agent must not be revoked
    let mut assurance_level: Option<String> = None;

    if let Some(ref aid) = agent_id {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let row: Option<(i64, String, String)> = db.any_conn()
            .query_row(
                "SELECT revoked, assurance_level, IFNULL(pop_public_key_b64u, '') FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
                sql_params![aid, &tenant_id],
                |r| Ok((r.get_i64(0)?, r.get_string(1)?, r.get_string(2)?)),
            )
            .ok()
            .flatten();
        let (revoked, db_assurance, pop_pk_b64u) =
            row.unwrap_or((1, "delegated_nonbank".to_string(), String::new())); // missing row → revoked
        assurance_level = Some(db_assurance.clone());
        if revoked != 0 {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level: Some(db_assurance),
                error: Some("Agent has been revoked".into()),
            });
        }
        if !pop_pk_b64u.is_empty() {
            if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id: agent_id.clone(),
                    human_key_image: human_ki.clone(),
                    intent_json: intent.clone(),
                    assurance_level: Some(db_assurance),
                    error: Some(
                        "Agent requires PoP: provide pop_challenge_id and pop_jws (see POST /agent/pop/challenge)"
                            .into(),
                    ),
                });
            }
            // TODO M2-callsite-sweep: sync take_pop_challenge is called from
            // inside a held MutexGuard<Connection>; converting to await would
            // require unwinding the surrounding sync match. The legacy path
            // wraps the SELECT+DELETE in BEGIN IMMEDIATE so SQLite races are
            // safe today. Repo::take_pop_challenge is the dual-backend entry
            // point once this handler is converted to fully async.
            let challenge_plain = match ajwt_support::take_pop_challenge(
                &mut db.any_conn(),
                &payload.pop_challenge_id,
                aid,
            ) {
                Ok(c) => c,
                Err(e) => {
                    return Json(VerifyAjwtResponse {
                        valid: false,
                        agent_id: agent_id.clone(),
                        human_key_image: human_ki.clone(),
                        intent_json: intent.clone(),
                        assurance_level: Some(db_assurance),
                        error: Some(e),
                    });
                }
            };
            if let Err(e) = ajwt_support::verify_ed25519_pop_jws(
                &challenge_plain,
                &payload.pop_jws,
                &pop_pk_b64u,
            ) {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id: agent_id.clone(),
                    human_key_image: human_ki.clone(),
                    intent_json: intent.clone(),
                    assurance_level: Some(db_assurance),
                    error: Some(e),
                });
            }
        }
    }

    if payload.consume_jti {
        let jti = match claims.get("jti").and_then(|v| v.as_str()) {
            Some(j) if !j.is_empty() => j.to_string(),
            _ => {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id,
                    human_key_image: human_ki,
                    intent_json: intent,
                    assurance_level,
                    error: Some("A-JWT missing jti; cannot consume".into()),
                });
            }
        };
        let exp = match claims.get("exp").and_then(|v| v.as_i64()) {
            Some(e) => e,
            None => {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id,
                    human_key_image: human_ki,
                    intent_json: intent,
                    assurance_level,
                    error: Some("A-JWT missing exp".into()),
                });
            }
        };
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        if let Err(e) = ajwt_support::consume_ajwt_jti(&mut db.any_conn(), &jti, exp) {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level,
                error: Some(e),
            });
        }
    }

    Json(VerifyAjwtResponse {
        valid: true,
        agent_id,
        human_key_image: human_ki,
        intent_json: intent,
        assurance_level,
        error: None,
    })
}

/// GET /agent/list/{human_key_image} — list agents for authenticated human only.
pub async fn list_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Path(human_ki): Path<String>,
) -> Result<Json<Vec<AgentRecord>>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let session_human = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    if session_human != human_ki {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Cannot list agents for another user".into(),
        )
            .into());
    }

    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AgentRecord> = db.any_conn()
        .query_map(
            "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, IFNULL(ring_key_image_hex, ''), issued_at, expires_at, revoked
         FROM agents WHERE human_key_image = ?1 AND tenant_id = ?2 ORDER BY issued_at DESC",
            sql_params![&human_ki, &tenant_id],
            |row| {
                Ok(AgentRecord {
                    agent_id: row.get_string(0)?,
                    human_key_image: row.get_string(1)?,
                    agent_checksum: row.get_string(2)?,
                    intent_json: row.get_string(3)?,
                    assurance_level: row.get_string(4)?,
                    ring_key_image_hex: row.get_string(5)?,
                    issued_at: row.get_i64(6)?,
                    expires_at: row.get_i64(7)?,
                    revoked: row.get_i64(8)? != 0,
                })
            },
        )
        // Previously `.flatten()`: a row that failed to decode was dropped, so a
        // caller listing their agents could silently be shown fewer than they
        // have. A decode failure is now a 500.
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db query: {e}")))?;
    Ok(Json(records))
}

/// POST /agent/attestation/challenge — one-time pre-registration challenge.
#[derive(Deserialize)]
pub struct AgentAttestationChallengeRequest {
    pub pop_public_key_b64u: String,
}

#[derive(Serialize)]
pub struct AgentAttestationChallengeResponse {
    pub attestation_challenge_id: String,
    pub nonce: String,
    pub pop_jkt: String,
    pub expires_at: i64,
}

/// Mint a one-time registration challenge bound to the authenticated human,
/// tenant and future Ed25519 PoP public key. Hardware/software attesters must
/// embed this nonce and key in their signed document before /agent/register.
pub async fn agent_attestation_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentAttestationChallengeRequest>,
) -> Result<Json<AgentAttestationChallengeResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    let pop_jkt = crypto_protocol::ed25519_jwk_thumbprint(&payload.pop_public_key_b64u)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let raw = URL_SAFE_NO_PAD
        .decode(payload.pop_public_key_b64u.trim())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("PoP public key base64url: {e}"),
            )
        })?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "PoP public key must be exactly 32 bytes".into(),
        )
    })?;
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|_| (StatusCode::BAD_REQUEST, "PoP public key is invalid".into()))?;
    if vk.is_weak() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP public key is a weak/small-order Ed25519 key".into(),
        )
            .into());
    }

    let id = format!("atc_{}", ajwt_support::random_hex_32());
    let nonce = ajwt_support::random_hex_32();
    let now = now_secs();
    let expires_at = now + 300;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    db.any_conn()
        .execute(
            "DELETE FROM agent_attestation_challenges WHERE expires_at < ?1 OR used_at IS NOT NULL",
            sql_params![now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    db.any_conn()
        .execute(
            "INSERT INTO agent_attestation_challenges (id, tenant_id, human_key_image, nonce, pop_public_key_b64u, expires_at, used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            sql_params![&id, &tenant_id, &human, &nonce, payload.pop_public_key_b64u.trim(), expires_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(AgentAttestationChallengeResponse {
        attestation_challenge_id: id,
        nonce,
        pop_jkt,
        expires_at,
    }))
}

/// POST /agent/pop/challenge — one-time PoP challenge for registered agents.
#[derive(Deserialize)]
pub struct AgentPopChallengeRequest {
    pub agent_id: String,
}

#[derive(Serialize)]
pub struct AgentPopChallengeResponse {
    pub pop_challenge_id: String,
    pub challenge: String,
    pub expires_at: i64,
}

pub async fn agent_pop_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentPopChallengeRequest>,
) -> Result<Json<AgentPopChallengeResponse>, AppError> {
    if payload.agent_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()).into());
    }
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human = session_key_image(&state, &headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let (db_human, revoked, exp_a): (String, i64, i64) = db.any_conn()
        .require(
            "SELECT human_key_image, revoked, expires_at FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&payload.agent_id, &tenant_id],
            |r| Ok((r.get_string(0)?, r.get_i64(1)?, r.get_i64(2)?)),
                || (StatusCode::NOT_FOUND, "agent not found".to_string()))?;
    if db_human != human {
        return Err((
            StatusCode::FORBIDDEN,
            "agent not owned by this session".into(),
        )
            .into());
    }
    if revoked != 0 {
        return Err((StatusCode::UNAUTHORIZED, "agent revoked".into()).into());
    }
    let now = ajwt_support::now_secs();
    if exp_a < now {
        return Err((StatusCode::UNAUTHORIZED, "agent expired".into()).into());
    }

    let challenge = ajwt_support::random_hex_32();
    let id = ajwt_support::random_challenge_id();
    // TODO M2-callsite-sweep: handler holds MutexGuard<Connection> for the
    // surrounding agent lookup; switching to Repo::insert_pop_challenge would
    // require dropping the guard early. Legacy path wraps DELETE+INSERT in
    // BEGIN IMMEDIATE so concurrent inserts under SQLite are atomic.
    let exp = ajwt_support::insert_pop_challenge(
        &mut db.any_conn(),
        &id,
        &payload.agent_id,
        &challenge,
        300,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(AgentPopChallengeResponse {
        pop_challenge_id: id,
        challenge,
        expires_at: exp,
    }))
}
