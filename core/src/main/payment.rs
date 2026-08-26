//! The two payment endpoints: /agent/payment/authorize checks the intent
//! against the leash, /agent/payment/consume spends against it.

use super::*;
use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
};
use sauron_core::agent;
use sauron_core::any_db::AnyRowGet;
use sauron_core::error::AppError;
use sauron_core::policy::{self, AssuranceLevel};
use sauron_core::risk;
use sauron_core::sql_params;
use sauron_core::tenancy as sauron_tenancy;
use sauron_core::{agent_action, state::ServerState};
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
pub(crate) struct AgentPaymentAuthorizeBody {
    /// Agent token minted by /agent/register or /agent/vc/issue.
    ajwt: String,
    /// Requested charge amount in minor units (e.g. cents).
    amount_minor: i64,
    /// ISO-4217 3-letter currency code.
    currency: String,
    /// Merchant-side idempotency/payment reference.
    payment_ref: String,
    /// Optional merchant account / destination identifier.
    #[serde(default)]
    merchant_id: String,
    /// Mandatory for payment authorization (PoP).
    #[serde(default)]
    pop_challenge_id: String,
    /// Mandatory for payment authorization (PoP).
    #[serde(default)]
    pop_jws: String,
    /// Canonical action envelope + ring signature for the cryptographic leash.
    agent_action: agent_action::AgentActionProof,
}

pub(crate) fn parse_ajwt_intent_claim(
    claims: &serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    match claims.get("intent") {
        Some(serde_json::Value::String(s)) => serde_json::from_str::<serde_json::Value>(s)
            .map_err(|_| AppError::Unauthorized("A-JWT intent is not valid JSON".into())),
        Some(v @ serde_json::Value::Object(_)) => Ok(v.clone()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "A-JWT missing intent claim".into(),
        )
            .into()),
    }
}

fn payment_scopes_from_intent(intent: &serde_json::Value) -> Vec<String> {
    if let Some(arr) = intent.get("scope").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(arr) = intent
        .get("constraints")
        .and_then(|v| v.get("scope"))
        .and_then(|v| v.as_array())
    {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(action) = intent.get("action").and_then(|v| v.as_str()) {
        let normalized = action.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            return vec![normalized];
        }
    }
    Vec::new()
}

fn enforce_strict_payment_intent(
    intent: &serde_json::Value,
    amount_minor: i64,
    request_currency: &str,
    request_merchant_id: &str,
) -> Result<(), AppError> {
    let scopes = payment_scopes_from_intent(intent);
    if !scopes.iter().any(|s| s == "payment_initiation") {
        return Err((
            StatusCode::FORBIDDEN,
            "Intent scope must explicitly include payment_initiation".into(),
        )
            .into());
    }

    let max_amount_major = intent.get("maxAmount").and_then(|v| v.as_f64()).ok_or((
        StatusCode::FORBIDDEN,
        "Intent must define numeric maxAmount for payments".into(),
    ))?;
    if !(max_amount_major.is_finite() && max_amount_major > 0.0) {
        return Err((StatusCode::FORBIDDEN, "Intent maxAmount must be > 0".into()).into());
    }
    let max_minor = (max_amount_major * 100.0).round() as i64;
    if amount_minor > max_minor {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested amount {} exceeds intent maxAmount {} {} ({} minor units)",
                amount_minor, max_amount_major, request_currency, max_minor
            ),
        )
            .into());
    }

    let intent_currency = intent
        .get("currency")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_uppercase())
        .ok_or((
            StatusCode::FORBIDDEN,
            "Intent must define currency for payments".into(),
        ))?;
    if intent_currency != request_currency {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested currency {} does not match intent currency {}",
                request_currency, intent_currency
            ),
        )
            .into());
    }

    let merchant_allowlist = intent
        .get("constraints")
        .and_then(|v| v.get("merchant_allowlist"))
        .and_then(|v| v.as_array());
    if let Some(allowlist) = merchant_allowlist {
        if request_merchant_id.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "merchant_id is required by intent constraints.merchant_allowlist".into(),
            )
                .into());
        }
        let allowed = allowlist.iter().any(|m| {
            m.as_str()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s == request_merchant_id)
                .unwrap_or(false)
        });
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "merchant_id '{}' is not allowed by intent",
                    request_merchant_id
                ),
            )
                .into());
        }
    }

    Ok(())
}

pub(crate) async fn agent_payment_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<AgentPaymentAuthorizeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.ajwt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "ajwt is required".into()).into());
    }
    if payload.amount_minor <= 0 {
        return Err((StatusCode::BAD_REQUEST, "amount_minor must be > 0".into()).into());
    }
    if payload.payment_ref.trim().is_empty() || payload.payment_ref.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "payment_ref is required (1..128 chars)".into(),
        )
            .into());
    }
    let payment_ref = payload.payment_ref.trim().to_string();
    let merchant_id = payload.merchant_id.trim().to_string();
    let currency = payload.currency.trim().to_ascii_uppercase();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "currency must be a 3-letter ISO uppercase code".into(),
        )
            .into());
    }

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let claims = agent::verify_ajwt_for_tenant(&jwt_secret, &payload.ajwt, &tenant_id)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;

    let human_key_image = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".into()))?
        .to_string();
    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?
        .to_string();

    // Global blast-radius ceiling — a hard circuit-breaker that no policy (broad,
    // missing, or misconfigured) and no enforcement mode can override. Uses the
    // same minor→major USD-equivalent convention as the policy engine.
    if let Some(max_usd) = sauron_core::runtime_mode::global_max_action_usd() {
        let amount_usd = payload.amount_minor as f64 / 100.0;
        if amount_usd > max_usd {
            tracing::warn!(
                target: "sauron::policy::blast_radius",
                %agent_id,
                amount_usd,
                max_usd,
                "payment refused by global per-action ceiling (SAURON_MAX_ACTION_USD)",
            );
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "payment {amount_usd:.2} exceeds the global per-action ceiling {max_usd:.2} (SAURON_MAX_ACTION_USD)"
                ),
            ).into());
        }
    }

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".into()))?
        .to_string();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".into()))?;

    let intent = parse_ajwt_intent_claim(&claims)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        risk::check_and_increment(
            &mut db.any_conn(),
            &risk::bucket_payment_authorize(&tenant_id, &agent_id),
            now,
            risk::limit_payment_authorize(),
        )
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
    }

    let (assurance_level, pop_jkt) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, assurance, pop_jkt, pop_pk_b64u): (i64, i64, String, String, String, String) = db
            .any_conn()
            .require(
                "SELECT revoked, expires_at, human_key_image, assurance_level, IFNULL(pop_jkt, ''), IFNULL(pop_public_key_b64u, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                sql_params![&tenant_id, &agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                || (StatusCode::NOT_FOUND, "Agent not found".to_string()),
            )?;
        if revoked != 0 {
            return Err((StatusCode::UNAUTHORIZED, "Agent has been revoked".into()).into());
        }
        if expires_at < now {
            return Err((StatusCode::UNAUTHORIZED, "Agent has expired".into()).into());
        }
        if db_human != human_key_image {
            return Err((StatusCode::UNAUTHORIZED, "Agent owner mismatch".into()).into());
        }
        if pop_jkt.is_empty() || pop_pk_b64u.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires PoP-enabled agent registration".into(),
            )
                .into());
        }
        if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires pop_challenge_id and pop_jws from /agent/pop/challenge".into(),
            ).into());
        }
        // TODO M2-callsite-sweep: sync take_pop_challenge inside a held
        // MutexGuard; Repo::take_pop_challenge exists for the post-sweep
        // async port. SELECT+DELETE is wrapped in BEGIN IMMEDIATE today.
        let challenge_plain = sauron_core::ajwt_support::take_pop_challenge(
            &mut db.any_conn(),
            &payload.pop_challenge_id,
            &agent_id,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        sauron_core::ajwt_support::verify_ed25519_pop_jws(
            &challenge_plain,
            &payload.pop_jws,
            &pop_pk_b64u,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        (assurance, pop_jkt)
    };

    let decision = policy::authorize_action(
        AssuranceLevel::from_db(&assurance_level),
        "payment_initiation",
    );
    if !decision.allowed {
        return Err((
            StatusCode::FORBIDDEN,
            format!("Policy denied payment_initiation: {}", decision.reason),
        )
            .into());
    }

    // Server-bound policy for this payment. The metadata keys are the ones a
    // payment can actually attest to; a policy that also declares an egress-shaped
    // cap (payload size, recipient count) will now DENY here rather than silently
    // pass, which is the correct reading of a constraint this action cannot report.
    {
        let intent_tool = intent
            .get("tool")
            .and_then(|v| v.as_str())
            .or_else(|| intent.get("action").and_then(|v| v.as_str()))
            .unwrap_or("payment_initiation")
            .to_string();
        let mut bound_action = sauron_core::policy::Action {
            action_id: format!("payauth-{jti}"),
            tool: intent_tool,
            amount_usd: Some(payload.amount_minor as f64 / 100.0),
            timestamp: now,
            ..Default::default()
        };
        bound_action
            .metadata
            .insert("currency".into(), serde_json::json!(currency.clone()));
        bound_action
            .metadata
            .insert("merchant_id".into(), serde_json::json!(merchant_id.clone()));
        sauron_core::policy::handlers::gate_action_on_bound_policy(
            &state,
            &tenant_id,
            &agent_id,
            &bound_action,
            "/agent/payment/authorize",
        )
        .await?;
    }

    enforce_strict_payment_intent(&intent, payload.amount_minor, &currency, &merchant_id)?;

    let validated = agent_action::validate_agent_action(
        &state,
        &payload.agent_action,
        agent_action::ValidateAgentActionOptions {
            tenant_id: &tenant_id,
            agent_id: &agent_id,
            human_key_image: &human_key_image,
            ajwt_jti: &jti,
            intent: Some(&intent),
            expected_action: "payment_initiation",
            expected_resource: Some(&payment_ref),
            expected_merchant_id: Some(&merchant_id),
            expected_amount_minor: Some(payload.amount_minor),
            expected_currency: Some(&currency),
            pop_jkt: Some(&pop_jkt),
            status: "accepted",
        },
    )?;

    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&mut db.any_conn(), &jti, exp)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    }

    let auth_id = format!("payauth_{}", sauron_core::ajwt_support::random_hex_32());
    let expires_at = std::cmp::min(exp, now + 300);
    // M2 port: insert payment authorization via dual-backend repo helper.
    {
        let repo = {
            let st = state.read_or_recover();
            st.repo.clone()
        };
        repo.insert_payment_authorization(
            &tenant_id,
            &auth_id,
            &agent_id,
            &jti,
            payload.amount_minor,
            &currency,
            &merchant_id,
            &payment_ref,
            now,
            expires_at,
        )
        .await
        .map_err(|e| match e {
            sauron_core::repository::RepoError::Replay(s) => (StatusCode::CONFLICT, s),
            sauron_core::repository::RepoError::Backend(s) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {s}"))
            }
        })?;
    }

    Ok(Json(serde_json::json!({
        "authorized": true,
        "authorization_id": auth_id,
        "agent_id": claims.get("agent_id").and_then(|v| v.as_str()).unwrap_or_default(),
        "amount_minor": payload.amount_minor,
        "currency": currency,
        "merchant_id": merchant_id,
        "payment_ref": payment_ref,
        "assurance_level": assurance_level,
        "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        "action_receipt": validated.receipt,
        "expires_at": expires_at,
        "controls": {
            "risk": { "window_secs": risk::window_secs() },
        },
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentPaymentConsumeBody {
    authorization_id: String,
}

/// POST /agent/payment/consume — redeem a payment authorization exactly once.
///
/// `/agent/payment/authorize` minted authorizations that nothing could spend:
/// `Repo::consume_payment_authorization` — the atomic single-use flip, written
/// for both backends and covered by unit tests — had no route reaching it, and
/// `docs/architecture/active-route-map.md` advertised a `/merchant/payment/consume` that was
/// never implemented. An authorization that cannot be consumed is not a
/// capability, it is a receipt.
///
/// Mounted under `/agent/` deliberately: that prefix is where the default-deny
/// per-call signature layer applies, so this route is signed, nonce-bound and
/// config-digest-checked without being added to `CALL_SIG_EXEMPT_PATHS`. The
/// middleware has already authenticated the caller by the time this runs; the
/// handler only has to bind the claim to the signer and consume.
///
/// The consume is the security-relevant part. `consumed = 1 WHERE consumed = 0`
/// under `BEGIN IMMEDIATE` (SQLite) or `FOR UPDATE` (Postgres) means a
/// concurrent burst on one authorization produces exactly one 200 and N-1
/// 409s — the double-spend property, on the agent path rather than the retired
/// KYC one.
pub(crate) async fn agent_payment_consume(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentPaymentConsumeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let auth_id = payload.authorization_id.trim().to_string();
    if auth_id.is_empty() || auth_id.len() > 128 {
        return Err(AppError::with_hint(
            StatusCode::BAD_REQUEST,
            "authorization_id_invalid",
            "authorization_id is required (1..128 chars)",
            "pass the authorization_id returned by POST /agent/payment/authorize",
        ));
    }

    // The signature proves who is calling; this proves the authorization being
    // spent belongs to them. Without it any signed agent could redeem another
    // agent's authorization by id within the same tenant.
    let signer = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let repo = {
        let st = state.read_or_recover();
        st.repo.clone()
    };
    let owner = repo
        .payment_authorization_agent(&tenant_id, &auth_id)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    match owner {
        None => {
            return Err(AppError::with_hint(
                StatusCode::NOT_FOUND,
                "authorization_not_found",
                "no such payment authorization in this tenant",
                "check the authorization_id and the x-sauron-tenant-id header",
            ))
        }
        Some(agent_id) if agent_id != signer => {
            return Err(AppError::with_hint(
                StatusCode::FORBIDDEN,
                "authorization_not_yours",
                "payment authorization belongs to a different agent",
                "only the agent that obtained the authorization may consume it",
            ))
        }
        Some(_) => {}
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    repo.consume_payment_authorization(&tenant_id, &auth_id, now)
        .await
        .map_err(|e| match e {
            sauron_core::repository::RepoError::Replay(s) => AppError::with_hint(
                StatusCode::CONFLICT,
                "authorization_already_consumed",
                s,
                "a payment authorization is single-use; obtain a new one via POST /agent/payment/authorize",
            ),
            sauron_core::repository::RepoError::Backend(s) => AppError::internal(s),
        })?;

    {
        let st = state.read_or_recover();
        st.log("AGENT_PAYMENT_CONSUME", "OK", &auth_id);
    }
    Ok(Json(serde_json::json!({
        "consumed": true,
        "authorization_id": auth_id,
    })))
}
