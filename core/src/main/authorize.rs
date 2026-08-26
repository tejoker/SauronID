//! POST /policy/authorize: the pre-execution authorization decision.

use super::*;
use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use sauron_core::agent;
use sauron_core::any_db::AnyRowGet;
use sauron_core::error::AppError;
use sauron_core::policy::{self, AssuranceLevel};
use sauron_core::sql_params;
use sauron_core::tenancy as sauron_tenancy;
use sauron_core::{agent_action, state::ServerState};
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
pub(crate) struct PolicyAuthorizeBody {
    agent_id: String,
    action: String,
    #[serde(default)]
    ajwt: Option<String>,
    #[serde(default)]
    agent_action: Option<agent_action::AgentActionProof>,
}

pub(crate) async fn policy_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<PolicyAuthorizeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_id.is_empty() || payload.action.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id and action are required".into(),
        )
            .into());
    }

    let ajwt = payload.ajwt.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "ajwt is required for policy authorization".into(),
    ))?;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let claims = agent::verify_ajwt_for_tenant(&jwt_secret, ajwt, &tenant_id)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;
    let claim_agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?;
    if claim_agent_id != payload.agent_id {
        return Err((StatusCode::UNAUTHORIZED, "A-JWT agent_id mismatch".into()).into());
    }
    let human_key_image = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".into()))?
        .to_string();
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

    let (assurance_level, revoked, expires_at, db_human, pop_jkt): (
        String,
        i64,
        i64,
        String,
        String,
    ) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn().require(
            "SELECT assurance_level, revoked, expires_at, human_key_image, IFNULL(pop_jkt, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
            sql_params![&tenant_id, &payload.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            || (StatusCode::NOT_FOUND, "Agent not found".to_string()),
        )?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if revoked != 0 || expires_at < now || db_human != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Agent is revoked or expired".into(),
        )
            .into());
    }

    let decision =
        policy::authorize_action(AssuranceLevel::from_db(&assurance_level), &payload.action);
    if !decision.allowed {
        return Ok(Json(serde_json::json!({
            "agent_id": payload.agent_id,
            "action": payload.action,
            "assurance_level": assurance_level,
            "allowed": false,
            "reason": decision.reason,
            "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        })));
    }

    let proof = payload.agent_action.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "agent_action is required for policy authorization".into(),
    ))?;
    let resource = payload.action.clone();
    let validated = agent_action::validate_agent_action(
        &state,
        proof,
        agent_action::ValidateAgentActionOptions {
            tenant_id: &tenant_id,
            agent_id: &payload.agent_id,
            human_key_image: &human_key_image,
            ajwt_jti: &jti,
            intent: Some(&intent),
            expected_action: &payload.action,
            expected_resource: Some(&resource),
            expected_merchant_id: Some(""),
            expected_amount_minor: Some(0),
            expected_currency: Some(""),
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

    Ok(Json(serde_json::json!({
        "agent_id": payload.agent_id,
        "action": payload.action,
        "assurance_level": assurance_level,
        "allowed": true,
        "reason": decision.reason,
        "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        "action_receipt": validated.receipt,
    })))
}
