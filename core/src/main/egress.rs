//! POST /agent/egress/log: voluntary outbound-call reporting.

use super::*;
use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
};
use sauron_core::error::AppError;
use sauron_core::state::ServerState;
use sauron_core::tenancy as sauron_tenancy;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
//  POST /agent/egress/log — voluntary outbound-call reporting (Gap 2)
//
//  Operators wire their agent runtime to call this endpoint BEFORE making any
//  third-party API request. Each row is included in the next agent-action
//  anchor batch, making after-the-fact log tampering require forging Bitcoin
//  AND Solana attestations of the matching merkle root.
//
//  This endpoint is GATED BY require_call_signature in the router, so the
//  reported event is bound to the specific agent + signed by its PoP key +
//  carries the matching x-sauron-agent-config-digest. An attacker who can
//  flip the agent runtime's behaviour cannot forge a log entry without ALSO
//  matching the registered checksum — at which point they had to call
//  /agent/<id>/checksum/update first, and that's audited.
//
//  This legacy telemetry endpoint is disabled by default in production. It
//  cannot prove interception; production agents must use the one-use
//  capability flow at /agent/egress/capability + /agent/egress/proxy.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct AgentEgressLogBody {
    agent_id: String,
    target_host: String,
    #[serde(default)]
    target_path: String,
    method: String,
    #[serde(default)]
    body_hash_hex: String,
    #[serde(default)]
    status_code: i64,
}

pub(crate) async fn agent_egress_log(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentEgressLogBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let enabled = sauron_core::runtime_mode::require_or_default(
        "SAURON_ENABLE_VOLUNTARY_EGRESS_LOG",
        true,
        false,
    );
    if !enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "voluntary egress telemetry is disabled in production; use the one-use capability gateway"
                .into(),
        ).into());
    }
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_id.is_empty() || payload.target_host.is_empty() || payload.method.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id, target_host, method are required".into(),
        )
            .into());
    }
    let signed_agent = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if signed_agent != payload.agent_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "egress log agent_id does not match signed caller".into(),
        )
            .into());
    }
    if !payload.body_hash_hex.is_empty()
        && (payload.body_hash_hex.len() != 64
            || !payload.body_hash_hex.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "body_hash_hex must be empty or 32-byte hex".into(),
        )
            .into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let id = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        // Shared with the enforcing proxy (/agent/egress/proxy) so both log +
        // anchor identically. Voluntary reports are always `allowed = true`.
        sauron_core::egress_gateway::record_egress(
            &mut db.any_conn(),
            &tenant_id,
            &payload.agent_id,
            &payload.target_host,
            &payload.target_path,
            &payload.method,
            &payload.body_hash_hex,
            payload.status_code,
            true,
            now,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };
    Ok(Json(serde_json::json!({ "id": id, "ts": now })))
}
