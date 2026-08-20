//! HTTP handler for `POST /v1/stats/submit-transparent`.
//!
//! Admin-gated through `admin::auth_middleware`, after `tenancy::extract_tenant`.
//! Same gating pattern as `/v1/policy/*`.
//!
//! This is the one route the Python, TypeScript and Go SDKs call. The Groth16
//! `/v1/stats/submit` sibling and the DP cohort surface that used to live here
//! are archived under `archive/removed-2026-08/`.

use crate::any_db::AnyRowGet;
use crate::sql_params;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, State},
    response::Json,
};

use crate::aggregation::store::persist_verified_submission;
use crate::aggregation::submission::{
    AggError, StatsSubmission, StatsSubmitResponse, TransparentStatsSubmission,
};
use crate::error::AppError;
use crate::state::ServerState;
use crate::tenancy::TenantId;

/// `POST /v1/stats/submit-transparent` — production stats path backed by a
/// native RISC Zero STARK receipt.  No trusted setup, ceremony file, proving
/// key, or server-selected verification key is involved; the server pins the
/// reviewed guest image ID and rejects Groth16-compressed receipts.
pub async fn submit_transparent_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Json(mut body): Json<TransparentStatsSubmission>,
) -> Result<Json<StatsSubmitResponse>, AppError> {
    use crate::transparent_proof::{TransparentProofError, TransparentStatement, STATS_PROGRAM_ID};

    body.tenant_id = tenant
        .map(|Extension(t)| t.0)
        .unwrap_or_else(|| TenantId::default_tenant().0);
    if body.proof.program_id != STATS_PROGRAM_ID {
        return Err(AppError::BadRequest(format!(
            "stats submissions require program_id '{STATS_PROGRAM_ID}'"
        )));
    }
    // Keep this list identical to the outputs implemented by the reviewed
    // transparent guest.  Rejecting before an expensive receipt verification
    // also prevents an unsupported legacy metric from consuming verifier CPU.
    const TRANSPARENT_STATS_METRICS: [&str; 4] = [
        "success_rate",
        "error_rate",
        "tool_call_count",
        "cost_total",
    ];
    if !TRANSPARENT_STATS_METRICS.contains(&body.metric_id.as_str()) {
        return Err(AppError::BadRequest(format!(
            "metric_id '{}' is not implemented by the reviewed stats guest",
            body.metric_id
        )));
    }
    enforce_stats_period(body.period_start, body.period_end)?;

    let started = Instant::now();
    let journal = crate::transparent_proof::verify_transparent_proof(&body.proof)
        .await
        .map_err(|e| match e {
            TransparentProofError::Malformed(_) | TransparentProofError::Unsupported(_) => {
                AppError::BadRequest(e.to_string())
            }
            TransparentProofError::Configuration(_) | TransparentProofError::Busy(_) => {
                AppError::ServiceUnavailable(e.to_string())
            }
            TransparentProofError::Invalid(_) => AppError::BadRequest(e.to_string()),
        })?;
    let (
        journal_tenant,
        journal_checkpoint,
        journal_anchor,
        journal_root,
        journal_size,
        journal_agent,
        journal_metric,
        journal_value,
        journal_start,
        journal_end,
    ) = match journal.statement {
        TransparentStatement::Stats {
            tenant_id,
            checkpoint_id,
            action_anchor_id,
            merkle_root,
            tree_size,
            agent_id_or_none,
            metric_id,
            claimed_value,
            period_start,
            period_end,
        } => (
            tenant_id,
            checkpoint_id,
            action_anchor_id,
            merkle_root,
            tree_size,
            agent_id_or_none,
            metric_id,
            claimed_value,
            period_start,
            period_end,
        ),
        _ => {
            return Err(AppError::BadRequest(
                "stats guest returned a non-stats journal".into(),
            ))
        }
    };
    if journal_tenant != body.tenant_id
        || journal_checkpoint != body.checkpoint_id
        || journal_agent != body.agent_id_or_none
        || journal_metric != body.metric_id
        || journal_value != body.claimed_value
        || journal_start != body.period_start
        || journal_end != body.period_end
    {
        return Err(AppError::BadRequest(
            "STARK journal does not exactly match the submitted tenant/scope/metric/value/period"
                .into(),
        ));
    }

    let (expected_root, expected_size, expected_anchor): (String, i64, String) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        let mut db = st
            .db
            .lock()
            .map_err(|_| AppError::Internal("db lock".into()))?;
        db.any_conn().require(
            "SELECT merkle_root, tree_size, anchor_id FROM zk_proof_checkpoints
             WHERE checkpoint_id = ?1 AND tenant_id = ?2
               AND circuit = 'StatsHonestComputation' AND finalized_at > 0",
            sql_params![&body.checkpoint_id, &body.tenant_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            || AppError::NotFound("finalized stats checkpoint not found".into()),
        )?
    };
    if !journal_root.eq_ignore_ascii_case(&expected_root)
        || journal_size != expected_size as u64
        || journal_anchor != expected_anchor
    {
        return Err(AppError::BadRequest(
            "STARK journal root/size/anchor does not match the server checkpoint".into(),
        ));
    }

    let stored = StatsSubmission {
        tenant_id: body.tenant_id,
        agent_id_or_none: body.agent_id_or_none,
        metric_id: body.metric_id,
        claimed_value: body.claimed_value,
        n_records: expected_size,
        period_start: body.period_start,
        period_end: body.period_end,
        merkle_root: expected_root,
        proof_b64: body.proof.receipt_b64,
        vk_id: body.proof.program_id,
        checkpoint_id: body.checkpoint_id,
        public_inputs: Vec::new(),
    };
    let latency_ms_verify = started.elapsed().as_millis() as u64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let db = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.db.clone()
    };
    let (_, statement_hash) =
        persist_verified_submission(&db, &stored, now).map_err(map_agg_err)?;
    Ok(Json(StatsSubmitResponse {
        stored: true,
        latency_ms_verify,
        statement_hash,
    }))
}

fn enforce_stats_period(period_start: i64, period_end: i64) -> Result<(), AppError> {
    if period_end < period_start {
        return Err(AppError::BadRequest("period_end < period_start".into()));
    }
    if !crate::runtime_mode::require_or_default("SAURON_ENFORCE_STATS_FRESHNESS", false, true) {
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let max_age = std::env::var("SAURON_STATS_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(14 * 24 * 3600)
        .clamp(300, 366 * 24 * 3600);
    let max_period = std::env::var("SAURON_STATS_MAX_PERIOD_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(8 * 24 * 3600)
        .clamp(60, 366 * 24 * 3600);
    if period_end < now - max_age {
        return Err(AppError::BadRequest(format!(
            "stats period is stale (period_end older than {max_age}s)"
        )));
    }
    if period_end > now + 300 {
        return Err(AppError::BadRequest(
            "stats period_end is more than 5 minutes in the future".into(),
        ));
    }
    if period_end.saturating_sub(period_start) > max_period {
        return Err(AppError::BadRequest(format!(
            "stats period exceeds maximum duration of {max_period}s"
        )));
    }
    Ok(())
}

fn map_agg_err(e: AggError) -> AppError {
    match e {
        AggError::Malformed(m) => AppError::BadRequest(m),
        AggError::Invalid(m) => AppError::BadRequest(m),
        AggError::KeyNotFound(m) => AppError::NotFound(m),
        AggError::VerifierFailed(m) => AppError::Internal(m),
        // Storage failures are flattened to a String well before they get here,
        // so contention has to be recognised from the message. A write that
        // lost a race is 503 + retry, not 500.
        AggError::Storage(m) => crate::error::from_db_message("storage", m),
    }
}
