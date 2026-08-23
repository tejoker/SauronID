//! Read-only operator reporting: anchor status, per-agent metrics, recent
//! egress, checksum audit trail and the user listing.

use super::*;
use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::any_db::AnyRowGet;
use crate::error::AppError;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

/// GET /admin/anchor/status — current state of the on-chain anchor pipeline.
// Clearer as default-then-assign-per-query than a struct literal with a dozen
// inline query_row calls.
#[allow(clippy::field_reassign_with_default)]
pub async fn get_anchor_status(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<AdminAnchorStatus>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let mut s = AdminAnchorStatus::default();
    s.bitcoin_provider = crate::bitcoin_anchor::configured_provider_label();
    s.bitcoin_network = crate::bitcoin_anchor::configured_network_label();
    s.bitcoin_synthetic = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors
             WHERE no_real_money = 1 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.bitcoin_total = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.bitcoin_pending_upgrade = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors
             WHERE provider = 'opentimestamps' AND ots_upgraded = 0
               AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.bitcoin_upgraded = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM bitcoin_merkle_anchors
             WHERE ots_upgraded = 1 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.solana_total = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM solana_merkle_anchors WHERE (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.solana_unconfirmed = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM solana_merkle_anchors
             WHERE confirmed = 0 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.solana_confirmed = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM solana_merkle_anchors
             WHERE confirmed = 1 AND (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    s.agent_action_batches = db.any_conn().scalar_or(
        "SELECT COUNT(*) FROM agent_action_anchors WHERE (?1 = '*' OR tenant_id = ?1)",
        sql_params![&scope],
        |r| r.get_i64(0),
        0,
    );
    if let Ok(Some(row)) = db.any_conn().query_row(
        "SELECT created_at, n_actions FROM agent_action_anchors
         WHERE (?1 = '*' OR tenant_id = ?1)
         ORDER BY created_at DESC LIMIT 1",
        sql_params![&scope],
        |r| Ok((r.get::<i64>(0)?, r.get::<i64>(1)?)),
    ) {
        s.last_batch_at = row.0;
        s.last_batch_n_actions = row.1;
    }
    Ok(Json(s))
}

#[derive(Serialize)]
pub struct AdminPerAgentMetric {
    pub agent_id: String,
    pub action_count: i64,
    pub egress_count: i64,
    pub last_action_at: i64,
}

/// GET /admin/per_agent_metrics?limit=N — per-agent action + egress counts, sorted by activity.
pub async fn get_per_agent_metrics(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminPerAgentMetric>>, AppError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminPerAgentMetric> = db.any_conn().query_map(
            "SELECT a.agent_id,
                    (SELECT COUNT(*) FROM agent_action_receipts r WHERE r.agent_id = a.agent_id) AS act_count,
                    (SELECT COUNT(*) FROM agent_egress_log e WHERE e.agent_id = a.agent_id)      AS egress_count,
                    (SELECT IFNULL(MAX(created_at),0) FROM agent_action_receipts r WHERE r.agent_id = a.agent_id) AS last_at
             FROM agents a
             WHERE (?1 = '*' OR a.tenant_id = ?1)
             ORDER BY act_count DESC, egress_count DESC
             LIMIT ?2",
            sql_params![&scope, limit],
            |row| {
            Ok(AdminPerAgentMetric {
                agent_id: row.get(0)?,
                action_count: row.get(1)?,
                egress_count: row.get(2)?,
                last_action_at: row.get(3)?,
            })
        }).map_err(AppError::internal)?;
    Ok(Json(records))
}

#[derive(Serialize)]
pub struct AdminEgressEntry {
    pub id: i64,
    pub agent_id: String,
    pub target_host: String,
    pub target_path: String,
    pub method: String,
    pub status_code: i64,
    pub ts: i64,
    pub allowed: bool,
}

/// GET /admin/egress/recent?limit=N — recent agent egress events.
pub async fn get_recent_egress(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminEgressEntry>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminEgressEntry> = db
        .any_conn()
        .query_map(
            "SELECT id, agent_id, target_host, target_path, method, status_code, ts, allowed
             FROM agent_egress_log
             WHERE (?1 = '*' OR tenant_id = ?1)
             ORDER BY ts DESC LIMIT ?2",
            sql_params![&scope, limit],
            |row| {
                Ok(AdminEgressEntry {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    target_host: row.get(2)?,
                    target_path: row.get(3)?,
                    method: row.get(4)?,
                    status_code: row.get(5)?,
                    ts: row.get(6)?,
                    allowed: row.get::<i64>(7)? != 0,
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

/// GET /admin/checksum/audit/{agent_id} — every checksum rotation for an agent.
#[derive(Serialize)]
pub struct AdminChecksumAudit {
    pub from_checksum: String,
    pub to_checksum: String,
    pub reason: String,
    pub actor: String,
    pub ts: i64,
}

pub async fn get_checksum_audit(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AdminChecksumAudit>>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminChecksumAudit> = db
        .any_conn()
        .query_map(
            "SELECT c.from_checksum, c.to_checksum, c.reason, c.actor, c.ts
             FROM agent_checksum_audit c
             JOIN agents a ON a.agent_id = c.agent_id
             WHERE c.agent_id = ?1 AND (?2 = '*' OR a.tenant_id = ?2)
             ORDER BY ts DESC",
            sql_params![agent_id, scope],
            |row| {
                Ok(AdminChecksumAudit {
                    from_checksum: row.get(0)?,
                    to_checksum: row.get(1)?,
                    reason: row.get(2)?,
                    actor: row.get(3)?,
                    ts: row.get(4)?,
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<Vec<AdminUserRecord>>, AppError> {
    // The `users` table (human identities + PII) is NOT tenant-scoped, so it
    // cannot be filtered per tenant. Listing it is therefore a cross-tenant
    // super-admin operation: refuse unless SAURON_ADMIN_CROSS_TENANT is set.
    require_cross_tenant_admin(authz.as_ref().map(|axum::Extension(a)| a))?;
    let repo = state.read_or_recover().repo.clone();
    let records: Vec<AdminUserRecord> = repo
        .list_users()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .into_iter()
        .map(
            |(key_image_hex, first_name, last_name, nationality)| AdminUserRecord {
                key_image_hex,
                first_name,
                last_name,
                nationality,
            },
        )
        .collect();
    Ok(Json(records))
}
