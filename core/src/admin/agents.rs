//! Cross-tenant agent administration: revocation, owner-session revocation,
//! agent listing and the recent-action feed.

use super::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::any_db::AnyRowGet;
use crate::error::AppError;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

// ─────────────────────────────────────────────────────
//  Live-data admin endpoints (Analytics 5/5)
//
//  Every dashboard number comes from a live SQL query against the SauronID core.
//  Replaces the pre-pivot parquet path (see the archive/banking-2025 git tag).
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminAgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub assurance_level: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub has_pop: bool,
    pub agent_type: String,
    /// The agent's declared mandate, verbatim as registered — scope, and any
    /// caps such as `maxAmount`/`currency`. Without it an operator console can
    /// only render "no intents declared" for every agent, which is the one thing
    /// about an agent a reviewer actually wants to see.
    pub intent_json: String,
    /// Attestation kind recorded at registration, normalised (`""` for none).
    pub attestation_kind: String,
    /// Whether that kind carries hardware-rooted evidence this build verifies.
    ///
    /// `SAURON_REQUIRE_HARDWARE_ATTESTATION` defaults OFF in production, so a
    /// default deployment accepts an unattested agent. Flipping that default
    /// would break every deployment not running on Nitro or TPM2, and it would
    /// not stop the escape it looks like it stops — a compromised agent inside
    /// an attested enclave still holds its owner's session. So the posture is
    /// surfaced instead of forced: an operator can see an unattested agent in
    /// the console rather than having to infer it from an absent field.
    pub hardware_attested: bool,
}

/// POST /admin/agents/{agent_id}/revoke — operator-side revocation (admin auth).
///
/// The public `DELETE /agent/{agent_id}` requires a user session header tied
/// to the human key image that owns the agent. The dashboard runs in an admin
/// context (no end-user session), so it uses this admin variant to revoke any
/// agent by id. Records an audit log entry under "AGENT_REVOKE_ADMIN".
/// Admin cross-tenant aggregate view. OFF by default (fail-closed: every admin
/// query is scoped to the request's resolved tenant). A single trusted
/// super-admin operator sets `SAURON_ADMIN_CROSS_TENANT=1` to see all tenants.
/// Multi-customer deployments MUST leave it off — this is the boundary that
/// prevents one tenant's admin from reading another's agents/receipts/PII.
pub(crate) fn cross_tenant_admin() -> bool {
    matches!(
        std::env::var("SAURON_ADMIN_CROSS_TENANT").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Scope token for admin queries: the request's tenant, or the `*` sentinel
/// (match-all — never a valid tenant id) when the authenticated principal is
/// allowed cross-tenant. Use in SQL as `(?N = '*' OR tenant_id = ?N)`.
///
/// The decision comes from the per-request [`AdminAuthz`] (set by
/// `auth_middleware` from the JWT scope/tenant-lock); when absent it falls back
/// to the legacy global `SAURON_ADMIN_CROSS_TENANT` flag.
pub(crate) fn admin_scope(authz: Option<&AdminAuthz>, tenant: &crate::tenancy::TenantId) -> String {
    let cross = authz
        .map(|a| a.cross_tenant)
        .unwrap_or_else(cross_tenant_admin);
    if cross {
        "*".to_string()
    } else {
        tenant.as_str().to_string()
    }
}

/// Deployment-global tables must never be returned to a tenant-locked admin.
/// These legacy tables do not carry tenant_id, so refusing the request is the
/// only safe behavior until they are migrated and backfilled.
pub(crate) fn require_cross_tenant_admin(authz: Option<&AdminAuthz>) -> Result<(), AppError> {
    let cross = authz
        .map(|a| a.cross_tenant)
        .unwrap_or_else(cross_tenant_admin);
    if cross {
        Ok(())
    } else {
        Err(AppError::Unauthorized(
            "this admin view is deployment-global; use a cross-tenant super-admin".into(),
        ))
    }
}

pub async fn revoke_agent_admin(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let rows = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "UPDATE agents SET revoked = 1 WHERE agent_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![&agent_id, &scope],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };
    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Agent not found".into()).into());
    }
    // M-3: prune the revoked agent's point from the in-memory ring.
    let pubkey: Option<String> = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn()
            .query_row(
                "SELECT public_key_hex FROM agents WHERE agent_id = ?1 AND (?2 = '*' OR tenant_id = ?2)",
                sql_params![&agent_id, &scope],
                |r| r.get(0),
            )
            .ok()
            .flatten()
    };
    if let Some(hex) = pubkey {
        state.write_or_recover().drop_ring_member(&hex);
    }
    {
        let st = state.read_or_recover();
        st.log("AGENT_REVOKE_ADMIN", "OK", &agent_id);
    }
    Ok(Json(
        serde_json::json!({ "revoked": true, "agent_id": agent_id }),
    ))
}

/// Is this owner within the calling admin's tenant scope?
///
/// `user_auth_credentials` carries no `tenant_id`, so the scope has to come from
/// `user_auth_tenant_bindings` — the same join the owner-mandate path uses.
/// `"*"` is the cross-tenant super-admin escape set by [`admin_scope`].
///
/// Separate from the handler so the scoping rule is testable without standing up
/// a `ServerState`: this is the check that stops a tenant-locked admin from
/// reaching an owner it cannot see, and it is worth a test of its own.
pub(crate) fn owner_visible_in_scope(
    conn: &mut crate::any_db::AnyConn<'_>,
    key_image: &str,
    scope: &str,
) -> bool {
    conn.scalar_or(
        "SELECT COUNT(*) FROM user_auth_credentials c
         JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
         WHERE c.key_image_hex = ?1 AND (?2 = '*' OR b.tenant_id = ?2)",
        sql_params![key_image, scope],
        |r| r.get_i64(0),
        0,
    ) > 0
}

/// POST /admin/users/{key_image}/revoke_sessions — cut an owner off.
///
/// The owner session authorises `POST /agent/register` and
/// `POST /agent/{id}/checksum/update`, so it MINTS agent authority: whoever
/// holds one can register a sibling agent with an intent it writes itself. It
/// is also a one-hour stateless bearer token, which used to mean a suspected
/// leak had no response — verification consulted no server state, so there was
/// nothing an operator could change.
///
/// Bumping the owner's `session_epoch` invalidates every session already issued
/// for it, because the epoch is inside the signed payload and
/// [`crate::user_session::key_image_from_headers`] compares it against the
/// stored one on every request. Existing agents keep working; they authenticate
/// with their own PoP keys, not with this. What stops is the ability to mint
/// new agent authority with the leaked token.
///
/// Tenant-scoped through `user_auth_tenant_bindings`, the same join the owner
/// mandate path uses — `user_auth_credentials` itself carries no `tenant_id`,
/// so a tenant-locked admin must not be able to bump an owner it cannot see.
pub async fn revoke_user_sessions(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    Path(key_image): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "key_image must be 64 hex characters".into(),
        ));
    }
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);

    let st = state.read_or_recover();
    let epoch = {
        let mut db = st
            .db
            .lock()
            .map_err(|e| AppError::ServiceUnavailable(e.to_string()))?;
        let mut conn = db.any_conn();

        // Resolve inside the caller's scope first. Without this a tenant-locked
        // admin could bump any owner in the deployment by guessing a key image.
        if !owner_visible_in_scope(&mut conn, &key_image, &scope) {
            return Err(AppError::NotFound("owner not found".into()));
        }
        crate::user_session::revoke_all(&mut conn, &key_image).map_err(AppError::Internal)?
    };
    st.log("USER_SESSIONS_REVOKE_ADMIN", "OK", &key_image);

    Ok(Json(serde_json::json!({
        "revoked": true,
        "key_image": key_image,
        "session_epoch": epoch,
    })))
}

/// GET /admin/agents — list every registered agent + checksum + revocation status.
pub async fn get_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
) -> Result<Json<Vec<AdminAgentRecord>>, AppError> {
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminAgentRecord> = db
        .any_conn()
        .query_map(
            "SELECT a.agent_id, a.human_key_image, a.agent_checksum, a.assurance_level,
                    a.issued_at, a.expires_at, a.revoked,
                    IFNULL(LENGTH(a.pop_public_key_b64u), 0),
                    IFNULL(ci.agent_type, ''),
                    IFNULL(a.intent_json, ''),
                    IFNULL(a.attestation_kind, '')
             FROM agents a
             LEFT JOIN agent_checksum_inputs ci ON ci.agent_id = a.agent_id
             WHERE (?1 = '*' OR a.tenant_id = ?1)
             ORDER BY a.issued_at DESC",
            sql_params![&scope],
            |row| {
                let pop_len: i64 = row.get(7)?;
                Ok(AdminAgentRecord {
                    agent_id: row.get(0)?,
                    human_key_image: row.get(1)?,
                    agent_checksum: row.get(2)?,
                    assurance_level: row.get(3)?,
                    issued_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    revoked: row.get::<i64>(6)? != 0,
                    has_pop: pop_len > 0,
                    agent_type: row.get(8)?,
                    intent_json: row.get(9)?,
                    attestation_kind: {
                        let raw: String = row.get(10)?;
                        let kind = crate::attestation::AttestationKind::parse(&raw)
                            .unwrap_or(crate::attestation::AttestationKind::None);
                        kind.as_str().to_string()
                    },
                    hardware_attested: {
                        let raw: String = row.get(10)?;
                        crate::attestation::AttestationKind::parse(&raw)
                            .map(|k| k.is_hardware_backed())
                            .unwrap_or(false)
                    },
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

#[derive(Serialize)]
pub struct AdminActionReceiptRecord {
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub status: String,
    pub policy_version: String,
    pub created_at: i64,
}

/// GET /admin/agent_actions/recent?limit=N — last N agent action receipts.
pub async fn get_recent_actions(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::Extension(tenant): axum::Extension<crate::tenancy::TenantId>,
    authz: Option<axum::Extension<AdminAuthz>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminActionReceiptRecord>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let scope = admin_scope(authz.as_ref().map(|axum::Extension(a)| a), &tenant);
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    let records: Vec<AdminActionReceiptRecord> = db
        .any_conn()
        .query_map(
            "SELECT receipt_id, action_hash, agent_id, status, policy_version, created_at
             FROM agent_action_receipts
             WHERE (?1 = '*' OR tenant_id = ?1)
             ORDER BY created_at DESC
             LIMIT ?2",
            sql_params![&scope, limit],
            |row| {
                Ok(AdminActionReceiptRecord {
                    receipt_id: row.get(0)?,
                    action_hash: row.get(1)?,
                    agent_id: row.get(2)?,
                    status: row.get(3)?,
                    policy_version: row.get(4)?,
                    created_at: row.get(5)?,
                })
            },
        )
        .map_err(AppError::internal)?;
    Ok(Json(records))
}

/// Verdict surface for the dashboard "Try" page. Each scenario exercises a
/// REAL governance primitive (no mocks): `replay` runs the live single-use
/// nonce store, `scope`/`normal` run the live tool-allowlist invariant.
#[derive(Serialize)]
pub struct DemoScenarioOut {
    pub result: String, // "allowed" | "stopped"
    pub status_code: u16,
    pub detail: serde_json::Value,
}

#[derive(Deserialize)]
pub struct RecentLimitQuery {
    pub limit: Option<i64>,
}
