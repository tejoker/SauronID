//! HTTP handlers for `/v1/agents/:agent_id/policy_binding` (Sprint 10
//! server-side binding, follow-up to Sprint 11.5 tenant scoping).
//!
//! Every handler:
//!   * Extracts `Extension<TenantId>` so the binding row is filtered/
//!     written within the caller's tenant.
//!   * Goes through the same admin gate as the rest of `/v1/agents/*`
//!     (see [`crate::routes::agent_spend_router`]).
//!
//! Trust model: the binding is *advisory* metadata that the dashboard +
//! evaluator can use to discover which policy a given agent should be
//! evaluated against. The authoritative policy contract still lives in
//! the policy table itself — this binding does NOT short-circuit
//! `/v1/policy/evaluate`'s `policy_id` argument; it just lets surfaces
//! that don't already know the policy pick the right one.
//!
//! Persistence: SQLite-backed in S10. The Postgres path lands when
//! the `Repo::Postgres` arm grows a `bind_agent_policy_tenant` helper
//! (deferred to S11.6 alongside per-tenant batching).

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::db::DbHandle;
use crate::error::AppError;
use crate::policy::PolicyStore;
use crate::state::ServerState;
use crate::tenancy::TenantId;

/// Body of `POST /v1/agents/:agent_id/policy_binding`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindPolicyBody {
    /// Policy id to bind to the agent. MUST exist in the caller's tenant
    /// policy store; cross-tenant ids are rejected as 400 to avoid
    /// leaking existence information.
    pub policy_id: String,
}

/// Response payload for the bind / get endpoints.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBindingRecord {
    /// Agent that's being bound.
    pub agent_id: String,
    /// Policy bound to that agent.
    pub policy_id: String,
    /// Unix-epoch seconds the binding was last written.
    pub bound_at: i64,
}

/// Response from `DELETE /v1/agents/:agent_id/policy_binding`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UnbindResponse {
    /// Always true on success (idempotent — same shape when nothing was
    /// bound). Callers should treat 200 + `unbound: true` as success.
    pub unbound: bool,
}

/// `POST /v1/agents/:agent_id/policy_binding` — idempotent bind.
///
/// Validates that both `agent_id` and `policy_id` exist in the caller's
/// tenant. Returns the freshly-persisted record. Last write wins on a
/// re-bind to a different policy.
pub async fn bind_policy(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
    Json(body): Json<BindPolicyBody>,
) -> Result<Json<PolicyBindingRecord>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    bind_policy_inner_tenant(state, &tenant_id, &agent_id, body).await
}

/// Pure-handler core for [`bind_policy`] driven by a full `ServerState`.
/// HTTP handlers go through this path; tests prefer
/// [`bind_policy_with_handles`] which only needs the db + policy store.
pub async fn bind_policy_inner_tenant(
    state: Arc<RwLock<ServerState>>,
    tenant_id: &str,
    agent_id: &str,
    body: BindPolicyBody,
) -> Result<Json<PolicyBindingRecord>, AppError> {
    let (store, db_handle) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        (Arc::clone(&st.policy_store), Arc::clone(&st.db))
    };
    bind_policy_with_handles(&store, &db_handle, tenant_id, agent_id, body).await
}

/// Low-level binding-upsert path used by both the production handler and
/// the unit tests. Validates that:
///
///   1. `agent_id` is non-empty and exists in the `agents` table under
///      the caller's tenant.
///   2. `policy_id` is non-empty and exists in `PolicyStore` under the
///      caller's tenant.
///
/// On success the row is written via `INSERT … ON CONFLICT … DO UPDATE`
/// so re-binds are idempotent (last write wins) and the response carries
/// the freshly-stamped `bound_at`.
pub async fn bind_policy_with_handles(
    store: &Arc<PolicyStore>,
    db_handle: &Arc<DbHandle>,
    tenant_id: &str,
    agent_id: &str,
    body: BindPolicyBody,
) -> Result<Json<PolicyBindingRecord>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    if body.policy_id.is_empty() {
        return Err(AppError::BadRequest("policy_id required".into()));
    }

    // Existence checks BEFORE we write — cheaper to reject a malformed
    // request than to roll back a transaction. Both checks are filtered
    // by tenant so a tenant cannot bind to another tenant's policy_id
    // (and we never leak that fact across tenants).
    if store.get_by_id_tenant(tenant_id, &body.policy_id).is_none() {
        return Err(AppError::BadRequest(format!(
            "policy_id {} not found in this tenant",
            body.policy_id
        )));
    }
    {
        let db = db_handle
            .lock()
            .map_err(|_| AppError::Internal("db lock".into()))?;
        let exists: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            sql_params![&agent_id, &tenant_id],
            |r| r.get(0),
            0,
        );
        if exists == 0 {
            return Err(AppError::BadRequest(format!(
                "agent_id {agent_id} not found in this tenant"
            )));
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    {
        let db = db_handle
            .lock()
            .map_err(|_| AppError::Internal("db lock".into()))?;
        db.any_conn().execute(
            "INSERT INTO agent_policy_bindings (tenant_id, agent_id, policy_id, bound_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(tenant_id, agent_id) DO UPDATE SET \
                policy_id = excluded.policy_id, \
                bound_at  = excluded.bound_at",
            sql_params![&tenant_id, &agent_id, &body.policy_id, &now],
        )
        .map_err(|e| AppError::Internal(format!("binding upsert: {e}")))?;
    }

    Ok(Json(PolicyBindingRecord {
        agent_id: agent_id.to_string(),
        policy_id: body.policy_id,
        bound_at: now,
    }))
}

/// `GET /v1/agents/:agent_id/policy_binding` — current binding or 404.
pub async fn get_binding(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
) -> Result<Json<PolicyBindingRecord>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    get_binding_inner_tenant(state, &tenant_id, &agent_id).await
}

/// Pure-handler core for [`get_binding`] driven by a full `ServerState`.
pub async fn get_binding_inner_tenant(
    state: Arc<RwLock<ServerState>>,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Json<PolicyBindingRecord>, AppError> {
    let db_handle = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        Arc::clone(&st.db)
    };
    get_binding_with_handle(&db_handle, tenant_id, agent_id).await
}

/// Low-level lookup driven by a raw `DbHandle`. Used by tests + by the
/// production state-driven handler above.
pub async fn get_binding_with_handle(
    db_handle: &Arc<DbHandle>,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Json<PolicyBindingRecord>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    let db = db_handle
        .lock()
        .map_err(|_| AppError::Internal("db lock".into()))?;
    let row = db.any_conn()
        .query_row(
            "SELECT policy_id, bound_at FROM agent_policy_bindings \
             WHERE tenant_id = ?1 AND agent_id = ?2",
            sql_params![&tenant_id, &agent_id],
            |r| Ok((r.get::<String>(0)?, r.get::<i64>(1)?)),
        )
        .ok()
        .flatten();
    match row {
        Some((policy_id, bound_at)) => Ok(Json(PolicyBindingRecord {
            agent_id: agent_id.to_string(),
            policy_id,
            bound_at,
        })),
        None => Err(AppError::NotFound(format!(
            "no binding for agent {agent_id}"
        ))),
    }
}

/// `DELETE /v1/agents/:agent_id/policy_binding` — drop the binding.
/// Idempotent: deleting an absent binding still returns 200.
pub async fn unbind_policy(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
) -> Result<Json<UnbindResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default().0;
    unbind_policy_inner_tenant(state, &tenant_id, &agent_id).await
}

/// Pure-handler core for [`unbind_policy`] driven by a full `ServerState`.
pub async fn unbind_policy_inner_tenant(
    state: Arc<RwLock<ServerState>>,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Json<UnbindResponse>, AppError> {
    let db_handle = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        Arc::clone(&st.db)
    };
    unbind_policy_with_handle(&db_handle, tenant_id, agent_id).await
}

/// Low-level delete driven by a raw `DbHandle`.
pub async fn unbind_policy_with_handle(
    db_handle: &Arc<DbHandle>,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Json<UnbindResponse>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    let db = db_handle
        .lock()
        .map_err(|_| AppError::Internal("db lock".into()))?;
    db.any_conn().execute(
        "DELETE FROM agent_policy_bindings WHERE tenant_id = ?1 AND agent_id = ?2",
        sql_params![&tenant_id, &agent_id],
    )
    .map_err(|e| AppError::Internal(format!("binding delete: {e}")))?;
    Ok(Json(UnbindResponse { unbound: true }))
}

/// Look up the policy_id currently bound to `(tenant_id, agent_id)`. Returns
/// `Ok(None)` when no row is present (the agent has no server-side policy
/// binding) and `Err` only on DB / lock failure.
///
/// Sprint 1 (advisory → enforce): the agent action endpoints
/// (`/agent/payment/authorize`, etc.) consult this to find which policy to
/// run `evaluate` against before issuing the authorisation.
pub fn lookup_bound_policy_id(
    db_handle: &Arc<DbHandle>,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Option<String>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    let db = db_handle
        .lock()
        .map_err(|_| AppError::Internal("db lock".into()))?;
    let row: Result<Option<String>, String> = db.any_conn().query_row(
        "SELECT policy_id FROM agent_policy_bindings WHERE tenant_id = ?1 AND agent_id = ?2",
        sql_params![&tenant_id, &agent_id],
        |r| r.get::<String>(0),
    );
    // `query_row` distinguishes the two cases itself: Ok(None) means no binding,
    // Err means the lookup failed. The old code had to match
    // rusqlite::Error::QueryReturnedNoRows to tell them apart.
    row.map_err(|e| AppError::Internal(format!("binding lookup: {e}")))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the low-level (db-handle driven) binding helpers.
    //! Each test owns its own SQLite-on-disk database for parallel safety.

    use rusqlite::params;
    use super::*;
    use crate::db::open_db_at;
    use crate::policy::compiler::compile;
    use crate::policy::parser::parse;
    use crate::policy::PolicyStore;

    const FX_MINIMAL: &str = include_str!("../../../schemas/fixtures/policy_minimal.yaml");

    fn fresh_handles(test_name: &str) -> (Arc<DbHandle>, Arc<PolicyStore>) {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("sauron-bind-{pid}-{nanos}-{test_name}.db"));
        let _ = std::fs::remove_file(&path);
        let handle = Arc::new(open_db_at(path.to_str().unwrap(), 2));
        let store = Arc::new(PolicyStore::new(Arc::clone(&handle)));
        (handle, store)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn seed_agent(db: &Arc<DbHandle>, tenant_id: &str, agent_id: &str) {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO agents
             (agent_id, human_key_image, agent_checksum, issued_at, expires_at, tenant_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                agent_id,
                "human-test",
                "checksum-test",
                0_i64,
                9_999_999_999_i64,
                tenant_id
            ],
        )
        .unwrap();
    }

    fn seed_policy(store: &Arc<PolicyStore>, tenant_id: &str) -> String {
        let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
        let policy_id = compiled.policy_id.clone();
        store.upsert_tenant(tenant_id, compiled).unwrap();
        policy_id
    }

    #[test]
    fn bind_then_get_returns_persisted_record() {
        let (db, store) = fresh_handles("bind_then_get");
        rt().block_on(async {
            seed_agent(&db, "default", "agent-bind-1");
            let policy_id = seed_policy(&store, "default");

            let bound = bind_policy_with_handles(
                &store,
                &db,
                "default",
                "agent-bind-1",
                BindPolicyBody {
                    policy_id: policy_id.clone(),
                },
            )
            .await
            .expect("bind ok")
            .0;
            assert_eq!(bound.agent_id, "agent-bind-1");
            assert_eq!(bound.policy_id, policy_id);
            assert!(bound.bound_at > 0);

            let fetched = get_binding_with_handle(&db, "default", "agent-bind-1")
                .await
                .expect("get ok")
                .0;
            assert_eq!(fetched, bound);
        });
    }

    #[test]
    #[allow(unused_must_use)] // test asserts DB side-effects, not the Json response
    fn rebind_is_idempotent_last_write_wins() {
        let (db, store) = fresh_handles("rebind_idempotent");
        rt().block_on(async {
            seed_agent(&db, "default", "agent-rebind");
            let policy_a = seed_policy(&store, "default");
            // Upload a SECOND policy by mutating the fixture's `agent` field
            // (re-compiles to a fresh policy_id).
            let p2 = parse(&FX_MINIMAL.replace("agent: ", "agent: rebind-target-")).unwrap();
            let compiled = compile(p2).unwrap();
            let policy_b = compiled.policy_id.clone();
            store.upsert_tenant("default", compiled).unwrap();

            bind_policy_with_handles(
                &store,
                &db,
                "default",
                "agent-rebind",
                BindPolicyBody {
                    policy_id: policy_a.clone(),
                },
            )
            .await
            .unwrap();
            let second = bind_policy_with_handles(
                &store,
                &db,
                "default",
                "agent-rebind",
                BindPolicyBody {
                    policy_id: policy_b.clone(),
                },
            )
            .await
            .unwrap()
            .0;
            assert_eq!(second.policy_id, policy_b, "last write wins");

            let fetched = get_binding_with_handle(&db, "default", "agent-rebind")
                .await
                .unwrap()
                .0;
            assert_eq!(fetched.policy_id, policy_b);
        });
    }

    #[test]
    #[allow(unused_must_use)] // test asserts DB side-effects, not the Json response
    fn unbind_is_idempotent_and_clears_row() {
        let (db, store) = fresh_handles("unbind_idempotent");
        rt().block_on(async {
            seed_agent(&db, "default", "agent-unbind");
            let policy_id = seed_policy(&store, "default");
            bind_policy_with_handles(
                &store,
                &db,
                "default",
                "agent-unbind",
                BindPolicyBody { policy_id },
            )
            .await
            .unwrap();

            unbind_policy_with_handle(&db, "default", "agent-unbind")
                .await
                .unwrap();
            // GET now returns NotFound.
            let r = get_binding_with_handle(&db, "default", "agent-unbind").await;
            assert!(matches!(r, Err(AppError::NotFound(_))));
            // Second unbind is still ok (idempotent).
            unbind_policy_with_handle(&db, "default", "agent-unbind")
                .await
                .unwrap();
        });
    }
}
