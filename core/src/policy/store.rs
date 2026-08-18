//! Policy store — in-memory cache backed by the `policies` SQL table.
//!
//! Lookups are by `policy_id` (primary) and by `agent` (secondary index).
//! Writes go through [`PolicyStore::upsert`] which persists to the
//! supplied DB handle and refreshes both indices.

use crate::any_db::AnyRowGet;
use crate::sql_params;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::db::DbHandle;
use crate::tenancy::DEFAULT_TENANT;

use super::compiler::{compile, CompileError, CompiledPolicy};
use super::parser::parse;
use super::types::PolicyParseError;

/// Errors returned by [`PolicyStore`] operations.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying DB error.
    Db(String),
    /// Policy parsing failed during hydration.
    Parse(PolicyParseError),
    /// Policy compilation failed during hydration.
    Compile(CompileError),
    /// Lock poisoned (should never happen in practice).
    Lock,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Db(s) => write!(f, "db: {s}"),
            StoreError::Parse(e) => write!(f, "parse: {e}"),
            StoreError::Compile(e) => write!(f, "compile: {e}"),
            StoreError::Lock => write!(f, "store lock poisoned"),
        }
    }
}

impl Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

impl From<PolicyParseError> for StoreError {
    fn from(e: PolicyParseError) -> Self {
        StoreError::Parse(e)
    }
}

impl From<CompileError> for StoreError {
    fn from(e: CompileError) -> Self {
        StoreError::Compile(e)
    }
}

/// Lightweight summary of a stored policy (for `GET /v1/policy/list`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    /// Server-assigned id (`pol_<32-hex>`).
    pub policy_id: String,
    /// Agent identifier.
    pub agent: String,
    /// DSL version.
    pub version: String,
    /// Unix-epoch seconds of last write.
    pub updated_at: i64,
}

/// Index key composing tenant id + policy id. `(tenant, policy_id)` is the
/// effective primary key once multi-tenancy is enabled (Sprint 11) — two
/// tenants are allowed to upload policies with the same `policy_id` (it's
/// a content hash, but agents can legitimately share a policy template).
type TenantKey = (String, String);

#[derive(Debug, Default)]
struct StoreIndex {
    by_id: HashMap<TenantKey, Arc<CompiledPolicy>>,
    /// `(tenant_id, agent) -> policy_id`
    by_agent: HashMap<TenantKey, String>,
    /// `(tenant_id, policy_id) -> epoch seconds`
    updated_at: HashMap<TenantKey, i64>,
}

/// In-memory policy cache backed by the SQLite `policies` table.
pub struct PolicyStore {
    db: Arc<DbHandle>,
    inner: RwLock<StoreIndex>,
}

impl fmt::Debug for PolicyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyStore").finish()
    }
}

impl PolicyStore {
    /// Build an empty store; call [`PolicyStore::hydrate`] to load from DB.
    pub fn new(db: Arc<DbHandle>) -> Self {
        Self {
            db,
            inner: RwLock::new(StoreIndex::default()),
        }
    }

    /// Load all rows from the `policies` table into the in-memory index.
    ///
    /// Reads `tenant_id` alongside the existing columns so multi-tenant
    /// hydration restores the `(tenant_id, policy_id)` index exactly as it
    /// was at shutdown. Legacy rows (pre-S11) backfill to the default
    /// tenant via the column DEFAULT and round-trip transparently.
    pub fn hydrate(&self) -> Result<usize, StoreError> {
        let mut conn = self.db.lock().map_err(|e| StoreError::Db(e.to_string()))?;
        let rows = conn
            .any_conn()
            .query_map(
                "SELECT policy_id, raw_yaml, updated_at, tenant_id FROM policies",
                sql_params![],
                |row| {
                    Ok((
                        row.get::<String>(0)?,
                        row.get::<String>(1)?,
                        row.get::<i64>(2)?,
                        row.get::<String>(3)?,
                    ))
                },
            )
            .map_err(StoreError::Db)?;
        drop(conn);

        let mut idx = self.inner.write().map_err(|_| StoreError::Lock)?;
        let mut count = 0;
        for (id, raw_yaml, updated_at, tenant) in rows {
            let policy = parse(&raw_yaml)?;
            let compiled = compile(policy)?;
            // Defensive: trust stored id over recomputed one, in case
            // canonicalisation rules ever shift between versions.
            let agent = compiled.agent.clone();
            let key = (tenant.clone(), id.clone());
            let arc = Arc::new(compiled);
            idx.by_id.insert(key.clone(), arc);
            idx.by_agent.insert((tenant.clone(), agent), id.clone());
            idx.updated_at.insert(key, updated_at);
            count += 1;
        }
        Ok(count)
    }

    /// Insert or update a compiled policy, persisting to DB. Backwards
    /// compatibility wrapper that defaults the tenant id; callers wired
    /// through `Extension<TenantId>` should prefer [`Self::upsert_tenant`].
    pub fn upsert(&self, compiled: CompiledPolicy) -> Result<(), StoreError> {
        self.upsert_tenant(DEFAULT_TENANT, compiled)
    }

    /// Insert or update a compiled policy under an explicit tenant.
    pub fn upsert_tenant(
        &self,
        tenant_id: &str,
        compiled: CompiledPolicy,
    ) -> Result<(), StoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let id = compiled.policy_id.clone();
        let agent = compiled.agent.clone();
        let version = compiled.raw.version.clone();
        let raw_yaml = serde_yaml_ng::to_string(&compiled.raw)
            .map_err(|e| StoreError::Db(format!("serialize: {e}")))?;

        {
            let mut conn = self.db.lock().map_err(|e| StoreError::Db(e.to_string()))?;
            conn.any_conn().execute(
                "INSERT INTO policies (policy_id, agent, version, raw_yaml, created_at, updated_at, tenant_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
                 ON CONFLICT(policy_id) DO UPDATE SET
                     agent = excluded.agent,
                     version = excluded.version,
                     raw_yaml = excluded.raw_yaml,
                     updated_at = excluded.updated_at,
                     tenant_id = excluded.tenant_id",
                sql_params![&id, &agent, &version, &raw_yaml, &now, &tenant_id],
            ).map_err(StoreError::Db)?;
        }

        let key = (tenant_id.to_string(), id.clone());
        let mut idx = self.inner.write().map_err(|_| StoreError::Lock)?;
        idx.by_id.insert(key.clone(), Arc::new(compiled));
        idx.by_agent
            .insert((tenant_id.to_string(), agent), id.clone());
        idx.updated_at.insert(key, now);
        Ok(())
    }

    /// Default-tenant lookup by primary id. Back-compat shim — new callers
    /// should use [`Self::get_by_id_tenant`].
    pub fn get_by_id(&self, id: &str) -> Option<Arc<CompiledPolicy>> {
        self.get_by_id_tenant(DEFAULT_TENANT, id)
    }

    /// Tenant-scoped lookup by primary id.
    pub fn get_by_id_tenant(&self, tenant_id: &str, id: &str) -> Option<Arc<CompiledPolicy>> {
        self.inner
            .read()
            .ok()?
            .by_id
            .get(&(tenant_id.to_string(), id.to_string()))
            .cloned()
    }

    /// Default-tenant agent-based lookup. Back-compat shim.
    pub fn get_by_agent(&self, agent: &str) -> Option<Arc<CompiledPolicy>> {
        self.get_by_agent_tenant(DEFAULT_TENANT, agent)
    }

    /// Tenant-scoped agent-based lookup (most recent upsert wins).
    pub fn get_by_agent_tenant(&self, tenant_id: &str, agent: &str) -> Option<Arc<CompiledPolicy>> {
        let idx = self.inner.read().ok()?;
        let id = idx
            .by_agent
            .get(&(tenant_id.to_string(), agent.to_string()))?;
        idx.by_id.get(&(tenant_id.to_string(), id.clone())).cloned()
    }

    /// All policies across every tenant. Back-compat — for new admin
    /// surfaces, prefer [`Self::list_for_tenant`] to avoid leaking
    /// cross-tenant rows.
    pub fn list_all(&self) -> Vec<PolicySummary> {
        let Ok(idx) = self.inner.read() else {
            return Vec::new();
        };
        idx.by_id
            .iter()
            .map(|((_tenant, id), cp)| PolicySummary {
                policy_id: id.clone(),
                agent: cp.agent.clone(),
                version: cp.raw.version.clone(),
                updated_at: idx
                    .updated_at
                    .get(&(_tenant.clone(), id.clone()))
                    .copied()
                    .unwrap_or(0),
            })
            .collect()
    }

    /// Tenant-scoped list: only policies owned by `tenant_id`.
    pub fn list_for_tenant(&self, tenant_id: &str) -> Vec<PolicySummary> {
        let Ok(idx) = self.inner.read() else {
            return Vec::new();
        };
        idx.by_id
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|((t, id), cp)| PolicySummary {
                policy_id: id.clone(),
                agent: cp.agent.clone(),
                version: cp.raw.version.clone(),
                updated_at: idx
                    .updated_at
                    .get(&(t.clone(), id.clone()))
                    .copied()
                    .unwrap_or(0),
            })
            .collect()
    }

    /// Default-tenant delete. Back-compat shim.
    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        self.delete_tenant(DEFAULT_TENANT, id)
    }

    /// Delete `policy_id` for an explicit tenant. Returns Ok(()) even if
    /// id was not present for that tenant (idempotent); DB errors surface.
    pub fn delete_tenant(&self, tenant_id: &str, id: &str) -> Result<(), StoreError> {
        {
            let mut conn = self.db.lock().map_err(|e| StoreError::Db(e.to_string()))?;
            conn.any_conn()
                .execute(
                    "DELETE FROM policies WHERE policy_id = ?1 AND tenant_id = ?2",
                    sql_params![&id, &tenant_id],
                )
                .map_err(StoreError::Db)?;
        }
        let key = (tenant_id.to_string(), id.to_string());
        let mut idx = self.inner.write().map_err(|_| StoreError::Lock)?;
        if let Some(cp) = idx.by_id.remove(&key) {
            idx.by_agent
                .remove(&(tenant_id.to_string(), cp.agent.clone()));
        }
        idx.updated_at.remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;

    fn fresh_store() -> Arc<PolicyStore> {
        let path = format!(
            "/tmp/sauron_policy_store_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let db = Arc::new(open_db_at(&path, 2));
        Arc::new(PolicyStore::new(db))
    }

    const FX_MINIMAL: &str = include_str!("../../../schemas/fixtures/policy_minimal.yaml");

    #[test]
    fn upsert_and_lookup_roundtrip() {
        let store = fresh_store();
        let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
        let id = compiled.policy_id.clone();
        let agent = compiled.agent.clone();
        store.upsert(compiled).unwrap();

        assert!(store.get_by_id(&id).is_some());
        assert!(store.get_by_agent(&agent).is_some());
        assert_eq!(store.list_all().len(), 1);
    }

    #[test]
    fn delete_removes_entry() {
        let store = fresh_store();
        let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
        let id = compiled.policy_id.clone();
        store.upsert(compiled).unwrap();
        store.delete(&id).unwrap();
        assert!(store.get_by_id(&id).is_none());
        assert_eq!(store.list_all().len(), 0);
    }

    #[test]
    fn hydrate_reads_persisted_rows() {
        let store = fresh_store();
        let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
        store.upsert(compiled).unwrap();

        // Build a fresh store on the same DB and hydrate.
        let store2 = Arc::new(PolicyStore::new(Arc::clone(&store.db)));
        let n = store2.hydrate().unwrap();
        assert_eq!(n, 1);
        assert_eq!(store2.list_all().len(), 1);
    }
}
