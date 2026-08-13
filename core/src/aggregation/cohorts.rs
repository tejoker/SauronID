//! Sprint 8 — Cohort definitions store.
//!
//! A cohort is an operator-defined grouping of opted-in tenants for
//! cross-customer benchmark publication. Each cohort carries its own
//! k-anonymity threshold and ε/δ DP budget per metric publication.
//!
//! Stores are in-memory caches backed by the SQLite `cohort_definitions`
//! table — hydrated at startup, upserts persist through to DB.
//!
//! ```text
//!   Operator (admin)                       Server (this module)
//!   ───────────────────                    ──────────────────────
//!   POST /v1/cohort  ────────────────────► CohortStore::upsert
//!     {cohort_id, label, tenant_ids,                │
//!      k_anonymity_threshold, epsilon, …}          ├─► persist
//!                                                  └─► refresh cache
//!   GET  /v1/cohort/published?cohort_id=X ───────► CohortStore::get
//!                                                  └─► publish::publish_cohort
//! ```

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::db::DbHandle;

/// Operator-managed cohort definition: an opt-in set of tenants grouped
/// by vendor / sector for cross-customer benchmark publication.
///
/// Cohorts are global (NOT tenant-scoped). The operator runs the
/// publication; individual tenants opt in by being included in
/// `tenant_ids`. See `docs/privacy-model.md` for the lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CohortDefinition {
    /// Stable cohort identifier — e.g. `coh_openai_banking`. Operators
    /// should use the `coh_` prefix convention.
    pub cohort_id: String,
    /// Human-readable label — e.g. `"OpenAI · Banking"`.
    pub label: String,
    /// Optional vendor tag — e.g. `"OpenAI"`, `"Anthropic"`, `"Gemini"`.
    #[serde(default)]
    pub vendor: Option<String>,
    /// Optional sector tag — e.g. `"banking"`, `"healthcare"`, `"retail"`.
    #[serde(default)]
    pub sector: Option<String>,
    /// Explicit list of opted-in tenant ids that contribute stats to
    /// this cohort. Empty list is allowed at definition time but the
    /// publication path will suppress any metric whose contributor
    /// count falls below `k_anonymity_threshold`.
    pub tenant_ids: Vec<String>,
    /// k-anonymity gate: suppress any metric whose contributor count
    /// (deduplicated per tenant) falls below this threshold. Default 5
    /// for dev, 10 for prod. See `dp::DEFAULT_K_THRESHOLD`.
    pub k_anonymity_threshold: usize,
    /// ε budget per metric per publication. Per-quartile noise uses
    /// `epsilon_per_metric / 4` because budget is split four ways for the
    /// four quartiles (basic composition — sequential ε sum).
    pub epsilon_per_metric: f64,
    /// δ for the (ε, δ)-DP envelope. The Laplace mechanism is
    /// (ε, 0)-DP so this is informational only at publication time, but
    /// it's carried through to the privacy notice for operator visibility.
    pub delta: f64,
    /// S8 ext — length of a regulatory cycle in seconds. The ε ledger
    /// resets at every cycle boundary aligned from the unix epoch. Default
    /// `7_776_000` (90 days, ~one quarter). `None` → use default.
    #[serde(default)]
    pub cycle_seconds: Option<u64>,
    /// S8 ext — lifetime ε cap for one cycle. Across all publications in
    /// the cycle, the sum of charged ε for one metric MUST NOT exceed this
    /// value. `None` → `epsilon_per_metric * 4` (one publication per
    /// quarter ⇒ four publications per year on a 90-day cycle).
    #[serde(default)]
    pub epsilon_cap_per_cycle: Option<f64>,
    /// S8 ext — lifetime δ cap for one cycle. `None` → `delta * 4`.
    #[serde(default)]
    pub delta_cap_per_cycle: Option<f64>,
}

/// Default cycle length (seconds). 7_776_000 ≈ 90 days, one calendar
/// quarter. Used when `CohortDefinition::cycle_seconds` is `None`.
pub const DEFAULT_CYCLE_SECONDS: u64 = 7_776_000;

impl CohortDefinition {
    /// Validate the static parts of a definition — ε > 0, δ ∈ [0, 1),
    /// k ≥ 1, non-empty cohort_id + label.
    pub fn validate(&self) -> Result<(), CohortError> {
        if self.cohort_id.trim().is_empty() {
            return Err(CohortError::Invalid("cohort_id empty".into()));
        }
        if self.label.trim().is_empty() {
            return Err(CohortError::Invalid("label empty".into()));
        }
        if !self.epsilon_per_metric.is_finite() || self.epsilon_per_metric <= 0.0 {
            return Err(CohortError::Invalid(format!(
                "epsilon_per_metric must be > 0, got {}",
                self.epsilon_per_metric
            )));
        }
        if !self.delta.is_finite() || self.delta < 0.0 || self.delta >= 1.0 {
            return Err(CohortError::Invalid(format!(
                "delta must be in [0,1), got {}",
                self.delta
            )));
        }
        if self.k_anonymity_threshold == 0 {
            return Err(CohortError::Invalid(
                "k_anonymity_threshold must be >= 1".into(),
            ));
        }
        if let Some(s) = self.cycle_seconds {
            if s == 0 {
                return Err(CohortError::Invalid(
                    "cycle_seconds must be > 0 when set".into(),
                ));
            }
        }
        if let Some(c) = self.epsilon_cap_per_cycle {
            if !c.is_finite() || c <= 0.0 {
                return Err(CohortError::Invalid(format!(
                    "epsilon_cap_per_cycle must be > 0, got {c}"
                )));
            }
        }
        if let Some(c) = self.delta_cap_per_cycle {
            if !c.is_finite() || !(0.0..1.0).contains(&c) {
                return Err(CohortError::Invalid(format!(
                    "delta_cap_per_cycle must be in [0,1), got {c}"
                )));
            }
        }
        Ok(())
    }

    /// Resolved cycle length in seconds (defaulting to
    /// [`DEFAULT_CYCLE_SECONDS`] when unset).
    pub fn effective_cycle_seconds(&self) -> u64 {
        self.cycle_seconds.unwrap_or(DEFAULT_CYCLE_SECONDS)
    }

    /// Resolved per-cycle ε cap. Defaults to `epsilon_per_metric * 4` —
    /// roughly one publication per quarter on a 90-day cycle.
    pub fn effective_epsilon_cap_per_cycle(&self) -> f64 {
        self.epsilon_cap_per_cycle
            .unwrap_or(self.epsilon_per_metric * 4.0)
    }

    /// Resolved per-cycle δ cap. Defaults to `delta * 4`.
    pub fn effective_delta_cap_per_cycle(&self) -> f64 {
        self.delta_cap_per_cycle.unwrap_or(self.delta * 4.0)
    }

    /// Compute the cycle start (unix epoch seconds, aligned from epoch 0)
    /// that contains `now_epoch_secs`. Operators rotate cycles via the
    /// budget rotate endpoint; this is the default alignment used when
    /// the operator has not explicitly rotated.
    pub fn cycle_start_for(&self, now_epoch_secs: i64) -> i64 {
        let period = self.effective_cycle_seconds() as i64;
        if period <= 0 {
            return 0;
        }
        // Floor-division alignment from epoch 0 — works for any positive
        // `now_epoch_secs`. Negative inputs (shouldn't happen) clamp to 0.
        if now_epoch_secs <= 0 {
            return 0;
        }
        (now_epoch_secs / period) * period
    }
}

/// Errors emitted by [`CohortStore`] operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CohortError {
    /// Validation failure on a definition.
    Invalid(String),
    /// Underlying storage / serialisation failure.
    Storage(String),
    /// Internal lock poisoning — should never happen in practice.
    Lock,
}

impl std::fmt::Display for CohortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CohortError::Invalid(s) => write!(f, "invalid cohort: {s}"),
            CohortError::Storage(s) => write!(f, "cohort storage: {s}"),
            CohortError::Lock => write!(f, "cohort store lock poisoned"),
        }
    }
}

impl std::error::Error for CohortError {}

/// In-memory cohort registry backed by the `cohort_definitions` table.
///
/// Hydrate at startup with [`CohortStore::hydrate`], then upserts and
/// deletes persist transparently. Lookups are lock-cheap reads.
pub struct CohortStore {
    db: Arc<DbHandle>,
    inner: RwLock<HashMap<String, CohortDefinition>>,
}

impl std::fmt::Debug for CohortStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortStore").finish()
    }
}

impl CohortStore {
    /// Build an empty store. Call [`Self::hydrate`] to load from DB.
    pub fn new(db: Arc<DbHandle>) -> Self {
        Self {
            db,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Load all rows from `cohort_definitions` into the in-memory map.
    /// Returns the number of cohorts loaded.
    pub fn hydrate(&self) -> Result<usize, CohortError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CohortError::Storage(e.to_string()))?;
        let rows = conn
            .any_conn()
            .query_map(
                "SELECT cohort_id, label, vendor, sector, tenant_ids_json,
                        k_anonymity_threshold, epsilon_per_metric, delta,
                        cycle_seconds, epsilon_cap_per_cycle, delta_cap_per_cycle
                 FROM cohort_definitions",
                sql_params![],
                |r| {
                let tenant_json: String = r.get(4)?;
                let k_int: i64 = r.get(5)?;
                Ok((
                    r.get::<String>(0)?,
                    r.get::<String>(1)?,
                    r.get::<Option<String>>(2)?,
                    r.get::<Option<String>>(3)?,
                    tenant_json,
                    k_int,
                    r.get::<f64>(6)?,
                    r.get::<f64>(7)?,
                    r.get::<Option<i64>>(8)?,
                    r.get::<Option<f64>>(9)?,
                    r.get::<Option<f64>>(10)?,
                ))
            })
            .map_err(|e| CohortError::Storage(e.to_string()))?;
        let collected = rows;
        drop(conn);

        let mut map = self.inner.write().map_err(|_| CohortError::Lock)?;
        map.clear();
        let mut n = 0;
        for (
            cohort_id,
            label,
            vendor,
            sector,
            tenants_json,
            k_int,
            eps,
            delta,
            cycle_seconds,
            epsilon_cap,
            delta_cap,
        ) in collected
        {
            let tenant_ids: Vec<String> = serde_json::from_str(&tenants_json)
                .map_err(|e| CohortError::Storage(format!("tenant_ids json: {e}")))?;
            let k_anonymity_threshold = if k_int < 1 { 1 } else { k_int as usize };
            let def = CohortDefinition {
                cohort_id: cohort_id.clone(),
                label,
                vendor,
                sector,
                tenant_ids,
                k_anonymity_threshold,
                epsilon_per_metric: eps,
                delta,
                cycle_seconds: cycle_seconds
                    .and_then(|v| if v > 0 { Some(v as u64) } else { None }),
                epsilon_cap_per_cycle: epsilon_cap,
                delta_cap_per_cycle: delta_cap,
            };
            map.insert(cohort_id, def);
            n += 1;
        }
        Ok(n)
    }

    /// Insert or update a cohort definition. Persists to DB then updates
    /// the in-memory cache atomically. `now_epoch` is the timestamp used
    /// for `created_at`/`updated_at` (caller supplies — easier to test).
    pub fn upsert(&self, def: CohortDefinition) -> Result<(), CohortError> {
        self.upsert_at(def, now_epoch())
    }

    /// Same as [`Self::upsert`] but with an explicit `now` for tests.
    pub fn upsert_at(&self, def: CohortDefinition, now: i64) -> Result<(), CohortError> {
        def.validate()?;
        let tenants_json = serde_json::to_string(&def.tenant_ids)
            .map_err(|e| CohortError::Storage(format!("tenant_ids json: {e}")))?;
        {
            let conn = self
                .db
                .lock()
                .map_err(|e| CohortError::Storage(e.to_string()))?;
            conn.any_conn().execute(
                "INSERT INTO cohort_definitions
                   (cohort_id, label, vendor, sector, tenant_ids_json,
                    k_anonymity_threshold, epsilon_per_metric, delta,
                    created_at, updated_at,
                    cycle_seconds, epsilon_cap_per_cycle, delta_cap_per_cycle)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12)
                 ON CONFLICT(cohort_id) DO UPDATE SET
                   label = excluded.label,
                   vendor = excluded.vendor,
                   sector = excluded.sector,
                   tenant_ids_json = excluded.tenant_ids_json,
                   k_anonymity_threshold = excluded.k_anonymity_threshold,
                   epsilon_per_metric = excluded.epsilon_per_metric,
                   delta = excluded.delta,
                   updated_at = excluded.updated_at,
                   cycle_seconds = excluded.cycle_seconds,
                   epsilon_cap_per_cycle = excluded.epsilon_cap_per_cycle,
                   delta_cap_per_cycle = excluded.delta_cap_per_cycle",
                sql_params![
                    &def.cohort_id,
                    &def.label,
                    &def.vendor,
                    &def.sector,
                    &tenants_json,
                    def.k_anonymity_threshold as i64,
                    &def.epsilon_per_metric,
                    &def.delta,
                    &now,
                    def.cycle_seconds.map(|v| v as i64),
                    &def.epsilon_cap_per_cycle,
                    &def.delta_cap_per_cycle,
                ],
            )
            .map_err(|e| CohortError::Storage(e.to_string()))?;
        }
        let mut map = self.inner.write().map_err(|_| CohortError::Lock)?;
        map.insert(def.cohort_id.clone(), def);
        Ok(())
    }

    /// Fetch a single cohort definition by id (cache hit — O(1)).
    pub fn get(&self, id: &str) -> Option<CohortDefinition> {
        self.inner.read().ok()?.get(id).cloned()
    }

    /// List all cohort definitions in alphabetical id order.
    pub fn list(&self) -> Vec<CohortDefinition> {
        let Ok(map) = self.inner.read() else {
            return Vec::new();
        };
        let mut v: Vec<_> = map.values().cloned().collect();
        v.sort_by(|a, b| a.cohort_id.cmp(&b.cohort_id));
        v
    }

    /// Remove a cohort definition. Idempotent — succeeds even when id
    /// is absent (matches the policy store contract).
    pub fn delete(&self, id: &str) -> Result<(), CohortError> {
        {
            let conn = self
                .db
                .lock()
                .map_err(|e| CohortError::Storage(e.to_string()))?;
            conn.any_conn().execute(
                "DELETE FROM cohort_definitions WHERE cohort_id = ?1",
                sql_params![&id],
            )
            .map_err(|e| CohortError::Storage(e.to_string()))?;
        }
        let mut map = self.inner.write().map_err(|_| CohortError::Lock)?;
        map.remove(id);
        Ok(())
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;

    fn temp_db(label: &str) -> Arc<DbHandle> {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("sauron-cohorts-{pid}-{nanos}-{label}.db"));
        let _ = std::fs::remove_file(&path);
        Arc::new(open_db_at(path.to_str().unwrap(), 2))
    }

    fn sample(id: &str) -> CohortDefinition {
        CohortDefinition {
            cohort_id: id.into(),
            label: "Test cohort".into(),
            vendor: Some("openai".into()),
            sector: Some("banking".into()),
            tenant_ids: vec!["t1".into(), "t2".into(), "t3".into()],
            k_anonymity_threshold: 3,
            epsilon_per_metric: 1.0,
            delta: 1e-6,
            cycle_seconds: None,
            epsilon_cap_per_cycle: None,
            delta_cap_per_cycle: None,
        }
    }

    #[test]
    fn upsert_and_get_roundtrip() {
        let db = temp_db("rt");
        let store = CohortStore::new(db);
        store.upsert(sample("coh_a")).unwrap();
        let got = store.get("coh_a").unwrap();
        assert_eq!(got.label, "Test cohort");
        assert_eq!(got.tenant_ids.len(), 3);
        assert_eq!(got.k_anonymity_threshold, 3);
    }

    #[test]
    fn upsert_replaces_existing() {
        let db = temp_db("replace");
        let store = CohortStore::new(db);
        store.upsert(sample("coh_a")).unwrap();
        let mut updated = sample("coh_a");
        updated.label = "Renamed".into();
        updated.tenant_ids.push("t4".into());
        store.upsert(updated).unwrap();
        let got = store.get("coh_a").unwrap();
        assert_eq!(got.label, "Renamed");
        assert_eq!(got.tenant_ids.len(), 4);
    }

    #[test]
    fn list_returns_sorted_definitions() {
        let db = temp_db("list");
        let store = CohortStore::new(db);
        store.upsert(sample("coh_z")).unwrap();
        store.upsert(sample("coh_a")).unwrap();
        store.upsert(sample("coh_m")).unwrap();
        let all = store.list();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].cohort_id, "coh_a");
        assert_eq!(all[1].cohort_id, "coh_m");
        assert_eq!(all[2].cohort_id, "coh_z");
    }

    #[test]
    fn delete_is_idempotent() {
        let db = temp_db("del");
        let store = CohortStore::new(db);
        store.upsert(sample("coh_a")).unwrap();
        store.delete("coh_a").unwrap();
        assert!(store.get("coh_a").is_none());
        // Deleting again is a no-op (idempotent contract).
        store.delete("coh_a").unwrap();
        store.delete("coh_never_existed").unwrap();
    }

    #[test]
    fn hydrate_restores_from_db() {
        let db = temp_db("hydrate");
        let store = CohortStore::new(Arc::clone(&db));
        store.upsert(sample("coh_a")).unwrap();
        store.upsert(sample("coh_b")).unwrap();

        let store2 = CohortStore::new(Arc::clone(&db));
        let n = store2.hydrate().unwrap();
        assert_eq!(n, 2);
        assert!(store2.get("coh_a").is_some());
        assert!(store2.get("coh_b").is_some());
    }

    #[test]
    fn validate_rejects_bad_inputs() {
        let mut def = sample("coh_a");
        def.epsilon_per_metric = 0.0;
        assert!(def.validate().is_err());
        let mut def = sample("coh_a");
        def.delta = 1.0;
        assert!(def.validate().is_err());
        let mut def = sample("coh_a");
        def.k_anonymity_threshold = 0;
        assert!(def.validate().is_err());
        let mut def = sample("coh_a");
        def.cohort_id = "".into();
        assert!(def.validate().is_err());
    }

    #[test]
    fn upsert_rejects_invalid_definition() {
        let db = temp_db("invalid");
        let store = CohortStore::new(db);
        let mut def = sample("coh_a");
        def.epsilon_per_metric = -1.0;
        let err = store.upsert(def).expect_err("must reject negative ε");
        match err {
            CohortError::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn deny_unknown_fields_on_json() {
        let json = r#"{
            "cohort_id": "x",
            "label": "x",
            "tenant_ids": [],
            "k_anonymity_threshold": 5,
            "epsilon_per_metric": 1.0,
            "delta": 1e-6,
            "rogue": true
        }"#;
        let r: Result<CohortDefinition, _> = serde_json::from_str(json);
        assert!(r.is_err(), "deny_unknown_fields must reject 'rogue'");
    }
}
