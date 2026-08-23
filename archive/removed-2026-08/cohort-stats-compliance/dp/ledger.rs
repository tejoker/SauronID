//! S8 extension — persistent per-cohort per-metric ε ledger.
//!
//! Closes the documented "No inter-period ε budget tracking" gap from
//! `docs/architecture/privacy-model.md`. Each publication checks the cohort's remaining
//! ε against a lifetime cap for the current regulatory cycle and refuses
//! publication when the budget is exhausted. Operators rotate (reset) the
//! budget per regulatory cycle through the
//! `POST /v1/cohort/:id/budget/rotate` endpoint.
//!
//! # Composition theorem
//!
//! Basic (sequential) composition by default — across N publications in
//! one cycle the privacy loss for one metric is bounded by
//! `Σ ε_i ≤ epsilon_cap`. Advanced composition (Dwork-Roth Thm 3.20)
//! would be tighter for large `k` but is unsafe here without per-history
//! tracking of every release; we keep basic composition for an honest,
//! conservative bound. RDP-based composition would be even tighter for
//! Gaussian fan-outs but is out of scope for the Laplace publication
//! pipeline.
//!
//! # Storage layout
//!
//! Two tables:
//! - `dp_budget_ledger(cohort_id, metric_id, cycle_start)` — running
//!   `(epsilon_spent, delta_spent)` plus the cycle's `(epsilon_cap,
//!   delta_cap)` and `last_published` timestamp.
//! - `dp_budget_publications(publication_id …)` — append-only audit trail
//!   of every published metric: ε spent, δ spent, noise scale, timestamp.
//!
//! Schema lives in `core/src/db.rs::init_schema` (SQLite) and
//! `migrations/postgres/0009_dp_budget_ledger.sql` (Postgres).

use crate::any_db::AnyRowGet;
use crate::sql_params;
use std::sync::Arc;

use crate::db::DbHandle;

/// One row from `dp_budget_ledger`. Surfaced through
/// [`DpBudgetLedger::get_ledger`] and the
/// `GET /v1/cohort/:id/budget` HTTP endpoint.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Cohort id.
    pub cohort_id: String,
    /// Metric id (e.g. `success_rate`, `latency_ms`).
    pub metric_id: String,
    /// Unix-epoch seconds — cycle start boundary.
    pub cycle_start: i64,
    /// ε already charged across all publications in this cycle.
    pub epsilon_spent: f64,
    /// δ already charged across all publications in this cycle.
    pub delta_spent: f64,
    /// Lifetime ε cap for this cycle. Operator-set on rotate (or
    /// derived from `CohortDefinition::effective_epsilon_cap_per_cycle`
    /// on first publication in the cycle).
    pub epsilon_cap: f64,
    /// Lifetime δ cap for this cycle.
    pub delta_cap: f64,
    /// Unix-epoch seconds of the latest publication into this row.
    /// `0` for a freshly-rotated cycle with no publications yet.
    pub last_published: i64,
}

/// Outcome of a `can_publish` check.
///
/// `Approved` carries the ε remaining AFTER this charge would land (so
/// callers can surface the headroom in their `privacy_notice`).
/// `Denied` carries the operator-visible reason plus the spent / cap so
/// the response body can explain why the metric is now suppressed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum BudgetDecision {
    /// ε is available — proceed with the publication. `remaining_eps`
    /// is the headroom AFTER charging `requested_eps`.
    Approved {
        /// ε remaining in the current cycle after this charge.
        remaining_eps: f64,
    },
    /// ε is exhausted (or δ would exceed cap). Caller should mark the
    /// metric `suppressed: true` and skip the noise step.
    Denied {
        /// Human-readable reason — already substituted into the
        /// publication's privacy notice.
        reason: String,
        /// ε already spent in this cycle.
        used: f64,
        /// Lifetime cap for this cycle.
        cap: f64,
    },
}

/// Errors emitted by [`DpBudgetLedger`] operations.
#[derive(Debug, Clone, PartialEq)]
pub enum LedgerError {
    /// Validation failure on inputs (e.g. negative ε / δ, empty id).
    Invalid(String),
    /// Backend storage failure.
    Storage(String),
    /// Lock poisoning — should never happen.
    Lock,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Invalid(s) => write!(f, "invalid ledger input: {s}"),
            LedgerError::Storage(s) => write!(f, "ledger storage: {s}"),
            LedgerError::Lock => write!(f, "ledger db lock poisoned"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Persistent per-cohort per-metric ε ledger.
///
/// Holds an `Arc<DbHandle>` to the SQLite store; every operation is
/// short-lived and atomic. Postgres-backed callers should construct the
/// ledger on the same `Arc<DbHandle>` and the underlying schema (see
/// `migrations/postgres/0009_dp_budget_ledger.sql`) mirrors the SQLite
/// table layout.
///
/// All public methods are `&self`-receivers so the ledger can sit behind
/// `Arc` and be shared across the axum handler set without contention.
#[derive(Clone)]
pub struct DpBudgetLedger {
    db: Arc<DbHandle>,
}

impl std::fmt::Debug for DpBudgetLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpBudgetLedger").finish()
    }
}

impl DpBudgetLedger {
    /// Construct a ledger handle. No I/O happens until a method is called.
    pub fn new(db: Arc<DbHandle>) -> Self {
        Self { db }
    }

    /// Ensure a `(cohort_id, metric_id, cycle_start)` ledger row exists
    /// with the given caps. Idempotent — if the row already exists, the
    /// caps are NOT overwritten (rotating caps is the explicit
    /// [`Self::rotate_cycle`] operation; quietly tightening or relaxing
    /// during a cycle would silently shift the privacy envelope).
    ///
    /// Atomic under `BEGIN IMMEDIATE` (SQLite single-writer lock).
    pub fn ensure_cycle(
        &self,
        cohort_id: &str,
        metric_id: &str,
        cycle_start: i64,
        epsilon_cap: f64,
        delta_cap: f64,
    ) -> Result<(), LedgerError> {
        validate_inputs(cohort_id, metric_id, epsilon_cap, delta_cap, cycle_start)?;
        let mut conn = self
            .db
            .lock()
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        // SQLite INSERT OR IGNORE is atomic. The row stays exactly as it
        // was on the first insert; subsequent ensure_cycle calls with
        // different caps are silently a no-op (operator must explicitly
        // call rotate_cycle to change caps).
        conn.any_conn()
            .execute(
                "INSERT OR IGNORE INTO dp_budget_ledger
               (cohort_id, metric_id, cycle_start,
                epsilon_spent, delta_spent,
                epsilon_cap, delta_cap, last_published)
             VALUES (?1, ?2, ?3, 0, 0, ?4, ?5, 0)",
                sql_params![
                    &cohort_id,
                    &metric_id,
                    &cycle_start,
                    &epsilon_cap,
                    &delta_cap
                ],
            )
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Check whether `requested_eps` (and `requested_delta`) fit under
    /// the cohort's lifetime budget for the current cycle. Does NOT
    /// modify the ledger — pair with [`Self::record_publication`] to
    /// actually charge.
    ///
    /// Returns [`BudgetDecision::Approved`] with the post-charge headroom
    /// if the request fits, or [`BudgetDecision::Denied`] with a human
    /// reason + spent / cap snapshot when the request would exceed the
    /// cap. Missing-row case: treated as Approved against a zero-spend
    /// ledger (caller is expected to have already called
    /// [`Self::ensure_cycle`]).
    pub fn can_publish(
        &self,
        cohort_id: &str,
        metric_id: &str,
        cycle_start: i64,
        requested_eps: f64,
        requested_delta: f64,
    ) -> Result<BudgetDecision, LedgerError> {
        if !requested_eps.is_finite() || requested_eps < 0.0 {
            return Err(LedgerError::Invalid(format!(
                "requested_eps must be >= 0 and finite, got {requested_eps}"
            )));
        }
        if !requested_delta.is_finite() || requested_delta < 0.0 {
            return Err(LedgerError::Invalid(format!(
                "requested_delta must be >= 0 and finite, got {requested_delta}"
            )));
        }
        let mut conn = self
            .db
            .lock()
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        let row: Option<(f64, f64, f64, f64)> = conn
            .any_conn()
            .query_row(
                "SELECT epsilon_spent, delta_spent, epsilon_cap, delta_cap
                 FROM dp_budget_ledger
                 WHERE cohort_id = ?1 AND metric_id = ?2 AND cycle_start = ?3",
                sql_params![&cohort_id, &metric_id, &cycle_start],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        // Missing row → treat as fresh slate. Caller should still have
        // called ensure_cycle so this branch is a defensive belt.
        let (spent_eps, spent_delta, cap_eps, cap_delta) =
            row.unwrap_or((0.0, 0.0, f64::INFINITY, f64::INFINITY));
        let new_eps = spent_eps + requested_eps;
        let new_delta = spent_delta + requested_delta;
        if new_eps > cap_eps {
            return Ok(BudgetDecision::Denied {
                reason: format!(
                    "epsilon budget exhausted for this cycle (cap={cap_eps:.6}, would spend {new_eps:.6})"
                ),
                used: spent_eps,
                cap: cap_eps,
            });
        }
        if new_delta > cap_delta {
            return Ok(BudgetDecision::Denied {
                reason: format!(
                    "delta budget exhausted for this cycle (cap={cap_delta:.6e}, would spend {new_delta:.6e})"
                ),
                used: spent_delta,
                cap: cap_delta,
            });
        }
        Ok(BudgetDecision::Approved {
            remaining_eps: cap_eps - new_eps,
        })
    }

    /// Charge `(eps, delta)` against `(cohort_id, metric_id, cycle_start)`,
    /// recording a `dp_budget_publications` row with the noise scale and
    /// timestamp. Returns the freshly-minted `publication_id`.
    ///
    /// SQLite path runs under `BEGIN IMMEDIATE TRANSACTION` so the
    /// read-modify-write of `epsilon_spent` is atomic against concurrent
    /// publications. Postgres callers should layer SERIALIZABLE on top
    /// (out of scope for this S8 ext — single-writer SQLite is the
    /// shipping backend).
    ///
    /// Caller MUST have already called [`Self::can_publish`] and
    /// [`Self::ensure_cycle`]. This method does NOT re-check the cap;
    /// it is the explicit charge step.
    pub fn record_publication(
        &self,
        cohort_id: &str,
        metric_id: &str,
        cycle_start: i64,
        eps: f64,
        delta: f64,
        noise_scale: f64,
    ) -> Result<String, LedgerError> {
        if !eps.is_finite() || eps < 0.0 {
            return Err(LedgerError::Invalid(format!(
                "eps must be >= 0 and finite, got {eps}"
            )));
        }
        if !delta.is_finite() || delta < 0.0 {
            return Err(LedgerError::Invalid(format!(
                "delta must be >= 0 and finite, got {delta}"
            )));
        }
        if !noise_scale.is_finite() || noise_scale < 0.0 {
            return Err(LedgerError::Invalid(format!(
                "noise_scale must be >= 0 and finite, got {noise_scale}"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let publication_id = new_publication_id();

        let mut conn = self
            .db
            .lock()
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        // Statements rather than `AnyConn::transaction`: that helper fixes the
        // error type to `String`, which would flatten `LedgerError::Invalid`
        // ("budget exceeded") into `Storage` and lose the distinction callers
        // map to a status code. `sql_translate` rewrites the BEGIN for
        // Postgres, where it is READ COMMITTED — safe here because the cap
        // guard is inside the UPDATE's WHERE clause, so the row lock does the
        // serialising, not the isolation level.
        conn.any_conn()
            .execute("BEGIN IMMEDIATE TRANSACTION", &[])
            .map_err(|e| LedgerError::Storage(format!("begin immediate: {e}")))?;

        let txn_res = (|| -> Result<(), LedgerError> {
            // Ensure the ledger row exists. Defensive — we cannot charge
            // against a row that does not exist, otherwise the FK on
            // dp_budget_publications would fail.
            let exists: Option<i64> = conn
                .any_conn()
                .query_row(
                    "SELECT 1 FROM dp_budget_ledger
                     WHERE cohort_id = ?1 AND metric_id = ?2 AND cycle_start = ?3",
                    sql_params![&cohort_id, &metric_id, &cycle_start],
                    |r| r.get(0),
                )
                .map_err(|e| LedgerError::Storage(e.to_string()))?;
            if exists.is_none() {
                return Err(LedgerError::Invalid(format!(
                    "ledger row missing for ({cohort_id}, {metric_id}, {cycle_start}); call ensure_cycle first"
                )));
            }
            // Atomic check-AND-charge: the cap guard lives in the WHERE clause,
            // inside this BEGIN IMMEDIATE txn. `can_publish` is only advisory —
            // two concurrent publishes could both pass it and then overspend.
            // Here the increment applies ONLY if it stays within cap; 0 rows
            // affected ⇒ the charge would exceed the budget, so reject + roll back.
            let charged = conn
                .any_conn()
                .execute(
                    "UPDATE dp_budget_ledger
                     SET epsilon_spent = epsilon_spent + ?4,
                         delta_spent   = delta_spent   + ?5,
                         last_published = ?6
                     WHERE cohort_id = ?1 AND metric_id = ?2 AND cycle_start = ?3
                       AND epsilon_spent + ?4 <= epsilon_cap
                       AND delta_spent   + ?5 <= delta_cap",
                    sql_params![&cohort_id, &metric_id, &cycle_start, &eps, &delta, &now],
                )
                .map_err(|e| LedgerError::Storage(e.to_string()))?;
            if charged == 0 {
                return Err(LedgerError::Invalid(format!(
                    "budget exceeded: charging eps={eps}/delta={delta} would exceed the cohort cap for cycle {cycle_start} (concurrent publish or stale can_publish)"
                )));
            }
            conn.any_conn()
                .execute(
                    "INSERT INTO dp_budget_publications
                   (publication_id, cohort_id, metric_id, cycle_start,
                    epsilon, delta, noise_scale, published_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    sql_params![
                        &publication_id,
                        &cohort_id,
                        &metric_id,
                        &cycle_start,
                        &eps,
                        &delta,
                        &noise_scale,
                        &now,
                    ],
                )
                .map_err(|e| LedgerError::Storage(e.to_string()))?;
            Ok(())
        })();

        match txn_res {
            Ok(()) => {
                conn.any_conn()
                    .execute("COMMIT", &[])
                    .map_err(|e| LedgerError::Storage(format!("commit: {e}")))?;
                Ok(publication_id)
            }
            Err(e) => {
                let _ = conn.any_conn().execute("ROLLBACK", &[]);
                Err(e)
            }
        }
    }

    /// Rotate the cycle: create a fresh `(cohort_id, metric_id,
    /// new_cycle_start)` row with the supplied caps and zero spend.
    /// Idempotent on the new cycle_start — re-rotating to the same key
    /// is a no-op for the spend (caps are reset to the new values).
    ///
    /// This is the operator-triggered regulatory reset (typically end of
    /// quarter). The prior cycle's row is left in place as an audit
    /// trail; query it via [`Self::get_ledger`].
    pub fn rotate_cycle(
        &self,
        cohort_id: &str,
        metric_id: &str,
        new_cycle_start: i64,
        new_eps_cap: f64,
        new_delta_cap: f64,
    ) -> Result<(), LedgerError> {
        validate_inputs(
            cohort_id,
            metric_id,
            new_eps_cap,
            new_delta_cap,
            new_cycle_start,
        )?;
        let mut conn = self
            .db
            .lock()
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        // ON CONFLICT: re-rotating to the same key resets caps but
        // preserves the spend column (so an operator who accidentally
        // calls rotate twice for the same cycle_start cannot wipe
        // existing publications' privacy accounting).
        conn.any_conn()
            .execute(
                "INSERT INTO dp_budget_ledger
               (cohort_id, metric_id, cycle_start,
                epsilon_spent, delta_spent,
                epsilon_cap, delta_cap, last_published)
             VALUES (?1, ?2, ?3, 0, 0, ?4, ?5, 0)
             ON CONFLICT(cohort_id, metric_id, cycle_start) DO UPDATE SET
               epsilon_cap = excluded.epsilon_cap,
               delta_cap   = excluded.delta_cap",
                sql_params![
                    &cohort_id,
                    &metric_id,
                    &new_cycle_start,
                    &new_eps_cap,
                    &new_delta_cap,
                ],
            )
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Fetch every ledger row for one cohort, ordered by `cycle_start`
    /// ascending then `metric_id` ascending. Surfaced through
    /// `GET /v1/cohort/:id/budget`.
    pub fn get_ledger(&self, cohort_id: &str) -> Result<Vec<LedgerEntry>, LedgerError> {
        if cohort_id.trim().is_empty() {
            return Err(LedgerError::Invalid("cohort_id empty".into()));
        }
        let mut conn = self
            .db
            .lock()
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        let rows = conn
            .any_conn()
            .query_map(
                "SELECT cohort_id, metric_id, cycle_start,
                        epsilon_spent, delta_spent,
                        epsilon_cap, delta_cap, last_published
                 FROM dp_budget_ledger
                 WHERE cohort_id = ?1
                 ORDER BY cycle_start ASC, metric_id ASC",
                sql_params![&cohort_id],
                |r| {
                    Ok(LedgerEntry {
                        cohort_id: r.get(0)?,
                        metric_id: r.get(1)?,
                        cycle_start: r.get(2)?,
                        epsilon_spent: r.get(3)?,
                        delta_spent: r.get(4)?,
                        epsilon_cap: r.get(5)?,
                        delta_cap: r.get(6)?,
                        last_published: r.get(7)?,
                    })
                },
            )
            .map_err(|e| LedgerError::Storage(e.to_string()))?;
        Ok(rows)
    }
}

fn validate_inputs(
    cohort_id: &str,
    metric_id: &str,
    epsilon_cap: f64,
    delta_cap: f64,
    cycle_start: i64,
) -> Result<(), LedgerError> {
    if cohort_id.trim().is_empty() {
        return Err(LedgerError::Invalid("cohort_id empty".into()));
    }
    if metric_id.trim().is_empty() {
        return Err(LedgerError::Invalid("metric_id empty".into()));
    }
    if cycle_start < 0 {
        return Err(LedgerError::Invalid(format!(
            "cycle_start must be >= 0, got {cycle_start}"
        )));
    }
    if !epsilon_cap.is_finite() || epsilon_cap <= 0.0 {
        return Err(LedgerError::Invalid(format!(
            "epsilon_cap must be > 0 and finite, got {epsilon_cap}"
        )));
    }
    if !delta_cap.is_finite() || !(0.0..1.0).contains(&delta_cap) {
        return Err(LedgerError::Invalid(format!(
            "delta_cap must be in [0, 1) and finite, got {delta_cap}"
        )));
    }
    Ok(())
}

/// Generate a fresh publication id — 32 hex chars from 16 random bytes.
/// Format: `pub_<hex>` so logs scan visually.
fn new_publication_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("pub_{}", hex::encode(bytes))
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
        let path = std::env::temp_dir().join(format!("sauron-ledger-{pid}-{nanos}-{label}.db"));
        let _ = std::fs::remove_file(&path);
        Arc::new(open_db_at(path.to_str().unwrap(), 2))
    }

    #[test]
    fn ensure_cycle_is_idempotent() {
        let db = temp_db("ensure_idem");
        let ledger = DpBudgetLedger::new(db);
        ledger
            .ensure_cycle("coh_a", "success_rate", 1_700_000_000, 4.0, 1e-5)
            .unwrap();
        // Re-calling with different caps must NOT overwrite (use rotate
        // explicitly for that — silently shifting the cap mid-cycle
        // would invalidate the privacy envelope).
        ledger
            .ensure_cycle("coh_a", "success_rate", 1_700_000_000, 999.0, 0.9)
            .unwrap();
        let rows = ledger.get_ledger("coh_a").unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            (rows[0].epsilon_cap - 4.0).abs() < 1e-12,
            "cap must not drift"
        );
    }

    #[test]
    fn record_publication_atomically_rejects_over_cap_charge() {
        // Regression: check (can_publish) and charge (record_publication) were
        // separate, so two concurrent publishes could both pass the check and
        // overspend. record_publication now charges only within cap.
        let db = temp_db("atomic_charge");
        let ledger = DpBudgetLedger::new(db);
        ledger.ensure_cycle("coh_a", "m", 0, 1.0, 1e-5).unwrap();
        // First charge to the cap succeeds.
        ledger
            .record_publication("coh_a", "m", 0, 1.0, 1e-7, 4.0)
            .unwrap();
        // A second charge (simulating a racing request that also passed
        // can_publish against zero spend) must be rejected — not overspend.
        let second = ledger.record_publication("coh_a", "m", 0, 0.5, 1e-7, 4.0);
        assert!(
            second.is_err(),
            "over-cap charge must be rejected atomically"
        );
        // Cap is fully consumed — any further request is denied (no overspend).
        match ledger.can_publish("coh_a", "m", 0, 0.0001, 0.0).unwrap() {
            BudgetDecision::Denied { .. } => {}
            other => panic!("expected Denied after cap consumed, got {other:?}"),
        }
    }

    #[test]
    fn can_publish_approves_below_cap() {
        let db = temp_db("approve");
        let ledger = DpBudgetLedger::new(db);
        ledger
            .ensure_cycle("coh_a", "success_rate", 0, 4.0, 1e-5)
            .unwrap();
        let dec = ledger
            .can_publish("coh_a", "success_rate", 0, 1.0, 1e-7)
            .unwrap();
        match dec {
            BudgetDecision::Approved { remaining_eps } => {
                assert!((remaining_eps - 3.0).abs() < 1e-12);
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    #[test]
    fn can_publish_denies_at_cap() {
        let db = temp_db("deny");
        let ledger = DpBudgetLedger::new(db);
        ledger
            .ensure_cycle("coh_a", "success_rate", 0, 1.0, 1e-5)
            .unwrap();
        // Spend the whole budget.
        ledger
            .record_publication("coh_a", "success_rate", 0, 1.0, 1e-7, 4.0)
            .unwrap();
        // Next request must be denied.
        let dec = ledger
            .can_publish("coh_a", "success_rate", 0, 0.5, 1e-7)
            .unwrap();
        match dec {
            BudgetDecision::Denied { reason, used, cap } => {
                assert!(reason.contains("epsilon"), "reason should mention epsilon");
                assert!((used - 1.0).abs() < 1e-12);
                assert!((cap - 1.0).abs() < 1e-12);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn record_publication_updates_spent() {
        let db = temp_db("record");
        let ledger = DpBudgetLedger::new(db);
        ledger
            .ensure_cycle("coh_a", "success_rate", 0, 4.0, 1e-5)
            .unwrap();
        ledger
            .record_publication("coh_a", "success_rate", 0, 1.0, 1e-7, 4.0)
            .unwrap();
        ledger
            .record_publication("coh_a", "success_rate", 0, 0.5, 1e-7, 4.0)
            .unwrap();
        let rows = ledger.get_ledger("coh_a").unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            (rows[0].epsilon_spent - 1.5).abs() < 1e-12,
            "spent {} should be 1.5",
            rows[0].epsilon_spent
        );
        assert!(rows[0].last_published > 0, "last_published should be set");
    }

    #[test]
    fn rotate_cycle_creates_new_entry() {
        let db = temp_db("rotate");
        let ledger = DpBudgetLedger::new(db);
        ledger
            .ensure_cycle("coh_a", "success_rate", 0, 1.0, 1e-5)
            .unwrap();
        ledger
            .record_publication("coh_a", "success_rate", 0, 1.0, 1e-7, 4.0)
            .unwrap();
        // Rotate to a new cycle start with a fresh cap.
        ledger
            .rotate_cycle("coh_a", "success_rate", 7_776_000, 2.0, 1e-5)
            .unwrap();
        let rows = ledger.get_ledger("coh_a").unwrap();
        // Two cycle rows now: the exhausted one and the fresh one.
        assert_eq!(rows.len(), 2);
        let fresh = rows.iter().find(|r| r.cycle_start == 7_776_000).unwrap();
        assert_eq!(fresh.epsilon_spent, 0.0, "fresh cycle starts at zero");
        assert!((fresh.epsilon_cap - 2.0).abs() < 1e-12);
        // The fresh cycle can publish again.
        let dec = ledger
            .can_publish("coh_a", "success_rate", 7_776_000, 1.0, 1e-7)
            .unwrap();
        assert!(matches!(dec, BudgetDecision::Approved { .. }));
    }

    #[test]
    fn record_publication_without_ensure_fails() {
        let db = temp_db("missing");
        let ledger = DpBudgetLedger::new(db);
        let err = ledger
            .record_publication("coh_missing", "m", 0, 1.0, 1e-7, 4.0)
            .expect_err("must fail without ensure_cycle");
        match err {
            LedgerError::Invalid(m) => assert!(m.contains("ensure_cycle")),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_inputs() {
        let db = temp_db("invalid");
        let ledger = DpBudgetLedger::new(db);
        // Empty cohort_id.
        assert!(ledger.ensure_cycle("", "m", 0, 1.0, 1e-7).is_err());
        // Non-finite epsilon_cap.
        assert!(ledger.ensure_cycle("coh", "m", 0, f64::NAN, 1e-7).is_err());
        // δ ≥ 1.
        assert!(ledger.ensure_cycle("coh", "m", 0, 1.0, 1.0).is_err());
        // can_publish with NaN.
        ledger.ensure_cycle("coh", "m", 0, 1.0, 1e-7).unwrap();
        assert!(ledger.can_publish("coh", "m", 0, f64::NAN, 0.0).is_err());
    }
}
