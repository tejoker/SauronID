//! Customer-side stat aggregation + transparent proof integrity.
//!
//! Wire flow:
//!
//! ```text
//!   SDK (agentic)                      Server (this module)
//!   ───────────────────                ──────────────────────
//!   collect complete v2 batch          /v1/stats/submit-transparent
//!   compute one reviewed metric        │
//!   prove reviewed STARK metric        ├─► transparent_proof verifier
//!   POST {statement, receipt} ────────►│      • native receipt + image ID
//!                                      │      • exact journal/body binding
//!                                      │      • authoritative checkpoint
//!                                      ├─► store::upsert_submission
//!                                      │      • idempotent INSERT
//!                                      ├─► store::anchor_submission
//!                                      │      • dedicated statement digest
//!                                      └─► returns {stored, latency_ms,
//!                                                  statement_hash}
//! ```
//!
//! The older `/v1/stats/submit` Circom/Groth16 path remains development-only
//! compatibility and is quarantined by production startup.
//!
//! Documentation: `docs/stats-submission.md`.

pub mod cohorts;
pub mod handlers;
pub mod publish;
pub mod store;
pub mod submission;
pub mod verify;

pub use cohorts::{CohortDefinition, CohortError, CohortStore, DEFAULT_CYCLE_SECONDS};
pub use publish::{
    publish_cohort, publish_cohort_with_ledger, PrivacyNotice, PublishError, PublishedCohort,
    PublishedMetric, QUARTILE_SENSITIVITY,
};
pub use store::{
    anchor_submission, get_one, list_cohort, list_for_cohort, persist_verified_submission,
    synthetic_action_hash, upsert_submission,
};
pub use submission::{CohortRow, StatsSubmission, StatsSubmitResponse};
pub use verify::{stats_scope_hash, verify_stats_submission, AggError, PROVABLE_METRICS};
