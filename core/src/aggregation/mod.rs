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
//! The older `/v1/stats/submit` Circom/Groth16 path is gone: it was
//! development-only, quarantined by production startup, and its verifier is
//! archived under `archive/removed-2026-08/groth16-zkp/`. The DP cohort publish
//! surface that used to live beside this module is archived too. What remains is
//! the one production path the Python, TypeScript and Go SDKs actually call.

pub mod handlers;
pub mod store;
pub mod submission;

pub use store::{
    anchor_submission, get_one, persist_verified_submission, synthetic_action_hash,
    upsert_submission,
};
pub use submission::{AggError, StatsSubmitResponse, TransparentStatsSubmission};
