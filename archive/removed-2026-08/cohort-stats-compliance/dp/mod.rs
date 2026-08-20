//! Differential privacy primitives for cross-customer benchmark publication.
//!
//! # Formal model
//!
//! A randomised mechanism `M` is `(ε, δ)`-differentially private if for all
//! neighboring databases `D` and `D'` (differing in one record) and all
//! measurable output sets `S`:
//!
//! ```text
//!   Pr[M(D) ∈ S] ≤ exp(ε) · Pr[M(D') ∈ S] + δ
//! ```
//!
//! `ε` is the privacy-loss budget (smaller = more private). `δ` is the
//! probability the bound fails (typically `δ ≪ 1/n`). Mechanisms in this
//! module add calibrated noise to query outputs to satisfy this property.
//! Composition theorems bound total privacy loss across multiple queries.
//!
//! Source: Dwork & Roth, *The Algorithmic Foundations of Differential
//! Privacy*, 2014.

pub mod budget;
pub mod composition;
pub mod gaussian;
pub mod k_anonymity;
pub mod laplace;
pub mod ledger;

pub use budget::{EpsilonBudget, EpsilonChargeEntry};
pub use composition::{advanced_composition, basic_composition, RdpAccountant};
pub use gaussian::GaussianMechanism;
pub use k_anonymity::{cohort_membership_count, suppress_small_cohorts, DEFAULT_K_THRESHOLD};
pub use laplace::LaplaceMechanism;
pub use ledger::{BudgetDecision, DpBudgetLedger, LedgerEntry, LedgerError};

/// Errors produced by the DP primitives.
#[derive(Debug, Clone, PartialEq)]
pub enum DpError {
    InvalidEpsilon(f64),
    InvalidDelta(f64),
    InvalidSensitivity(f64),
    NonFinite,
    BudgetExhausted {
        needed_epsilon: f64,
        available_epsilon: f64,
    },
    Composition(String),
}

impl std::fmt::Display for DpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpError::InvalidEpsilon(v) => write!(f, "epsilon must be > 0, got {}", v),
            DpError::InvalidDelta(v) => write!(f, "delta must be in (0,1), got {}", v),
            DpError::InvalidSensitivity(v) => {
                write!(f, "sensitivity must be >= 0, got {}", v)
            }
            DpError::NonFinite => write!(f, "non-finite value"),
            DpError::BudgetExhausted {
                needed_epsilon,
                available_epsilon,
            } => write!(
                f,
                "epsilon budget exhausted: needed {}, available {}",
                needed_epsilon, available_epsilon
            ),
            DpError::Composition(msg) => write!(f, "composition error: {}", msg),
        }
    }
}

impl std::error::Error for DpError {}
