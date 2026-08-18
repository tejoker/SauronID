//! Runtime invariant library for the policy DSL.
//!
//! Each invariant is a small struct implementing [`RuntimeCheck`]. The
//! [`compile`](super::compiler::compile) function turns a parsed [`Policy`](super::ast::Policy)
//! into a `Vec<Box<dyn RuntimeCheck>>`; the [`evaluate`](super::evaluator::evaluate)
//! function runs them in order against an [`EvaluationContext`].
//!
//! `DataFlowCheck` is a fail-closed sentinel until real taint tracking is
//! available. Free-form `invariants:` strings (e.g.
//! `"spend_total <= max_budget_usd"`) ARE compiled: `super::expressions` parses
//! them and `super::compiler` wraps each one in an `ExpressionCheck`.
//!
//! ## Who fills `Action.metadata`
//!
//! Several checks read their per-action signal from `metadata`, and whether an
//! absent key means "allow" or "deny" depends entirely on who writes the bag.
//! On every enforcement path the SERVER builds the `Action` — see
//! `super::handlers::gate_action_on_bound_policy` and its callers — so an absent
//! key means "this action has no such dimension" (a payment has no
//! `payload_bytes`; a sandboxed `file_read` has no `target_domain`), and reading
//! it as zero or not-applicable is correct. The one caller-authored `Action` is
//! `POST /v1/policy/evaluate`, which is admin-gated and explicitly a simulator.
//!
//! That is a load-bearing assumption, so it is written down here. A future route
//! that let an AGENT supply metadata would invert it: absence would then mean
//! "the constrained party declined to say", and every numeric cap in this module
//! would be waived by omission. Populate these keys server-side from what the
//! gateway observed — as `egress_gateway::agent_egress_proxy` does for
//! `target_domain`, `payload_bytes`, `content_type` and `pii_detected` — rather
//! than accepting them from the caller.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod allowlist;
pub mod budget;
pub mod business_hours;
pub mod chain_depth;
pub mod concurrency;
pub mod content_type_allowlist;
pub mod cooldown;
pub mod currency_allowlist;
pub mod daily_budget;
pub mod data_flow;
pub mod domain_allowlist;
pub mod domain_denylist;
pub mod dry_run;
pub mod geo_restriction;
pub mod holiday_blackout;
pub mod language_allowlist;
pub mod payload_size;
pub mod per_action_cap;
pub mod pii_detection;
pub mod rate;
pub mod recipient_count;
pub mod scope;
pub mod signature;
pub mod threshold;
pub mod time;
pub mod tool_denylist;
pub mod version_pin;
pub mod weekly_rate;

pub use allowlist::AllowlistCheck;
pub use budget::BudgetCheck;
pub use business_hours::BusinessHoursCheck;
pub use chain_depth::ChainDepthCheck;
pub use concurrency::ConcurrencyCheck;
pub use content_type_allowlist::ContentTypeCheck;
pub use cooldown::CooldownCheck;
pub use currency_allowlist::CurrencyAllowlistCheck;
pub use daily_budget::DailyBudgetCheck;
pub use data_flow::DataFlowCheck;
pub use domain_allowlist::DomainAllowlistCheck;
pub use domain_denylist::DomainDenylistCheck;
pub use dry_run::DryRunCheck;
pub use geo_restriction::GeoRestrictionCheck;
pub use holiday_blackout::HolidayBlackoutCheck;
pub use language_allowlist::LanguageAllowlistCheck;
pub use payload_size::PayloadSizeCheck;
pub use per_action_cap::PerActionCapCheck;
pub use pii_detection::PiiDetectionCheck;
pub use rate::RateCheck;
pub use recipient_count::RecipientCountCheck;
pub use scope::ScopeCheck;
pub use signature::SignatureCheck;
pub use threshold::ThresholdCheck;
pub use time::TimeCheck;
pub use tool_denylist::ToolDenylistCheck;
pub use version_pin::VersionPinCheck;
pub use weekly_rate::WeeklyRateCheck;

/// Trait implemented by every runtime invariant.
///
/// `name()` returns a static identifier used in deny verdicts and trace
/// output (`"budget"`, `"scope"`, etc.). `evaluate()` is pure and side
/// effect free — it only reads the supplied [`EvaluationContext`].
pub trait RuntimeCheck: Send + Sync + std::fmt::Debug {
    /// Stable identifier — used in `Verdict::Deny.check` and trace logs.
    fn name(&self) -> &'static str;

    /// Run the check. Returns [`Verdict::Allow`] when the action is
    /// permitted by this invariant, [`Verdict::Deny`] otherwise.
    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict;
}

/// Verdict returned by a single check or by the evaluator as a whole.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// The action is permitted (by this check, or by all checks).
    Allow,
    /// The action is denied. `check` identifies the invariant; `reason`
    /// is a human-readable explanation.
    Deny {
        /// Name of the invariant that produced the deny.
        check: String,
        /// Human-readable reason — safe to surface to operators.
        reason: String,
    },
}

impl Verdict {
    /// `true` if this verdict is `Verdict::Allow`.
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// `true` if this verdict is `Verdict::Deny { .. }`.
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny { .. })
    }
}

/// Read-only context handed to every [`RuntimeCheck::evaluate`].
///
/// Callers populate `spend_total_usd`, `recent_call_timestamps`,
/// `now_epoch`, and `now_tz_hhmm` from DB lookups or wall-clock reads
/// before invoking the evaluator. The action and computed context fields
/// are borrowed so the evaluator never allocates per call.
///
/// Sprint 3 added the following additive fields with safe defaults so
/// existing call sites can use `..Default::default()`:
/// - `daily_spend_usd` — running daily spend used by `DailyBudgetCheck`.
/// - `weekly_call_timestamps` — last 7-day call timestamps used by
///   `WeeklyRateCheck`.
/// - `in_flight_actions` — concurrent action count used by
///   `ConcurrencyCheck`.
/// - `last_action_at` — last action timestamp for `CooldownCheck`.
/// - `now_weekday` — 0=Sunday..6=Saturday for `BusinessHoursCheck`.
/// - `now_date_yyyy_mm_dd` — current date for `HolidayBlackoutCheck`.
#[derive(Debug)]
pub struct EvaluationContext<'a> {
    /// The action being evaluated.
    pub action: &'a Action,
    /// Running total spend (USD) for this policy/agent/period — fetched
    /// from DB by the caller.
    pub spend_total_usd: f64,
    /// Unix-epoch timestamps (seconds) of recent calls, used by [`RateCheck`].
    /// Caller may pass the last N timestamps.
    pub recent_call_timestamps: &'a [i64],
    /// Current unix-epoch seconds. Used as the rate-window upper bound.
    pub now_epoch: i64,
    /// `HH:MM` 24-hour wall-clock in the policy's timezone — precomputed
    /// by the caller so the evaluator stays timezone-agnostic.
    pub now_tz_hhmm: String,
    /// Daily rolling spend (USD), used by `DailyBudgetCheck`. Defaults to 0.
    pub daily_spend_usd: f64,
    /// Last 7-day call timestamps (seconds), used by `WeeklyRateCheck`.
    pub weekly_call_timestamps: &'a [i64],
    /// Currently-running action count, used by `ConcurrencyCheck`.
    pub in_flight_actions: u32,
    /// Unix epoch of the agent's previous action — used by `CooldownCheck`.
    pub last_action_at: Option<i64>,
    /// Current weekday — 0=Sunday, 1=Monday, …, 6=Saturday. Used by
    /// `BusinessHoursCheck` because `now_tz_hhmm` is time only.
    pub now_weekday: u8,
    /// Current date in `YYYY-MM-DD` form, used by `HolidayBlackoutCheck`.
    pub now_date_yyyy_mm_dd: String,
}

impl<'a> EvaluationContext<'a> {
    /// Build a context with the given `action` and safe defaults for the
    /// rest. Lets call sites that only care about one or two fields skip
    /// the `..Default::default()` dance while still benefiting from the
    /// additive Sprint 3 field expansion.
    pub fn with_defaults(action: &'a Action) -> Self {
        Self {
            action,
            spend_total_usd: 0.0,
            recent_call_timestamps: &[],
            now_epoch: 0,
            now_tz_hhmm: String::new(),
            daily_spend_usd: 0.0,
            weekly_call_timestamps: &[],
            in_flight_actions: 0,
            last_action_at: None,
            now_weekday: 0,
            now_date_yyyy_mm_dd: String::new(),
        }
    }
}

/// The action being evaluated.
///
/// One `Action` corresponds to a single tool invocation the agent wants
/// to make. Fields are all optional except `action_id` + `tool` because
/// not every invariant needs every field (a code-gen agent has no
/// monetary amount, a payment agent has no `data_classification`).
///
/// Sprint 3 adds an additive `metadata: HashMap<String, Value>` bag —
/// invariants such as `DomainAllowlistCheck`, `PayloadSizeCheck`, and
/// `PiiDetectionCheck` read their per-action signals from it. The bag is
/// flat: keys are stable strings (`target_domain`, `payload_bytes`,
/// `pii_detected`, …), values are arbitrary JSON. New invariants can
/// extend the key set without changing the [`Action`] struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct Action {
    /// Caller-supplied unique identifier (used in receipts + audit).
    pub action_id: String,
    /// Tool/method the agent wants to call (e.g. `http_get`,
    /// `sepa_payment_initiate`).
    pub tool: String,
    /// Monetary amount in USD if this action moves money. `None` for
    /// non-monetary actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_usd: Option<f64>,
    /// Data classification tag of the resource the action touches
    /// (`"pii"`, `"public"`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
    /// Roles that have signed this action (for M-of-N enforcement).
    #[serde(default)]
    pub signatures: Vec<String>,
    /// How many delegation hops separate this action from the root agent.
    #[serde(default)]
    pub delegation_depth: u32,
    /// Unix-epoch seconds when the action was created.
    pub timestamp: i64,
    /// Free-form metadata bag consumed by Sprint 3 invariants. See
    /// individual `*_check.rs` modules for the keys each reads.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}
