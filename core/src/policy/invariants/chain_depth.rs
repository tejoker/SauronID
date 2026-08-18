//! Chain-depth invariant.
//!
//! Denies any action whose `metadata.chain_depth` exceeds the configured
//! maximum. Distinct from `delegation_depth` (already a top-level
//! [`Action`] field counting sub-agent delegations): `chain_depth` counts
//! the length of the *agent call chain* leading to this action, e.g. how
//! many tool-call layers deep the agent's reasoning loop is.
//!
//! Reads `binding.max_chain_depth` and the per-action `chain_depth`
//! metadata field (`u64`). Use this to prevent runaway agent loops.

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Hard cap on agent-call chain depth (distinct from `delegation_depth`).
#[derive(Debug, Clone, Copy)]
pub struct ChainDepthCheck {
    max_chain_depth: u32,
}

impl ChainDepthCheck {
    /// Build from the configured cap.
    pub fn new(max_chain_depth: u32) -> Self {
        Self { max_chain_depth }
    }
}

impl RuntimeCheck for ChainDepthCheck {
    fn name(&self) -> &'static str {
        "chain_depth"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        // Absent → zero. See the metadata trust model in `super`: the server
        // writes this bag, so an absent key means the action is not part of a
        // call chain, not that the agent withheld its depth.
        let depth = ctx
            .action
            .metadata
            .get("chain_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if depth > self.max_chain_depth as u64 {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("chain_depth {depth} exceeds max {}", self.max_chain_depth),
            }
        } else {
            Verdict::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::invariants::Action;
    use serde_json::json;

    fn ctx<'a>(a: &'a Action) -> EvaluationContext<'a> {
        EvaluationContext::with_defaults(a)
    }

    fn action_with(depth: u64) -> Action {
        let mut a = Action::default();
        a.metadata.insert("chain_depth".into(), json!(depth));
        a
    }

    #[test]
    fn allows_under_cap() {
        let c = ChainDepthCheck::new(5);
        let a = action_with(2);
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_over_cap() {
        let c = ChainDepthCheck::new(5);
        let a = action_with(10);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_exact_cap() {
        let c = ChainDepthCheck::new(5);
        let a = action_with(5);
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn missing_depth_treated_as_zero() {
        let c = ChainDepthCheck::new(0);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }
}
