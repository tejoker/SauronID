//! Recipient-count invariant.
//!
//! Denies any action whose `metadata.recipient_count` exceeds the
//! configured maximum. Reads `binding.max_recipients` and the per-action
//! `recipient_count` metadata field (`u64` JSON number). Use this to cap
//! email/notification fanout per send (e.g. "agent may not BCC more than
//! 50 people").

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Maximum number of recipients allowed on a single action.
#[derive(Debug, Clone, Copy)]
pub struct RecipientCountCheck {
    max_recipients: u32,
}

impl RecipientCountCheck {
    /// Build from the configured cap.
    pub fn new(max_recipients: u32) -> Self {
        Self { max_recipients }
    }
}

impl RuntimeCheck for RecipientCountCheck {
    fn name(&self) -> &'static str {
        "recipient_count"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        let Some(n) = ctx
            .action
            .metadata
            .get("recipient_count")
            .and_then(|v| v.as_u64())
        else {
            // No recipient_count declared → treat as zero → allow. See the
            // metadata trust model in `super`.
            return Verdict::Allow;
        };
        if n > self.max_recipients as u64 {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("{} recipients exceeds max {}", n, self.max_recipients),
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

    fn action_with(n: u64) -> Action {
        let mut a = Action::default();
        a.metadata.insert("recipient_count".into(), json!(n));
        a
    }

    #[test]
    fn allows_under_max() {
        let c = RecipientCountCheck::new(50);
        let a = action_with(10);
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_over_max() {
        let c = RecipientCountCheck::new(50);
        let a = action_with(100);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_exact_max() {
        let c = RecipientCountCheck::new(50);
        let a = action_with(50);
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn missing_count_allows() {
        let c = RecipientCountCheck::new(50);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }
}
