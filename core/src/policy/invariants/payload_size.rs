//! Payload-size invariant.
//!
//! Denies any action whose `metadata.payload_bytes` exceeds the configured
//! maximum. Reads `binding.max_payload_bytes` and the per-action
//! `payload_bytes` metadata field (`u64` JSON number). Use this to cap
//! how much data an agent can push in one request (e.g. file uploads,
//! email attachments, code-gen output).

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Maximum payload size in bytes.
#[derive(Debug, Clone, Copy)]
pub struct PayloadSizeCheck {
    max_bytes: u64,
}

impl PayloadSizeCheck {
    /// Build from the configured cap.
    pub fn new(max_bytes: u64) -> Self {
        Self { max_bytes }
    }
}

impl RuntimeCheck for PayloadSizeCheck {
    fn name(&self) -> &'static str {
        "payload_size"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        // Fail closed: an action that does not declare its size cannot show it
        // is under the cap. "Undeclared means zero" let the constrained party
        // waive the constraint by omission.
        let bytes = match ctx.require_u64("payload_bytes", "payload_size") {
            Ok(v) => v,
            Err(deny) => return deny,
        };
        if bytes > self.max_bytes {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("payload {bytes} bytes exceeds max {} bytes", self.max_bytes),
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

    fn action_with_bytes(b: u64) -> Action {
        let mut a = Action::default();
        a.metadata.insert("payload_bytes".into(), json!(b));
        a
    }

    #[test]
    fn allows_under_max() {
        let c = PayloadSizeCheck::new(1024);
        let a = action_with_bytes(512);
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_over_max() {
        let c = PayloadSizeCheck::new(1024);
        let a = action_with_bytes(2048);
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_exact_max() {
        let c = PayloadSizeCheck::new(1024);
        let a = action_with_bytes(1024);
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    /// The fail-open this check used to have: an action that never mentioned
    /// `payload_bytes` satisfied every payload cap, so the cheapest way past the
    /// gate was to omit the field it measures.
    #[test]
    fn an_undeclared_payload_is_denied_not_treated_as_zero() {
        let c = PayloadSizeCheck::new(1024);
        let a = Action::default();
        let v = c.evaluate(&ctx(&a));
        assert!(v.is_deny(), "undeclared payload must not satisfy the cap");
        if let Verdict::Deny { reason, check } = v {
            assert_eq!(check, "payload_size");
            assert!(
                reason.contains("payload_bytes"),
                "deny must name the missing key: {reason}"
            );
        }
    }
}
