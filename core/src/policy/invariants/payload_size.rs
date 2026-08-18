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
        let Some(bytes) = ctx
            .action
            .metadata
            .get("payload_bytes")
            .and_then(|v| v.as_u64())
        else {
            // No payload declared → treat as zero-byte → allow. Safe because the
            // SERVER writes this bag on every enforcement path (see the trust
            // model in `super`), so an absent key means "this action has no
            // payload", not "the agent declined to say".
            return Verdict::Allow;
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

    /// Absent means "no payload", which is a server observation on every
    /// enforcement path — a payment action legitimately has none, and a policy
    /// that also carries a payload cap must not deny it for that.
    #[test]
    fn missing_payload_allows() {
        let c = PayloadSizeCheck::new(1024);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }
}
