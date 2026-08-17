//! PII detection invariant.
//!
//! Denies any action that flags as containing PII. Reads
//! `binding.pii_block` and the per-action `pii_detected` metadata field.
//! Primary signal is the caller-provided `pii_detected: true` flag
//! (the SDK or a side-car detector populates this). As a defence in
//! depth, if `metadata.payload` is present and is a string, we also run
//! a STUB regex for obvious email/SSN patterns. The stub is documented
//! as best-effort — production deployments should rely on the caller's
//! flag.

use once_cell::sync::Lazy;
use regex::Regex;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Loose email regex — matches `<local>@<domain>.<tld>`. False-positive
/// rate is acceptable here because this is the fallback, not the
/// primary signal.
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b").expect("email regex compiles")
});

/// US-SSN regex — three digits, two digits, four digits separated by
/// dashes. We intentionally don't try to detect SSNs without dashes (too
/// many false positives against phone numbers / dates).
static SSN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex compiles"));

/// Block any action that contains PII.
///
/// Sprint 3 uses a hybrid signal: caller flag first, regex stub second.
/// A real DLP-grade detector (NER + IBAN/credit-card luhn/…) is deferred.
#[derive(Debug, Clone, Copy, Default)]
pub struct PiiDetectionCheck;

impl PiiDetectionCheck {
    /// Construct the check. No configuration — the binding's
    /// `pii_block: true` only controls whether the check is included.
    pub fn new() -> Self {
        Self
    }
}

impl RuntimeCheck for PiiDetectionCheck {
    fn name(&self) -> &'static str {
        "pii_detection"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        // The server sets this on the egress path from the same rules the
        // redactor uses, so `true` is a server observation, not an agent claim.
        // Absent means there was no payload to scan — see the metadata trust
        // model in `super`.
        if let Some(true) = ctx
            .action
            .metadata
            .get("pii_detected")
            .and_then(|v| v.as_bool())
        {
            return Verdict::Deny {
                check: self.name().to_string(),
                reason: "action.metadata.pii_detected is true".to_string(),
            };
        }
        // Fallback: best-effort regex on string payload. Documented STUB.
        if let Some(payload) = ctx.action.metadata.get("payload").and_then(|v| v.as_str()) {
            if EMAIL_RE.is_match(payload) {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: "payload contains email-like pattern".to_string(),
                };
            }
            if SSN_RE.is_match(payload) {
                return Verdict::Deny {
                    check: self.name().to_string(),
                    reason: "payload contains SSN-like pattern".to_string(),
                };
            }
        }
        Verdict::Allow
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

    #[test]
    fn denies_when_caller_flag_set() {
        let mut a = Action::default();
        a.metadata.insert("pii_detected".into(), json!(true));
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_when_caller_flag_false() {
        let mut a = Action::default();
        a.metadata.insert("pii_detected".into(), json!(false));
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_allow());
    }

    #[test]
    fn denies_on_email_pattern_in_payload() {
        let mut a = Action::default();
        a.metadata.insert(
            "payload".into(),
            json!("contact me at jane@example.com please"),
        );
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn denies_on_ssn_pattern_in_payload() {
        let mut a = Action::default();
        a.metadata
            .insert("payload".into(), json!("SSN 123-45-6789 forwarded"));
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_clean_payload() {
        let mut a = Action::default();
        a.metadata
            .insert("payload".into(), json!("nothing sensitive here"));
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_allow());
    }

    /// The regex backstop still catches a caller that claims `false` and ships an
    /// email anyway — the flag is a hint the server usually writes, not the last
    /// word.
    #[test]
    fn a_false_claim_is_still_checked_against_the_payload_body() {
        let mut a = Action::default();
        a.metadata.insert("pii_detected".into(), json!(false));
        a.metadata
            .insert("payload".into(), json!("reach me at jane@example.com"));
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_deny());
    }

    /// A caller that claims `false` but ships an email is still caught.
    #[test]
    fn a_false_claim_is_still_checked_against_the_payload() {
        let mut a = Action::default();
        a.metadata.insert("pii_detected".into(), json!(false));
        a.metadata
            .insert("payload".into(), json!("reach me at jane@example.com"));
        assert!(PiiDetectionCheck::new().evaluate(&ctx(&a)).is_deny());
    }
}
