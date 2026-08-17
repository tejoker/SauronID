//! Domain denylist invariant.
//!
//! Denies any action whose `metadata.target_domain` is in the configured
//! denylist. Reads `binding.domain_denylist` and the per-action
//! `target_domain` metadata field. Use this to enforce hard blocks on
//! known-bad hosts (`competitor.com`, internal-only domains, …). Pairs
//! cleanly with `DomainAllowlistCheck` — denylist runs first by
//! convention but both produce independent verdicts.

use std::collections::HashSet;

use super::{EvaluationContext, RuntimeCheck, Verdict};

/// Outbound-domain denylist. Action denied if `target_domain` matches any
/// configured entry. Missing target domain is treated as allow (only the
/// allowlist check is responsible for the "must declare" semantic).
#[derive(Debug, Clone)]
pub struct DomainDenylistCheck {
    domains: HashSet<String>,
}

impl DomainDenylistCheck {
    /// Build from a list of denied domains. Comparison is case-insensitive
    /// — we lowercase at construction.
    pub fn new(domains: Vec<String>) -> Self {
        Self {
            domains: domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl RuntimeCheck for DomainDenylistCheck {
    fn name(&self) -> &'static str {
        "domain_denylist"
    }

    fn evaluate(&self, ctx: &EvaluationContext) -> Verdict {
        // Fail closed. A denylist cannot clear an action whose destination it
        // was never told — and the sibling `domain_allowlist` check already
        // denies on the same missing field, so allowing here was inconsistent
        // as well as unsafe.
        let raw = match ctx.require_str("target_domain", "domain_denylist") {
            Ok(v) => v,
            Err(deny) => return deny,
        };
        let tag = raw.to_ascii_lowercase();
        if self.domains.contains(&tag) {
            Verdict::Deny {
                check: self.name().to_string(),
                reason: format!("domain '{tag}' is on deny list"),
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

    fn action_with(domain: Option<&str>) -> Action {
        let mut a = Action::default();
        if let Some(d) = domain {
            a.metadata.insert("target_domain".into(), json!(d));
        }
        a
    }

    #[test]
    fn denies_when_in_list() {
        let c = DomainDenylistCheck::new(vec!["competitor.com".into()]);
        let a = action_with(Some("competitor.com"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn allows_when_not_in_list() {
        let c = DomainDenylistCheck::new(vec!["competitor.com".into()]);
        let a = action_with(Some("partner.com"));
        assert!(c.evaluate(&ctx(&a)).is_allow());
    }

    /// Fail-closed, and consistent with the sibling `domain_allowlist`, which
    /// already denied on this same missing field.
    #[test]
    fn a_missing_target_domain_is_denied() {
        let c = DomainDenylistCheck::new(vec!["evil.test".into()]);
        let a = Action::default();
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }

    #[test]
    fn case_insensitive() {
        let c = DomainDenylistCheck::new(vec!["COMPETITOR.com".into()]);
        let a = action_with(Some("competitor.COM"));
        assert!(c.evaluate(&ctx(&a)).is_deny());
    }
}
