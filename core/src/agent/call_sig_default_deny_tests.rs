//! Extracted verbatim from the inline `mod call_sig_default_deny_tests` that `agent.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::{call_sig_required_for, CALL_SIG_EXEMPT_PATHS};
use axum::http::Method;

/// Every `/agent/...` path the binary actually mounts, read out of the
/// router source at compile time.
///
/// The previous version of this module tested a list someone typed here by
/// hand, which can only ever assert what its author already knew about. A
/// route added to `main.rs` and forgotten here was invisible — the exact
/// failure the default-deny layer exists to prevent. Embedding the router
/// source means the test's input is the router itself.
fn mounted_agent_paths() -> Vec<String> {
    const ROUTER_SRC: &str = include_str!("../main.rs");
    let mut out = Vec::new();
    for piece in ROUTER_SRC.split(".route(").skip(1) {
        let Some(open) = piece.find('"') else {
            continue;
        };
        let rest = &piece[open + 1..];
        let Some(close) = rest.find('"') else {
            continue;
        };
        let path = &rest[..close];
        if path.starts_with("/agent/") && !out.iter().any(|p| p == path) {
            out.push(path.to_string());
        }
    }
    assert!(
        out.len() >= 15,
        "expected to parse the agent surface out of main.rs, found {}: has the router moved?",
        out.len()
    );
    out
}

#[test]
fn every_mounted_agent_route_is_signed_or_explicitly_exempt() {
    for path in mounted_agent_paths() {
        // Axum path params never reach the predicate as literals; a
        // concrete id exercises the same branch.
        let concrete = path.replace("{agent_id}", "agt_abc123").replace(
            "{human_key_image}",
            "0011223344556677889900112233445566778899001122334455667788990011",
        );
        let exempt = CALL_SIG_EXEMPT_PATHS.contains(&concrete.as_str());
        let required = call_sig_required_for(&Method::POST, &concrete);
        assert!(
            required || exempt,
            "{path} is mounted, takes writes, and is neither protected nor on \
                 CALL_SIG_EXEMPT_PATHS — add it to the exempt list with a reason, \
                 or leave it protected"
        );
    }
}

#[test]
fn the_ring_member_read_is_exempt_but_only_that_exact_shape() {
    // The one read an anonymous signer cannot do without: an LSAG covers
    // every member key, so this must be reachable without announcing an
    // agent id. Exempt.
    assert!(!call_sig_required_for(
        &Method::GET,
        "/agent/rings/r_payments/members"
    ));
    // Everything adjacent stays protected. A prefix rule would have let all
    // of these through, which is how the single-segment carve-out below
    // went wrong in the first place.
    for (m, p) in [
        (Method::POST, "/agent/rings/r_payments/members"),
        (Method::DELETE, "/agent/rings/r_payments/members"),
        (Method::GET, "/agent/rings/r_payments/subscribe"),
        (Method::POST, "/agent/rings/r_payments/subscribe"),
        (Method::GET, "/agent/rings/r_payments"),
        (Method::GET, "/agent/rings/r_payments/members/extra"),
        (Method::GET, "/agent/rings//members"),
    ] {
        assert!(call_sig_required_for(&m, p), "{m} {p} must still be signed");
    }
}

#[test]
fn the_single_segment_carve_out_is_read_only() {
    // What it was written for: a read of a record the caller already holds.
    assert!(!call_sig_required_for(&Method::GET, "/agent/agt_abc123"));
    assert!(!call_sig_required_for(&Method::HEAD, "/agent/agt_abc123"));
    // What it must never cover. Before the method check, every one of these
    // was silently unprotected purely for having no second slash.
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        assert!(
            call_sig_required_for(&method, "/agent/spend"),
            "{method} on a one-word agent route must still be signed"
        );
    }
}

#[test]
fn known_authority_bearing_routes_stay_protected() {
    for p in [
        "/agent/action/challenge",
        "/agent/payment/authorize",
        "/agent/egress/log",
        "/agent/egress/capability",
        "/agent/egress/proxy",
        "/agent/kyc/consent",
        "/agent/vc/issue",
        // A route nobody has written yet.
        "/agent/action/submit",
    ] {
        assert!(
            call_sig_required_for(&Method::POST, p),
            "{p} must stay protected"
        );
    }
}

#[test]
fn exempt_paths_are_exempt_and_nothing_else_is() {
    for p in CALL_SIG_EXEMPT_PATHS {
        assert!(
            !call_sig_required_for(&Method::POST, p),
            "{p} is on the exempt list"
        );
    }
    // Non-agent surfaces are governed by their own auth layers.
    for p in ["/admin/stats", "/healthz", "/user/auth"] {
        assert!(!call_sig_required_for(&Method::POST, p));
    }
}

#[test]
fn exemptions_stay_deliberate() {
    // A tripwire: growing this list is a security decision, so it should be
    // a visible diff here as well as in the constant.
    assert_eq!(
        CALL_SIG_EXEMPT_PATHS.len(),
        8,
        "exempt list changed — is the new entry genuinely unable to carry a signature?"
    );
}
