//! Extracted verbatim from the inline `mod tests` that `admin.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;
use axum::http::StatusCode;

/// Serialises the env mutation below — `set_var` is process-wide and cargo
/// runs tests in this binary on parallel threads.
static STATIC_KEY_TENANT_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// F3: a static admin key carries no scope and no tenant allowlist, so the
/// only thing choosing which tenant it reads is the caller's own
/// `x-sauron-tenant-id` header. In production that has to be a deliberate
/// declaration, not a default — otherwise handing the key to one tenant's
/// admin hands them every other tenant.
#[test]
fn a_static_key_may_not_roam_tenants_in_production_unless_declared() {
    let _guard = STATIC_KEY_TENANT_ENV
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let restore = (
        std::env::var("ENV").ok(),
        std::env::var("SAURON_ENV").ok(),
        std::env::var("SAURON_ADMIN_CROSS_TENANT").ok(),
    );
    std::env::set_var("ENV", "production");
    std::env::remove_var("SAURON_ENV");
    std::env::remove_var("SAURON_ADMIN_CROSS_TENANT");

    // Its own tenant is always fine.
    assert!(static_key_may_target(crate::tenancy::DEFAULT_TENANT));
    // Someone else's is not, until the operator says the key is global.
    assert!(
        !static_key_may_target("acme_corp"),
        "a static key must not silently target another tenant in production"
    );
    std::env::set_var("SAURON_ADMIN_CROSS_TENANT", "1");
    assert!(
        static_key_may_target("acme_corp"),
        "an explicitly operator-global key may target any tenant"
    );

    // Development keeps roaming: the seeded demo drives several tenants
    // through one key and blocking that breaks every local walkthrough.
    std::env::remove_var("SAURON_ADMIN_CROSS_TENANT");
    std::env::set_var("ENV", "development");
    assert!(static_key_may_target("acme_corp"));

    for (k, v) in [
        ("ENV", restore.0),
        ("SAURON_ENV", restore.1),
        ("SAURON_ADMIN_CROSS_TENANT", restore.2),
    ] {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
}

// Locks the exact OpenTimestamps detached-file framing the `ots` tooling
// expects: HEADER_MAGIC ‖ version(1) ‖ OpSHA256(0x08) ‖ msg(32) ‖ timestamp.
#[test]
fn ots_detached_framing_is_spec_exact() {
    let root = [0xABu8; 32];
    let blob = vec![0x01, 0x02, 0x03, 0x04];
    let out = build_ots_detached(&root, &blob);

    // Header magic verbatim from the OpenTimestamps spec.
    let expected_magic: &[u8] =
        b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
    assert_eq!(expected_magic.len(), 31);
    assert_eq!(&out[..31], expected_magic, "header magic must match spec");

    // Version varuint (1) then OpSHA256 tag (0x08).
    assert_eq!(out[31], 0x01, "major version varuint");
    assert_eq!(out[32], 0x08, "file_hash_op must be OpSHA256");

    // The 32-byte message (merkle root) then the calendar timestamp blob.
    assert_eq!(&out[33..65], &root, "msg must be the 32-byte root");
    assert_eq!(&out[65..], &blob[..], "timestamp blob appended verbatim");

    assert_eq!(out.len(), 31 + 1 + 1 + 32 + blob.len());
}

// ── /admin/keys/issue (issue_admin_jwt) ──────────────────────────────

const TEST_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn issue_req(scopes: &[&str], tenants: &[&str], ttl: Option<i64>) -> IssueAdminKeyRequest {
    IssueAdminKeyRequest {
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        tenants: tenants.iter().map(|s| s.to_string()).collect(),
        ttl_secs: ttl,
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn issue_valid_token_verifies_with_middleware_path() {
    let t0 = now();
    let req = issue_req(&["admin:read", "admin:write"], &["t1", "t2"], Some(7200));
    let resp = issue_admin_jwt(Some(TEST_SECRET), true, &req, t0).expect("issue");
    assert_eq!(resp.scopes, vec!["admin:read", "admin:write"]);
    assert_eq!(resp.tenants, vec!["t1", "t2"]);
    assert_eq!(resp.expires_at, t0 + 7200);
    // The exact decode path auth_middleware runs.
    let (scp, tnt) = verify_admin_jwt(&resp.token, TEST_SECRET).expect("token must verify");
    assert_eq!(scp, vec!["admin:read", "admin:write"]);
    assert_eq!(tnt, vec!["t1", "t2"]);
    assert!(!scopes_are_super(&scp), "issued token must never be super");
}

#[test]
fn issue_refuses_scope_escalation() {
    for esc in ["admin:super", "admin:full", "*", "ADMIN:SUPER"] {
        let req = issue_req(&[esc], &["t1"], None);
        let err = issue_admin_jwt(Some(TEST_SECRET), true, &req, now())
            .expect_err("escalation must be refused");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST, "scope {esc}");
        assert!(err.to_string().contains("scope escalation refused"));
    }
    // Unknown scope is also a 400.
    let req = issue_req(&["admin:banana"], &["t1"], None);
    let err = issue_admin_jwt(Some(TEST_SECRET), true, &req, now()).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn issue_without_secret_is_503_with_fix_hint() {
    let req = issue_req(&["admin:read"], &["t1"], None);
    let err = issue_admin_jwt(None, true, &req, now()).expect_err("must fail closed");
    assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(err.to_string().contains("admin_jwt_secret_unset"));
}

#[test]
fn issue_requires_cross_tenant_super() {
    let req = issue_req(&["admin:read"], &["t1"], None);
    let err = issue_admin_jwt(Some(TEST_SECRET), false, &req, now()).unwrap_err();
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn issue_requires_nonempty_valid_tenants() {
    let err = issue_admin_jwt(
        Some(TEST_SECRET),
        true,
        &issue_req(&["admin:read"], &[], None),
        now(),
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    let err = issue_admin_jwt(
        Some(TEST_SECRET),
        true,
        &issue_req(&["admin:read"], &["../etc"], None),
        now(),
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn issue_clamps_ttl_to_1h_90d() {
    let t0 = now();
    let low = issue_admin_jwt(
        Some(TEST_SECRET),
        true,
        &issue_req(&["admin:read"], &["t1"], Some(10)),
        t0,
    )
    .unwrap();
    assert_eq!(low.expires_at, t0 + MIN_ISSUED_KEY_TTL_SECS);
    let high = issue_admin_jwt(
        Some(TEST_SECRET),
        true,
        &issue_req(&["admin:read"], &["t1"], Some(i64::MAX / 2)),
        t0,
    )
    .unwrap();
    assert_eq!(high.expires_at, t0 + MAX_ISSUED_KEY_TTL_SECS);
}
