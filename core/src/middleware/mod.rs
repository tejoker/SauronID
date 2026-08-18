//! S12 hardening middleware (global pre-auth defenses).
//!
//! This module bundles two layers that run OUTSIDE the existing tenant /
//! auth / call-signature middleware stack so they can defend the surface
//! before any handler-specific logic kicks in:
//!
//! - [`rate_limit`] — token-bucket global rate limit keyed by remote IP.
//!   Fires BEFORE auth so an unauthenticated brute-force flood cannot
//!   reach the admin auth code path.
//! - [`audit_log`] — security-event audit trail. Captures auth failures,
//!   signature mismatches, cross-tenant attempts, policy violations,
//!   admin-key rotations, and rate-limit trips. Writes to a dedicated
//!   tracing target so the operator can ship the log to a SIEM with no
//!   additional plumbing; also persists to a tenant-scoped SQL table for
//!   in-DB queryability via `GET /v1/admin/audit`.
//!
//! Both layers use only stdlib + already-vendored crates — no new
//! `Cargo.toml` dependencies, per the S12 constraint sheet.

pub mod audit_log;
pub mod panic;
pub mod rate_limit;
pub mod security_headers;

pub use audit_log::{
    audit_log_middleware, ensure_security_audit_schema, init_audit_sink, query_audit_events,
    record, AuditEvent, AuditQuery, AuditRecord,
};
pub use panic::handle_request_panic;
pub use rate_limit::{global_rate_limit_middleware, GlobalRateLimitConfig, GlobalRateLimiter};
pub use security_headers::security_headers_middleware;
