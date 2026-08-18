//! Minimal error type for HTTP boundary handlers.
//!
//! Replaces `.unwrap()` / `.expect()` / `panic!` inside axum handlers so that
//! a malicious or malformed request can no longer DoS the server. Every
//! variant maps to a non-5xx-leaking HTTP response that does not expose
//! internal panic strings to the caller.
//!
//! Use `AppError::from(rusqlite::Error)` or `.map_err(AppError::internal)?` at
//! call sites that previously `.unwrap()`'d a fallible value.
//!
//! Responses are a JSON envelope that teaches the caller how to recover:
//! `{"error":{"code":"<stable_snake_case>","message":"...","fix":"..."}}`.
//! `code` is stable machine-matchable; `message` keeps the exact legacy text
//! (existing substring assertions in redteam/e2e suites still pass); `fix` is
//! a one-line remediation hint.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    ServiceUnavailable(String),
    Internal(String),
    /// Fully specified error with explicit status, stable code, and a
    /// remediation hint. Used where a generic per-variant hint is not enough
    /// (e.g. each distinct call-signature middleware rejection).
    Detailed {
        status: StatusCode,
        code: &'static str,
        message: String,
        fix: &'static str,
    },
}

impl AppError {
    pub fn internal<E: fmt::Display>(e: E) -> Self {
        AppError::Internal(e.to_string())
    }
    pub fn bad_request<S: Into<String>>(s: S) -> Self {
        AppError::BadRequest(s.into())
    }
    /// Error with an explicit stable code and one-line fix hint.
    pub fn with_hint<S: Into<String>>(
        status: StatusCode,
        code: &'static str,
        message: S,
        fix: &'static str,
    ) -> Self {
        AppError::Detailed {
            status,
            code,
            message: message.into(),
            fix,
        }
    }
    /// HTTP status this error maps to (without consuming it).
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Detailed { status, .. } => *status,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(s) => write!(f, "bad request: {s}"),
            AppError::Unauthorized(s) => write!(f, "unauthorized: {s}"),
            AppError::NotFound(s) => write!(f, "not found: {s}"),
            AppError::Conflict(s) => write!(f, "conflict: {s}"),
            AppError::ServiceUnavailable(s) => write!(f, "service unavailable: {s}"),
            AppError::Internal(s) => write!(f, "internal: {s}"),
            AppError::Detailed { code, message, .. } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, fix) = match self {
            AppError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                m,
                "check the request body and parameters against the API schema; see docs/sdk-integration.md",
            ),
            AppError::Unauthorized(m) => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                m,
                "check credentials and required x-sauron-* headers; see docs/sdk-integration.md",
            ),
            AppError::NotFound(m) => (
                StatusCode::NOT_FOUND,
                "not_found",
                m,
                "check the resource id and that it belongs to your tenant",
            ),
            AppError::Conflict(m) => (
                StatusCode::CONFLICT,
                "conflict",
                m,
                "the resource already exists or was modified concurrently; re-fetch current state and retry",
            ),
            AppError::ServiceUnavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                m,
                "a dependency is temporarily unavailable; retry with backoff",
            ),
            // Internal errors: log full detail, return generic message to caller
            // to avoid leaking implementation details to pentesters.
            AppError::Internal(m) => {
                tracing::error!(target: "sauron::error", detail = %m, "internal handler error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal server error".to_string(),
                    "retry; contact the operator with the request timestamp if the error persists",
                )
            }
            AppError::Detailed {
                status,
                code,
                message,
                fix,
            } => (status, code, message, fix),
        };
        (
            status,
            Json(serde_json::json!({
                "error": { "code": code, "message": message, "fix": fix }
            })),
        )
            .into_response()
    }
}

/// Hint returned whenever a request loses a race for the database.
const CONTENTION_FIX: &str =
    "the database was busy with another write; retry after a short delay. If this is \
     frequent, the single-writer SQLite tier is saturated — see docs/production-readiness.md";

/// True when a database error message describes write contention rather than a
/// fault.
///
/// String matching is a last resort, used only on the paths where the typed
/// error has already been flattened — `AnyConn::transaction` returns `String`
/// because it spans two backends. Where the `rusqlite::Error` survives, the
/// conversion below matches on the error code instead, which is exact.
pub fn is_db_contention(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("database is locked")     // SQLITE_BUSY
        || m.contains("database table is locked") // SQLITE_LOCKED
        || m.contains("deadlock detected")   // Postgres 40P01
        || m.contains("could not serialize access") // Postgres 40001
}

/// Map a flattened database error string to a response.
///
/// Contention is `503` with a retry hint; everything else stays `500`. The two
/// look identical to a client otherwise, and they call for opposite reactions —
/// retry shortly, versus stop and page someone.
pub fn from_db_message(context: &str, message: impl std::fmt::Display) -> AppError {
    let message = message.to_string();
    if is_db_contention(&message) {
        return AppError::with_hint(
            StatusCode::SERVICE_UNAVAILABLE,
            "db_contention",
            format!("{context}: {message}"),
            CONTENTION_FIX,
        );
    }
    AppError::Internal(format!("{context}: {message}"))
}

/// Adopt a legacy `(StatusCode, String)` handler error.
///
/// Handlers used to return that tuple directly, which axum renders as a
/// plain-text body — no `code`, no `fix`, and a different shape from the
/// `AppError` routes next to them. The README documents
/// `.json()["error"]["fix"]`, so half the surface was quietly not honouring the
/// contract the other half advertised.
///
/// This exists so those handlers can move by changing their return type alone:
/// `?` applies the conversion at the ~120 `map_err(|e| (StatusCode::X, e))` and
/// `ok_or((StatusCode::X, …))` sites without touching them. The message is
/// carried through byte-for-byte, which is what keeps the substring assertions
/// in the red-team and e2e suites passing.
///
/// The resulting `code` is the status-derived one — `bad_request`,
/// `unauthorized`, and so on. That is the same code the hand-written
/// `AppError::BadRequest` arms produce, so this is parity with the already
/// converted handlers, not a weaker version of them. Where a caller needs to
/// discriminate more finely than the status allows, the site says so explicitly
/// with [`AppError::with_hint`] — as the call-signature rejections do.
impl From<(StatusCode, String)> for AppError {
    fn from((status, message): (StatusCode, String)) -> Self {
        match status {
            StatusCode::BAD_REQUEST => AppError::BadRequest(message),
            StatusCode::UNAUTHORIZED => AppError::Unauthorized(message),
            StatusCode::NOT_FOUND => AppError::NotFound(message),
            StatusCode::CONFLICT => AppError::Conflict(message),
            StatusCode::SERVICE_UNAVAILABLE => AppError::ServiceUnavailable(message),
            StatusCode::INTERNAL_SERVER_ERROR => AppError::Internal(message),
            // 403, 422, 429 and the rest have no variant of their own. Keeping
            // the status verbatim matters more than inventing one: a caller that
            // branches on 429 must keep seeing 429.
            other => AppError::Detailed {
                status: other,
                code: match other {
                    StatusCode::FORBIDDEN => "forbidden",
                    StatusCode::UNPROCESSABLE_ENTITY => "unprocessable_entity",
                    StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                    StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
                    _ => "error",
                },
                message,
                fix: "see the message; docs/sdk-integration.md lists the headers and body each route expects",
            },
        }
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        // Losing a race for the write lock is load, not a fault. Reported as
        // 500 it tells the caller to stop retrying the one thing that would
        // have succeeded a moment later.
        if let rusqlite::Error::SqliteFailure(inner, _) = &e {
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) {
                return AppError::with_hint(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "db_contention",
                    format!("sqlite: {e}"),
                    CONTENTION_FIX,
                );
            }
        }
        AppError::Internal(format!("sqlite: {e}"))
    }
}

#[cfg(test)]
mod contention_tests {
    use super::*;

    /// The distinction this module exists to make: a client that gets 500 stops
    /// retrying, and contention is precisely the case where it should.
    #[test]
    fn sqlite_busy_is_service_unavailable_not_internal() {
        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy,
                extended_code: 5,
            },
            Some("database is locked".into()),
        );
        match AppError::from(busy) {
            AppError::Detailed { status, code, .. } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(code, "db_contention");
            }
            other => panic!("expected a 503 contention error, got {other:?}"),
        }
    }

    #[test]
    fn a_real_sqlite_fault_stays_internal() {
        let corrupt = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseCorrupt,
                extended_code: 11,
            },
            Some("database disk image is malformed".into()),
        );
        assert!(matches!(AppError::from(corrupt), AppError::Internal(_)));
    }

    #[test]
    fn flattened_messages_are_classified_for_both_backends() {
        // SQLite, and the two Postgres serialization failures.
        for m in [
            "begin: database is locked",
            "database table is locked",
            "deadlock detected",
            "could not serialize access due to concurrent update",
        ] {
            assert!(is_db_contention(m), "{m} should be contention");
        }
        for m in [
            "no such table: agents",
            "UNIQUE constraint failed: clients.name",
            "disk I/O error",
        ] {
            assert!(!is_db_contention(m), "{m} is a fault, not contention");
        }
    }

    #[test]
    fn from_db_message_keeps_the_context_and_the_cause() {
        let e = from_db_message("begin", "database is locked");
        match e {
            AppError::Detailed {
                status, message, ..
            } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert!(message.contains("begin"), "context lost: {message}");
                assert!(message.contains("locked"), "cause lost: {message}");
            }
            other => panic!("expected 503, got {other:?}"),
        }
    }
}
