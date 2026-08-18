//! Turn a panicking request into a response, distinguishing overload from a bug.
//!
//! Around ninety call sites take a pooled SQLite connection with `.unwrap()`.
//! That is infallible in the normal case and panics in exactly one: the pool
//! timed out because every connection was busy. Under a plain
//! `CatchPanicLayer::new()` the caller saw a bare `500` — "this server is
//! broken" — for what is really "this server is briefly saturated". A client
//! cannot tell those apart, so it cannot retry the one worth retrying, and a
//! load balancer cannot drain the node that needs draining.
//!
//! Recognising [`crate::db::POOL_TIMEOUT_MARKER`] in the panic payload converts
//! that case to `503` with `Retry-After`. Everything else stays a `500`,
//! because everything else really is a bug.
//!
//! This lives in the library rather than next to the router in `main.rs` so it
//! can be exercised over real HTTP by `core/tests/pool_exhaustion_503.rs`. A
//! panic handler that has never been made to fire is a guess.
//!
//! ponytail: reading the panic payload is a shim, not the destination. The real
//! fix is for `lock()` failures to travel as `Result` to the handler, which is
//! ~90 mechanical call sites across a dozen error types; do that and this
//! module collapses to a plain 500.

use axum::http::{header::CONTENT_TYPE, header::RETRY_AFTER, StatusCode};
use axum::response::{IntoResponse, Response};

/// Body returned when the connection pool is saturated.
const POOL_EXHAUSTED_BODY: &str = r#"{"error":{"code":"db_pool_exhausted","message":"database connection pool exhausted","fix":"retry after a short delay; if this persists, raise SAURON_DB_POOL_SIZE, lower SAURON_DB_POOL_TIMEOUT_MS to shed load sooner, or reduce concurrent write volume"}}"#;

/// Body returned for any other panic.
const INTERNAL_BODY: &str = r#"{"error":{"code":"internal_error","message":"internal server error","fix":"retry; if it persists, check the server logs for the panic payload"}}"#;

/// `CatchPanicLayer::custom` handler. See the module docs.
pub fn handle_request_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    // A panic payload is `String` for a formatted `panic!`/`unwrap`, and
    // `&'static str` for a literal. Anything else is not something we can read.
    let payload = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default();

    if payload.contains(crate::db::POOL_TIMEOUT_MARKER) {
        tracing::warn!(
            target: "sauron::db",
            "database connection pool exhausted — shedding request with 503"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "1"), (CONTENT_TYPE, "application/json")],
            POOL_EXHAUSTED_BODY,
        )
            .into_response();
    }

    tracing::error!(target: "sauron::panic", payload = %payload, "request handler panicked");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(CONTENT_TYPE, "application/json")],
        INTERNAL_BODY,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_panic_is_still_a_bug() {
        let res = handle_request_panic(Box::new("index out of bounds".to_string()));
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(res.headers().get(RETRY_AFTER).is_none());
    }

    #[test]
    fn a_pool_timeout_is_overload() {
        let payload = format!(
            "called `Result::unwrap()` on an `Err` value: {}: timed out waiting for connection",
            crate::db::POOL_TIMEOUT_MARKER
        );
        let res = handle_request_panic(Box::new(payload));
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers().get(RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn a_str_payload_is_read_too() {
        // `panic!("literal")` produces &'static str, not String.
        let res = handle_request_panic(Box::new("deliberate literal panic"));
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
