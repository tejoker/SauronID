//! Overload must answer `503`, over real HTTP, against a genuinely full pool.
//!
//! The unit tests in `db.rs` prove the panic payload carries the marker, and
//! the ones in `middleware/panic.rs` prove the handler maps that marker to a
//! 503. Neither proves the two halves meet: that a handler doing what ~90 real
//! call sites do — `st.db.lock().unwrap()` — produces a response a client can
//! act on rather than a bare 500.
//!
//! So this test saturates a real r2d2 pool, sends a real request through a real
//! `CatchPanicLayer`, and asserts on the status, the `Retry-After` header and
//! the error envelope. It is the difference between "the mapping function
//! returns 503" and "the server returns 503".

use std::time::Duration;

use axum::{body::Body, http::Request, http::StatusCode, routing::get, Router};
use http_body_util::BodyExt;
use sauron_core::db::{open_db_at_with_timeout, DbHandle};
use sauron_core::middleware::handle_request_panic;
use tower::ServiceExt;
use tower_http::catch_panic::CatchPanicLayer;

/// A handler written the way the ~90 real ones are.
async fn takes_a_connection(
    axum::extract::State(db): axum::extract::State<std::sync::Arc<DbHandle>>,
) -> &'static str {
    let conn = db.lock().unwrap();
    let _: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
    "ok"
}

fn app(db: std::sync::Arc<DbHandle>) -> Router {
    Router::new()
        .route("/takes-a-connection", get(takes_a_connection))
        .layer(CatchPanicLayer::custom(handle_request_panic))
        .with_state(db)
}

fn temp_db(pool_size: u32, timeout: Duration) -> (std::sync::Arc<DbHandle>, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "sauron-pool-503-{}-{:?}.sqlite",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let db = open_db_at_with_timeout(path.to_str().unwrap(), pool_size, timeout);
    (std::sync::Arc::new(db), path)
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

#[tokio::test]
async fn a_saturated_pool_sheds_the_request_with_503_and_retry_after() {
    // One connection, and a timeout short enough that the assertion is fast.
    // Production keeps r2d2's 30s default unless SAURON_DB_POOL_TIMEOUT_MS says
    // otherwise; the shedding behaviour is identical either way.
    let (db, path) = temp_db(1, Duration::from_millis(200));

    // Hold the only connection for the duration of the request. This is exactly
    // what sustained write load does, minus the waiting.
    let hog = db.lock().expect("the first caller gets the connection");

    let response = app(db.clone())
        .oneshot(
            Request::builder()
                .uri("/takes-a-connection")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("the layer must produce a response, not propagate the panic");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "overload is 503 — a 500 here tells the client to stop retrying something it should retry"
    );
    assert_eq!(
        response.headers().get("retry-after").unwrap(),
        "1",
        "a 503 without Retry-After leaves the client guessing"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("error envelope is JSON");
    assert_eq!(json["error"]["code"], "db_pool_exhausted");
    assert!(
        json["error"]["fix"]
            .as_str()
            .unwrap()
            .contains("SAURON_DB_POOL_SIZE"),
        "the fix field should name the knob that resolves it"
    );

    drop(hog);
    cleanup(&path);
}

#[tokio::test]
async fn the_same_handler_succeeds_when_a_connection_is_free() {
    // Guards against the test above passing for the wrong reason — a route that
    // 503s unconditionally would satisfy it just as well.
    let (db, path) = temp_db(1, Duration::from_millis(200));

    let response = app(db.clone())
        .oneshot(
            Request::builder()
                .uri("/takes-a-connection")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    cleanup(&path);
}

#[tokio::test]
async fn the_pool_recovers_once_the_connection_is_returned() {
    // Shedding is only correct if it is temporary. A node that answers 503
    // forever after one burst is worse than one that answers 500.
    let (db, path) = temp_db(1, Duration::from_millis(200));

    let hog = db.lock().unwrap();
    let shed = app(db.clone())
        .oneshot(
            Request::builder()
                .uri("/takes-a-connection")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);

    drop(hog);

    let recovered = app(db.clone())
        .oneshot(
            Request::builder()
                .uri("/takes-a-connection")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        recovered.status(),
        StatusCode::OK,
        "the node must serve again as soon as load drops"
    );

    cleanup(&path);
}
