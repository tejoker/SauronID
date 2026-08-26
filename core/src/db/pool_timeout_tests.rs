//! Extracted verbatim from the inline `mod pool_timeout_tests` that `db.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

use super::*;

/// The HTTP layer answers 503 by looking for [`POOL_TIMEOUT_MARKER`] in the
/// panic payload, and `Result::unwrap` builds that payload with `Debug`. So
/// the marker has to survive the round trip through an actual panic — not
/// just be present in a `format!("{:?}")` we write ourselves.
///
/// This is also the guard against r2d2: its own error `Debug`-prints as
/// `Error(None)`, which carries nothing to match on. If someone "simplifies"
/// `lock()` back to returning `r2d2::Error`, overload starts answering 500
/// again with no other test noticing. This one fails.
#[test]
fn an_exhausted_pool_panics_with_the_marker_the_http_layer_matches() {
    let pool = Pool::builder()
        .max_size(1)
        .connection_timeout(std::time::Duration::from_millis(50))
        .build(SqliteConnectionManager::memory())
        .expect("pool builds");
    let handle = DbHandle {
        pool,
        pg_pool: None,
    };

    // Hold the only connection, so the next caller can only time out.
    let _held = handle.lock().expect("first connection is free");

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = handle.lock().unwrap();
    }))
    .expect_err("a saturated pool must fail");

    let payload = panicked
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panicked.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();

    assert!(
        payload.contains(POOL_TIMEOUT_MARKER),
        "panic payload must carry the marker so overload answers 503, got: {payload}"
    );
}

/// Display is what the `.map_err(|e| e.to_string())` call sites surface, so
/// it should read as load rather than as a marker string.
#[test]
fn display_explains_the_condition_without_leaking_the_marker() {
    let pool = Pool::builder()
        .max_size(1)
        .connection_timeout(std::time::Duration::from_millis(50))
        .build(SqliteConnectionManager::memory())
        .expect("pool builds");
    let handle = DbHandle {
        pool,
        pg_pool: None,
    };
    let _held = handle.lock_sqlite().expect("first connection is free");

    let err = handle
        .lock_sqlite()
        .expect_err("a saturated pool must fail");
    let shown = err.to_string();
    assert!(shown.contains("pool exhausted"), "got: {shown}");
    assert!(!shown.contains(POOL_TIMEOUT_MARKER), "got: {shown}");
}
