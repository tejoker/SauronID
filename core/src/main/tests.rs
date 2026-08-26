//! Extracted verbatim from the inline `mod tests` that `main.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

#[tokio::test]
async fn request_panic_is_contained_as_internal_server_error() {
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;
    use tower_http::catch_panic::CatchPanicLayer;

    async fn panic_handler() -> axum::http::StatusCode {
        panic!("deliberate request-path panic")
    }

    let app = Router::new()
        .route("/panic", get(panic_handler))
        .layer(CatchPanicLayer::new());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/panic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("panic containment must return an HTTP response");
    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}
