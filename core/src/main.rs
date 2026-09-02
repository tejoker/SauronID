use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header::AUTHORIZATION, header::CONTENT_TYPE, HeaderName, Method, StatusCode},
    middleware,
    routing::{get, post},
    Router,
};
use hmac::Hmac;
use sauron_core::middleware::{
    audit_log_middleware, global_rate_limit_middleware, handle_request_panic, init_audit_sink,
    security_headers_middleware, GlobalRateLimitConfig, GlobalRateLimiter,
};
use sauron_core::routes::{
    admin_router, agent_spend_router, audit_reports_router, audit_router, policy_router,
    proofs_router, stats_router,
};
use sauron_core::tenancy as sauron_tenancy;
use sauron_core::{agent, db};
use sauron_core::{agent_action, state::ServerState, usage};
use sha2::Sha256;
use std::sync::{Arc, RwLock};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

type HmacSha256 = Hmac<Sha256>;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Refuse to boot a production deployment that is silently single-node.
///
/// The acknowledgement used to be required with or without
/// `SAURON_DB_BACKEND=postgres`, because selecting Postgres moved almost
/// nothing: `agents`, `agent_action_receipts`, `spend_ledger` and the rest kept
/// writing to the local SQLite sidecar, which no amount of operator-side
/// Postgres HA covers. The comment here said to re-add the bypass "only when
/// the drift test flips". It has: `core/tests/postgres_backend_drift.sh` now
/// asserts the rows are in Postgres and the sidecar is empty, and fails if they
/// are not.
///
/// So a configured Postgres backend is now a real answer to "is this
/// single-node", and demanding the acknowledgement anyway would train operators
/// to set a flag that no longer means anything. SQLite deployments — still the
/// default — are unaffected.
fn assert_production_sqlite_acknowledged() {
    if sauron_core::runtime_mode::is_development_runtime() {
        return;
    }
    // Read the same way `db::open_pg_pool` does. A DATABASE_URL is required
    // with it: without one the handle logs and stays on SQLite, so treating the
    // flag alone as sufficient would let a typo disable this gate.
    let backend = std::env::var("SAURON_DB_BACKEND")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let url_set = std::env::var("DATABASE_URL").is_ok_and(|u| !u.trim().is_empty());
    if matches!(backend.as_str(), "postgres" | "pg" | "postgresql") && url_set {
        return;
    }

    let ok = std::env::var("SAURON_ACCEPT_SINGLE_NODE_SQLITE")
        .map(|v| {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        })
        .unwrap_or(false);
    if !ok {
        panic!(
            "[FATAL] SQLite is single-node (no cross-region HA). Set SAURON_ACCEPT_SINGLE_NODE_SQLITE=1 to acknowledge this deployment, or run on PostgreSQL with SAURON_DB_BACKEND=postgres and DATABASE_URL set."
        );
    }
}

fn init_tracing() {
    // RUST_LOG controls level. SAURON_LOG_FORMAT=json switches to JSON-line output.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,sauron_core=debug"));
    let json_mode = std::env::var("SAURON_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let registry = tracing_subscriber::registry().with(filter);
    if json_mode {
        registry
            .with(fmt::layer().json().with_current_span(false))
            .init();
    } else {
        registry.with(fmt::layer()).init();
    }
}

use once_cell::sync::Lazy;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};
use sauron_core::sync_recover::RwLockRecover;

// Dev-only endpoints live in their own file; see its header for the gating.
// Compiled only into the demo/test lanes — a client build has no such code.
#[cfg(feature = "demo")]
mod dev_endpoints;
#[cfg(feature = "demo")]
use dev_endpoints::{dev_buy_tokens, dev_leash_demo, dev_register_user};

static METRICS_REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);
static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "http_requests_total",
            "Total HTTP requests handled by the server.",
        ),
        &["method", "path", "status"],
    )
    .expect("counter");
    METRICS_REGISTRY
        .register(Box::new(c.clone()))
        .expect("register");
    c
});
static HTTP_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "http_request_duration_seconds",
            "HTTP request duration in seconds.",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
        &["method", "path"],
    )
    .expect("histogram");
    METRICS_REGISTRY
        .register(Box::new(h.clone()))
        .expect("register");
    h
});

fn init_metrics() {
    // Force lazy init.
    Lazy::force(&HTTP_REQUESTS_TOTAL);
    Lazy::force(&HTTP_REQUEST_DURATION_SECONDS);
}

/// Public landing page (HTML). Any browser hitting the core's root gets a
/// small index pointing them at the real UI (Next.js dashboard) and the
/// other useful endpoints. Avoids the cold-clone confusion where a user
/// types `127.0.0.1:3001` and gets a bare 404.
async fn landing_page() -> axum::response::Response {
    let html = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SauronID core</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root { color-scheme: dark; }
body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
       background:#0b0d10; color:#e6e6e6; margin: 0; padding: 0; }
main { max-width: 760px; margin: 4em auto; padding: 0 1.5em; }
h1 { font-weight: 700; letter-spacing: -0.02em; margin: 0 0 0.2em; }
.lede { color:#a4a8ad; margin: 0 0 2em; }
.card { background:#15181c; border:1px solid #25292f; border-radius:8px;
        padding:1em 1.25em; margin: 0.6em 0; display:flex; gap:1em; align-items:center; }
.card .label { font-weight:600; min-width:130px; }
.card a { color:#7eb6ff; text-decoration:none; word-break:break-all; }
.card a:hover { text-decoration:underline; }
.card.primary { border-color:#3a7bd5; background:#152035; }
code { font: 12.5px ui-monospace, SFMono-Regular, Menlo, monospace;
       background:#0e1116; border:1px solid #25292f; border-radius:4px; padding:1px 6px; }
pre  { font: 12.5px ui-monospace, SFMono-Regular, Menlo, monospace;
       background:#0e1116; border:1px solid #25292f; border-radius:6px; padding:0.8em 1em;
       overflow-x:auto; }
h2 { margin-top: 2em; font-size: 1em; color:#a4a8ad; text-transform: uppercase; letter-spacing:0.06em; }
.note { color:#7c8085; font-size: 12.5px; margin-top:0.4em; }
</style>
</head>
<body>
<main>
<h1>SauronID core</h1>
<p class="lede">You hit the API server (port 3001). The actual browser UI is the dashboard, on a different port.</p>
<div class="card primary"><span class="label">Dashboard →</span>
  <a href="http://127.0.0.1:3000">http://127.0.0.1:3000</a></div>
<div class="card"><span class="label">Analytics API →</span>
  <a href="http://127.0.0.1:8002/api/live/overview">http://127.0.0.1:8002/api/live/overview</a></div>
<div class="card"><span class="label">Health (public) →</span> <a href="/health">/health</a></div>
<div class="card"><span class="label">Metrics →</span> <a href="/metrics">/metrics</a></div>
<h2>API examples</h2>
<pre>curl -H 'x-admin-key: $SAURON_ADMIN_KEY' http://127.0.0.1:3001/admin/agents
curl -H 'x-admin-key: $SAURON_ADMIN_KEY' http://127.0.0.1:3001/admin/anchor/status
curl -H 'x-admin-key: $SAURON_ADMIN_KEY' http://127.0.0.1:3001/admin/health/detailed</pre>
<h2>CLI examples</h2>
<pre>sauronid-cli keypair
sauronid-cli sign-call --method POST --path /agent/payment/authorize --body '{}' \
  --priv agent.priv --agent-id agt_... --config-digest sha256:...
sauronid-cli register --session $SESSION
sauronid-cli health</pre>
<p class="note">If <code>http://127.0.0.1:3000</code> doesn't load, the Next.js dashboard isn't running. Start the full stack with <code>./launch.sh</code>.</p>
</main>
</body>
</html>"#;
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(html))
        .unwrap()
}

async fn metrics_handler() -> (StatusCode, [(&'static str, &'static str); 1], String) {
    let metric_families = METRICS_REGISTRY.gather();
    let mut buf = String::new();
    let encoder = TextEncoder::new();
    if encoder.encode_utf8(&metric_families, &mut buf).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain")],
            "encode error".to_string(),
        );
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        buf,
    )
}

async fn http_metrics_middleware(req: Request, next: middleware::Next) -> axum::response::Response {
    let method = req.method().to_string();
    // The ROUTE TEMPLATE, never the concrete path. Labelling with
    // `req.uri().path()` put one Prometheus time series per agent id, key image,
    // anchor id, ring id and consent request id — 13 of this router's paths carry
    // a parameter — and the prometheus crate keeps every label combination for
    // the life of the process. That is unbounded memory growth in the gateway and
    // a cardinality explosion in whatever scrapes it. `MatchedPath` collapses it
    // to the number of routes.
    //
    // A request that matched no route has no template; it is bucketed under a
    // single literal rather than leaking the attacker-controlled path it asked
    // for, which is the same reasoning in reverse.
    let path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16().to_string();
    let elapsed = started.elapsed().as_secs_f64();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[&method, &path])
        .observe(elapsed);
    resp
}

#[tokio::main]

async fn main() {
    init_tracing();
    init_metrics();

    sauron_core::admin::init_admin_auth().expect("admin auth init failed");

    // Sprint 1 (advisory → enforce): refuse to start in production when a
    // critical enforcement gate has been explicitly disabled without the
    // matching SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD opt-in.
    if let Err(reason) = sauron_core::runtime_mode::assert_production_enforcement_safe() {
        panic!("[FATAL] {reason}");
    }

    // Initialise la base SQLite en mémoire.
    let db_handle = db::open_db();
    let db_arc = Arc::new(db_handle);
    let state = Arc::new(RwLock::new(ServerState::new(Arc::clone(&db_arc)).await));
    assert_production_sqlite_acknowledged();

    // Background GC for time-bounded tables (JTIs, PoP challenges, risk counters, audit log).
    sauron_core::state::spawn_background_gc(Arc::clone(&db_arc));

    // S12: wire the security audit sinks (tracing target + optional file
    // sink via SAURON_AUDIT_LOG_PATH + the DB sink for in-DB queries).
    // Schema is created by db::init_schema, this call just stitches the
    // process-global sinks together.
    init_audit_sink(Arc::clone(&db_arc));

    // S12: global pre-auth ingress rate limiter. Token bucket per remote
    // IP. Disabled by setting SAURON_GLOBAL_RATE_LIMIT_RPS=0 (or burst=0).
    let global_limiter = Arc::new(GlobalRateLimiter::new(GlobalRateLimitConfig::from_env()));
    global_limiter.spawn_pruner();

    // Background OTS proof upgrader: promotes calendar-pending anchors to full
    // Bitcoin block attestations once the block is mined and the calendar batches up.
    sauron_core::bitcoin_anchor::spawn_ots_upgrader(Arc::clone(&db_arc));

    // Background agent-action anchor: every N minutes, build a merkle root over
    // newly-appended agent_action_receipts and anchor it to BTC OTS + Solana.
    // Closes the audit-log tampering gap for agent actions specifically.
    sauron_core::agent_action_anchor::spawn_action_anchor_task(Arc::clone(&state));

    // Background Solana confirmer: polls getSignatureStatuses for unconfirmed
    // Solana memo anchors and marks them confirmed once finalized.
    if let Some(rpc_url) = std::env::var("SAURON_SOLANA_RPC_URL").ok().filter(|_| {
        std::env::var("SAURON_SOLANA_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false)
    }) {
        sauron_core::solana_anchor::spawn_solana_confirmer(Arc::clone(&db_arc), rpc_url);
    }

    // Dev-only endpoints. Disabled in prod. Set SAURON_ENABLE_DEV_ENDPOINTS=1 to enable.
    // The env var is the second layer; the first is `--features demo`, without
    // which the handlers are not compiled and this block does not exist.
    #[cfg(feature = "demo")]
    let enable_dev_endpoints = std::env::var("SAURON_ENABLE_DEV_ENDPOINTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    #[allow(unused_mut)]
    let mut app = Router::new();

    #[cfg(feature = "demo")]
    if enable_dev_endpoints {
        app = app
            .route("/dev/register_user", post(dev_register_user))
            .route("/dev/buy_tokens", post(dev_buy_tokens))
            .route("/dev/leash/demo", post(dev_leash_demo));
    }

    let app = app
        // ZKP
        // A-JWT Agentic Layer
        // H1: PEM cert chains (TPM2 EK + attestation) can exceed the global
        // 64KB body cap. Lift only this route to 1MB.
        .route(
            "/agent/register",
            post(agent::register_agent).route_layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route("/agent/token", post(agent::issue_agent_token))
        // Self-sovereign AGENT credential (not a human identity)
        .route("/agent/vc/issue", post(agent_vc_issue))
        .route("/agent/verify", post(agent::verify_agent_token))
        .route(
            "/agent/attestation/challenge",
            post(agent::agent_attestation_challenge),
        )
        .route("/agent/pop/challenge", post(agent::agent_pop_challenge))
        .route(
            "/agent/action/challenge",
            post(agent_action::action_challenge),
        )
        .route(
            "/agent/action/receipt/verify",
            post(agent_action::receipt_verify),
        )
        // Anonymous ring-policy action path (phase 3; gated by SAURON_ANON_RINGS).
        // The ring signature is the auth, so no per-call-signature layer here.
        .route("/agent/action/anon", post(agent_action::submit_anon_action))
        // The signing set. An LSAG is computed across every member's key, so
        // without this read no agent could produce a signature the anon path
        // would accept — the only other source was behind the admin key, and an
        // agent holding that could enumerate the ring anyway. Members are
        // unlinkable pseudonyms; see rings::agent_members_handler for why
        // serving them needs no proof of membership.
        .route(
            "/agent/rings/{ring_id}/members",
            get(sauron_core::rings::agent_members_handler),
        )
        // Phase 4: report token usage for a prior anon receipt (gated likewise).
        .route("/agent/usage", post(usage::record_usage_handler))
        .route("/agent/payment/authorize", post(agent_payment_authorize))
        .route("/policy/authorize", post(policy_authorize))
        .route("/agent/list/{human_key_image}", get(agent::list_agents))
        .route(
            "/agent/{agent_id}/checksum/update",
            post(agent::update_agent_checksum),
        )
        // Redeem a payment authorization exactly once. Under /agent/ so the
        // default-deny call-signature layer covers it.
        .route("/agent/payment/consume", post(agent_payment_consume))
        .route("/agent/egress/log", post(agent_egress_log))
        // In-path egress gateway (Phase 1; gated by SAURON_EGRESS_GATEWAY).
        // Same per-call-sig gate as /egress/log — the ring sig proves the bound
        // agent; the handler enforces intent_json.egress_allowlist before forwarding.
        .route(
            "/agent/egress/capability",
            post(sauron_core::egress_gateway::issue_egress_capability),
        )
        .route(
            "/agent/egress/proxy",
            post(sauron_core::egress_gateway::agent_egress_proxy),
        )
        .route(
            "/agent/{agent_id}",
            get(agent::get_agent).delete(agent::revoke_agent),
        )
        .route("/user/auth", post(user_auth))
        .route("/user/auth/challenge", post(user_auth_challenge))
        .route("/user/auth/finish", post(user_auth_finish))
        // Public health — returns {ok} ONLY (no admin key). Detailed report is
        // /admin/health/detailed (admin-gated, prevents recon).
        .route("/health", get(sauron_core::admin::health_public))
        // Kubernetes-style aliases: /healthz mirrors /health (liveness);
        // /readyz additionally requires a live DB roundtrip (503 otherwise).
        .route("/healthz", get(sauron_core::admin::health_public))
        .route("/readyz", get(sauron_core::admin::readyz))
        // Public landing page — anyone hitting the core in a browser gets a
        // small HTML index with links to the actual dashboard, API endpoints,
        // and CLI examples instead of a bare 404.
        .route("/", get(landing_page))
        // Admin
        .nest("/admin", admin_router())
        // Sprint 2: policy DSL CRUD + evaluate (admin-gated).
        .nest("/v1/stats", stats_router())
        .nest("/v1/policy", policy_router())
        // Sprint 3 follow-up: server-authoritative spend ledger (admin-gated).
        // Closes redteam A3 — local BudgetTracker is no longer the source of truth.
        .nest("/v1/agents", agent_spend_router())
        // Sprint 4: ZK action-log proof verification (admin-gated, DEV vkeys).
        .nest("/v1/proofs", proofs_router())
        // Sprint 7: customer stat aggregation + ZK integrity (admin-gated).
        // Stores per-tenant claimed metric values bound to a Merkle root via
        // the StatsHonestComputation circuit. DP publish lives in Sprint 8.
        // Sprint 8: DP-published cohort surface (admin-gated, operator-global).
        // Aggregates raw stats per cohort, applies Laplace noise per quartile
        // under the cohort's ε budget, suppresses metrics below k-anonymity.
        // S12: security audit log query (admin-gated, tenant-scoped).
        .nest("/v1/admin/audit", audit_router())
        // Sprint 19-20: periodic ZK audit report module.
        // Bundles receipts + stats proofs + anchors + policy events
        // into a signed report a compliance officer can hand to an
        // external auditor.
        .nest("/v1/audit", audit_reports_router())
        // S6: dedicated attestation surface — operators POST raw Nitro
        // COSE_Sign1 blobs at `/v1/attestation/nitro/verify` to validate
        // the document, surface the parsed module_id + PCRs, and confirm
        // the measurement matches their registered expected hash.
        // Sprint 11 multi-tenancy: extract `TenantId` from
        // `x-sauron-tenant-id` header / admin JWT `tnt` claim and attach
        // to request extensions. Falls back to the `"default"` tenant for
        // any legacy caller, preserving the 412-test baseline and the
        // live demo flow. Layered globally so every `/v1/*`, `/admin/*`,
        // and `/agent/*` handler has access via `Extension<TenantId>`.
        // Per-call signature: DEFAULT DENY across the whole /agent/* surface.
        // Applied once here instead of route by route, so a new agent route is
        // protected the moment it exists and must be named in
        // agent::CALL_SIG_EXEMPT_PATHS to be opened. The previous opt-in layout
        // protected whatever someone remembered to annotate — a missing line
        // shipped an unprotected route and broke no test.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            agent::require_call_signature_default_deny,
        ))
        .layer(middleware::from_fn(sauron_tenancy::extract_tenant))
        .layer(middleware::from_fn(http_metrics_middleware))
        // Q4: stamp response security headers (nosniff, XFO/CSP frame-ancestors,
        // Referrer-Policy, HSTS) on every response. Complements the locked-down
        // CORS layer below.
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // H1: global 64KB request-body cap. Per-route overrides (agent PEM
        // registration and native STARK receipts) are applied with a bounded
        // DefaultBodyLimit on only those routes. The body limit short-circuits
        // before the route handler reads the body.
        .layer(DefaultBodyLimit::max(64 * 1024))
        // Last-resort request isolation. Request paths must still avoid
        // panicking while holding shared locks because poisoning can outlive
        // the recovered HTTP response.
        .layer(CatchPanicLayer::custom(handle_request_panic))
        .layer({
            let allowed_origins: Vec<axum::http::HeaderValue> =
                std::env::var("SAURON_ALLOWED_ORIGINS")
                    .unwrap_or_else(|_| "http://localhost:3000,http://localhost:3001".to_string())
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
            if allowed_origins.is_empty() {
                panic!(
                    "[FATAL] SAURON_ALLOWED_ORIGINS resolved to no valid origins. \
                     Set it explicitly or remove the env var to use the localhost default. \
                     Refusing to start with permissive CORS."
                );
            } else {
                // M3: explicit allow-lists for methods + headers. Browser preflight
                // (OPTIONS) inspects Access-Control-Allow-{Methods,Headers}; with
                // `Any` any custom header would pass which widens the abuse surface
                // for cross-origin POSTs. Lock to the verbs + headers actually used
                // by /agent/* + /admin/* + dashboard.
                let allowed_headers: Vec<HeaderName> = vec![
                    CONTENT_TYPE,
                    AUTHORIZATION,
                    // SauronID session/admin
                    HeaderName::from_static("x-sauron-session"),
                    HeaderName::from_static("x-admin-key"),
                    // Per-call signature (call-sig middleware)
                    HeaderName::from_static("x-sauron-agent-id"),
                    HeaderName::from_static("x-sauron-call-ts"),
                    HeaderName::from_static("x-sauron-call-nonce"),
                    HeaderName::from_static("x-sauron-call-sig"),
                    HeaderName::from_static("x-sauron-call-audience"),
                    HeaderName::from_static("x-sauron-protocol-version"),
                    HeaderName::from_static("x-sauron-agent-config-digest"),
                    // Issuer-side enrollment
                    HeaderName::from_static("x-sauron-issuer-key"),
                ];
                CorsLayer::new()
                    .allow_origin(allowed_origins)
                    .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                    .allow_headers(allowed_headers)
            }
        })
        // S12: security audit log middleware. Runs AFTER handlers so the
        // response status is visible (records 401/403/407 failures). Must
        // be outer than the route-level auth layers it observes.
        .layer(middleware::from_fn(audit_log_middleware))
        // S12: global ingress rate limiter. Outermost of the security
        // stack so an unauthenticated brute-force flood never reaches
        // auth, tenant resolution, or any handler.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&global_limiter),
            global_rate_limit_middleware,
        ))
        .with_state(state);

    // Metrics endpoint reads from the global prometheus Registry — no router state needed.
    let metrics_router: Router = Router::new().route("/metrics", get(metrics_handler));
    let app = app.merge(metrics_router);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    {
        // An operator must be able to see the registration ceiling without
        // waiting for a refused registration to tell them.
        let (ok, detail) = sauron_core::licence::status_line();
        if ok {
            tracing::info!(target: "sauron::startup", licence = %detail, "deployment licence");
        } else {
            tracing::warn!(target: "sauron::startup", licence = %detail, "deployment licence");
        }
    }
    tracing::info!(target: "sauron::startup", %addr, "Sauron Server started");

    // `into_make_service_with_connect_info::<SocketAddr>` so the S12 global
    // rate limiter can pull the peer IP from `ConnectInfo` when neither
    // X-Forwarded-For nor X-Real-IP is set by an upstream proxy.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

// The route handlers this binary owns, one file per endpoint group under
// src/main/. A bin root resolves `mod` from src/, hence the #[path].
#[cfg(feature = "demo")]
#[path = "main/user_credentials.rs"]
mod user_credentials;
#[path = "main/vc.rs"]
mod vc;
use vc::*;
#[path = "main/authorize.rs"]
mod authorize;
use authorize::*;
#[path = "main/payment.rs"]
mod payment;
use payment::*;
#[path = "main/session.rs"]
mod session;
use session::*;
#[path = "main/egress.rs"]
mod egress;
use egress::*;

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
