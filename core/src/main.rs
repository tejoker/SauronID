use axum::{
    extract::{DefaultBodyLimit, Json, Request, State},
    http::{
        header::AUTHORIZATION, header::CONTENT_TYPE, HeaderMap, HeaderName, Method, StatusCode,
    },
    middleware,
    routing::{get, post},
    Router,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use hmac::{Hmac, Mac};
use sauron_core::any_db::AnyRowGet;
use sauron_core::error::AppError;
use sauron_core::middleware::{
    audit_log_middleware, global_rate_limit_middleware, handle_request_panic, init_audit_sink,
    security_headers_middleware, GlobalRateLimitConfig, GlobalRateLimiter,
};
use sauron_core::policy::{self, AssuranceLevel};
use sauron_core::risk;
use sauron_core::routes::{
    admin_router, agent_spend_router, audit_reports_router, audit_router, policy_router,
    proofs_router, stats_router,
};
use sauron_core::sql_params;
use sauron_core::tenancy as sauron_tenancy;
use sauron_core::{agent, db, identity::Identity};
use sauron_core::{agent_action, state::ServerState, usage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
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
mod dev_endpoints;
use dev_endpoints::{dev_buy_tokens, dev_leash_demo, dev_oprf_eval, dev_register_user};

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
    let enable_dev_endpoints = std::env::var("SAURON_ENABLE_DEV_ENDPOINTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    let mut app = Router::new();

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

// ─────────────────────────────────────────────────────
//  OPRF
// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
//  Flux 1 : /register — Dépôt KYC → Token A
// ─────────────────────────────────────────────────────

fn validate_user_auth_public_key(value: &str) -> Result<(), AppError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "auth_public_key_b64u must be unpadded base64url".into(),
            )
        })?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "auth_public_key_b64u must decode to 32 bytes".into(),
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "auth_public_key_b64u is not a valid Ed25519 public key".into(),
        )
    })?;
    Ok(())
}

fn store_user_auth_credential(
    state: &Arc<RwLock<ServerState>>,
    tenant_id: &str,
    key_image_hex: &str,
    public_key_b64u: &str,
    now: i64,
) -> Result<(), AppError> {
    validate_user_auth_public_key(public_key_b64u)?;
    let st = state.read_or_recover();
    let mut db = st.db.lock().unwrap();
    db.any_conn()
        .execute(
            "INSERT OR IGNORE INTO user_auth_credentials
         (key_image_hex, ed25519_public_key_b64u, created_at) VALUES (?1, ?2, ?3)",
            sql_params![&key_image_hex, &public_key_b64u, &now],
        )
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                format!("authentication credential conflict: {e}"),
            )
        })?;
    let stored: String = db.any_conn().require(
        "SELECT ed25519_public_key_b64u FROM user_auth_credentials WHERE key_image_hex = ?1",
        sql_params![&key_image_hex],
        |r| r.get(0),
        || {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored credential unreadable".to_string(),
            )
        },
    )?;
    if stored != public_key_b64u {
        return Err((
            StatusCode::CONFLICT,
            "user already has a different authentication key; authenticated rotation is required"
                .into(),
        )
            .into());
    }
    db.any_conn()
        .execute(
            "INSERT OR IGNORE INTO user_auth_tenant_bindings
         (tenant_id, key_image_hex, created_at) VALUES (?1, ?2, ?3)",
            sql_params![&tenant_id, &key_image_hex, &now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

// ─────────────────────────────────────────────────────
//  POST /agent/vc/issue — mint a self-sovereign agent VC
//
//  This is an AGENT credential, not a human one: it binds the agent's
//  ring key, PoP key and checksum to a scope and a TTL, and the
//  autonomous-policy invariant scenario drives the whole autonomous_web3
//  flow through it. The human-identity parts it used to carry — the
//  nationality jurisdiction gate and the issuer-verified Groth16 root of
//  trust — are archived; what is left is the agent binding.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentVcIssueBody {
    /// Human owner's key_image (legacy optional hint; server trusts authenticated session).
    #[serde(default)]
    human_key_image: String,
    /// SHA-256 of agent's behavioral config (tamper detection).
    agent_checksum: String,
    /// Human-readable description of agent's purpose.
    description: String,
    /// JSON array of allowed actions, e.g. ["read:profile", "prove:age", "prove:nationality"].
    scope: Vec<String>,
    /// Agent public key (Ristretto compressed hex) used in delegated-agent ring signatures.
    public_key_hex: String,
    /// Agent ring key image (Ristretto compressed hex) bound to action-time signatures.
    ring_key_image_hex: String,
    /// PoP JWK thumbprint. Mandatory for action endpoints.
    pop_jkt: String,
    /// Ed25519 public key, 32-byte raw as base64url. Mandatory for PoP challenges.
    pop_public_key_b64u: String,
    /// Lifetime hours (default 24, max 720).
    #[serde(default = "default_vc_ttl")]
    ttl_hours: i64,
}

fn default_vc_ttl() -> i64 {
    24
}

async fn agent_vc_issue(
    headers: HeaderMap,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentVcIssueBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()).into());
    }
    if payload.public_key_hex.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_hex is required for action-time ring signatures".into(),
        )
            .into());
    }
    if !payload
        .ring_key_image_hex
        .chars()
        .all(|c| c.is_ascii_hexdigit())
        || payload.ring_key_image_hex.len() != 64
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "ring_key_image_hex is required and must be 32-byte hex".into(),
        )
            .into());
    }
    if payload.pop_jkt.trim().is_empty() || payload.pop_public_key_b64u.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP is mandatory: pop_jkt and pop_public_key_b64u are required".into(),
        )
            .into());
    }

    let agent_point = {
        let bytes = hex::decode(payload.public_key_hex.trim()).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be valid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be 32-byte compressed Ristretto point".into(),
            )
        })?;
        CompressedRistretto(arr).decompress().ok_or((
            StatusCode::BAD_REQUEST,
            "public_key_hex is not a valid Ristretto point".into(),
        ))?
    };

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let human_key_image = agent::session_key_image(&state, &headers, &jwt_secret, &tenant_id)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Valid x-sauron-session header required".into(),
        ))?;
    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "human_key_image payload does not match authenticated session".into(),
        )
            .into());
    }

    // 1. Verify authenticated human exists and resolve trust source.
    let human_pub_hex: String = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_user(&human_key_image)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map(|u| u.public_key_hex)
            .ok_or((
                StatusCode::NOT_FOUND,
                "Human user not found — must be registered in trusted user directory first"
                    .to_string(),
            ))?
    };
    let (human_in_user_ring, has_bank_link) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();

        let has_bank_link: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
            sql_params![&human_key_image],
            |r| r.get_i64(0),
            0,
        ) > 0;

        let bytes = hex::decode(&human_pub_hex).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Human user public key encoding invalid".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Human user public key length invalid".into(),
            )
        })?;
        let pt = CompressedRistretto(arr).decompress().ok_or((
            StatusCode::UNAUTHORIZED,
            "Human user public key point invalid".into(),
        ))?;

        (st.user_group.members.contains(&pt), has_bank_link)
    };

    let vc_issue_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        {
            let st = state.read_or_recover();
            let mut db = st.db.lock().unwrap();
            risk::check_and_increment(
                &mut db.any_conn(),
                &risk::bucket_agent_vc_issue(&tenant_id, &human_key_image),
                vc_issue_ts,
                risk::limit_agent_vc_issue(),
            )
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        }
    }

    // The non-bank root of trust used to be a Groth16 proof verified through an
    // external ZKP issuer. Both are archived under
    // archive/removed-2026-08/groth16-zkp/, so there is exactly one root of trust
    // left and a caller without it gets told that rather than a 500.
    let non_bank_kya_assertions: Option<serde_json::Map<String, serde_json::Value>> = None;
    if !(has_bank_link && human_in_user_ring) {
        return Err((
            StatusCode::BAD_REQUEST,
            "no root of trust for this human: the issuer-verified ZKP path is archived, \
             so the human must have a linked account and be a member of the user ring"
                .to_string(),
        )
            .into());
    }
    let root_of_trust = "did:sauron:idp:bank_kyc".to_string();

    // 2. Uniqueness check — each human may issue at most 10 active VCs, and
    // each action signing key/key-image pair may back only one active agent.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let active_count: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agent_vcs
             WHERE agent_id IN (SELECT agent_id FROM agents WHERE tenant_id = ?1 AND human_key_image = ?2)
             AND revoked = 0 AND expires_at > ?3",
            sql_params![&tenant_id, &human_key_image, now],
            |r| r.get_i64(0),
            0,
        );
        if active_count >= 10 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Maximum 10 active agent VCs per human. Revoke some first.".into(),
            )
                .into());
        }
        // Advisory only — `uq_agents_active_public_key` is the real arbiter, so
        // a registration that races past this check still fails at the INSERT.
        let pub_in_use: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1 AND public_key_hex = ?2 AND revoked = 0 AND expires_at > ?3",
            sql_params![&tenant_id, &payload.public_key_hex, now],
            |r| r.get_i64(0),
            0,
        ) > 0;
        if pub_in_use {
            return Err((
                StatusCode::CONFLICT,
                "public_key_hex already registered to an active agent".into(),
            )
                .into());
        }
        let key_image_in_use: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1 AND ring_key_image_hex = ?2 AND revoked = 0 AND expires_at > ?3",
            sql_params![&tenant_id, &payload.ring_key_image_hex, now],
            |r| r.get_i64(0),
            0,
        ) > 0;
        if key_image_in_use {
            return Err((
                StatusCode::CONFLICT,
                "ring_key_image_hex already registered to an active agent".into(),
            )
                .into());
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ttl_secs = payload.ttl_hours.clamp(1, 720) * 3600;
    let expires_at = now + ttl_secs;

    // 3. Derive agent_id
    let agent_id = {
        let mut h = Sha256::new();
        h.update(payload.agent_checksum.as_bytes());
        h.update(human_key_image.as_bytes());
        h.update(now.to_le_bytes());
        format!("agt_{}", &hex::encode(h.finalize())[..24])
    };
    let intent_json = serde_json::json!({
        "description": payload.description.clone(),
        "scope": payload.scope.clone()
    })
    .to_string();

    // 4. Build VC (self-sovereign, Sauron as issuer)
    let vc = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://sauronid.io/credentials/agent/v1"
        ],
        "id": format!("urn:sauronid:agent-vc:{}", agent_id),
        "type": ["VerifiableCredential", "SauronAgentCredential"],
        "issuer": "did:sauron:idp",
        "issuanceDate": now,
        "expirationDate": expires_at,
        "credentialSubject": {
            "id": format!("did:sauron:agent:{}", agent_id),
            "agentId": agent_id,
            "agentChecksum": payload.agent_checksum.clone(),
            "humanOwner": format!("did:sauron:user:{}", &human_key_image[..16]),
            "description": payload.description.clone(),
            "scope": payload.scope.clone(),
            "agentPublicKey": payload.public_key_hex.clone(),
            "ringKeyImage": payload.ring_key_image_hex.clone(),
            "popThumbprint": payload.pop_jkt.clone(),
            "rootOfTrust": root_of_trust,
            "kyaEvidence": non_bank_kya_assertions,
        },
    });

    // 5. Sign VC with its own HKDF-separated HMAC key.
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let vc_canonical = vc.to_string();
    let vc_key = sauron_core::crypto_protocol::derive_subkey(&jwt_secret, "agent-vc-hmac-v1");
    let mut vc_mac = HmacSha256::new_from_slice(&vc_key).expect("HMAC key");
    vc_mac.update(vc_canonical.as_bytes());
    let vc_hash = hex::encode(vc_mac.finalize().into_bytes());

    // 6. Persist in agents + agent_vcs tables
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        // Register in agents table (so A-JWT flow works normally)
        db.any_conn().execute(
            "INSERT OR REPLACE INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, tenant_id)
             VALUES (?1,?2,?3,?4,'autonomous_web3',?5,?6,?7,?8,0,NULL,0,?9,?10,?11)
             ON CONFLICT(agent_id) DO UPDATE SET
               human_key_image = excluded.human_key_image,
               agent_checksum = excluded.agent_checksum,
               intent_json = excluded.intent_json,
               assurance_level = excluded.assurance_level,
               public_key_hex = excluded.public_key_hex,
               ring_key_image_hex = excluded.ring_key_image_hex,
               issued_at = excluded.issued_at,
               expires_at = excluded.expires_at,
               revoked = excluded.revoked,
               parent_agent_id = excluded.parent_agent_id,
               delegation_depth = excluded.delegation_depth,
               pop_jkt = excluded.pop_jkt,
               pop_public_key_b64u = excluded.pop_public_key_b64u,
               tenant_id = excluded.tenant_id",
            sql_params![
                &agent_id,
                &human_key_image,
                &payload.agent_checksum,
                &intent_json,
                &payload.public_key_hex,
                &payload.ring_key_image_hex,
                now,
                expires_at,
                &payload.pop_jkt,
                &payload.pop_public_key_b64u,
                &tenant_id,
            ],
        ).map_err(|e| {
            // The active-key partial unique indexes are the registration race
            // arbiter; losing that race is a conflict, not a server fault.
            let msg = e.to_lowercase();
            if msg.contains("uq_agents_active") || msg.contains("unique") || msg.contains("duplicate key") {
                (StatusCode::CONFLICT, "public_key_hex or ring_key_image_hex already registered to an active agent".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e)
            }
        })?;

        // Persist VC
        db.any_conn().execute(
            "INSERT OR REPLACE INTO agent_vcs (agent_id, vc_json, vc_hash, issued_at, expires_at)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(agent_id) DO UPDATE SET
               vc_json = excluded.vc_json,
               vc_hash = excluded.vc_hash,
               issued_at = excluded.issued_at,
               expires_at = excluded.expires_at",
            sql_params![&agent_id, &vc_canonical, &vc_hash, now, expires_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    // Add the caller-owned signing key to the in-memory delegated-agent ring.
    {
        let mut st = state.write_or_recover();
        if !st.agent_group.members.contains(&agent_point) {
            st.agent_group.members.push(agent_point);
        }
    }

    // 7. Forge A-JWT so agent can start using it immediately
    let extra = agent::AjwtExtraClaims {
        cnf_jkt: Some(payload.pop_jkt.clone()),
        workflow_id: None,
        delegation_chain: None,
    };
    let ajwt = agent::forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &intent_json,
        &tenant_id,
        ttl_secs,
        Some(&extra),
    );

    {
        let st = state.read_or_recover();
        st.log(
            "AGENT_VC_ISSUE",
            "OK",
            &format!("agent={} human={}", &agent_id[..16], &human_key_image[..16]),
        );
    }

    tracing::info!(
        target: "sauron::kya",
        agent = &agent_id[..16],
        scope = ?payload.scope,
        "self-sovereign VC issued"
    );

    Ok(Json(serde_json::json!({
        "agent_id": agent_id,
        "assurance_level": "autonomous_web3",
        "vc": vc,
        "vc_hash": vc_hash,
        "ajwt": ajwt,
        "agent_public_key_hex": payload.public_key_hex,
        "ring_key_image_hex": payload.ring_key_image_hex,
        "expires_at": expires_at,
        "trust_chain": if has_bank_link && human_in_user_ring {
            "SauronID self-sovereign (bank-linked human trust root)"
        } else {
            "SauronID self-sovereign (non-bank CredentialVerification proof root)"
        },
    })))
}

#[cfg(test)]
mod tests {
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
}

#[derive(Deserialize)]
struct PolicyAuthorizeBody {
    agent_id: String,
    action: String,
    #[serde(default)]
    ajwt: Option<String>,
    #[serde(default)]
    agent_action: Option<agent_action::AgentActionProof>,
}

async fn policy_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<PolicyAuthorizeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_id.is_empty() || payload.action.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id and action are required".into(),
        )
            .into());
    }

    let ajwt = payload.ajwt.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "ajwt is required for policy authorization".into(),
    ))?;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let claims = agent::verify_ajwt_for_tenant(&jwt_secret, ajwt, &tenant_id)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;
    let claim_agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?;
    if claim_agent_id != payload.agent_id {
        return Err((StatusCode::UNAUTHORIZED, "A-JWT agent_id mismatch".into()).into());
    }
    let human_key_image = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".into()))?
        .to_string();
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".into()))?
        .to_string();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".into()))?;
    let intent = parse_ajwt_intent_claim(&claims)?;

    let (assurance_level, revoked, expires_at, db_human, pop_jkt): (
        String,
        i64,
        i64,
        String,
        String,
    ) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        db.any_conn().require(
            "SELECT assurance_level, revoked, expires_at, human_key_image, IFNULL(pop_jkt, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
            sql_params![&tenant_id, &payload.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            || (StatusCode::NOT_FOUND, "Agent not found".to_string()),
        )?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if revoked != 0 || expires_at < now || db_human != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Agent is revoked or expired".into(),
        )
            .into());
    }

    let decision =
        policy::authorize_action(AssuranceLevel::from_db(&assurance_level), &payload.action);
    if !decision.allowed {
        return Ok(Json(serde_json::json!({
            "agent_id": payload.agent_id,
            "action": payload.action,
            "assurance_level": assurance_level,
            "allowed": false,
            "reason": decision.reason,
            "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        })));
    }

    let proof = payload.agent_action.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "agent_action is required for policy authorization".into(),
    ))?;
    let resource = payload.action.clone();
    let validated = agent_action::validate_agent_action(
        &state,
        proof,
        agent_action::ValidateAgentActionOptions {
            tenant_id: &tenant_id,
            agent_id: &payload.agent_id,
            human_key_image: &human_key_image,
            ajwt_jti: &jti,
            intent: Some(&intent),
            expected_action: &payload.action,
            expected_resource: Some(&resource),
            expected_merchant_id: Some(""),
            expected_amount_minor: Some(0),
            expected_currency: Some(""),
            pop_jkt: Some(&pop_jkt),
            status: "accepted",
        },
    )?;
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&mut db.any_conn(), &jti, exp)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    }

    Ok(Json(serde_json::json!({
        "agent_id": payload.agent_id,
        "action": payload.action,
        "assurance_level": assurance_level,
        "allowed": true,
        "reason": decision.reason,
        "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        "action_receipt": validated.receipt,
    })))
}

#[derive(Deserialize)]
struct AgentPaymentAuthorizeBody {
    /// Agent token minted by /agent/register or /agent/vc/issue.
    ajwt: String,
    /// Requested charge amount in minor units (e.g. cents).
    amount_minor: i64,
    /// ISO-4217 3-letter currency code.
    currency: String,
    /// Merchant-side idempotency/payment reference.
    payment_ref: String,
    /// Optional merchant account / destination identifier.
    #[serde(default)]
    merchant_id: String,
    /// Mandatory for payment authorization (PoP).
    #[serde(default)]
    pop_challenge_id: String,
    /// Mandatory for payment authorization (PoP).
    #[serde(default)]
    pop_jws: String,
    /// Canonical action envelope + ring signature for the cryptographic leash.
    agent_action: agent_action::AgentActionProof,
}

fn parse_ajwt_intent_claim(claims: &serde_json::Value) -> Result<serde_json::Value, AppError> {
    match claims.get("intent") {
        Some(serde_json::Value::String(s)) => serde_json::from_str::<serde_json::Value>(s)
            .map_err(|_| AppError::Unauthorized("A-JWT intent is not valid JSON".into())),
        Some(v @ serde_json::Value::Object(_)) => Ok(v.clone()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "A-JWT missing intent claim".into(),
        )
            .into()),
    }
}

fn payment_scopes_from_intent(intent: &serde_json::Value) -> Vec<String> {
    if let Some(arr) = intent.get("scope").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(arr) = intent
        .get("constraints")
        .and_then(|v| v.get("scope"))
        .and_then(|v| v.as_array())
    {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(action) = intent.get("action").and_then(|v| v.as_str()) {
        let normalized = action.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            return vec![normalized];
        }
    }
    Vec::new()
}

fn enforce_strict_payment_intent(
    intent: &serde_json::Value,
    amount_minor: i64,
    request_currency: &str,
    request_merchant_id: &str,
) -> Result<(), AppError> {
    let scopes = payment_scopes_from_intent(intent);
    if !scopes.iter().any(|s| s == "payment_initiation") {
        return Err((
            StatusCode::FORBIDDEN,
            "Intent scope must explicitly include payment_initiation".into(),
        )
            .into());
    }

    let max_amount_major = intent.get("maxAmount").and_then(|v| v.as_f64()).ok_or((
        StatusCode::FORBIDDEN,
        "Intent must define numeric maxAmount for payments".into(),
    ))?;
    if !(max_amount_major.is_finite() && max_amount_major > 0.0) {
        return Err((StatusCode::FORBIDDEN, "Intent maxAmount must be > 0".into()).into());
    }
    let max_minor = (max_amount_major * 100.0).round() as i64;
    if amount_minor > max_minor {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested amount {} exceeds intent maxAmount {} {} ({} minor units)",
                amount_minor, max_amount_major, request_currency, max_minor
            ),
        )
            .into());
    }

    let intent_currency = intent
        .get("currency")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_uppercase())
        .ok_or((
            StatusCode::FORBIDDEN,
            "Intent must define currency for payments".into(),
        ))?;
    if intent_currency != request_currency {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested currency {} does not match intent currency {}",
                request_currency, intent_currency
            ),
        )
            .into());
    }

    let merchant_allowlist = intent
        .get("constraints")
        .and_then(|v| v.get("merchant_allowlist"))
        .and_then(|v| v.as_array());
    if let Some(allowlist) = merchant_allowlist {
        if request_merchant_id.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "merchant_id is required by intent constraints.merchant_allowlist".into(),
            )
                .into());
        }
        let allowed = allowlist.iter().any(|m| {
            m.as_str()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s == request_merchant_id)
                .unwrap_or(false)
        });
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "merchant_id '{}' is not allowed by intent",
                    request_merchant_id
                ),
            )
                .into());
        }
    }

    Ok(())
}

async fn agent_payment_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<AgentPaymentAuthorizeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.ajwt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "ajwt is required".into()).into());
    }
    if payload.amount_minor <= 0 {
        return Err((StatusCode::BAD_REQUEST, "amount_minor must be > 0".into()).into());
    }
    if payload.payment_ref.trim().is_empty() || payload.payment_ref.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "payment_ref is required (1..128 chars)".into(),
        )
            .into());
    }
    let payment_ref = payload.payment_ref.trim().to_string();
    let merchant_id = payload.merchant_id.trim().to_string();
    let currency = payload.currency.trim().to_ascii_uppercase();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "currency must be a 3-letter ISO uppercase code".into(),
        )
            .into());
    }

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let claims = agent::verify_ajwt_for_tenant(&jwt_secret, &payload.ajwt, &tenant_id)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;

    let human_key_image = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".into()))?
        .to_string();
    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?
        .to_string();

    // Global blast-radius ceiling — a hard circuit-breaker that no policy (broad,
    // missing, or misconfigured) and no enforcement mode can override. Uses the
    // same minor→major USD-equivalent convention as the policy engine.
    if let Some(max_usd) = sauron_core::runtime_mode::global_max_action_usd() {
        let amount_usd = payload.amount_minor as f64 / 100.0;
        if amount_usd > max_usd {
            tracing::warn!(
                target: "sauron::policy::blast_radius",
                %agent_id,
                amount_usd,
                max_usd,
                "payment refused by global per-action ceiling (SAURON_MAX_ACTION_USD)",
            );
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "payment {amount_usd:.2} exceeds the global per-action ceiling {max_usd:.2} (SAURON_MAX_ACTION_USD)"
                ),
            ).into());
        }
    }

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".into()))?
        .to_string();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".into()))?;

    let intent = parse_ajwt_intent_claim(&claims)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        risk::check_and_increment(
            &mut db.any_conn(),
            &risk::bucket_payment_authorize(&tenant_id, &agent_id),
            now,
            risk::limit_payment_authorize(),
        )
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
    }

    let (assurance_level, pop_jkt) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, assurance, pop_jkt, pop_pk_b64u): (i64, i64, String, String, String, String) = db
            .any_conn()
            .require(
                "SELECT revoked, expires_at, human_key_image, assurance_level, IFNULL(pop_jkt, ''), IFNULL(pop_public_key_b64u, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                sql_params![&tenant_id, &agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                || (StatusCode::NOT_FOUND, "Agent not found".to_string()),
            )?;
        if revoked != 0 {
            return Err((StatusCode::UNAUTHORIZED, "Agent has been revoked".into()).into());
        }
        if expires_at < now {
            return Err((StatusCode::UNAUTHORIZED, "Agent has expired".into()).into());
        }
        if db_human != human_key_image {
            return Err((StatusCode::UNAUTHORIZED, "Agent owner mismatch".into()).into());
        }
        if pop_jkt.is_empty() || pop_pk_b64u.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires PoP-enabled agent registration".into(),
            )
                .into());
        }
        if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires pop_challenge_id and pop_jws from /agent/pop/challenge".into(),
            ).into());
        }
        // TODO M2-callsite-sweep: sync take_pop_challenge inside a held
        // MutexGuard; Repo::take_pop_challenge exists for the post-sweep
        // async port. SELECT+DELETE is wrapped in BEGIN IMMEDIATE today.
        let challenge_plain = sauron_core::ajwt_support::take_pop_challenge(
            &mut db.any_conn(),
            &payload.pop_challenge_id,
            &agent_id,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        sauron_core::ajwt_support::verify_ed25519_pop_jws(
            &challenge_plain,
            &payload.pop_jws,
            &pop_pk_b64u,
        )
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        (assurance, pop_jkt)
    };

    let decision = policy::authorize_action(
        AssuranceLevel::from_db(&assurance_level),
        "payment_initiation",
    );
    if !decision.allowed {
        return Err((
            StatusCode::FORBIDDEN,
            format!("Policy denied payment_initiation: {}", decision.reason),
        )
            .into());
    }

    // Server-bound policy for this payment. The metadata keys are the ones a
    // payment can actually attest to; a policy that also declares an egress-shaped
    // cap (payload size, recipient count) will now DENY here rather than silently
    // pass, which is the correct reading of a constraint this action cannot report.
    {
        let intent_tool = intent
            .get("tool")
            .and_then(|v| v.as_str())
            .or_else(|| intent.get("action").and_then(|v| v.as_str()))
            .unwrap_or("payment_initiation")
            .to_string();
        let mut bound_action = sauron_core::policy::Action {
            action_id: format!("payauth-{jti}"),
            tool: intent_tool,
            amount_usd: Some(payload.amount_minor as f64 / 100.0),
            timestamp: now,
            ..Default::default()
        };
        bound_action
            .metadata
            .insert("currency".into(), serde_json::json!(currency.clone()));
        bound_action
            .metadata
            .insert("merchant_id".into(), serde_json::json!(merchant_id.clone()));
        sauron_core::policy::handlers::gate_action_on_bound_policy(
            &state,
            &tenant_id,
            &agent_id,
            &bound_action,
            "/agent/payment/authorize",
        )
        .await?;
    }

    enforce_strict_payment_intent(&intent, payload.amount_minor, &currency, &merchant_id)?;

    let validated = agent_action::validate_agent_action(
        &state,
        &payload.agent_action,
        agent_action::ValidateAgentActionOptions {
            tenant_id: &tenant_id,
            agent_id: &agent_id,
            human_key_image: &human_key_image,
            ajwt_jti: &jti,
            intent: Some(&intent),
            expected_action: "payment_initiation",
            expected_resource: Some(&payment_ref),
            expected_merchant_id: Some(&merchant_id),
            expected_amount_minor: Some(payload.amount_minor),
            expected_currency: Some(&currency),
            pop_jkt: Some(&pop_jkt),
            status: "accepted",
        },
    )?;

    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&mut db.any_conn(), &jti, exp)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    }

    let auth_id = format!("payauth_{}", sauron_core::ajwt_support::random_hex_32());
    let expires_at = std::cmp::min(exp, now + 300);
    // M2 port: insert payment authorization via dual-backend repo helper.
    {
        let repo = {
            let st = state.read_or_recover();
            st.repo.clone()
        };
        repo.insert_payment_authorization(
            &tenant_id,
            &auth_id,
            &agent_id,
            &jti,
            payload.amount_minor,
            &currency,
            &merchant_id,
            &payment_ref,
            now,
            expires_at,
        )
        .await
        .map_err(|e| match e {
            sauron_core::repository::RepoError::Replay(s) => (StatusCode::CONFLICT, s),
            sauron_core::repository::RepoError::Backend(s) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {s}"))
            }
        })?;
    }

    Ok(Json(serde_json::json!({
        "authorized": true,
        "authorization_id": auth_id,
        "agent_id": claims.get("agent_id").and_then(|v| v.as_str()).unwrap_or_default(),
        "amount_minor": payload.amount_minor,
        "currency": currency,
        "merchant_id": merchant_id,
        "payment_ref": payment_ref,
        "assurance_level": assurance_level,
        "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        "action_receipt": validated.receipt,
        "expires_at": expires_at,
        "controls": {
            "risk": { "window_secs": risk::window_secs() },
        },
    })))
}

// ─────────────────────────────────────────────────────
//  Helpers: user session
// ─────────────────────────────────────────────────────
//
// Minting and verification live in `sauron_core::user_session`. They used to be
// duplicated here, which is how the binary ended up issuing `v2` tokens that the
// agent routes — already ported to the module — refused on arrival. One
// implementation, one token version.

/// Mint a session bound to the owner's CURRENT epoch.
///
/// Reading the epoch at mint time is what keeps `issue` and `verify` agreeing:
/// a token minted under a stale epoch is dead the moment it is used.
fn issue_session_for(
    state: &Arc<RwLock<ServerState>>,
    jwt_secret: &[u8],
    tenant_id: &str,
    key_image: &str,
) -> Result<(String, i64), AppError> {
    let epoch = {
        let st = state.read_or_recover();
        let mut db = st
            .db
            .lock()
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
        sauron_core::user_session::current_epoch(&mut db.any_conn(), key_image)
    };
    Ok(sauron_core::user_session::issue(
        jwt_secret, tenant_id, key_image, epoch,
    ))
}

// ─────────────────────────────────────────────────────
//  POST /user/auth — email+password → session token
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAuthChallengeBody {
    key_image_hex: String,
}

#[derive(Serialize)]
struct UserAuthChallengeResponse {
    challenge_id: String,
    nonce: String,
    expires_at: i64,
    signing_payload_b64u: String,
}

async fn user_auth_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<UserAuthChallengeBody>,
) -> Result<Json<UserAuthChallengeResponse>, AppError> {
    use base64::Engine as _;

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let key_image = payload.key_image_hex.trim().to_ascii_lowercase();
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "key_image_hex must be 32-byte hex".into(),
        )
            .into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let expires_at = now + 120;
    let challenge_id = format!("uac_{}", sauron_core::ajwt_support::random_hex_32());
    let nonce = sauron_core::ajwt_support::random_hex_32();
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let _ = db.any_conn().execute(
            "DELETE FROM user_auth_challenges WHERE expires_at < ?1 OR used_at > 0",
            sql_params![now - 300],
        );
        let total: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM user_auth_challenges",
            sql_params![],
            |r| r.get_i64(0),
            0,
        );
        let active_for_subject: i64 = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM user_auth_challenges
                 WHERE tenant_id = ?1 AND key_image_hex = ?2 AND used_at = 0 AND expires_at >= ?3",
            sql_params![&tenant_id, &key_image, now],
            |r| r.get_i64(0),
            0,
        );
        if total >= 100_000 || active_for_subject >= 5 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "authentication challenge capacity exceeded".into(),
            )
                .into());
        }
        // Insert even for an unknown key image so the response shape and timing
        // do not become a reliable account-enumeration oracle.
        db.any_conn()
            .execute(
                "INSERT INTO user_auth_challenges
             (challenge_id, tenant_id, key_image_hex, nonce, expires_at, used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                sql_params![&challenge_id, &tenant_id, &key_image, &nonce, expires_at],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    let signing_payload = sauron_core::crypto_protocol::user_auth_challenge_payload(
        &challenge_id,
        &tenant_id,
        &key_image,
        &nonce,
        expires_at,
    );
    Ok(Json(UserAuthChallengeResponse {
        challenge_id,
        nonce,
        expires_at,
        signing_payload_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_payload),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAuthFinishBody {
    challenge_id: String,
    key_image_hex: String,
    signature_b64u: String,
}

async fn user_auth_finish(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<UserAuthFinishBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    use base64::Engine as _;

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let key_image = payload.key_image_hex.trim().to_ascii_lowercase();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (nonce, expires_at, public_key_b64u, jwt_secret) = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let challenge: (String, i64) = db.any_conn().require(
            "SELECT nonce, expires_at FROM user_auth_challenges
                 WHERE challenge_id = ?1 AND tenant_id = ?2 AND key_image_hex = ?3
                   AND used_at = 0 AND expires_at >= ?4",
            sql_params![&payload.challenge_id, &tenant_id, &key_image, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
            || {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authentication proof".to_string(),
                )
            },
        )?;
        let public_key: String = db.any_conn().require(
            "SELECT c.ed25519_public_key_b64u
                 FROM user_auth_credentials c
                 JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
                 WHERE c.key_image_hex = ?1 AND b.tenant_id = ?2",
            sql_params![&key_image, &tenant_id],
            |r| r.get_string(0),
            || {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authentication proof".to_string(),
                )
            },
        )?;
        (challenge.0, challenge.1, public_key, st.jwt_secret.clone())
    };
    let public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&public_key_b64u)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid authentication proof".into(),
        ))?;
    let signature: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.signature_b64u.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid authentication proof".into(),
        ))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid authentication proof".into(),
        )
    })?;
    let signed = sauron_core::crypto_protocol::user_auth_challenge_payload(
        &payload.challenge_id,
        &tenant_id,
        &key_image,
        &nonce,
        expires_at,
    );
    verifying_key
        .verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid authentication proof".into(),
            )
        })?;

    // Consume only after a valid signature. The conditional write is the
    // replay arbiter if two valid finishes race; exactly one receives a session.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        let consumed = db
            .any_conn()
            .execute(
                "UPDATE user_auth_challenges SET used_at = ?1
                 WHERE challenge_id = ?2 AND tenant_id = ?3 AND key_image_hex = ?4
                   AND used_at = 0 AND expires_at >= ?1",
                sql_params![now, &payload.challenge_id, &tenant_id, &key_image],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if consumed != 1 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "invalid authentication proof".into(),
            )
                .into());
        }
    }
    let (session, session_expires_at) =
        issue_session_for(&state, &jwt_secret, &tenant_id, &key_image)?;
    Ok(Json(serde_json::json!({
        "session": session,
        "key_image": key_image,
        "expires_at": session_expires_at,
        "authentication": "ed25519_challenge_v1"
    })))
}

#[derive(Deserialize)]
struct UserAuthBody {
    email: String,
    password: String,
}

async fn user_auth(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<UserAuthBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let enabled = sauron_core::runtime_mode::require_or_default(
        "SAURON_ENABLE_LEGACY_OPRF_AUTH",
        /* dev_default */ true,
        /* prod_default */ false,
    );
    if !enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "password-derived legacy identity authentication is disabled in production; use /user/auth/challenge and /user/auth/finish".into(),
        ).into());
    }
    let (server_k, jwt_secret) = {
        let st = state.read_or_recover();
        (st.k, st.jwt_secret.clone())
    };
    let oprf_result = dev_oprf_eval(server_k, &payload.email, &payload.password);
    let identity = Identity::from_oprf(oprf_result);
    {
        let st = state.read_or_recover();
        if !st.user_group.members.contains(&identity.public) {
            return Err((StatusCode::UNAUTHORIZED, "User not registered".into()).into());
        }
    }
    let key_image = hex::encode(identity.key_image().compress().as_bytes());
    let profile: Option<(String, String)> = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_user(&key_image)
            .await
            .ok()
            .flatten()
            .map(|u| (u.first_name, u.last_name))
    };
    let (session, expires_at) = issue_session_for(&state, &jwt_secret, &tenant_id, &key_image)?;
    Ok(Json(serde_json::json!({
        "session": session,
        "key_image": key_image,
        "expires_at": expires_at,
        "first_name": profile.as_ref().map(|p| &p.0).unwrap_or(&String::new()),
        "last_name":  profile.as_ref().map(|p| &p.1).unwrap_or(&String::new()),
    })))
}

// ─────────────────────────────────────────────────────
//  GET /user/consents — list all consents for user
// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
//  DELETE /user/consent/{request_id} — revoke a consent
// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
//  GET /user/credential — fetch BabyJubJub VC for ZKP proofs (frictionless)
//
//  Called automatically by the consent popup after the user authenticates.
//  No extra user action needed — credential retrieved in background.
// ─────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────
//  POST /agent/egress/log — voluntary outbound-call reporting (Gap 2)
//
//  Operators wire their agent runtime to call this endpoint BEFORE making any
//  third-party API request. Each row is included in the next agent-action
//  anchor batch, making after-the-fact log tampering require forging Bitcoin
//  AND Solana attestations of the matching merkle root.
//
//  This endpoint is GATED BY require_call_signature in the router, so the
//  reported event is bound to the specific agent + signed by its PoP key +
//  carries the matching x-sauron-agent-config-digest. An attacker who can
//  flip the agent runtime's behaviour cannot forge a log entry without ALSO
//  matching the registered checksum — at which point they had to call
//  /agent/<id>/checksum/update first, and that's audited.
//
//  This legacy telemetry endpoint is disabled by default in production. It
//  cannot prove interception; production agents must use the one-use
//  capability flow at /agent/egress/capability + /agent/egress/proxy.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentEgressLogBody {
    agent_id: String,
    target_host: String,
    #[serde(default)]
    target_path: String,
    method: String,
    #[serde(default)]
    body_hash_hex: String,
    #[serde(default)]
    status_code: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPaymentConsumeBody {
    authorization_id: String,
}

/// POST /agent/payment/consume — redeem a payment authorization exactly once.
///
/// `/agent/payment/authorize` minted authorizations that nothing could spend:
/// `Repo::consume_payment_authorization` — the atomic single-use flip, written
/// for both backends and covered by unit tests — had no route reaching it, and
/// `docs/active-route-map.md` advertised a `/merchant/payment/consume` that was
/// never implemented. An authorization that cannot be consumed is not a
/// capability, it is a receipt.
///
/// Mounted under `/agent/` deliberately: that prefix is where the default-deny
/// per-call signature layer applies, so this route is signed, nonce-bound and
/// config-digest-checked without being added to `CALL_SIG_EXEMPT_PATHS`. The
/// middleware has already authenticated the caller by the time this runs; the
/// handler only has to bind the claim to the signer and consume.
///
/// The consume is the security-relevant part. `consumed = 1 WHERE consumed = 0`
/// under `BEGIN IMMEDIATE` (SQLite) or `FOR UPDATE` (Postgres) means a
/// concurrent burst on one authorization produces exactly one 200 and N-1
/// 409s — the double-spend property, on the agent path rather than the retired
/// KYC one.
async fn agent_payment_consume(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentPaymentConsumeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let auth_id = payload.authorization_id.trim().to_string();
    if auth_id.is_empty() || auth_id.len() > 128 {
        return Err(AppError::with_hint(
            StatusCode::BAD_REQUEST,
            "authorization_id_invalid",
            "authorization_id is required (1..128 chars)",
            "pass the authorization_id returned by POST /agent/payment/authorize",
        ));
    }

    // The signature proves who is calling; this proves the authorization being
    // spent belongs to them. Without it any signed agent could redeem another
    // agent's authorization by id within the same tenant.
    let signer = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let repo = {
        let st = state.read_or_recover();
        st.repo.clone()
    };
    let owner = repo
        .payment_authorization_agent(&tenant_id, &auth_id)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    match owner {
        None => {
            return Err(AppError::with_hint(
                StatusCode::NOT_FOUND,
                "authorization_not_found",
                "no such payment authorization in this tenant",
                "check the authorization_id and the x-sauron-tenant-id header",
            ))
        }
        Some(agent_id) if agent_id != signer => {
            return Err(AppError::with_hint(
                StatusCode::FORBIDDEN,
                "authorization_not_yours",
                "payment authorization belongs to a different agent",
                "only the agent that obtained the authorization may consume it",
            ))
        }
        Some(_) => {}
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    repo.consume_payment_authorization(&tenant_id, &auth_id, now)
        .await
        .map_err(|e| match e {
            sauron_core::repository::RepoError::Replay(s) => AppError::with_hint(
                StatusCode::CONFLICT,
                "authorization_already_consumed",
                s,
                "a payment authorization is single-use; obtain a new one via POST /agent/payment/authorize",
            ),
            sauron_core::repository::RepoError::Backend(s) => AppError::internal(s),
        })?;

    {
        let st = state.read_or_recover();
        st.log("AGENT_PAYMENT_CONSUME", "OK", &auth_id);
    }
    Ok(Json(serde_json::json!({
        "consumed": true,
        "authorization_id": auth_id,
    })))
}

async fn agent_egress_log(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentEgressLogBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let enabled = sauron_core::runtime_mode::require_or_default(
        "SAURON_ENABLE_VOLUNTARY_EGRESS_LOG",
        true,
        false,
    );
    if !enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "voluntary egress telemetry is disabled in production; use the one-use capability gateway"
                .into(),
        ).into());
    }
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_id.is_empty() || payload.target_host.is_empty() || payload.method.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id, target_host, method are required".into(),
        )
            .into());
    }
    let signed_agent = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if signed_agent != payload.agent_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "egress log agent_id does not match signed caller".into(),
        )
            .into());
    }
    if !payload.body_hash_hex.is_empty()
        && (payload.body_hash_hex.len() != 64
            || !payload.body_hash_hex.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "body_hash_hex must be empty or 32-byte hex".into(),
        )
            .into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let id = {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        // Shared with the enforcing proxy (/agent/egress/proxy) so both log +
        // anchor identically. Voluntary reports are always `allowed = true`.
        sauron_core::egress_gateway::record_egress(
            &mut db.any_conn(),
            &tenant_id,
            &payload.agent_id,
            &payload.target_host,
            &payload.target_path,
            &payload.method,
            &payload.body_hash_hex,
            payload.status_code,
            true,
            now,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };
    Ok(Json(serde_json::json!({ "id": id, "ts": now })))
}

// ─────────────────────────────────────────────────────
//  POST /agent/vc/issue — self-sovereign agent VC (KYA without banks)
//
//  Protocol:
//    1. Human proves liveness (passed as liveness_proof).
//       In prod: OPRF key_image proves uniqueness, liveness_confidence proves humanness.
//       In dev: accepted if confidence ≥ 0.7 (mock provider).
//    2. Sauron verifies the human is unique (key_image must not have issued >N VCs).
//    3. Sauron issues a signed Agent VC:
//         - agent_id, agent_checksum, human_key_image
//         - scope (what the agent may do)
//         - timestamp + expiry
//         - Merkle-committed (tamper-evident log)
//       Signed with server JWT secret (same trust anchor as A-JWT).
//    4. VC stored in agent_vcs table.
//    5. Optional: agent_checksum anchored to on-chain AgentDelegationRegistry
//       (existing Solana/EVM contracts).
//
//  Trust chain: SauronID server key → VC → agent_id
//  Verification by retail site: POST /agent/verify with A-JWT → server returns VC proof.
// ─────────────────────────────────────────────────────
