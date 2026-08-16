use axum::{
    body::{to_bytes, Body},
    extract::{DefaultBodyLimit, Extension, Json, Path, Request, State},
    http::{
        header::AUTHORIZATION, header::CONTENT_TYPE, HeaderMap, HeaderName, Method, StatusCode,
    },
    middleware,
    routing::{delete, get, post},
    Router,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::Identity as _;
use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use rusqlite::params;
use sauron_core::any_db::{AnyRowGet, AsAnyConn};
use sauron_core::compliance;
use sauron_core::crypto_protocol::{partner_registration_payload, PartnerRegistrationInput};
use sauron_core::issuer_runtime::IssuerVerifyError;
use sauron_core::middleware::{
    audit_log_middleware, global_rate_limit_middleware, handle_request_panic, init_audit_sink,
    security_headers_middleware, GlobalRateLimitConfig, GlobalRateLimiter,
};
use sauron_core::policy::{self, AssuranceLevel};
use sauron_core::risk;
use sauron_core::routes::{
    admin_router, agent_spend_router, attestation_router, audit_reports_router, audit_router,
    cohort_router, policy_router, proofs_router, stats_router,
};
use sauron_core::sql_params;
use sauron_core::tenancy as sauron_tenancy;
use sauron_core::{
    agent, db,
    identity::{Identity, UserData},
};
use sauron_core::{agent_action, oprf, ring, state::ServerState, usage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

type HmacSha256 = Hmac<Sha256>;

fn assert_production_sqlite_acknowledged() {
    if sauron_core::runtime_mode::is_development_runtime() {
        return;
    }
    // The single-node SQLite tier is load-bearing in EVERY production config.
    // Even with SAURON_DB_BACKEND=postgres, only a subset of tables are ported
    // to the Repo/Postgres path (see core/tests/postgres_backend_drift.sh) — the
    // rest (agents, agent_action_receipts, spend_ledger, …) still write to the
    // local SQLite sidecar, which is NOT covered by the operator's Postgres HA.
    // So the acknowledgement is required regardless of backend until the port
    // is complete; re-add a postgres bypass here only when the drift test flips.
    let ok = std::env::var("SAURON_ACCEPT_SINGLE_NODE_SQLITE")
        .map(|v| {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        })
        .unwrap_or(false);
    if !ok {
        panic!(
            "[FATAL] SQLite is single-node (no cross-region HA) and stays load-bearing even under SAURON_DB_BACKEND=postgres (partial port — see core/tests/postgres_backend_drift.sh). Set SAURON_ACCEPT_SINGLE_NODE_SQLITE=1 to acknowledge this deployment, or finish the Postgres port before claiming global production readiness."
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
    let path = req.uri().path().to_string();
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

    let mut app = Router::new()
        // OPRF
        .route("/oprf", post(handle_oprf))
        // Flux 1: dépôt KYC
        .route("/register", post(handle_register));

    if enable_dev_endpoints {
        app = app
            .route("/dev/register_user", post(dev_register_user))
            .route("/dev/buy_tokens", post(dev_buy_tokens))
            .route("/dev/leash/demo", post(dev_leash_demo))
            .route("/dev/consent_profile", post(dev_consent_profile));
    }

    let app = app
        .route("/bank/register", post(bank_register_user))
        .route("/register/bank", post(bank_register_user))
        // ZKP
        .route("/zkp/proof_material", post(handle_zkp_proof_material))
        // A-JWT Agentic Layer
        // H1: PEM cert chains (TPM2 EK + attestation) can exceed the global
        // 64KB body cap. Lift only this route to 1MB.
        .route(
            "/agent/register",
            post(agent::register_agent).route_layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route("/agent/token", post(agent::issue_agent_token))
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
        // Phase 4: report token usage for a prior anon receipt (gated likewise).
        .route("/agent/usage", post(usage::record_usage_handler))
        .route("/agent/payment/authorize", post(agent_payment_authorize))
        .route("/policy/authorize", post(policy_authorize))
        .route("/agent/list/{human_key_image}", get(agent::list_agents))
        .route(
            "/agent/{agent_id}/checksum/update",
            post(agent::update_agent_checksum),
        )
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
        // User consent flow (KYC retrieval with explicit user consent)
        .route("/kyc/request", post(kyc_request))
        .route("/kyc/consent", post(kyc_consent))
        .route("/kyc/consent_info/{request_id}", get(kyc_consent_info))
        .route(
            "/kyc/retrieve",
            post(kyc_retrieve).route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                delegated_agent_binding_middleware,
            )),
        )
        // User self-service (manage own consents + agents)
        .route("/user/auth", post(user_auth))
        .route("/user/auth/challenge", post(user_auth_challenge))
        .route("/user/auth/finish", post(user_auth_finish))
        .route("/user/consents", get(user_consents))
        .route("/user/credential", get(user_get_credential))
        .route("/user/consent/{request_id}", delete(user_revoke_consent))
        // Agent KYC consent flow (agent acts on behalf of human)
        .route("/agent/kyc/consent", post(agent_kyc_consent))
        // Self-sovereign agent VC (KYA without banks)
        .route("/agent/vc/issue", post(agent_vc_issue))
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
        .nest("/v1/policy", policy_router())
        // Sprint 3 follow-up: server-authoritative spend ledger (admin-gated).
        // Closes redteam A3 — local BudgetTracker is no longer the source of truth.
        .nest("/v1/agents", agent_spend_router())
        // Sprint 4: ZK action-log proof verification (admin-gated, DEV vkeys).
        .nest("/v1/proofs", proofs_router())
        // Sprint 7: customer stat aggregation + ZK integrity (admin-gated).
        // Stores per-tenant claimed metric values bound to a Merkle root via
        // the StatsHonestComputation circuit. DP publish lives in Sprint 8.
        .nest("/v1/stats", stats_router())
        // Sprint 8: DP-published cohort surface (admin-gated, operator-global).
        // Aggregates raw stats per cohort, applies Laplace noise per quartile
        // under the cohort's ε budget, suppresses metrics below k-anonymity.
        .nest("/v1/cohort", cohort_router())
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
        .nest("/v1/attestation", attestation_router())
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

#[derive(Deserialize)]
struct OprfRequest {
    blinded_point: Vec<u8>,
}

#[derive(Serialize)]
struct OprfResponse {
    evaluated_point: Vec<u8>,
}

async fn handle_oprf(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<OprfRequest>,
) -> Result<Json<OprfResponse>, (StatusCode, String)> {
    let enabled = sauron_core::runtime_mode::require_or_default(
        "SAURON_ENABLE_LEGACY_OPRF",
        /* dev_default */ true,
        /* prod_default */ false,
    );
    if !enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "legacy unauthenticated OPRF is quarantined in production; deploy an independently reviewed OPAQUE service or explicitly set SAURON_ENABLE_LEGACY_OPRF=1".into(),
        ));
    }
    let bytes: [u8; 32] = payload.blinded_point.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "blinded_point must be 32 bytes".into(),
        )
    })?;
    let compressed = CompressedRistretto::from_slice(&bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid Ristretto encoding".into()))?;
    let point = compressed
        .decompress()
        .ok_or((StatusCode::BAD_REQUEST, "invalid Ristretto point".into()))?;
    if point == RistrettoPoint::identity() {
        return Err((
            StatusCode::BAD_REQUEST,
            "identity point is not a valid OPRF input".into(),
        ));
    }
    let st = state.read_or_recover();
    let evaluated = oprf::server_evaluate(point, st.k);
    Ok(Json(OprfResponse {
        evaluated_point: evaluated.compress().as_bytes().to_vec(),
    }))
}

// ─────────────────────────────────────────────────────
//  Flux 1 : /register — Dépôt KYC → Token A
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    /// Clé publique OPRF de l'utilisateur (dérivée de email+password).
    public_key: Vec<u8>,
    /// key_image de l'utilisateur = secret * H(public). Permet la recherche en Flux 3.
    key_image: Vec<u8>,
    /// Données KYC de l'utilisateur.
    profile: UserData,
    /// Ring Signature du site partenaire sur le message = hex(public_key).
    /// Prouve qu'un client légitime soumet ce KYC — mais lequel reste anonyme.
    client_signature: ring::RingSignature,
    /// [MERKLE] Commitment cryptographique du client : SHA256(secret_client) encodé en hex.
    /// Le client conserve son secret ; Sauron s'engage sur le commitment dans l'arbre de Merkle.
    /// Champ optionnel — si absent, la réponse n'inclut pas de preuve Merkle.
    #[serde(default)]
    commitment: Option<String>,
    /// Passwordless authentication key held by the user. It is covered by the
    /// partner ring signature and never enters server custody.
    #[serde(default)]
    auth_public_key_b64u: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    /// Statut de l'opération.
    status: String,
    /// [MERKLE] Nouvelle racine de l'arbre de Merkle après insertion du commitment.
    /// Présent uniquement si un `commitment` a été envoyé dans la requête.
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_root: Option<String>,
    /// [MERKLE] Chemin de preuve : hashes frères de la feuille vers la racine (hex).
    /// Le client conserve ces données pour prouver que Sauron a ingéré son KYC.
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_proof: Option<Vec<String>>,
    /// [MERKLE] Index de la feuille dans l'arbre (0-based). Requis pour vérifier la preuve.
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_index: Option<usize>,
}

#[derive(Deserialize)]
struct BankRegisterRequest {
    /// Registered BANK client name (must exist in clients table).
    bank_client_name: String,
    /// Optional bank-side customer identifier.
    #[serde(default)]
    bank_customer_id: Option<String>,
    /// User Ristretto public key (compressed hex).
    public_key_hex: String,
    /// User key image (compressed hex) used as stable identity handle.
    key_image_hex: String,
    first_name: String,
    last_name: String,
    email: String,
    date_of_birth: String,
    nationality: String,
    /// User-held Ed25519 key, bound by the bank attestation.
    auth_public_key_b64u: String,
    /// HMAC-SHA256 signature over canonical payload.
    attestation_signature: String,
    /// Unix timestamp issued by bank.
    attestation_issued_at: i64,
    /// Replay-protection nonce.
    attestation_nonce: String,
}

#[derive(Serialize)]
struct BankRegisterResponse {
    status: String,
    bank_client_name: String,
    key_image_hex: String,
    user_preexisting: bool,
}

fn bank_provider_secret(bank_client_name: &str) -> Option<String> {
    let raw = std::env::var("BANK_PROVIDER_SECRETS_JSON").ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed
        .get(bank_client_name)
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn bank_attestation_payload(tenant_id: &str, req: &BankRegisterRequest) -> String {
    [
        tenant_id.to_string(),
        req.bank_client_name.clone(),
        req.bank_customer_id.clone().unwrap_or_default(),
        req.key_image_hex.clone(),
        req.public_key_hex.clone(),
        req.first_name.clone(),
        req.last_name.clone(),
        req.email.clone(),
        req.date_of_birth.clone(),
        req.nationality.to_uppercase(),
        req.auth_public_key_b64u.clone(),
        req.attestation_issued_at.to_string(),
        req.attestation_nonce.clone(),
    ]
    .join("|")
}

fn verify_bank_attestation(
    tenant_id: &str,
    req: &BankRegisterRequest,
) -> Result<(), (StatusCode, String)> {
    if req.attestation_signature.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "attestation_signature required".into(),
        ));
    }
    if req.attestation_nonce.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "attestation_nonce required".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if (now - req.attestation_issued_at).abs() > 300 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "attestation_issued_at outside 5-minute skew".into(),
        ));
    }

    let secret = bank_provider_secret(&req.bank_client_name).ok_or((
        StatusCode::UNAUTHORIZED,
        "unknown bank_client_name in BANK_PROVIDER_SECRETS_JSON".into(),
    ))?;

    let sig = hex::decode(req.attestation_signature.trim()).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "attestation_signature must be hex-encoded HMAC".into(),
        )
    })?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to initialize HMAC".into(),
        )
    })?;
    mac.update(bank_attestation_payload(tenant_id, req).as_bytes());
    mac.verify_slice(&sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid bank attestation signature".into(),
        )
    })
}

fn validate_user_auth_public_key(value: &str) -> Result<(), (StatusCode, String)> {
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
) -> Result<(), (StatusCode, String)> {
    validate_user_auth_public_key(public_key_b64u)?;
    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
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
        ));
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

async fn bank_register_user(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<BankRegisterRequest>,
) -> Result<Json<BankRegisterResponse>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if !sauron_core::feature_flags::bank_kyc_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "bank KYC ingest disabled (SAURON_DISABLE_BANK_KYC=1)".into(),
        ));
    }
    if payload.bank_client_name.is_empty()
        || payload.public_key_hex.is_empty()
        || payload.key_image_hex.is_empty()
        || payload.auth_public_key_b64u.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "bank_client_name, public_key_hex, key_image_hex and auth_public_key_b64u are required"
                .into(),
        ));
    }

    let pk_bytes = hex::decode(&payload.public_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "public_key_hex must be valid hex".into(),
        )
    })?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "public_key_hex must be 32-byte compressed Ristretto point".into(),
        )
    })?;
    let pk_point = CompressedRistretto(pk_arr).decompress().ok_or((
        StatusCode::BAD_REQUEST,
        "public_key_hex is not a valid Ristretto point".into(),
    ))?;

    let ki_bytes = hex::decode(&payload.key_image_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "key_image_hex must be valid hex".into(),
        )
    })?;
    if ki_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "key_image_hex must be 32 bytes".into(),
        ));
    }

    // Verify caller is known BANK client.
    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let bank_exists: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM clients c
                 JOIN client_tenant_bindings b ON b.client_name = c.name
                 WHERE c.name = ?1 AND c.client_type = 'BANK' AND b.tenant_id = ?2",
            sql_params![&payload.bank_client_name, &tenant_id],
            |r| r.get::<i64>(0),
            0,
        ) > 0;
        if !bank_exists {
            return Err((
                StatusCode::FORBIDDEN,
                "bank_client_name is not a registered BANK client".into(),
            ));
        }
    }

    verify_bank_attestation(&tenant_id, &payload)?;
    validate_user_auth_public_key(&payload.auth_public_key_b64u)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let nationality = payload.nationality.to_uppercase();

    // M2 port: consume the bank attestation nonce via the dual-backend repo
    // helper BEFORE we acquire the SQLite MutexGuard. Drops the guard across
    // the await; the legacy path inside Repo::Sqlite still wraps the INSERT
    // in BEGIN IMMEDIATE for parity with Postgres serialisable isolation.
    {
        let repo = {
            let st = state.read_or_recover();
            st.repo.clone()
        };
        repo.consume_bank_attestation_nonce(
            &payload.bank_client_name,
            &payload.attestation_nonce,
            payload.attestation_issued_at,
        )
        .await
        .map_err(|e| match e {
            sauron_core::repository::RepoError::Replay(s) => (StatusCode::CONFLICT, s),
            sauron_core::repository::RepoError::Backend(s) => {
                (StatusCode::INTERNAL_SERVER_ERROR, s)
            }
        })?;
    }

    let user_preexisting = {
        let repo = state.read_or_recover().repo.clone();

        let exists = repo
            .user_exists(&payload.key_image_hex)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        repo.upsert_user(
            &payload.key_image_hex,
            &payload.public_key_hex,
            &payload.first_name,
            &payload.last_name,
            &payload.email,
            &payload.date_of_birth,
            &nationality,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        store_user_auth_credential(
            &state,
            &tenant_id,
            &payload.key_image_hex,
            &payload.auth_public_key_b64u,
            now,
        )?;

        // bank_kyc_links is a SQLite-only table (never routed through the repo),
        // so it stays on the raw handle — consistent on both backends.
        if let Some(bank_customer_id) = payload
            .bank_customer_id
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            let metadata = serde_json::json!({
                "source": "bank_webhook",
                "bank_client_name": payload.bank_client_name,
                "attestation_nonce": payload.attestation_nonce,
            })
            .to_string();
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            db.any_conn().execute(
                "INSERT OR REPLACE INTO bank_kyc_links (bank_customer_id, user_key_image, updated_at, metadata_json)
                 VALUES (?1, ?2, ?3, ?4)",
                sql_params![&bank_customer_id, &payload.key_image_hex, &now, &metadata],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        repo.insert_user_registration(
            &tenant_id,
            &payload.bank_client_name,
            &payload.key_image_hex,
            "bank_webhook",
            now,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        exists
    };

    {
        let mut st = state.write_or_recover();
        if !st.user_group.members.contains(&pk_point) {
            st.user_group.members.push(pk_point);
        }
    }

    {
        let st = state.read_or_recover();
        let short_ki: String = payload.key_image_hex.chars().take(16).collect();
        st.log(
            "BANK_REGISTER",
            "OK",
            &format!("bank={} user={}", payload.bank_client_name, short_ki),
        );
    }

    Ok(Json(BankRegisterResponse {
        status: "success".to_string(),
        bank_client_name: payload.bank_client_name,
        key_image_hex: payload.key_image_hex,
        user_preexisting,
    }))
}

async fn handle_register(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let pk_bytes: [u8; 32] = payload
        .public_key
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let pk_compressed =
        CompressedRistretto::from_slice(&pk_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let pk_point = pk_compressed.decompress().ok_or(StatusCode::BAD_REQUEST)?;
    if pk_point == RistrettoPoint::identity() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let ki_bytes: [u8; 32] = payload
        .key_image
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let ki_point = CompressedRistretto::from_slice(&ki_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .decompress()
        .ok_or(StatusCode::BAD_REQUEST)?;
    if ki_point == RistrettoPoint::identity() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let hex_pk = hex::encode(pk_bytes);
    let hex_ki = hex::encode(ki_bytes);
    let p = &payload.profile;
    let commitment = payload.commitment.as_deref().unwrap_or("");
    if !sauron_core::runtime_mode::is_development_runtime()
        && payload.auth_public_key_b64u.is_empty()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !payload.auth_public_key_b64u.is_empty()
        && validate_user_auth_public_key(&payload.auth_public_key_b64u).is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let msg = partner_registration_payload(&PartnerRegistrationInput {
        tenant_id: &tenant_id,
        public_key_hex: &hex_pk,
        key_image_hex: &hex_ki,
        first_name: &p.first_name,
        last_name: &p.last_name,
        email: &p.email,
        date_of_birth: &p.date_of_birth,
        nationality: &p.nationality,
        commitment,
        auth_public_key_b64u: &payload.auth_public_key_b64u,
    });

    // Verify against this tenant's FULL_KYC ring only. A valid partner in a
    // different tenant, or a BANK/ZKP_ONLY key, is not registration authority.
    let tenant_partner_ring: Vec<RistrettoPoint> = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let points = db
            .any_conn()
            .query_map(
                "SELECT c.public_key_hex FROM clients c
                 JOIN client_tenant_bindings b ON b.client_name = c.name
                 WHERE b.tenant_id = ?1 AND c.client_type = 'FULL_KYC'
                 ORDER BY c.name",
                sql_params![&tenant_id],
                |r| r.get::<String>(0),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .into_iter()
            .filter_map(|encoded| {
                let bytes = hex::decode(encoded).ok()?;
                let array: [u8; 32] = bytes.try_into().ok()?;
                CompressedRistretto(array).decompress()
            })
            .collect();
        points
    };
    if tenant_partner_ring.is_empty()
        || !ring::verify(&msg, &tenant_partner_ring, &payload.client_signature)
    {
        tracing::warn!(target: "sauron::security", endpoint = "/register", tenant_id = %tenant_id, "invalid or unauthorized tenant partner signature");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Persister l'utilisateur dans la DB (dual-backend repo).
    {
        let repo = state.read_or_recover().repo.clone();
        repo.insert_user_if_absent(
            &hex_ki,
            &hex_pk,
            &p.first_name,
            &p.last_name,
            &p.email,
            &p.date_of_birth,
            &p.nationality,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !payload.auth_public_key_b64u.is_empty() {
            store_user_auth_credential(
                &state,
                &tenant_id,
                &hex_ki,
                &payload.auth_public_key_b64u,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            )
            .map_err(|(status, _)| status)?;
        }
    }

    // Mettre à jour le groupe en mémoire + insérer le commitment Merkle.
    let mut merkle_root_out: Option<String> = None;
    let mut merkle_proof_out: Option<Vec<String>> = None;
    let mut leaf_index_out: Option<usize> = None;
    // Stashed inside the state write-guard, persisted via the dual-backend repo
    // once the guard is dropped (the Postgres path is async — can't .await while
    // holding a std RwLock guard).
    let mut merkle_leaf_to_persist: Option<(String, i64)> = None;
    {
        let mut st = state.write_or_recover();
        st.user_group.add_member(pk_point);

        // ── Merkle Commitment Ledger ─────────────────────────────
        if let Some(ref commitment_hex) = payload.commitment {
            match st.merkle_ledger.add_commitment(commitment_hex) {
                Ok(receipt) => {
                    // Persister la feuille en DB pour reconstruction au redémarrage.
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    merkle_leaf_to_persist = Some((commitment_hex.clone(), ts));
                    tracing::debug!(
                        target: "sauron::merkle",
                        leaf_index = receipt.leaf_index,
                        root_prefix = &receipt.merkle_root[..16],
                        proofs = receipt.merkle_proof.len(),
                        "merkle leaf inserted"
                    );
                    merkle_root_out = Some(receipt.merkle_root);
                    merkle_proof_out = Some(receipt.merkle_proof);
                    leaf_index_out = Some(receipt.leaf_index);
                }
                Err(e) => {
                    // Le commitment est invalide : on rejette la requête pour éviter
                    // d'accepter un KYC sans pouvoir émettre la preuve.
                    tracing::warn!(target: "sauron::merkle", error = %e, "invalid commitment rejected");
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
        // ────────────────────────────────────────────────────────

        st.log("REGISTER", "OK", &hex_ki[..16]);
        tracing::info!(
            target: "sauron::register",
            group_size = st.user_group.members.len(),
            merkle_leaves = st.merkle_ledger.len(),
            "register accepted"
        );
    }

    // Persist the merkle leaf through the dual-backend repo (SQLite default,
    // Postgres when SAURON_DB_BACKEND=postgres). Best-effort: it only feeds
    // ledger reconstruction on restart, so a failure is non-fatal.
    if let Some((commitment_hex, ts)) = merkle_leaf_to_persist {
        let repo = state.read_or_recover().repo.clone();
        if let Err(e) = repo
            .insert_merkle_leaf(&tenant_id, &commitment_hex, ts)
            .await
        {
            tracing::warn!(target: "sauron::merkle", error = %e, "merkle leaf persist failed (non-fatal)");
        }
    }

    // ── Dual anchoring (non-blocking, independent failure paths) ─────────
    // Bitcoin via OpenTimestamps (default) and Solana via Memo Program. Each
    // anchor is independent; one provider's failure does not block the other,
    // and neither blocks the user-facing /register response.
    if let Some(ref root_hex) = merkle_root_out {
        if let Ok(root_bytes) = hex::decode(root_hex) {
            if root_bytes.len() == 32 {
                let root_arr: [u8; 32] = root_bytes.try_into().unwrap();
                let st = state.read_or_recover();
                if let Some(ref svc) = st.bitcoin_anchor {
                    let svc = svc.clone();
                    let db = Arc::clone(&st.db);
                    tokio::spawn(async move {
                        match svc.publish_new_root(&db, root_arr).await {
                            Ok(receipt) => tracing::info!(
                                target: "sauron::bitcoin_anchor",
                                provider = ?svc.provider(),
                                network = %receipt.network,
                                txid_prefix = %&receipt.txid[..receipt.txid.len().min(20)],
                                ots_calendar = ?receipt.ots_calendar_url,
                                no_real_money = receipt.no_real_money,
                                "merkle root anchored on Bitcoin"
                            ),
                            Err(e) => tracing::warn!(
                                target: "sauron::bitcoin_anchor",
                                error = %e,
                                "publish_new_root failed (non-fatal)"
                            ),
                        }
                    });
                }
                if let Some(ref svc) = st.solana_anchor {
                    let svc = svc.clone();
                    let db = Arc::clone(&st.db);
                    tokio::spawn(async move {
                        match svc.publish_root(&db, root_arr).await {
                            Ok(receipt) => tracing::info!(
                                target: "sauron::solana",
                                network = %receipt.network,
                                signature = %receipt.signature,
                                "merkle root anchored on Solana"
                            ),
                            Err(e) => tracing::warn!(
                                target: "sauron::solana",
                                error = %e,
                                "publish_root failed (non-fatal)"
                            ),
                        }
                    });
                }
            }
        }
    }
    // ─────────────────────────────────────────────────────────────────────

    Ok(Json(RegisterResponse {
        status: "success".to_string(),
        merkle_root: merkle_root_out,
        merkle_proof: merkle_proof_out,
        leaf_index: leaf_index_out,
    }))
}

// ─────────────────────────────────────────────────────
//  Dev-only endpoints. Disabled in prod. Set SAURON_ENABLE_DEV_ENDPOINTS=1 to enable.
//  Exposes server-side OPRF evaluation so the frontend
//  doesn't need to implement Ristretto255.
// ─────────────────────────────────────────────────────

/// Recalcule le résultat OPRF sans le protocole blind.
/// Équivalent à client_unblind(server_evaluate(client_blind(e,p), k), r)
/// mais sans le masquage (k est connu, pour usage interne uniquement).
fn dev_oprf_eval(
    server_k: curve25519_dalek::scalar::Scalar,
    email: &str,
    password: &str,
) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(email.as_bytes());
    hasher.update(b"|SALT|");
    hasher.update(password.as_bytes());
    let base = RistrettoPoint::hash_from_bytes::<Sha512>(hasher.finalize().as_ref());
    server_k * base
}

// ─────────────────────────────────────────────────────
//  ZKP : construction d'anneau filtré et vérification de preuve
// ─────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// POST /zkp/proof_material
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DevRegisterUserRequest {
    email: String,
    password: String,
    site_name: String,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    #[serde(default)]
    date_of_birth: String,
    #[serde(default)]
    nationality: String,
    /// Base64url Ed25519 public key of the OWNER, bound to this user's key
    /// image exactly as /register and /bank/register bind one.
    ///
    /// Without it a dev-seeded user has no owner key, so it cannot sign an
    /// agent mandate and the demo cannot show the property that matters:
    /// authority granted by the owner rather than asserted by the operator.
    /// Optional, so the seeded password demo is unaffected.
    #[serde(default)]
    auth_public_key_b64u: String,
}
#[derive(Serialize)]
struct DevRegisterUserResponse {
    public_key_hex: String,
    key_image_hex: String,
    message: String,
}
async fn dev_register_user(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevRegisterUserRequest>,
) -> Result<Json<DevRegisterUserResponse>, (StatusCode, String)> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "Dev only".into()));
    }
    let server_k = state.read_or_recover().k;
    let oprf_result = dev_oprf_eval(server_k, &payload.email, &payload.password);
    let identity = Identity::from_oprf(oprf_result);
    {
        let repo = state.read_or_recover().repo.clone();
        repo.upsert_user(
            &identity.key_image_hex(),
            &identity.public_hex(),
            &payload.first_name,
            &payload.last_name,
            &payload.email,
            &payload.date_of_birth,
            &payload.nationality,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if !payload.auth_public_key_b64u.trim().is_empty() {
            store_user_auth_credential(
                &state,
                "default",
                &identity.key_image_hex(),
                payload.auth_public_key_b64u.trim(),
                ts,
            )?;
        }
        repo.insert_user_registration(
            "default",
            &payload.site_name,
            &identity.key_image_hex(),
            "register",
            ts,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // bank_kyc_links: SQLite-only table, stays on the raw handle.
        let bank_customer_id = format!("DEV-{}", identity.key_image_hex());
        let metadata =
            serde_json::json!({ "source": "dev", "site_name": payload.site_name }).to_string();
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn().execute(
            "INSERT OR IGNORE INTO bank_kyc_links (bank_customer_id, user_key_image, updated_at, metadata_json) VALUES (?1, ?2, ?3, ?4)",
            sql_params![&bank_customer_id, identity.key_image_hex(), 1000000, &metadata],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let mut st = state.write_or_recover();
    if !st.user_group.members.contains(&identity.public) {
        st.user_group.members.push(identity.public);
    }

    Ok(Json(DevRegisterUserResponse {
        public_key_hex: identity.public_hex(),
        key_image_hex: identity.key_image_hex(),
        message: "ok".into(),
    }))
}

#[derive(Deserialize)]
struct DevBuyTokensRequest {
    site_name: String,
    amount: i64,
}
#[derive(Serialize)]
struct DevBuyTokensResponse {
    message: String,
    new_tokens_b: i64,
}

async fn dev_buy_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevBuyTokensRequest>,
) -> Result<Json<DevBuyTokensResponse>, (StatusCode, String)> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "Dev only".into()));
    }
    let db = state.read_or_recover().db.lock().unwrap();
    db.any_conn()
        .execute(
            "UPDATE clients SET tokens_b = tokens_b + ?1 WHERE name = ?2",
            sql_params![&payload.amount, &payload.site_name],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let new_tokens_b: i64 = db.any_conn().require(
        "SELECT tokens_b FROM clients WHERE name = ?1",
        sql_params![&payload.site_name],
        |r| r.get(0),
        || (StatusCode::NOT_FOUND, "client not found".to_string()),
    )?;
    Ok(Json(DevBuyTokensResponse {
        message: "ok".into(),
        new_tokens_b,
    }))
}

struct DevAjwtToken {
    jti: String,
    exp: i64,
    intent: serde_json::Value,
}

fn dev_mint_agent_token(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    pop_jkt: &str,
) -> Result<DevAjwtToken, (StatusCode, String)> {
    let extra = agent::AjwtExtraClaims {
        cnf_jkt: Some(pop_jkt.to_string()),
        workflow_id: Some("dev-leash-demo".into()),
        delegation_chain: None,
    };
    let ajwt = agent::forge_ajwt(
        jwt_secret,
        human_key_image,
        agent_id,
        agent_checksum,
        intent_json,
        "default",
        300,
        Some(&extra),
    );
    let claims = agent::verify_ajwt(jwt_secret, &ajwt).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "dev A-JWT mint failed".into(),
    ))?;
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "dev A-JWT missing jti".into(),
        ))?
        .to_string();
    let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "dev A-JWT missing exp".into(),
    ))?;
    let intent = parse_ajwt_intent_claim(&claims)?;
    Ok(DevAjwtToken { jti, exp, intent })
}

#[allow(clippy::too_many_arguments)]
fn dev_action_proof(
    agent_identity: &Identity,
    ring_members: &[RistrettoPoint],
    signer_index: usize,
    agent_id: &str,
    human_key_image: &str,
    token: &DevAjwtToken,
    action: &str,
    resource: &str,
    merchant_id: &str,
    amount_minor: i64,
    currency: &str,
) -> agent_action::AgentActionProof {
    let envelope = agent_action::AgentActionEnvelope {
        agent_id: agent_id.to_string(),
        human_key_image: human_key_image.to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        merchant_id: merchant_id.to_string(),
        amount_minor,
        currency: currency.to_ascii_uppercase(),
        nonce: format!(
            "dev_{}_{}",
            action,
            sauron_core::ajwt_support::random_hex_32()
        ),
        expires_at: agent_action::now_secs() + 120,
        policy_hash: agent_action::expected_policy_hash(action),
        ajwt_jti: token.jti.clone(),
    };
    let msg = agent_action::canonical_envelope_bytes(&envelope);
    let ring_signature = ring::sign(&msg, ring_members, agent_identity, signer_index);
    agent_action::AgentActionProof {
        envelope,
        ring_signature,
    }
}

async fn dev_leash_demo(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "Dev only".into()));
    }

    let now = agent_action::now_secs();
    let human = Identity::random();
    let agent_identity = Identity::random();
    let decoy_identity = Identity::random();
    let outsider_identity = Identity::random();
    let human_key_image = human.key_image_hex();
    let agent_id = format!("dev_leash_{}", sauron_core::ajwt_support::random_hex_32());
    let outsider_agent_id = format!(
        "dev_out_of_ring_{}",
        sauron_core::ajwt_support::random_hex_32()
    );
    let agent_checksum = {
        let mut h = Sha256::new();
        h.update(b"dev-leash-demo|");
        h.update(agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let decoy_agent_id = format!("dev_decoy_{}", sauron_core::ajwt_support::random_hex_32());
    let decoy_checksum = {
        let mut h = Sha256::new();
        h.update(b"dev-leash-demo-decoy|");
        h.update(decoy_agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let outsider_checksum = {
        let mut h = Sha256::new();
        h.update(b"dev-leash-demo-outsider|");
        h.update(outsider_agent_id.as_bytes());
        hex::encode(h.finalize())
    };
    let intent_json = serde_json::json!({
        "scope": ["payment_initiation", "payment_consume", "kyc_consent", "prove_age"],
        "constraints": {
            "max_amount_minor": 5000,
            "currency": "EUR",
            "merchant_id": "demo_merchant"
        }
    })
    .to_string();
    let pop_jkt = "dev-leash-pop-thumbprint";
    // The server rebuilds this ring from the database with `ORDER BY agent_id`,
    // and an LSAG signature is order-sensitive — a ring with the same members in
    // a different order does not verify. Derive both the ring and the signer's
    // index from that same ordering instead of assuming the agent comes first.
    let mut ring_entries = [
        (agent_id.clone(), agent_identity.public),
        (decoy_agent_id.clone(), decoy_identity.public),
    ];
    ring_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let ring_members: Vec<_> = ring_entries.iter().map(|(_, point)| *point).collect();
    let signer_index = ring_entries
        .iter()
        .position(|(id, _)| id == &agent_id)
        .expect("demo agent is a ring member");
    {
        let repo = state.read_or_recover().repo.clone();
        repo.upsert_user(
            &human_key_image,
            &human.public_hex(),
            "Dev",
            "Leash",
            "dev-leash@example.test",
            "1990-01-01",
            "FR",
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "INSERT OR REPLACE INTO bank_kyc_links
             (bank_customer_id, user_key_image, updated_at, metadata_json)
             VALUES (?1, ?2, ?3, ?4)",
                sql_params![
                    format!("DEV-{}", &human_key_image),
                    &human_key_image,
                    &now,
                    &serde_json::json!({ "source": "dev_leash_demo" }).to_string()
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // The authoritative ring is rebuilt from the database by
        // agent_action::validate_agent_action — every active agent of the tenant
        // with a non-empty public_key_hex. So the rows here MUST reproduce the
        // ring these proofs are signed against, `[agent, decoy]`:
        //
        //  * the decoy was never inserted, so the reconstructed ring was missing
        //    a member and every valid signature failed to verify;
        //  * the outsider was inserted as fully active, so it was IN the
        //    reconstructed ring — the one thing the out-of-ring case needs it not
        //    to be.
        //
        // The outsider therefore registers with an empty public_key_hex: still a
        // real agent record, deliberately without a ring key. That is exactly
        // what "not in the ring" means once the ring is defined by registration.
        for (row_agent_id, checksum, public_key_hex, ring_key_image_hex) in [
            (
                &agent_id,
                &agent_checksum,
                agent_identity.public_hex(),
                agent_identity.key_image_hex(),
            ),
            (
                &decoy_agent_id,
                &decoy_checksum,
                decoy_identity.public_hex(),
                decoy_identity.key_image_hex(),
            ),
            (
                &outsider_agent_id,
                &outsider_checksum,
                String::new(),
                outsider_identity.key_image_hex(),
            ),
        ] {
            db.any_conn().execute(
                // pop_public_key_b64u must differ per agent: there is a partial
                // unique index on (tenant_id, pop_public_key_b64u) for active
                // rows, so two demo agents sharing one literal key made the
                // second INSERT OR REPLACE delete the first. The demo then
                // validated against an agent that no longer existed and reported
                // "Agent not found" for its own happy path, while every negative
                // case still passed — a leash that denies everything looks
                // healthy until you check what it allows.
                "INSERT OR REPLACE INTO agents
                 (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u)
                 VALUES (?1, ?2, ?3, ?4, 'delegated_bank', ?5, ?6, ?7, ?8, 0, NULL, 0, ?9, ?10)",
                sql_params![
                    &row_agent_id,
                    &human_key_image,
                    &checksum,
                    &intent_json,
                    &public_key_hex,
                    &ring_key_image_hex,
                    &now,
                    now + 600,
                    &pop_jkt,
                    format!("dev-pop-public-key-{row_agent_id}"),
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }
    {
        let mut st = state.write_or_recover();
        for member in &ring_members {
            if !st.agent_group.members.contains(member) {
                st.agent_group.members.push(*member);
            }
        }
    }

    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let validate_payment = |proof: &agent_action::AgentActionProof,
                            token: &DevAjwtToken,
                            agent_id: &str,
                            resource: &str,
                            merchant_id: &str,
                            amount_minor: i64| {
        agent_action::validate_agent_action(
            &state,
            proof,
            agent_action::ValidateAgentActionOptions {
                tenant_id: "default",
                agent_id,
                human_key_image: &human_key_image,
                ajwt_jti: &token.jti,
                intent: Some(&token.intent),
                expected_action: "payment_initiation",
                expected_resource: Some(resource),
                expected_merchant_id: Some(merchant_id),
                expected_amount_minor: Some(amount_minor),
                expected_currency: Some("EUR"),
                pop_jkt: Some(pop_jkt),
                status: "accepted",
            },
        )
    };

    let valid_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let valid_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &valid_token,
        "payment_initiation",
        "dev-payment-valid",
        "demo_merchant",
        4200,
        "EUR",
    );
    let valid_result = validate_payment(
        &valid_proof,
        &valid_token,
        &agent_id,
        "dev-payment-valid",
        "demo_merchant",
        4200,
    );
    // Surface WHY the happy path failed. Swallowing it with `.ok()` made the
    // demo report `valid_leash_passes: false` with no way to tell whether the
    // signature, the ring, the policy or the DB write rejected it.
    let valid_error = valid_result
        .as_ref()
        .err()
        .map(|(c, m)| format!("{c}: {m}"));
    if let Some(ref why) = valid_error {
        tracing::error!(target: "sauron::dev_leash", error = %why, "valid leash path was rejected");
    }
    let valid_receipt = valid_result.ok().map(|v| v.receipt);
    let valid_leash_passes = valid_receipt.is_some();

    let missing_signature_fails = serde_json::from_value::<agent_action::AgentActionProof>(
        serde_json::json!({ "envelope": valid_proof.envelope.clone() }),
    )
    .is_err();

    let bad_sig_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let mut bad_sig_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &bad_sig_token,
        "payment_initiation",
        "dev-payment-bad-sig",
        "demo_merchant",
        4200,
        "EUR",
    );
    bad_sig_proof.ring_signature.responses[0] += Scalar::ONE;
    let bad_signature_fails = validate_payment(
        &bad_sig_proof,
        &bad_sig_token,
        &agent_id,
        "dev-payment-bad-sig",
        "demo_merchant",
        4200,
    )
    .is_err();

    let tamper_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let mut tampered_amount_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &tamper_token,
        "payment_initiation",
        "dev-payment-tamper",
        "demo_merchant",
        4200,
        "EUR",
    );
    tampered_amount_proof.envelope.amount_minor = 4300;
    let tampered_amount_fails = validate_payment(
        &tampered_amount_proof,
        &tamper_token,
        &agent_id,
        "dev-payment-tamper",
        "demo_merchant",
        4300,
    )
    .is_err();

    let wrong_merchant_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let wrong_merchant_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &wrong_merchant_token,
        "payment_initiation",
        "dev-payment-wrong-merchant",
        "demo_merchant",
        4200,
        "EUR",
    );
    let wrong_merchant_fails = validate_payment(
        &wrong_merchant_proof,
        &wrong_merchant_token,
        &agent_id,
        "dev-payment-wrong-merchant",
        "evil_merchant",
        4200,
    )
    .is_err();

    let replay_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let replay_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &replay_token,
        "payment_initiation",
        "dev-payment-replay",
        "demo_merchant",
        4200,
        "EUR",
    );
    let _ = validate_payment(
        &replay_proof,
        &replay_token,
        &agent_id,
        "dev-payment-replay",
        "demo_merchant",
        4200,
    );
    let nonce_replay_fails = validate_payment(
        &replay_proof,
        &replay_token,
        &agent_id,
        "dev-payment-replay",
        "demo_merchant",
        4200,
    )
    .is_err();

    let ajwt_replay_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let ajwt_replay_fails = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let first = sauron_core::ajwt_support::consume_ajwt_jti(
            &db,
            &ajwt_replay_token.jti,
            ajwt_replay_token.exp,
        );
        let second = sauron_core::ajwt_support::consume_ajwt_jti(
            &db,
            &ajwt_replay_token.jti,
            ajwt_replay_token.exp,
        );
        first.is_ok() && second.is_err()
    };

    let out_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &outsider_agent_id,
        &outsider_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let out_ring = vec![outsider_identity.public, decoy_identity.public];
    let out_proof = dev_action_proof(
        &outsider_identity,
        &out_ring,
        0,
        &outsider_agent_id,
        &human_key_image,
        &out_token,
        "payment_initiation",
        "dev-payment-out-of-ring",
        "demo_merchant",
        4200,
        "EUR",
    );
    let out_of_ring_agent_fails = validate_payment(
        &out_proof,
        &out_token,
        &outsider_agent_id,
        "dev-payment-out-of-ring",
        "demo_merchant",
        4200,
    )
    .is_err();

    let revoked_token = dev_mint_agent_token(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &agent_checksum,
        &intent_json,
        pop_jkt,
    )?;
    let revoked_proof = dev_action_proof(
        &agent_identity,
        &ring_members,
        signer_index,
        &agent_id,
        &human_key_image,
        &revoked_token,
        "payment_initiation",
        "dev-payment-revoked",
        "demo_merchant",
        4200,
        "EUR",
    );
    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        db.any_conn()
            .execute(
                "UPDATE agents SET revoked = 1 WHERE agent_id = ?1",
                sql_params![&agent_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    let revoked_agent_fails = validate_payment(
        &revoked_proof,
        &revoked_token,
        &agent_id,
        "dev-payment-revoked",
        "demo_merchant",
        4200,
    )
    .is_err();

    let receipt_verification = if let Some(receipt) = valid_receipt {
        let st = state.read_or_recover();
        let signature_valid = agent_action::verify_receipt_signature(&st.jwt_secret, &receipt);
        let stored = {
            let db = st.db.lock().unwrap();
            db.any_conn().scalar_or(
                "SELECT COUNT(*) FROM agent_action_receipts WHERE receipt_id = ?1 AND action_hash = ?2 AND signature = ?3",
                sql_params![&receipt.receipt_id, &receipt.action_hash, &receipt.signature],
                |r| r.get::<i64>(0),
                0)
                > 0
        };
        serde_json::json!({
            "valid": signature_valid && stored,
            "action_hash": receipt.action_hash,
            "agent_id": receipt.agent_id,
            "policy_version": receipt.policy_version,
            "status": receipt.status,
        })
    } else {
        serde_json::json!({ "valid": false })
    };

    Ok(Json(serde_json::json!({
        "valid_leash_passes": valid_leash_passes,
        "valid_leash_error": valid_error,
        "missing_signature_fails": missing_signature_fails,
        "bad_signature_fails": bad_signature_fails,
        "tampered_amount_fails": tampered_amount_fails,
        "wrong_merchant_fails": wrong_merchant_fails,
        "nonce_replay_fails": nonce_replay_fails,
        "ajwt_replay_fails": ajwt_replay_fails,
        "revoked_agent_fails": revoked_agent_fails,
        "out_of_ring_agent_fails": out_of_ring_agent_fails,
        "receipt_verification": receipt_verification,
    })))
}

#[derive(Deserialize)]
struct DevConsentProfileBody {
    consent_token: String,
    site_name: String,
    #[serde(default)]
    min_age: Option<i64>,
    #[serde(default)]
    required_fields: Vec<String>,
}

fn dev_estimated_age_years(date_of_birth: &str, now_secs: i64) -> Option<i64> {
    let birth_year = date_of_birth.get(0..4)?.parse::<i64>().ok()?;
    let current_year = 1970 + (now_secs / 31_556_952);
    Some(current_year.saturating_sub(birth_year))
}

async fn dev_consent_profile(
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<DevConsentProfileBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !sauron_core::runtime_mode::is_development_runtime() {
        return Err((StatusCode::FORBIDDEN, "dev routes are disabled".into()));
    }

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // consent_log is still on the raw handle (ported separately); scope the
    // lock so it drops before the async users read.
    let user_key_image: String = {
        let repo = state.read_or_recover().repo.clone();
        repo.resolve_consent_user(&tenant_id, &payload.consent_token, &payload.site_name, now)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "invalid, used, revoked, or expired consent token".to_string(),
            ))?
    };

    let user = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_user(&user_key_image)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "consent user not found".to_string()))?
    };
    let (first_name, last_name, email, date_of_birth, nationality) = (
        user.first_name,
        user.last_name,
        user.email,
        user.date_of_birth,
        user.nationality,
    );

    let mut missing_fields = Vec::new();
    for field in payload.required_fields {
        let missing = match field.as_str() {
            "first_name" => first_name.trim().is_empty(),
            "last_name" => last_name.trim().is_empty(),
            "email" => email.trim().is_empty(),
            "date_of_birth" => date_of_birth.trim().is_empty(),
            "nationality" => nationality.trim().is_empty(),
            _ => true,
        };
        if missing {
            missing_fields.push(field);
        }
    }
    let min_age = payload.min_age.unwrap_or(18);
    let age_years = dev_estimated_age_years(&date_of_birth, now).unwrap_or_default();

    Ok(Json(serde_json::json!({
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "date_of_birth": date_of_birth,
        "nationality": nationality,
        "min_age": min_age,
        "is_over_threshold": age_years >= min_age,
        "profile_complete": missing_fields.is_empty(),
        "missing_fields": missing_fields,
        "dev_only": true,
    })))
}

#[derive(Deserialize)]
struct ZkpProofMaterialRequest {
    #[serde(default)]
    credential_hash: Option<String>,
    #[serde(default)]
    leaf_index: Option<usize>,
}

async fn handle_zkp_proof_material(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ZkpProofMaterialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !sauron_core::feature_flags::zkp_issuer_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "ZKP issuer integration disabled (SAURON_DISABLE_ZKP=1)".into(),
        ));
    }
    let (issuer_url, client) = {
        let st = state.read_or_recover();
        (st.issuer_url.clone(), st.issuer_runtime.client.clone())
    };
    let body = serde_json::json!({
        "credentialHash": payload.credential_hash,
        "leafIndex": payload.leaf_index,
    });
    let mut request = client
        .post(format!("{issuer_url}/proof-material"))
        .json(&body);
    if let Ok(secret) = std::env::var("SAURON_ISSUER_SHARED_SECRET") {
        request = request.header("x-sauron-issuer-key", secret);
    }
    let response = request
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Issuer unreachable: {e}")))?;

    if !response.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Issuer proof-material failed: {}",
                response.text().await.unwrap_or_default()
            ),
        ));
    }

    let data = response.json::<serde_json::Value>().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Issuer payload parse error: {e}"),
        )
    })?;
    Ok(Json(data))
}

// ─────────────────────────────────────────────────────
//  Phase 2: User Consent Flow
//
//  OAuth-style popup: retail site requests consent, user approves in a Sauron
//  popup, site retrieves KYC using a one-time consent_token.
//
//  POST /kyc/request       — site asks for user consent (returns request_id + popup URL)
//  GET  /kyc/consent_info  — consent page fetches request info (site name, claims)
//  POST /kyc/consent       — user approves (email+password, dev mode)
//  POST /kyc/retrieve      — site retrieves KYC using the consent_token
// ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct DelegatedAgentBinding {
    agent_id: String,
    human_key_image: String,
    ajwt_jti: String,
    ajwt_exp: i64,
    intent: serde_json::Value,
    pop_jkt: String,
}

async fn delegated_agent_binding_middleware(
    State(state): State<Arc<RwLock<ServerState>>>,
    request: Request,
    next: middleware::Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let tenant_id = parts
        .extensions
        .get::<sauron_tenancy::TenantId>()
        .map(|t| t.0.clone())
        .unwrap_or_default();
    let body_bytes = to_bytes(body, 64 * 1024).await.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Unable to read request body".to_string(),
        )
    })?;

    let payload: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid JSON body".to_string()))?;

    let consent_token = payload
        .get("consent_token")
        .and_then(|v| v.as_str())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "consent_token is required".to_string(),
        ))?
        .to_string();

    let (user_key_image, issuing_agent_id) = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_consent_by_token(&tenant_id, &consent_token)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Invalid or revoked consent token".to_string(),
            ))?
    };

    let mut request = Request::from_parts(parts, Body::from(body_bytes));

    if let Some(expected_agent_id) = issuing_agent_id {
        let ajwt = request
            .headers()
            .get("x-agent-ajwt")
            .and_then(|v| v.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "x-agent-ajwt header required for delegated consent".to_string(),
            ))?;

        let jwt_secret = state.read_or_recover().jwt_secret.clone();
        let claims = agent::verify_ajwt_for_tenant(&jwt_secret, ajwt, &tenant_id).ok_or((
            StatusCode::UNAUTHORIZED,
            "Invalid or expired A-JWT".to_string(),
        ))?;

        let claim_agent_id = claims
            .get("agent_id")
            .and_then(|v| v.as_str())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "A-JWT missing agent_id".to_string(),
            ))?
            .to_string();
        let claim_human_key_image = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub".to_string()))?
            .to_string();
        let ajwt_jti = claims
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing jti".to_string()))?
            .to_string();
        let ajwt_exp = claims
            .get("exp")
            .and_then(|v| v.as_i64())
            .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing exp".to_string()))?;
        let intent = parse_ajwt_intent_claim(&claims)?;

        if claim_agent_id != expected_agent_id {
            return Err((
                StatusCode::UNAUTHORIZED,
                "A-JWT agent_id does not match delegated consent issuer".to_string(),
            ));
        }

        if claim_human_key_image != user_key_image {
            return Err((
                StatusCode::UNAUTHORIZED,
                "A-JWT subject does not match consent owner".to_string(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (db_human, revoked, expires_at, agent_pub_hex, pop_jkt): (
            String,
            i64,
            i64,
            String,
            String,
        ) = {
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            db.any_conn().require(
                "SELECT human_key_image, revoked, expires_at, public_key_hex, IFNULL(pop_jkt, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                sql_params![&tenant_id, &claim_agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                || (StatusCode::UNAUTHORIZED, "Agent not found".to_string()),
            )?
        };

        if revoked != 0 || expires_at < now || db_human != claim_human_key_image {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (revoked, expired, or owner mismatch)".to_string(),
            ));
        }

        if agent_pub_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (agent missing ring public key)".to_string(),
            ));
        }

        let agent_in_ring = {
            let st = state.read_or_recover();
            let bytes = hex::decode(&agent_pub_hex).map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Delegated agent binding failed (invalid public key encoding)".to_string(),
                )
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Delegated agent binding failed (invalid public key length)".to_string(),
                )
            })?;
            let pt = CompressedRistretto(arr).decompress().ok_or((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (invalid public key point)".to_string(),
            ))?;
            st.agent_group.members.contains(&pt)
        };

        if !agent_in_ring {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding failed (agent not in delegated ring)".to_string(),
            ));
        }

        request.extensions_mut().insert(DelegatedAgentBinding {
            agent_id: claim_agent_id,
            human_key_image: claim_human_key_image,
            ajwt_jti,
            ajwt_exp,
            intent,
            pop_jkt,
        });
    }

    Ok(next.run(request).await)
}

#[derive(Deserialize)]
struct KycRequestBody {
    /// Name of the site requesting consent.
    site_name: String,
    /// ZKP claim assertions the site wants to receive.
    #[serde(default)]
    requested_claims: Vec<String>,
    /// Optional redirect URL to postMessage the consent_token back to.
    #[serde(default)]
    #[allow(dead_code)]
    redirect_origin: String,
}

#[derive(Serialize)]
struct KycRequestResponse {
    request_id: String,
    consent_url: String,
    expires_at: i64,
}

fn is_supported_zkp_claim(claim: &str) -> bool {
    matches!(
        claim,
        "age_over_threshold"
            | "age_threshold"
            | "credential_valid"
            | "nationality_match"
            | "merkle_inclusion"
    )
}

fn normalize_requested_claims(mut claims: Vec<String>) -> Result<Vec<String>, Vec<String>> {
    if claims.is_empty() {
        claims = vec![
            "age_over_threshold".to_string(),
            "age_threshold".to_string(),
        ];
    }
    let unsupported: Vec<String> = claims
        .iter()
        .filter(|claim| !is_supported_zkp_claim(claim))
        .cloned()
        .collect();
    if !unsupported.is_empty() {
        return Err(unsupported);
    }
    Ok(claims)
}

async fn kyc_request(
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<KycRequestBody>,
) -> Result<Json<KycRequestResponse>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if !sauron_core::feature_flags::user_kyc_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "end-user KYC consent flow disabled (SAURON_DISABLE_USER_KYC=1)".into(),
        ));
    }
    if payload.site_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "site_name required".into()));
    }

    let requested_claims =
        normalize_requested_claims(payload.requested_claims).map_err(|unsupported| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "requested_claims must be ZKP assertions only. Unsupported: {:?}",
                    unsupported
                ),
            )
        })?;

    // Mandatory ZKP-only mode: only ZKP_ONLY relying parties may open consent requests.
    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let exists: bool = db.any_conn().scalar_or(
            "SELECT COUNT(*) FROM clients WHERE name = ?1 AND client_type = 'ZKP_ONLY'",
            sql_params![&payload.site_name],
            |r| r.get::<i64>(0),
            0,
        ) > 0;
        if !exists {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Site '{}' must be registered as ZKP_ONLY for consent retrieval",
                    payload.site_name
                ),
            ));
        }
    }

    // Generate request_id — include nanoseconds + random bytes to prevent same-second collisions.
    use sha2::{Digest as _, Sha256};
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let nonce = sauron_core::ajwt_support::random_hex_32();
    let mut h = Sha256::new();
    h.update(payload.site_name.as_bytes());
    h.update(ts.to_le_bytes());
    h.update(nonce.as_bytes());
    let request_id = hex::encode(&h.finalize()[..16]);
    let ts = (ts / 1_000_000_000) as i64;

    let claims_json = serde_json::to_string(&requested_claims).unwrap_or_else(|_| "[]".into());
    let expires_at = ts + 600; // 10 minutes

    // Store pending consent request in canonical consent_log (user_key_image stays empty until consent).
    // M2 port: pending INSERT goes through Repo::insert_pending_consent so the
    // Postgres backend handles it natively. requests_log audit insert stays in
    // the SQLite-only path (it is a fire-and-forget audit trail).
    {
        let repo = {
            let st = state.read_or_recover();
            st.repo.clone()
        };
        repo.insert_pending_consent(&tenant_id, &request_id, &payload.site_name, &claims_json)
            .await
            .map_err(|e| {
                (
                    StatusCode::CONFLICT,
                    format!("Unable to create consent request: {e}"),
                )
            })?;
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let _ = db.any_conn().execute(
            "INSERT INTO requests_log (timestamp, action_type, status, detail) VALUES (?1,'KYC_REQUEST','PENDING',?2)",
            sql_params![&ts, format!("site={} &request_id={}", &payload.site_name, &request_id)],
        );
    }

    let consent_url = format!(
        "{}/consent?request_id={}&site={}&claims={}",
        std::env::var("NEXT_PUBLIC_API_URL").unwrap_or_else(|_| "http://localhost:3000".into()),
        request_id,
        urlencoding_simple(&payload.site_name),
        urlencoding_simple(&claims_json),
    );

    Ok(Json(KycRequestResponse {
        request_id,
        consent_url,
        expires_at,
    }))
}

fn urlencoding_simple(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

#[derive(Serialize)]
struct KycConsentInfo {
    request_id: String,
    site_name: String,
    requested_claims: Vec<String>,
    status: String,
}

async fn kyc_consent_info(
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Result<Json<KycConsentInfo>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let repo = state.read_or_recover().repo.clone();
    let (site_name, claims_json, consent_token): (String, String, Option<String>) = repo
        .get_consent_info(&tenant_id, &request_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Consent request not found or expired".to_string(),
        ))?;

    let requested_claims: Vec<String> = serde_json::from_str(&claims_json).unwrap_or_default();
    let status = if consent_token.is_some() {
        "granted"
    } else {
        "pending"
    };

    Ok(Json(KycConsentInfo {
        request_id,
        site_name,
        requested_claims,
        status: status.into(),
    }))
}

#[derive(Deserialize)]
struct KycConsentBody {
    request_id: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct KycConsentResponse {
    consent_token: String,
    expires_at: i64,
}

async fn kyc_consent(
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<KycConsentBody>,
) -> Result<Json<KycConsentResponse>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if !sauron_core::feature_flags::user_kyc_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "end-user KYC consent flow disabled (SAURON_DISABLE_USER_KYC=1)".into(),
        ));
    }
    // Validate the consent request exists and is pending
    let site_name = {
        let repo = state.read_or_recover().repo.clone();
        repo.pending_consent_site(&tenant_id, &payload.request_id, false)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::NOT_FOUND,
                "Consent request not found or expired".to_string(),
            ))?
    };

    // Authenticate the user (dev mode: OPRF server-side)
    let server_k = state.read_or_recover().k;
    let oprf_result = dev_oprf_eval(server_k, &payload.email, &payload.password);
    let user_identity = Identity::from_oprf(oprf_result);
    let hex_ki = hex::encode(user_identity.key_image().compress().as_bytes());

    // Verify user exists
    {
        let st = state.read_or_recover();
        if !st.user_group.members.contains(&user_identity.public) {
            return Err((
                StatusCode::NOT_FOUND,
                format!("{} is not registered on Sauron", payload.email),
            ));
        }
    }

    // Generate consent_token
    use sha2::{Digest as _, Sha256};
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut h = Sha256::new();
    h.update(payload.request_id.as_bytes());
    h.update(hex_ki.as_bytes());
    h.update(ts.to_le_bytes());
    let consent_token = hex::encode(&h.finalize()[..]);
    let expires_at = ts + 300; // 5 minutes to use the token

    // Update pending consent row atomically (dual-backend repo)
    {
        let repo = state.read_or_recover().repo.clone();
        let rows = repo
            .grant_consent_token(
                &tenant_id,
                &payload.request_id,
                &hex_ki,
                ts,
                expires_at,
                &consent_token,
                None,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if rows == 0 {
            return Err((
                StatusCode::CONFLICT,
                "Consent already granted for this request".into(),
            ));
        }

        // Also log the consent in requests_log (SQLite-only table, raw handle).
        {
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            let _ = db.any_conn().execute(
                "INSERT INTO requests_log (timestamp, action_type, status, detail) VALUES (?1,'KYC_CONSENT','OK',?2)",
                sql_params![ts, format!("site={} user={}", site_name, &hex_ki[..16])],
            );
        }
    }

    // Email is PII — log site + request_id only.
    tracing::info!(
        target: "sauron::consent",
        site = %site_name,
        request_id = %payload.request_id,
        "user consented"
    );

    Ok(Json(KycConsentResponse {
        consent_token,
        expires_at,
    }))
}

#[derive(Deserialize)]
struct KycRetrieveBody {
    /// The consent_token returned to the site after user approval.
    consent_token: String,
    /// Site name (for balance decrement).
    site_name: String,
    /// Optional Groth16 ZKP proof submitted by the client.
    #[serde(default)]
    zkp_proof: Option<serde_json::Value>,
    /// Circuit name for the ZKP proof (e.g. "AgeVerification").
    #[serde(default)]
    zkp_circuit: Option<String>,
    /// Public signals for the ZKP proof.
    #[serde(default)]
    zkp_public_signals: Option<Vec<String>>,
    /// Optional action to authorize through assurance-level policy engine.
    #[serde(default)]
    required_action: Option<String>,
    /// Required for agent-mediated retrieval: canonical action envelope + ring signature.
    #[serde(default)]
    agent_action: Option<agent_action::AgentActionProof>,
}

async fn kyc_retrieve(
    agent_binding: Option<Extension<DelegatedAgentBinding>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<KycRetrieveBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if !sauron_core::feature_flags::user_kyc_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "end-user KYC retrieval disabled (SAURON_DISABLE_USER_KYC=1)".into(),
        ));
    }
    let groth16_enabled =
        sauron_core::runtime_mode::require_or_default("SAURON_ENABLE_GROTH16", true, false);
    let kyc_groth16_enabled =
        sauron_core::runtime_mode::require_or_default("SAURON_ENABLE_KYC_GROTH16", true, false);
    if !groth16_enabled || !kyc_groth16_enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "legacy KYC Groth16 verification is quarantined; deploy the reviewed transparent proof path or explicitly enable both reviewed Groth16 gates"
                .into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // M2 port: atomic consent-token consume via the dual-backend repo helper.
    // SQLite path wraps in BEGIN IMMEDIATE; Postgres path uses serialisable
    // isolation with FOR UPDATE + UPDATE … RETURNING. Replay/expired/revoked
    // map to RepoError::Replay, surfaced here as 401/409.
    let repo = {
        let st = state.read_or_recover();
        st.repo.clone()
    };
    let (user_ki, stored_site, issuing_agent_id, requested_claims_json) = repo
        .consume_consent_token(&tenant_id, &payload.consent_token, now)
        .await
        .map_err(|e| match e {
            sauron_core::repository::RepoError::Replay(s) => {
                let code = if s.contains("already used") {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::UNAUTHORIZED
                };
                (code, s)
            }
            sauron_core::repository::RepoError::Backend(s) => {
                (StatusCode::INTERNAL_SERVER_ERROR, s)
            }
        })?;

    if stored_site != payload.site_name {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Consent token was not issued for this site".into(),
        ));
    }

    if let Some(expected_agent_id) = issuing_agent_id.clone() {
        let binding = &agent_binding
            .as_ref()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding missing".into(),
            ))?
            .0;
        if binding.agent_id != expected_agent_id || binding.human_key_image != user_ki {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent binding mismatch".into(),
            ));
        }
    }

    // Risk + compliance (DB-backed nationality only; never trust client-supplied jurisdiction).
    let jurisdiction_decision: compliance::JurisdictionDecision = {
        // Risk counter stays on the raw handle (risk_rate_counters is not a
        // ported table); scope it so the lock drops before the async read.
        {
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            risk::check_and_increment(
                &db,
                &risk::bucket_kyc_retrieve(&tenant_id, &payload.site_name, &user_ki),
                now,
                risk::limit_kyc_retrieve(),
            )
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        }
        let nationality: String = {
            let repo = state.read_or_recover().repo.clone();
            repo.get_user(&user_ki)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| u.nationality)
                .unwrap_or_default()
        };
        let st = state.read_or_recover();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?
    };

    // ZKP-only identity disclosure is mandatory.
    let proof = payload
        .zkp_proof
        .clone()
        .ok_or((StatusCode::BAD_REQUEST, "zkp_proof is required".into()))?;
    let public_signals = payload.zkp_public_signals.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "zkp_public_signals are required".into(),
    ))?;
    if public_signals.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "zkp_public_signals must not be empty".into(),
        ));
    }
    let circuit = payload
        .zkp_circuit
        .clone()
        .unwrap_or_else(|| "CredentialVerification".to_string());

    enforce_authoritative_kyc_public_inputs(&circuit, &public_signals)?;

    let (issuer_urls, issuer_rt) = {
        let st = state.read_or_recover();
        (st.issuer_urls.clone(), st.issuer_runtime.clone())
    };
    let requested_dev_mock = proof
        .get("dev_mock")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let verify_body = serde_json::json!({
        "circuit": circuit,
        "proof": proof,
        "public_signals": public_signals,
        "publicSignals": public_signals
    });
    let proof_verified = if requested_dev_mock {
        if !sauron_core::runtime_mode::is_development_runtime() {
            return Err((
                StatusCode::BAD_REQUEST,
                "dev_mock proofs are disabled outside development".into(),
            ));
        }
        true
    } else {
        match issuer_rt
            .verify_proof_failover(&issuer_urls, &verify_body)
            .await
        {
            Ok(v) => v,
            Err(IssuerVerifyError::CircuitOpen) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ZKP issuer verify-proof temporarily unavailable (circuit open)".into(),
                ));
            }
            Err(IssuerVerifyError::Transport(e)) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("ZKP issuer unreachable: {e}"),
                ));
            }
            Err(IssuerVerifyError::JsonParse) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "ZKP issuer returned unreadable JSON for verify-proof".into(),
                ));
            }
            Err(IssuerVerifyError::Upstream(status)) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("ZKP issuer verify-proof returned HTTP {status}"),
                ));
            }
        }
    };

    if !proof_verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            "ZKP proof verification failed".into(),
        ));
    }

    let assertions = build_zkp_assertions(&circuit, &public_signals);
    let requested_claims: Vec<String> =
        serde_json::from_str(&requested_claims_json).unwrap_or_default();
    let disclosed_claims =
        select_disclosed_claims(&assertions, &requested_claims).map_err(|unsupported| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "Unsupported claim request for zkp-only disclosure: {:?}",
                    unsupported
                ),
            )
        })?;

    // Mark token as used + charge one connection credit + record api_usage
    let billing = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();

        let charged = db
            .any_conn()
            .execute(
                "UPDATE clients SET tokens_b = tokens_b - 1 WHERE name = ?1 AND tokens_b > 0",
                sql_params![&payload.site_name],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if charged == 0 {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                format!(
                    "Client '{}' has no credits. Buy credits before retrieval.",
                    payload.site_name
                ),
            ));
        }

        let tokens_b_remaining: i64 = db.any_conn().scalar_or(
            "SELECT tokens_b FROM clients WHERE name = ?1",
            sql_params![&payload.site_name],
            |r| r.get(0),
            0,
        );

        serde_json::json!({
            "charged": true,
            "unit": "connection",
            "amount": 1,
            "tokens_b_remaining": tokens_b_remaining,
        })
    };

    // Record api_usage (token already marked used atomically at the top)
    {
        let st = state.read_or_recover();
        {
            let db = st.db.lock().unwrap();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let is_agent_int = if issuing_agent_id.is_some() {
                1i64
            } else {
                0i64
            };
            let action = if issuing_agent_id.is_some() {
                "kyc_agent"
            } else {
                "kyc_human"
            };
            let _ = db.any_conn().execute(
                "INSERT INTO api_usage (client_name, action, is_agent, timestamp) VALUES (?1,?2,?3,?4)",
                sql_params![&payload.site_name, &action, &is_agent_int, &ts],
            );
        }
        st.log(
            "KYC_RETRIEVE",
            "OK",
            &format!("site={} user={}", payload.site_name, &user_ki[..16]),
        );
    }
    // user_registrations via the dual-backend repo (best-effort, outside the
    // raw-lock scope so the Postgres path can .await).
    {
        let repo = state.read_or_recover().repo.clone();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let _ = repo
            .insert_user_registration(
                &tenant_id,
                &payload.site_name,
                &user_ki,
                "kyc_retrieval",
                ts,
            )
            .await;
    }

    // ── Ring membership verification ─────────────────────────────────────────
    // Verify human is in user_group ring.
    // If consent was issued by an agent, also verify agent is in agent_group ring.
    // Agent inherits human's ring membership — site sees BOTH proofs.
    // Resolve the human public key via the dual-backend repo before the
    // in-memory ring checks (which still need the raw handle for `agents`).
    let human_pub_hex: Option<String> = {
        let repo = state.read_or_recover().repo.clone();
        repo.get_user(&user_ki)
            .await
            .ok()
            .flatten()
            .map(|u| u.public_key_hex)
    };
    let (human_in_user_ring, agent_in_agent_ring, agent_pub_key_hex, agent_assurance_level) = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();

        let human_in_ring = if let Some(ref hex) = human_pub_hex {
            if let Ok(bytes) = hex::decode(hex) {
                if let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> {
                    if let Some(pt) = CompressedRistretto(arr).decompress() {
                        st.user_group.members.contains(&pt)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // If agent-issued consent, verify agent ring membership
        let (agent_in_ring, agent_hex, agent_assurance) = if let Some(ref aid) = issuing_agent_id {
            let agent_row: Option<(String, String)> = db
                .any_conn()
                .query_row(
                    "SELECT public_key_hex, assurance_level FROM agents WHERE tenant_id = ?1 AND agent_id = ?2 AND revoked = 0",
                    sql_params![&tenant_id, aid],
                    |r| Ok((r.get::<String>(0)?, r.get::<String>(1)?)),
                )
                .ok()
                .flatten();
            let in_ring = if let Some((ref hex, _)) = agent_row {
                if !hex.is_empty() {
                    if let Ok(bytes) = hex::decode(hex) {
                        if let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> {
                            if let Some(pt) = CompressedRistretto(arr).decompress() {
                                st.agent_group.members.contains(&pt)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            let agent_hex = agent_row.as_ref().map(|r| r.0.clone());
            let agent_assurance = agent_row.as_ref().map(|r| r.1.clone());
            (in_ring, agent_hex, agent_assurance)
        } else {
            (false, None, None)
        };

        (human_in_ring, agent_in_ring, agent_hex, agent_assurance)
    };

    let is_agent = issuing_agent_id.is_some();
    let trust_verified = human_in_user_ring && (!is_agent || agent_in_agent_ring);

    if !trust_verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Ring trust verification failed for consent owner or delegated agent".into(),
        ));
    }

    if is_agent
        && payload
            .required_action
            .as_deref()
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "required_action is mandatory for agent-mediated retrieval".into(),
        ));
    }

    let action_policy = if is_agent {
        let action = payload.required_action.as_deref().unwrap_or_default();
        let assurance_str = agent_assurance_level
            .clone()
            .unwrap_or_else(|| "delegated_nonbank".to_string());
        let decision = policy::authorize_action(AssuranceLevel::from_db(&assurance_str), action);
        if !decision.allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Policy denied action '{}': {}", action, decision.reason),
            ));
        }
        Some(serde_json::json!({
            "action": action,
            "allowed": true,
            "reason": decision.reason,
            "assurance_level": assurance_str,
            "policy_version": policy::KYA_POLICY_MATRIX_VERSION,
        }))
    } else {
        None
    };

    let action_receipt = if is_agent {
        let binding = agent_binding.as_ref().map(|ext| &ext.0).ok_or((
            StatusCode::UNAUTHORIZED,
            "delegated agent binding context missing".into(),
        ))?;
        let required_action = payload.required_action.as_deref().unwrap_or_default();
        let proof = payload.agent_action.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "agent_action is required for agent-mediated retrieval".into(),
        ))?;
        let resource = format!("kyc_retrieve:{}", payload.site_name);
        let validated = agent_action::validate_agent_action(
            &state,
            proof,
            agent_action::ValidateAgentActionOptions {
                tenant_id: &tenant_id,
                agent_id: &binding.agent_id,
                human_key_image: &binding.human_key_image,
                ajwt_jti: &binding.ajwt_jti,
                intent: Some(&binding.intent),
                expected_action: required_action,
                expected_resource: Some(&resource),
                expected_merchant_id: Some(&payload.site_name),
                expected_amount_minor: Some(0),
                expected_currency: Some(""),
                pop_jkt: Some(&binding.pop_jkt),
                status: "accepted",
            },
        )?;
        {
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            sauron_core::ajwt_support::consume_ajwt_jti(&db, &binding.ajwt_jti, binding.ajwt_exp)
                .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        }
        Some(validated.receipt)
    } else {
        None
    };

    tracing::info!(
        target: "sauron::consent",
        site = %payload.site_name,
        is_agent,
        user_ring = human_in_user_ring,
        agent_ring = agent_in_agent_ring,
        "kyc retrieved"
    );

    let issuer_controls = {
        let st = state.read_or_recover();
        st.issuer_runtime.circuit_snapshots_json(&st.issuer_urls)
    };
    let controls = serde_json::json!({
        "compliance": jurisdiction_decision.for_agent_api(),
        "issuer": issuer_controls,
        "risk": { "window_secs": risk::window_secs() },
    });

    let resp = serde_json::json!({
        "disclosure_mode": "zkp_only",
        "proof": {
            "verified": true,
            "circuit": circuit,
            "public_signals": public_signals,
        },
        "billing": billing,
        "claims": disclosed_claims,
        "identity": {
            "is_agent": is_agent,
            "agent_id": issuing_agent_id,
            "agent_pub_key_hex": agent_pub_key_hex,
            "agent_assurance_level": agent_assurance_level,
            "human_in_user_ring": human_in_user_ring,
            "agent_in_agent_ring": if is_agent { Some(agent_in_agent_ring) } else { None },
            "trust_verified": trust_verified,
            "policy": action_policy,
            "action_receipt": action_receipt,
        },
        "controls": controls,
    });

    Ok(Json(resp))
}

/// Bind every security-relevant public signal in the legacy KYC circuits to
/// server-authoritative policy. A valid proof over prover-chosen dates, issuer
/// keys, roots, or thresholds proves the wrong statement and must be rejected.
fn enforce_authoritative_kyc_public_inputs(
    circuit: &str,
    public_signals: &[String],
) -> Result<(), (StatusCode, String)> {
    if sauron_core::runtime_mode::is_development_runtime() {
        return Ok(());
    }

    fn decimal(label: &str, value: &str) -> Result<String, (StatusCode, String)> {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{label} must be an unsigned decimal public signal"),
            ));
        }
        let canonical = value.trim_start_matches('0');
        Ok(if canonical.is_empty() {
            "0".to_string()
        } else {
            canonical.to_string()
        })
    }

    fn required_env(name: &str) -> Result<String, (StatusCode, String)> {
        let raw = std::env::var(name).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("production KYC proof policy is missing {name}"),
            )
        })?;
        decimal(name, &raw).map_err(|(_, detail)| (StatusCode::INTERNAL_SERVER_ERROR, detail))
    }

    fn require_equal(label: &str, got: &str, expected: &str) -> Result<(), (StatusCode, String)> {
        if decimal(label, got)? != decimal(label, expected)? {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("KYC proof {label} is not the server-authoritative value"),
            ));
        }
        Ok(())
    }

    let today = chrono::Utc::now().format("%Y%m%d").to_string();
    let threshold = required_env("SAURON_ZKP_AGE_THRESHOLD")?;
    let issuer_ax = required_env("SAURON_ZKP_ISSUER_PUBKEY_AX")?;
    let issuer_ay = required_env("SAURON_ZKP_ISSUER_PUBKEY_AY")?;

    match circuit {
        "AgeVerification" => {
            if public_signals.len() != 5 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "AgeVerification requires exactly 5 public signals".into(),
                ));
            }
            if public_signals[0].trim() != "1" {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "AgeVerification valid output must equal 1".into(),
                ));
            }
            let (threshold_i, date_i, ax_i, ay_i) = (1, 2, 3, 4);
            require_equal("ageThreshold", &public_signals[threshold_i], &threshold)?;
            require_equal("currentDate", &public_signals[date_i], &today)?;
            require_equal("issuerPubKeyAx", &public_signals[ax_i], &issuer_ax)?;
            require_equal("issuerPubKeyAy", &public_signals[ay_i], &issuer_ay)?;
        }
        "CredentialVerification" => {
            if public_signals.len() != 9 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "CredentialVerification requires exactly 9 public signals".into(),
                ));
            }
            if !public_signals[..3].iter().all(|v| v.trim() == "1") {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "CredentialVerification outputs must all equal 1".into(),
                ));
            }
            let (date_i, threshold_i, nationality_i, root_i, ax_i, ay_i) =
                (3, 4, 5, 6, 7, 8);
            let required_nationality = required_env("SAURON_ZKP_REQUIRED_NATIONALITY")?;
            let merkle_root = required_env("SAURON_ZKP_CREDENTIAL_MERKLE_ROOT")?;
            require_equal("currentDate", &public_signals[date_i], &today)?;
            require_equal("ageThreshold", &public_signals[threshold_i], &threshold)?;
            require_equal(
                "requiredNationality",
                &public_signals[nationality_i],
                &required_nationality,
            )?;
            require_equal("merkleRoot", &public_signals[root_i], &merkle_root)?;
            require_equal("issuerPubKeyAx", &public_signals[ax_i], &issuer_ax)?;
            require_equal("issuerPubKeyAy", &public_signals[ay_i], &issuer_ay)?;
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "production KYC accepts only the reviewed AgeVerification or CredentialVerification circuits"
                    .into(),
            ))
        }
    }
    Ok(())
}

fn build_zkp_assertions(
    circuit: &str,
    public_signals: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    fn parse_bool_signal(v: Option<&String>) -> Option<bool> {
        v.and_then(|s| s.parse::<u8>().ok()).and_then(|n| match n {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        })
    }

    fn parse_u64_signal(v: Option<&String>) -> Option<u64> {
        v.and_then(|s| s.parse::<u64>().ok())
    }

    let mut assertions = serde_json::Map::new();
    assertions.insert("proof_verified".to_string(), serde_json::Value::Bool(true));
    assertions.insert(
        "circuit".to_string(),
        serde_json::Value::String(circuit.to_string()),
    );

    match circuit {
        "AgeVerification" => {
            let (age_ok, threshold) = if public_signals.len() >= 5 {
                // Accept both layouts:
                //  - outputs-last:  [ageThreshold, currentDate, issuerAx, issuerAy, valid]
                //  - outputs-first: [valid, ageThreshold, currentDate, issuerAx, issuerAy]
                let first_bool = parse_bool_signal(public_signals.first());
                let last_bool = parse_bool_signal(public_signals.last());

                if first_bool.is_some() && last_bool.is_none() {
                    (
                        first_bool.unwrap_or(false),
                        parse_u64_signal(public_signals.get(1)).unwrap_or(0),
                    )
                } else {
                    (
                        last_bool.unwrap_or(false),
                        parse_u64_signal(public_signals.first()).unwrap_or(0),
                    )
                }
            } else {
                // Backward-compatible mock layout: [age_ok, threshold]
                let age_ok = parse_bool_signal(public_signals.first()).unwrap_or(false);
                let threshold = parse_u64_signal(public_signals.get(1)).unwrap_or(0);
                (age_ok, threshold)
            };
            assertions.insert(
                "age_over_threshold".to_string(),
                serde_json::Value::Bool(age_ok),
            );
            assertions.insert(
                "age_threshold".to_string(),
                serde_json::Value::Number(serde_json::Number::from(threshold)),
            );
        }
        "CredentialVerification" => {
            let (age_ok, nationality_ok, credential_ok, threshold) = if public_signals.len() >= 9 {
                // Accept both layouts:
                //  - outputs-last:
                //    [currentDate, ageThreshold, requiredNationality, merkleRoot, issuerAx, issuerAy, ageVerified, nationalityMatched, credentialValid]
                //  - outputs-first:
                //    [ageVerified, nationalityMatched, credentialValid, currentDate, ageThreshold, requiredNationality, merkleRoot, issuerAx, issuerAy]
                let first_three_binary = public_signals
                    .iter()
                    .take(3)
                    .all(|v| parse_bool_signal(Some(v)).is_some());

                if first_three_binary {
                    (
                        parse_bool_signal(public_signals.first()).unwrap_or(false),
                        parse_bool_signal(public_signals.get(1)).unwrap_or(false),
                        parse_bool_signal(public_signals.get(2)).unwrap_or(false),
                        parse_u64_signal(public_signals.get(4)).unwrap_or(0),
                    )
                } else {
                    let n = public_signals.len();
                    (
                        parse_bool_signal(public_signals.get(n - 3)).unwrap_or(false),
                        parse_bool_signal(public_signals.get(n - 2)).unwrap_or(false),
                        parse_bool_signal(public_signals.get(n - 1)).unwrap_or(false),
                        parse_u64_signal(public_signals.get(1)).unwrap_or(0),
                    )
                }
            } else {
                // Backward-compatible mock layout: [age_ok, nationality_ok, credential_ok]
                let age_ok = parse_bool_signal(public_signals.first()).unwrap_or(false);
                let nationality_ok = parse_bool_signal(public_signals.get(1)).unwrap_or(false);
                let credential_ok = parse_bool_signal(public_signals.get(2)).unwrap_or(false);
                (age_ok, nationality_ok, credential_ok, 0)
            };
            assertions.insert(
                "age_over_threshold".to_string(),
                serde_json::Value::Bool(age_ok),
            );
            assertions.insert(
                "age_threshold".to_string(),
                serde_json::Value::Number(serde_json::Number::from(threshold)),
            );
            assertions.insert(
                "nationality_match".to_string(),
                serde_json::Value::Bool(nationality_ok),
            );
            assertions.insert(
                "credential_valid".to_string(),
                serde_json::Value::Bool(credential_ok),
            );
        }
        "MerkleInclusion" => {
            let inclusion_ok = if public_signals.len() >= 4 {
                public_signals
                    .last()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1
            } else {
                public_signals
                    .first()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0)
                    == 1
            };
            assertions.insert(
                "merkle_inclusion".to_string(),
                serde_json::Value::Bool(inclusion_ok),
            );
        }
        _ => {}
    }

    assertions
}

fn select_disclosed_claims(
    assertions: &serde_json::Map<String, serde_json::Value>,
    requested_claims: &[String],
) -> Result<serde_json::Map<String, serde_json::Value>, Vec<String>> {
    let unsupported: Vec<String> = requested_claims
        .iter()
        .filter(|claim| !assertions.contains_key(*claim))
        .cloned()
        .collect();
    if !unsupported.is_empty() {
        return Err(unsupported);
    }

    if requested_claims.is_empty() {
        return Ok(assertions.clone());
    }

    let mut disclosed = serde_json::Map::new();
    for claim in requested_claims {
        if let Some(value) = assertions.get(claim) {
            disclosed.insert(claim.clone(), value.clone());
        }
    }
    Ok(disclosed)
}

#[cfg(test)]
mod tests {
    use super::{build_zkp_assertions, select_disclosed_claims};

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

    #[test]
    fn age_verification_assertions_are_parsed() {
        let signals = vec!["1".to_string(), "21".to_string()];
        let assertions = build_zkp_assertions("AgeVerification", &signals);

        assert_eq!(
            assertions.get("proof_verified").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            assertions
                .get("age_over_threshold")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            assertions.get("age_threshold").and_then(|v| v.as_u64()),
            Some(21)
        );
    }

    #[test]
    fn credential_verification_assertions_are_parsed() {
        let signals = vec!["1".to_string(), "0".to_string(), "1".to_string()];
        let assertions = build_zkp_assertions("CredentialVerification", &signals);

        assert_eq!(
            assertions
                .get("age_over_threshold")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            assertions
                .get("nationality_match")
                .and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            assertions.get("credential_valid").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn requested_claims_reject_unsupported_keys() {
        let signals = vec!["1".to_string(), "18".to_string()];
        let assertions = build_zkp_assertions("AgeVerification", &signals);
        let requested = vec!["age_over_threshold".to_string(), "email".to_string()];

        let unsupported = select_disclosed_claims(&assertions, &requested).unwrap_err();
        assert_eq!(unsupported, vec!["email".to_string()]);
    }

    #[test]
    fn empty_requested_claims_returns_all_assertions() {
        let signals = vec!["1".to_string(), "18".to_string()];
        let assertions = build_zkp_assertions("AgeVerification", &signals);

        let disclosed = select_disclosed_claims(&assertions, &[]).unwrap();
        assert_eq!(disclosed, assertions);
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
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_id.is_empty() || payload.action.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id and action are required".into(),
        ));
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
        return Err((StatusCode::UNAUTHORIZED, "A-JWT agent_id mismatch".into()));
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
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT assurance_level, revoked, expires_at, human_key_image, IFNULL(pop_jkt, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
            params![tenant_id, payload.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".into()))?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if revoked != 0 || expires_at < now || db_human != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Agent is revoked or expired".into(),
        ));
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
        let db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&db, &jti, exp)
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

fn parse_ajwt_intent_claim(
    claims: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    match claims.get("intent") {
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str::<serde_json::Value>(s).map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "A-JWT intent is not valid JSON".into(),
                )
            })
        }
        Some(v @ serde_json::Value::Object(_)) => Ok(v.clone()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "A-JWT missing intent claim".into(),
        )),
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
) -> Result<(), (StatusCode, String)> {
    let scopes = payment_scopes_from_intent(intent);
    if !scopes.iter().any(|s| s == "payment_initiation") {
        return Err((
            StatusCode::FORBIDDEN,
            "Intent scope must explicitly include payment_initiation".into(),
        ));
    }

    let max_amount_major = intent.get("maxAmount").and_then(|v| v.as_f64()).ok_or((
        StatusCode::FORBIDDEN,
        "Intent must define numeric maxAmount for payments".into(),
    ))?;
    if !(max_amount_major.is_finite() && max_amount_major > 0.0) {
        return Err((StatusCode::FORBIDDEN, "Intent maxAmount must be > 0".into()));
    }
    let max_minor = (max_amount_major * 100.0).round() as i64;
    if amount_minor > max_minor {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Requested amount {} exceeds intent maxAmount {} {} ({} minor units)",
                amount_minor, max_amount_major, request_currency, max_minor
            ),
        ));
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
        ));
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
            ));
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
            ));
        }
    }

    Ok(())
}

async fn agent_payment_authorize(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    Json(payload): Json<AgentPaymentAuthorizeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.ajwt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "ajwt is required".into()));
    }
    if payload.amount_minor <= 0 {
        return Err((StatusCode::BAD_REQUEST, "amount_minor must be > 0".into()));
    }
    if payload.payment_ref.trim().is_empty() || payload.payment_ref.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "payment_ref is required (1..128 chars)".into(),
        ));
    }
    let payment_ref = payload.payment_ref.trim().to_string();
    let merchant_id = payload.merchant_id.trim().to_string();
    let currency = payload.currency.trim().to_ascii_uppercase();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "currency must be a 3-letter ISO uppercase code".into(),
        ));
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
            ));
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
    let payment_jurisdiction = {
        {
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            risk::check_and_increment(
                &db,
                &risk::bucket_payment_authorize(&tenant_id, &agent_id),
                now,
                risk::limit_payment_authorize(),
            )
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        }
        let nationality: String = {
            let repo = state.read_or_recover().repo.clone();
            repo.get_user(&human_key_image)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| u.nationality)
                .unwrap_or_default()
        };
        let st = state.read_or_recover();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?
    };

    let (assurance_level, pop_jkt) = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, assurance, pop_jkt, pop_pk_b64u): (i64, i64, String, String, String, String) = db
            .query_row(
                "SELECT revoked, expires_at, human_key_image, assurance_level, IFNULL(pop_jkt, ''), IFNULL(pop_public_key_b64u, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                params![tenant_id, agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".into()))?;
        if revoked != 0 {
            return Err((StatusCode::UNAUTHORIZED, "Agent has been revoked".into()));
        }
        if expires_at < now {
            return Err((StatusCode::UNAUTHORIZED, "Agent has expired".into()));
        }
        if db_human != human_key_image {
            return Err((StatusCode::UNAUTHORIZED, "Agent owner mismatch".into()));
        }
        if pop_jkt.is_empty() || pop_pk_b64u.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires PoP-enabled agent registration".into(),
            ));
        }
        if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Payment authorization requires pop_challenge_id and pop_jws from /agent/pop/challenge".into(),
            ));
        }
        // TODO M2-callsite-sweep: sync take_pop_challenge inside a held
        // MutexGuard; Repo::take_pop_challenge exists for the post-sweep
        // async port. SELECT+DELETE is wrapped in BEGIN IMMEDIATE today.
        let challenge_plain = sauron_core::ajwt_support::take_pop_challenge(
            &db,
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
        ));
    }

    // Sprint 1 (advisory → enforce): consult the server-bound policy for
    // this (tenant, agent). If the binding denies and enforcement mode is
    // `enforce`, short-circuit with 403 before any payment authorisation
    // is issued. `advisory` logs + continues, `off` skips entirely.
    let enforcement_mode = sauron_core::runtime_mode::policy_enforcement_mode();
    if !matches!(
        enforcement_mode,
        sauron_core::runtime_mode::PolicyEnforcementMode::Off
    ) {
        // Build a minimal Action describing the requested payment.
        // - `tool` reuses the intent action name when present, defaulting
        //   to `payment_initiation` (matches the legacy KYA matrix label).
        // - `amount_usd` carries the minor-unit amount converted to a
        //   floating-point USD-equivalent; bound policies that gate by
        //   monetary amount use this directly.
        let intent_tool = intent
            .get("tool")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                intent
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("payment_initiation")
                    .to_string()
            });
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
        match sauron_core::policy::handlers::enforce_bound_policy_for_action(
            &state,
            &tenant_id,
            &agent_id,
            &bound_action,
        )
        .await
        {
            Ok(sauron_core::policy::handlers::BoundPolicyOutcome::Deny {
                policy_id,
                check,
                reason,
            }) => {
                tracing::warn!(
                    target: "sauron::policy::enforcement",
                    %tenant_id,
                    %agent_id,
                    %policy_id,
                    %check,
                    %reason,
                    enforce = matches!(
                        enforcement_mode,
                        sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                    ),
                    "bound policy denied /agent/payment/authorize",
                );
                if matches!(
                    enforcement_mode,
                    sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                ) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        format!("policy {policy_id} denied {check}: {reason}"),
                    ));
                }
            }
            Ok(sauron_core::policy::handlers::BoundPolicyOutcome::PolicyUnavailable {
                policy_id,
            }) => {
                // A binding exists but its policy is not loadable. Never a
                // license to allow — fail closed in enforce mode.
                tracing::error!(
                    target: "sauron::policy::enforcement",
                    %tenant_id,
                    %agent_id,
                    %policy_id,
                    enforce = matches!(
                        enforcement_mode,
                        sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                    ),
                    "bound policy unavailable (binding exists, policy not loadable) — failing closed",
                );
                if matches!(
                    enforcement_mode,
                    sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                ) {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("bound policy {policy_id} is unavailable (failing closed)"),
                    ));
                }
            }
            Ok(sauron_core::policy::handlers::BoundPolicyOutcome::NoBinding) => {
                // Opt-in strict mode: every protected agent must carry a
                // binding. Deny unmanaged agents when require-binding is set.
                if matches!(
                    enforcement_mode,
                    sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                ) && sauron_core::runtime_mode::policy_require_binding()
                {
                    tracing::warn!(
                        target: "sauron::policy::enforcement",
                        %tenant_id,
                        %agent_id,
                        "no bound policy and SAURON_POLICY_REQUIRE_BINDING=1 — denying",
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        "no bound policy for agent (SAURON_POLICY_REQUIRE_BINDING)".to_string(),
                    ));
                }
            }
            Ok(sauron_core::policy::handlers::BoundPolicyOutcome::Allow { .. }) => {}
            Err(e) => {
                // H-7: fail CLOSED in enforce mode. An infra error during policy
                // evaluation previously fell through and authorised the action —
                // an attacker who can induce an eval error (DB pressure, etc.)
                // could bypass the bound policy. In enforce mode we now refuse;
                // advisory/off modes still fall through (dev convenience).
                tracing::warn!(
                    target: "sauron::policy::enforcement",
                    error = %e,
                    enforce = matches!(
                        enforcement_mode,
                        sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                    ),
                    "bound policy enforcement errored",
                );
                if matches!(
                    enforcement_mode,
                    sauron_core::runtime_mode::PolicyEnforcementMode::Enforce
                ) {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("policy enforcement unavailable (failing closed): {e}"),
                    ));
                }
            }
        }
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
        let db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&db, &jti, exp)
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

    let issuer_snap = {
        let st = state.read_or_recover();
        st.issuer_runtime.circuit_snapshots_json(&st.issuer_urls)
    };
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
            "compliance": payment_jurisdiction.for_agent_api(),
            "issuer": issuer_snap,
            "risk": { "window_secs": risk::window_secs() },
        },
    })))
}

// ─────────────────────────────────────────────────────
//  Helpers: user session (stateless HMAC, 1h TTL)
// ─────────────────────────────────────────────────────

fn issue_user_session(jwt_secret: &[u8], tenant_id: &str, key_image: &str) -> (String, i64) {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 3600;
    let payload = format!("v2|{}|{}|{}", tenant_id, key_image, expires_at);
    // HMAC-SHA256, NOT naked SHA256.
    // Naked SHA256(secret || msg) is vulnerable to length-extension: an attacker
    // who has any valid (payload, sig) can extend the message with controlled
    // bytes and produce a valid signature without knowing the secret. HMAC's
    // inner+outer pad construction makes this impossible.
    let session_key = sauron_core::crypto_protocol::derive_subkey(jwt_secret, "session-hmac-v1");
    let mut mac = HmacSha256::new_from_slice(&session_key).expect("HMAC key");
    mac.update(b"|SESSION|");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    (format!("{}|{}", payload, sig), expires_at)
}

fn verify_user_session(
    jwt_secret: &[u8],
    session: &str,
    expected_tenant_id: &str,
) -> Option<String> {
    use subtle::ConstantTimeEq;
    let pos = session.rfind('|')?;
    let payload = &session[..pos];
    let sig = &session[pos + 1..];
    let session_key = sauron_core::crypto_protocol::derive_subkey(jwt_secret, "session-hmac-v1");
    let mut mac = HmacSha256::new_from_slice(&session_key).expect("HMAC key");
    mac.update(b"|SESSION|");
    mac.update(payload.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());
    if computed.as_bytes().ct_eq(sig.as_bytes()).unwrap_u8() == 0 {
        return None;
    }
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 4 || fields[0] != "v2" || fields[1] != expected_tenant_id {
        return None;
    }
    let key_image = fields[2];
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let expires_at: i64 = fields[3].parse().ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if expires_at < now {
        return None;
    }
    Some(key_image.to_string())
}

fn session_key_image(
    headers: &HeaderMap,
    jwt_secret: &[u8],
    expected_tenant_id: &str,
) -> Option<String> {
    let val = headers.get("x-sauron-session")?.to_str().ok()?;
    verify_user_session(jwt_secret, val, expected_tenant_id)
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
) -> Result<Json<UserAuthChallengeResponse>, (StatusCode, String)> {
    use base64::Engine as _;

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let key_image = payload.key_image_hex.trim().to_ascii_lowercase();
    if key_image.len() != 64 || !key_image.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "key_image_hex must be 32-byte hex".into(),
        ));
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
        let db = st.db.lock().unwrap();
        let _ = db.execute(
            "DELETE FROM user_auth_challenges WHERE expires_at < ?1 OR used_at > 0",
            params![now - 300],
        );
        let total: i64 = db
            .query_row("SELECT COUNT(*) FROM user_auth_challenges", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        let active_for_subject: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM user_auth_challenges
                 WHERE tenant_id = ?1 AND key_image_hex = ?2 AND used_at = 0 AND expires_at >= ?3",
                params![&tenant_id, &key_image, now],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if total >= 100_000 || active_for_subject >= 5 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "authentication challenge capacity exceeded".into(),
            ));
        }
        // Insert even for an unknown key image so the response shape and timing
        // do not become a reliable account-enumeration oracle.
        db.execute(
            "INSERT INTO user_auth_challenges
             (challenge_id, tenant_id, key_image_hex, nonce, expires_at, used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![&challenge_id, &tenant_id, &key_image, &nonce, expires_at],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use base64::Engine as _;

    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let key_image = payload.key_image_hex.trim().to_ascii_lowercase();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (nonce, expires_at, public_key_b64u, jwt_secret) = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let challenge: (String, i64) = db
            .query_row(
                "SELECT nonce, expires_at FROM user_auth_challenges
                 WHERE challenge_id = ?1 AND tenant_id = ?2 AND key_image_hex = ?3
                   AND used_at = 0 AND expires_at >= ?4",
                params![&payload.challenge_id, &tenant_id, &key_image, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authentication proof".into(),
                )
            })?;
        let public_key: String = db
            .query_row(
                "SELECT c.ed25519_public_key_b64u
                 FROM user_auth_credentials c
                 JOIN user_auth_tenant_bindings b ON b.key_image_hex = c.key_image_hex
                 WHERE c.key_image_hex = ?1 AND b.tenant_id = ?2",
                params![&key_image, &tenant_id],
                |r| r.get(0),
            )
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authentication proof".into(),
                )
            })?;
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
        let db = st.db.lock().unwrap();
        let consumed = db
            .execute(
                "UPDATE user_auth_challenges SET used_at = ?1
                 WHERE challenge_id = ?2 AND tenant_id = ?3 AND key_image_hex = ?4
                   AND used_at = 0 AND expires_at >= ?1",
                params![now, &payload.challenge_id, &tenant_id, &key_image],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if consumed != 1 {
            return Err((
                StatusCode::UNAUTHORIZED,
                "invalid authentication proof".into(),
            ));
        }
    }
    let (session, session_expires_at) = issue_user_session(&jwt_secret, &tenant_id, &key_image);
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
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
        ));
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
            return Err((StatusCode::UNAUTHORIZED, "User not registered".into()));
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
    let (session, expires_at) = issue_user_session(&jwt_secret, &tenant_id, &key_image);
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

async fn user_consents(
    headers: HeaderMap,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Invalid or expired session".into(),
    ))?;
    let repo = state.read_or_recover().repo.clone();
    let rows: Vec<serde_json::Value> = repo
        .list_user_consents(&tenant_id, &key_image)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .map(|(request_id, site_name, granted_at, token_used, revoked)| {
            serde_json::json!({
                "request_id": request_id,
                "site_name":  site_name,
                "granted_at": granted_at,
                "used":       token_used != 0,
                "revoked":    revoked != 0,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "consents": rows })))
}

// ─────────────────────────────────────────────────────
//  DELETE /user/consent/{request_id} — revoke a consent
// ─────────────────────────────────────────────────────

async fn user_revoke_consent(
    headers: HeaderMap,
    Path(request_id): Path<String>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Invalid or expired session".into(),
    ))?;
    let repo = state.read_or_recover().repo.clone();
    let n = repo
        .revoke_consent(&tenant_id, &request_id, &key_image)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if n == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Consent not found or not yours".into(),
        ));
    }
    Ok(Json(serde_json::json!({ "revoked": true })))
}

// ─────────────────────────────────────────────────────
//  GET /user/credential — fetch BabyJubJub VC for ZKP proofs (frictionless)
//
//  Called automatically by the consent popup after the user authenticates.
//  No extra user action needed — credential retrieved in background.
// ─────────────────────────────────────────────────────

async fn user_get_credential(
    headers: HeaderMap,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if !sauron_core::feature_flags::zkp_issuer_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "ZKP credential issuance disabled (SAURON_DISABLE_ZKP=1)".into(),
        ));
    }
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let key_image = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Invalid or expired session".into(),
    ))?;

    // Plan-2 call-site sweep: these credential lookups now go through the `Repo`
    // abstraction instead of a sync `MutexGuard<Connection>` + inline rusqlite.
    // The SQLite branch runs the identical query (verified locally); the same
    // call routes to Postgres under `SAURON_DB_BACKEND=postgres`. Obtained once
    // and reused for the claim below (also removes two blocking reads from the
    // async runtime).
    let repo = {
        let st = state.read_or_recover();
        st.repo.clone()
    };

    // Look up pre-auth code (no claimed flag yet — we claim atomically below).
    let (pre_auth_code, subject_did) = repo
        .select_credential_code(&tenant_id, &key_image)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "No credential registered. Register via a bank or enroll first.".into(),
        ))?;

    // Fast path: return cached VC if already issued.
    if let Some(vc_json) = repo
        .select_user_credential(&tenant_id, &key_image)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        let vc: serde_json::Value =
            serde_json::from_str(&vc_json).unwrap_or(serde_json::json!({ "raw": vc_json }));
        return Ok(Json(
            serde_json::json!({ "credential": vc, "cached": true }),
        ));
    }

    // M3 port: atomic credential-code claim via dual-backend repo helper.
    // Same TOCTOU pattern as payment_auth: conditional UPDATE under
    // serialisable isolation, RETURNING confirms the flip.
    let claimed_now = repo
        .claim_credential_code(&tenant_id, &key_image)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !claimed_now {
        // Lost the race — another request is mid-flight or just finished. Re-check cache.
        if let Some(vc_json) = repo
            .select_user_credential(&tenant_id, &key_image)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            let vc: serde_json::Value =
                serde_json::from_str(&vc_json).unwrap_or(serde_json::json!({ "raw": vc_json }));
            return Ok(Json(
                serde_json::json!({ "credential": vc, "cached": true }),
            ));
        }
        return Err((
            StatusCode::CONFLICT,
            "Credential claim already in progress; retry shortly".into(),
        ));
    }

    // We won the race — release the claim on any failure path so the user can
    // retry. Routed through the dual-backend repo (Postgres when enabled); the
    // conditional single-statement UPDATE is atomic on both backends.

    // Claim from issuer
    let (issuer_url, client) = {
        let st = state.read_or_recover();
        (st.issuer_url.clone(), st.issuer_runtime.client.clone())
    };
    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
        "subject_did": subject_did,
    });

    let mut request = client.post(format!("{issuer_url}/credential")).json(&body);
    if let Ok(secret) = std::env::var("SAURON_ISSUER_SHARED_SECRET") {
        request = request.header("x-sauron-issuer-key", secret);
    }
    let resp = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = repo.release_credential_code(&tenant_id, &key_image).await;
            return Err((StatusCode::BAD_GATEWAY, format!("Issuer unreachable: {e}")));
        }
    };

    if !resp.status().is_success() {
        let _ = repo.release_credential_code(&tenant_id, &key_image).await;
        return Err((
            StatusCode::BAD_GATEWAY,
            "Issuer returned error during credential claim".into(),
        ));
    }

    let vc: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            let _ = repo.release_credential_code(&tenant_id, &key_image).await;
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("Issuer response parse error: {e}"),
            ));
        }
    };

    // Cache the credential via the dual-backend repo. The claimed=1 flag was
    // set atomically above, no need to re-UPDATE.
    {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let _ = repo
            .upsert_user_credential(&tenant_id, &key_image, &vc.to_string(), ts)
            .await;
    }

    Ok(Json(
        serde_json::json!({ "credential": vc, "cached": false }),
    ))
}

// ─────────────────────────────────────────────────────
//  POST /agent/kyc/consent — agent acts on behalf of human
//
//  Agent presents A-JWT → server validates → issues consent_token
//  in the human owner's name → site can call /kyc/retrieve normally.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentKycConsentBody {
    /// A-JWT issued to the agent by SauronID.
    ajwt: String,
    /// Site requesting KYC.
    site_name: String,
    /// Consent request ID (from /kyc/request).
    request_id: String,
    /// From `POST /agent/pop/challenge` when the agent has PoP keys registered.
    #[serde(default)]
    pop_challenge_id: String,
    /// Compact JWS signing the challenge plaintext (Ed25519).
    #[serde(default)]
    pop_jws: String,
    /// Canonical action envelope + ring signature for the cryptographic leash.
    agent_action: agent_action::AgentActionProof,
}

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

async fn agent_egress_log(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    headers: HeaderMap,
    Json(payload): Json<AgentEgressLogBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
        ));
    }
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if payload.agent_id.is_empty() || payload.target_host.is_empty() || payload.method.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id, target_host, method are required".into(),
        ));
    }
    let signed_agent = headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if signed_agent != payload.agent_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "egress log agent_id does not match signed caller".into(),
        ));
    }
    if !payload.body_hash_hex.is_empty()
        && (payload.body_hash_hex.len() != 64
            || !payload.body_hash_hex.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "body_hash_hex must be empty or 32-byte hex".into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let id = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        // Shared with the enforcing proxy (/agent/egress/proxy) so both log +
        // anchor identically. Voluntary reports are always `allowed = true`.
        sauron_core::egress_gateway::record_egress(
            &db,
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

async fn agent_kyc_consent(
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentKycConsentBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    // 1. Verify A-JWT
    let jwt_secret = state.read_or_recover().jwt_secret.clone();
    let claims = agent::verify_ajwt_for_tenant(&jwt_secret, &payload.ajwt, &tenant_id)
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired A-JWT".into()))?;

    let human_key_image = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing sub claim".into()))?
        .to_string();
    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::UNAUTHORIZED, "A-JWT missing agent_id".into()))?
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

    let consent_guard_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        {
            let st = state.read_or_recover();
            let db = st.db.lock().unwrap();
            risk::check_and_increment(
                &db,
                &risk::bucket_agent_kyc_consent(&tenant_id, &payload.site_name, &human_key_image),
                consent_guard_ts,
                risk::limit_agent_kyc_consent(),
            )
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        }
        let nationality: String = {
            let repo = state.read_or_recover().repo.clone();
            repo.get_user(&human_key_image)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| u.nationality)
                .unwrap_or_default()
        };
        let st = state.read_or_recover();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?;
    }

    // 2. Verify agent status + mandatory delegated-ring membership + KYA policy
    let (assurance_level, pop_jkt) = {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let (revoked, expires_at, db_human, agent_pub_hex, assurance, pop_jkt, pop_pk_b64u): (
            i64,
            i64,
            String,
            String,
            String,
            String,
            String,
        ) = db
            .query_row(
                "SELECT revoked, expires_at, human_key_image, public_key_hex, assurance_level, IFNULL(pop_jkt, ''), IFNULL(pop_public_key_b64u, '') FROM agents WHERE tenant_id = ?1 AND agent_id = ?2",
                params![tenant_id, agent_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap_or((
                1,
                0,
                String::new(),
                String::new(),
                "delegated_nonbank".to_string(),
                String::new(),
                String::new(),
            ));
        if revoked != 0 {
            return Err((StatusCode::UNAUTHORIZED, "Agent has been revoked".into()));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if expires_at < now {
            return Err((StatusCode::UNAUTHORIZED, "Agent has expired".into()));
        }
        if db_human != human_key_image {
            return Err((StatusCode::UNAUTHORIZED, "Agent owner mismatch".into()));
        }
        if agent_pub_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Delegated agent missing ring public key".into(),
            ));
        }
        let bytes = hex::decode(&agent_pub_hex).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key encoding invalid".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key length invalid".into(),
            )
        })?;
        let pt = CompressedRistretto(arr).decompress().ok_or((
            StatusCode::UNAUTHORIZED,
            "Agent public key point invalid".into(),
        ))?;
        if !st.agent_group.members.contains(&pt) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent not in delegated ring".into(),
            ));
        }

        if pop_jkt.is_empty() || pop_pk_b64u.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent KYC consent requires PoP-enabled agent registration".into(),
            ));
        }
        if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent requires PoP: provide pop_challenge_id and pop_jws from /agent/pop/challenge"
                    .into(),
            ));
        }
        // TODO M2-callsite-sweep: same pattern as the /agent/payment/authorize
        // site — sync take_pop_challenge under MutexGuard. Repo helper exists.
        let challenge_plain = sauron_core::ajwt_support::take_pop_challenge(
            &db,
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

    let level = policy::AssuranceLevel::from_db(&assurance_level);
    if !policy::can_agent_issue_kyc_consent(level) {
        return Err((
            StatusCode::FORBIDDEN,
            "delegated_nonbank agents cannot issue KYC consent; use bank-linked delegated registration or /agent/vc/issue"
                .into(),
        ));
    }

    // 3. Verify consent request exists + is for this site + not yet claimed
    let stored_site: String = {
        let repo = state.read_or_recover().repo.clone();
        repo.pending_consent_site(&tenant_id, &payload.request_id, true)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::NOT_FOUND,
                "Consent request not found, already claimed, or already used".to_string(),
            ))?
    };
    if stored_site != payload.site_name {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Request ID does not match site_name".into(),
        ));
    }

    let action_resource = format!("kyc_consent:{}", payload.request_id);
    let validated = agent_action::validate_agent_action(
        &state,
        &payload.agent_action,
        agent_action::ValidateAgentActionOptions {
            tenant_id: &tenant_id,
            agent_id: &agent_id,
            human_key_image: &human_key_image,
            ajwt_jti: &jti,
            intent: Some(&intent),
            expected_action: "kyc_consent",
            expected_resource: Some(&action_resource),
            expected_merchant_id: Some(&payload.site_name),
            expected_amount_minor: Some(0),
            expected_currency: Some(""),
            pop_jkt: Some(&pop_jkt),
            status: "accepted",
        },
    )?;

    // 3b. Server-side JTI consumption (one consent per A-JWT)
    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        sauron_core::ajwt_support::consume_ajwt_jti(&db, &jti, exp)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    }

    // 4. Issue consent_token for the human
    let consent_token = {
        let key = sauron_core::crypto_protocol::derive_subkey(
            jwt_secret.as_slice(),
            "agent-consent-hmac-v1",
        );
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
        mac.update(&sauron_core::crypto_protocol::canonical_fields(
            "sauron.agent-consent.v1",
            &[
                ("tenant_id", &tenant_id),
                ("request_id", &payload.request_id),
                ("human_key_image", &human_key_image),
                ("agent_id", &agent_id),
            ],
        ));
        hex::encode(mac.finalize().into_bytes())
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expires_at = now + 300;

    {
        let repo = state.read_or_recover().repo.clone();
        // Atomic: only update if consent_token is still NULL (race-safe)
        let rows = repo
            .grant_consent_token(
                &tenant_id,
                &payload.request_id,
                &human_key_image,
                now,
                expires_at,
                &consent_token,
                Some(agent_id.as_str()),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if rows == 0 {
            return Err((
                StatusCode::CONFLICT,
                "Consent already claimed by another agent".into(),
            ));
        }
        let st = state.read_or_recover();
        st.log(
            "AGENT_KYC_CONSENT",
            "OK",
            &format!(
                "agent={} site={} human={}",
                &agent_id[..16],
                payload.site_name,
                &human_key_image[..16]
            ),
        );
    }

    tracing::info!(
        target: "sauron::agent",
        agent = &agent_id[..16],
        site = %payload.site_name,
        "kyc consent issued"
    );

    Ok(Json(serde_json::json!({
        "consent_token": consent_token,
        "expires_at": expires_at,
        "on_behalf_of": human_key_image,
        "agent_id": agent_id,
        "assurance_level": assurance_level,
        "action_receipt": validated.receipt,
    })))
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
    /// Optional Groth16 ZKP proof for non-bank KYA.
    #[serde(default)]
    zkp_proof: Option<serde_json::Value>,
    /// Circuit name for non-bank proof (defaults to CredentialVerification).
    #[serde(default)]
    zkp_circuit: Option<String>,
    /// Public signals for non-bank proof.
    #[serde(default)]
    zkp_public_signals: Option<Vec<String>>,
}

fn default_vc_ttl() -> i64 {
    24
}

async fn agent_vc_issue(
    headers: HeaderMap,
    tenant: Option<axum::Extension<sauron_tenancy::TenantId>>,
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentVcIssueBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    if !sauron_core::feature_flags::zkp_issuer_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "agent VC issuance disabled (SAURON_DISABLE_ZKP=1)".into(),
        ));
    }
    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()));
    }
    if payload.public_key_hex.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_hex is required for action-time ring signatures".into(),
        ));
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
        ));
    }
    if payload.pop_jkt.trim().is_empty() || payload.pop_public_key_b64u.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP is mandatory: pop_jkt and pop_public_key_b64u are required".into(),
        ));
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
    let human_key_image = session_key_image(&headers, &jwt_secret, &tenant_id).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "human_key_image payload does not match authenticated session".into(),
        ));
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
        let db = st.db.lock().unwrap();

        let has_bank_link: bool = db
            .query_row(
                "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
                params![human_key_image],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

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
            let db = st.db.lock().unwrap();
            risk::check_and_increment(
                &db,
                &risk::bucket_agent_vc_issue(&tenant_id, &human_key_image),
                vc_issue_ts,
                risk::limit_agent_vc_issue(),
            )
            .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e))?;
        }
        let nationality: String = {
            let repo = state.read_or_recover().repo.clone();
            repo.get_user(&human_key_image)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| u.nationality)
                .unwrap_or_default()
        };
        let st = state.read_or_recover();
        compliance::enforce_jurisdiction(&st.compliance, &nationality)
            .map_err(|e| (StatusCode::FORBIDDEN, e))?;
    }

    let mut non_bank_kya_assertions: Option<serde_json::Map<String, serde_json::Value>> = None;
    let root_of_trust: String;

    if has_bank_link && human_in_user_ring {
        root_of_trust = "did:sauron:idp:bank_kyc".to_string();
    } else {
        let proof = payload.zkp_proof.clone().ok_or((
            StatusCode::BAD_REQUEST,
            "zkp_proof is required for non-bank KYA issuance".into(),
        ))?;
        let public_signals = payload.zkp_public_signals.clone().ok_or((
            StatusCode::BAD_REQUEST,
            "zkp_public_signals are required for non-bank KYA issuance".into(),
        ))?;
        if public_signals.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "zkp_public_signals must not be empty".into(),
            ));
        }
        let circuit = payload
            .zkp_circuit
            .clone()
            .unwrap_or_else(|| "CredentialVerification".to_string());

        let requested_dev_mock = proof
            .get("dev_mock")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if requested_dev_mock && !sauron_core::runtime_mode::is_development_runtime() {
            return Err((
                StatusCode::BAD_REQUEST,
                "dev_mock proofs are disabled outside development".into(),
            ));
        }

        let (issuer_urls, issuer_rt) = {
            let st = state.read_or_recover();
            (st.issuer_urls.clone(), st.issuer_runtime.clone())
        };
        let verify_body = serde_json::json!({
            "circuit": circuit,
            "proof": proof,
            "public_signals": public_signals,
            "publicSignals": public_signals,
        });
        let proof_verified = if requested_dev_mock {
            true
        } else {
            match issuer_rt
                .verify_proof_failover(&issuer_urls, &verify_body)
                .await
            {
                Ok(v) => v,
                Err(IssuerVerifyError::CircuitOpen) => {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ZKP issuer verify-proof temporarily unavailable (circuit open)".into(),
                    ));
                }
                Err(IssuerVerifyError::Transport(e)) => {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("ZKP issuer unreachable: {e}"),
                    ));
                }
                Err(IssuerVerifyError::JsonParse) => {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        "ZKP issuer returned unreadable JSON for verify-proof".into(),
                    ));
                }
                Err(IssuerVerifyError::Upstream(status)) => {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        format!("ZKP issuer verify-proof returned HTTP {status}"),
                    ));
                }
            }
        };

        if !proof_verified {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Non-bank KYA proof verification failed".into(),
            ));
        }

        let assertions = build_zkp_assertions(&circuit, &public_signals);
        let credential_valid = assertions
            .get("credential_valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !credential_valid {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Non-bank KYA requires credential_valid=1 in CredentialVerification proof".into(),
            ));
        }

        non_bank_kya_assertions = Some(assertions);
        root_of_trust = "did:sauron:idp:non_bank_zkp".to_string();
    }

    // 2. Uniqueness check — each human may issue at most 10 active VCs, and
    // each action signing key/key-image pair may back only one active agent.
    {
        let st = state.read_or_recover();
        let db = st.db.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let active_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM agent_vcs
             WHERE agent_id IN (SELECT agent_id FROM agents WHERE tenant_id = ?1 AND human_key_image = ?2)
             AND revoked = 0 AND expires_at > ?3",
                params![tenant_id, human_key_image, now],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if active_count >= 10 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Maximum 10 active agent VCs per human. Revoke some first.".into(),
            ));
        }
        let pub_in_use: bool = db.query_row(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1 AND public_key_hex = ?2 AND revoked = 0 AND expires_at > ?3",
            params![tenant_id, payload.public_key_hex, now],
            |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if pub_in_use {
            return Err((
                StatusCode::CONFLICT,
                "public_key_hex already registered to an active agent".into(),
            ));
        }
        let key_image_in_use: bool = db.query_row(
            "SELECT COUNT(*) FROM agents WHERE tenant_id = ?1 AND ring_key_image_hex = ?2 AND revoked = 0 AND expires_at > ?3",
            params![tenant_id, payload.ring_key_image_hex, now],
            |r| r.get::<_, i64>(0),
        ).unwrap_or(0) > 0;
        if key_image_in_use {
            return Err((
                StatusCode::CONFLICT,
                "ring_key_image_hex already registered to an active agent".into(),
            ));
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
        let db = st.db.lock().unwrap();
        // Register in agents table (so A-JWT flow works normally)
        db.execute(
            "INSERT OR REPLACE INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, tenant_id)
             VALUES (?1,?2,?3,?4,'autonomous_web3',?5,?6,?7,?8,0,NULL,0,?9,?10,?11)",
            params![
                agent_id.clone(),
                human_key_image.clone(),
                payload.agent_checksum.clone(),
                intent_json.clone(),
                payload.public_key_hex.clone(),
                payload.ring_key_image_hex.clone(),
                now,
                expires_at,
                payload.pop_jkt.clone(),
                payload.pop_public_key_b64u.clone(),
                tenant_id.clone(),
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Persist VC
        db.execute(
            "INSERT OR REPLACE INTO agent_vcs (agent_id, vc_json, vc_hash, issued_at, expires_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                agent_id.clone(),
                vc_canonical.clone(),
                vc_hash.clone(),
                now,
                expires_at
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
mod user_session_security_tests {
    use super::*;

    #[test]
    fn session_is_tenant_bound_and_tamper_evident() {
        let key = [9u8; 32];
        let key_image = "ab".repeat(32);
        let (session, _) = issue_user_session(&key, "tenant-a", &key_image);
        assert_eq!(
            verify_user_session(&key, &session, "tenant-a"),
            Some(key_image)
        );
        assert!(verify_user_session(&key, &session, "tenant-b").is_none());
        let tampered = session.replacen("tenant-a", "tenant-b", 1);
        assert!(verify_user_session(&key, &tampered, "tenant-b").is_none());
    }
}
