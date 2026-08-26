//! Health and readiness endpoints: the public one, `readyz`, and the detailed
//! operator view.

use axum::{extract::State, http::StatusCode, response::Json};
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::any_db::AnyRowGet;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

/// GET /health (public) — minimal liveness probe.
///
/// Returns ONLY `{ok: bool}`. Does not leak runtime mode, feature flags,
/// anchor configuration, or DB backend — those would be reconnaissance
/// information for an attacker. The detailed structured report lives at
/// `/admin/health/detailed` behind admin auth.
pub async fn health_public(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<serde_json::Value> {
    // Keep this trivial. Just check the DB roundtrip.
    let ok = {
        let st = state.read_or_recover();
        match st.db.lock() {
            Ok(mut conn) => conn
                .any_conn()
                .query_row("SELECT 1", sql_params![], |r| r.get::<i64>(0))
                .is_ok(),
            Err(_) => false,
        }
    };
    Json(serde_json::json!({ "ok": ok }))
}

/// GET /readyz (public) — readiness probe: liveness plus a DB roundtrip.
///
/// 200 `{"ready":true}` when the database answers `SELECT 1`, otherwise
/// 503 `{"ready":false,"reason":...}`. Like `/health`, the reason is kept
/// generic — DB backend details are recon information; the full detail is
/// logged server-side and available at `/admin/health/detailed`.
pub async fn readyz(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_ok = {
        let st = state.read_or_recover();
        match st.db.lock() {
            Ok(mut conn) => match conn
                .any_conn()
                .query_row("SELECT 1", sql_params![], |r| r.get_i64(0))
            {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(target: "sauron::health", error = %e, "readyz DB probe failed");
                    false
                }
            },
            Err(e) => {
                tracing::error!(target: "sauron::health", error = %e, "readyz DB pool unavailable");
                false
            }
        }
    };
    if db_ok {
        (StatusCode::OK, Json(serde_json::json!({ "ready": true })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ready": false, "reason": "database unreachable" })),
        )
    }
}

/// GET /admin/health/detailed — structured health for operators.
///
/// Same shape as the previous public `/health`, but admin-gated so the
/// configuration surface isn't exposed to unauthenticated clients. Operators
/// scrape this from internal load balancers / monitoring agents.
#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub runtime: &'static str,
    pub call_sig_enforce: bool,
    pub require_agent_type: bool,
    pub require_hardware_attestation: bool,
    pub require_preregistered_measurement: bool,
    pub policy_require_binding: bool,
    pub egress_gateway_enabled: bool,
    pub global_max_action_usd: Option<f64>,
    /// Sprint 1: surfaces SAURON_POLICY_ENFORCEMENT_MODE so operators
    /// can confirm the server is fail-closed before traffic flips.
    pub policy_enforcement_mode: &'static str,
    pub bitcoin_anchor: HealthComponent,
    pub solana_anchor: HealthComponent,
    pub database: HealthComponent,
    /// Durability of the security-audit sinks. `ok=false` (and a warning) once
    /// any audit event failed to persist — regulated deployments alert on this.
    pub audit: HealthComponent,
    pub feature_flags: HealthFlags,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct HealthComponent {
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct HealthFlags {}

pub async fn health(State(state): State<Arc<RwLock<ServerState>>>) -> Json<HealthResponse> {
    let runtime = if crate::runtime_mode::is_development_runtime() {
        "development"
    } else {
        "production"
    };

    let flag = |name: &str| -> bool {
        match std::env::var(name).ok() {
            Some(v) => {
                let low = v.to_ascii_lowercase();
                v == "1" || low == "true" || low == "yes"
            }
            None => false,
        }
    };

    // Sprint 1: shared runtime_mode helper. Dev defaults advisory, prod enforce.
    let call_sig_enforce =
        crate::runtime_mode::require_or_default("SAURON_REQUIRE_CALL_SIG", false, true);
    let require_agent_type =
        crate::runtime_mode::require_or_default("SAURON_REQUIRE_AGENT_TYPE", false, true);
    let require_hardware_attestation = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_HARDWARE_ATTESTATION",
        false,
        false,
    );
    let require_preregistered_measurement = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_PREREGISTERED_MEASUREMENT",
        false,
        false,
    );
    let policy_require_binding = crate::runtime_mode::policy_require_binding();
    let egress_gateway_enabled = crate::egress_gateway::egress_gateway_enabled();
    let global_max_action_usd = crate::runtime_mode::global_max_action_usd();
    let policy_enforcement_mode = crate::runtime_mode::policy_enforcement_mode();

    let mut warnings: Vec<String> = Vec::new();

    // Bitcoin anchor health
    let bitcoin_anchor = match state.read_or_recover().bitcoin_anchor.as_ref() {
        Some(svc) if svc.provider() == crate::bitcoin_anchor::AnchorProvider::OpenTimestamps => {
            HealthComponent {
                ok: true,
                detail: "provider=OpenTimestamps".into(),
            }
        }
        Some(svc) => {
            if runtime == "production" {
                warnings.push(
                    "Production runtime uses a mock Bitcoin anchor; commitments are not externally verifiable"
                        .into(),
                );
            }
            HealthComponent {
                ok: runtime != "production",
                detail: format!("provider={:?} (development only)", svc.provider()),
            }
        }
        None => {
            warnings.push(
                "Bitcoin anchor disabled — audit log is not externally verifiable on BTC".into(),
            );
            HealthComponent {
                ok: false,
                detail: "disabled".into(),
            }
        }
    };
    let solana_anchor = match state.read_or_recover().solana_anchor.as_ref() {
        Some(svc) => HealthComponent {
            ok: true,
            detail: format!("signer={}", &svc.signer_pubkey_b58()[..20]),
        },
        None => {
            warnings.push(
                "Solana anchor disabled — audit log is not externally verifiable on Solana".into(),
            );
            HealthComponent {
                ok: false,
                detail: "disabled (set SAURON_SOLANA_ENABLED=1)".into(),
            }
        }
    };

    // DB roundtrip
    //
    // The label used to be the literal "sqlite" regardless of backend, so a
    // PostgreSQL deployment reported `"database": {"detail": "sqlite"}` while
    // `db.lock()` was correctly dispatching to Postgres — the check was right and
    // only its name was wrong. That matters twice over: an operator reads this to
    // confirm which tier they are on, and the benchmark harness reads it to record
    // which backend a result was measured against, where the two differ by more
    // than 10x on throughput.
    let database = {
        let st = state.read_or_recover();
        let backend = if st.db.is_postgres() {
            "postgres"
        } else {
            "sqlite"
        };
        match st.db.lock() {
            Ok(mut conn) => match conn
                .any_conn()
                .query_row("SELECT 1", sql_params![], |r| r.get_i64(0))
            {
                Ok(_) => HealthComponent {
                    ok: true,
                    detail: backend.into(),
                },
                Err(e) => HealthComponent {
                    ok: false,
                    detail: format!("{backend} query failed: {e}"),
                },
            },
            Err(e) => HealthComponent {
                ok: false,
                detail: format!("db lock: {e}"),
            },
        }
    };

    let feature_flags = HealthFlags {};

    if runtime == "production" && !call_sig_enforce {
        warnings.push("Production runtime but SAURON_REQUIRE_CALL_SIG is not enforced — per-call signature is advisory only".into());
    }
    if runtime == "production" && !require_agent_type {
        warnings.push("Production runtime but SAURON_REQUIRE_AGENT_TYPE is off — operators can supply unverified checksums".into());
    }
    if runtime == "production" && require_hardware_attestation && !require_preregistered_measurement
    {
        warnings.push(
            "Hardware assurance is enabled without authoritative pre-registered measurements"
                .into(),
        );
    }
    if runtime == "production" && !policy_require_binding {
        warnings.push("Production runtime permits protected agents without a bound policy".into());
    }
    if runtime == "production" && !egress_gateway_enabled {
        warnings.push("Production runtime has the enforcing egress gateway disabled".into());
    }
    if runtime == "production" && global_max_action_usd.is_none() {
        warnings
            .push("Production runtime has no SAURON_MAX_ACTION_USD blast-radius ceiling".into());
    }
    if runtime == "production"
        && matches!(
            policy_enforcement_mode,
            crate::runtime_mode::PolicyEnforcementMode::Advisory
                | crate::runtime_mode::PolicyEnforcementMode::Off
        )
    {
        warnings.push(format!(
            "Production runtime but SAURON_POLICY_ENFORCEMENT_MODE is '{}' — bound policy denies do not block action endpoints",
            policy_enforcement_mode.as_str()
        ));
    }
    if !flag("SAURON_VAULT_TRANSIT_ENABLED") && runtime == "production" {
        warnings.push(
            "Production runtime but Vault Transit is not enabled — root secrets in plain env"
                .into(),
        );
    }

    // Audit-sink durability: a non-zero failure count means at least one
    // security event may not have been durably recorded → health failure.
    let audit_failures = crate::middleware::audit_log::audit_sink_failure_count();
    let audit = if audit_failures == 0 {
        HealthComponent {
            ok: true,
            detail: "0 sink failures".into(),
        }
    } else {
        warnings.push(format!(
            "{audit_failures} security-audit sink write failure(s) — events may be missing from the tamper-evident log"
        ));
        HealthComponent {
            ok: false,
            detail: format!("{audit_failures} sink failures"),
        }
    };

    let ok = database.ok && audit.ok && warnings.is_empty();

    Json(HealthResponse {
        ok,
        runtime,
        call_sig_enforce,
        require_agent_type,
        require_hardware_attestation,
        require_preregistered_measurement,
        policy_require_binding,
        egress_gateway_enabled,
        global_max_action_usd,
        policy_enforcement_mode: policy_enforcement_mode.as_str(),
        bitcoin_anchor,
        solana_anchor,
        database,
        audit,
        feature_flags,
        warnings,
    })
}
