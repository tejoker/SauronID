//! Security-event audit trail.
//!
//! A dedicated channel for "what happened on the security boundary"
//! that an operator can ship to a SIEM without scraping the chatty
//! `sauron::*` info logs. Records:
//!
//! - `AuthFailed` — invalid admin key / JWT / call signature.
//! - `SignatureMismatch` — agent call-sig verification failed.
//! - `CrossTenantAttempt` — a request tagged with tenant X tried to
//!   touch tenant Y data.
//! - `PolicyViolation` — DSL evaluation rejected an action.
//! - `AdminKeyRotated` — operator rotated `SAURON_ADMIN_KEY{,S}`.
//! - `RateLimitTripped` — global pre-auth rate limiter fired.
//! - `AdminAction` — an authenticated admin request COMPLETED. Successes,
//!   not just failures: the static admin key can target any tenant by
//!   setting `x-sauron-tenant-id`, and until this variant existed such a
//!   read returned 200 and left no record at all. A boundary whose
//!   legitimate uses are invisible cannot be reviewed after the fact.
//!
//! ## Sinks
//!
//! - Tracing target `sauron::audit::security`. Operator points
//!   `tracing-subscriber` (or any tracing exporter) at this target to
//!   ship to a SIEM.
//! - Optional file sink: when `SAURON_AUDIT_LOG_PATH` is set the
//!   process appends one JSON object per line to that file. Rotation is
//!   the operator's responsibility (logrotate, ECS sidecar, etc).
//! - In-DB table `security_audit_log` (tenant-scoped). Surfaced via
//!   `GET /v1/admin/audit` for operator-side querying without leaving
//!   the SauronID stack.
//!
//! ## Tenant scoping
//!
//! Every record carries a `tenant_id`. The DB index supports
//! `(tenant_id, timestamp)` so an operator query is cheap. The admin
//! query endpoint enforces tenant isolation: a request resolved to
//! tenant `X` can ONLY see records where `tenant_id = X` (unless the
//! special `*` tenant is used, which is reserved for super-admin
//! tooling and is NOT exposed to the HTTP surface).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

use crate::any_db::{AnyConn, SqlValue};
use crate::db::DbHandle;
use crate::sql_params;
use crate::state::ServerState;
use crate::tenancy::TenantId;

/// Structured security event. Variants intentionally narrow — adding a
/// new event requires schema audit + SIEM-rule update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditEvent {
    /// Caller failed auth (admin key, JWT, or call signature).
    AuthFailed {
        ip: String,
        path: String,
        reason: String,
    },
    /// Agent call-signature header set was present but did not verify.
    SignatureMismatch { agent_id: String, path: String },
    /// A request scoped to `tenant_id` reached for resources owned by
    /// `target_tenant`. The default tenant is treated as out-of-band
    /// for legacy traffic; this fires only when both ids are explicitly
    /// set AND differ.
    CrossTenantAttempt {
        tenant_id: String,
        target_tenant: String,
        path: String,
    },
    /// Policy DSL evaluation rejected an action.
    PolicyViolation {
        tenant_id: String,
        agent_id: String,
        policy_id: String,
        check: String,
        reason: String,
    },
    /// Operator rotated the admin key. `key_fingerprint` is the first
    /// 12 hex chars of SHA-256 over the new key bytes — enough to
    /// correlate across rotations without revealing the secret.
    AdminKeyRotated { key_fingerprint: String },
    /// Global ingress rate limiter rejected a request.
    RateLimitTripped { ip: String, path: String },
    /// An authenticated admin request ran to completion.
    ///
    /// `principal` names HOW the caller authenticated, never the credential
    /// itself: `admin_jwt` (scoped, optionally tenant-locked) or `static_key`.
    /// `cross_tenant` records whether the principal was permitted to read
    /// beyond `tenant_id` — the pair (static_key, cross_tenant=false,
    /// tenant_id=acme) is exactly the header-chosen-tenant access that used to
    /// leave no trace.
    AdminAction {
        tenant_id: String,
        principal: String,
        cross_tenant: bool,
        method: String,
        path: String,
        status: u16,
    },
    /// An in-path egress attempt was denied (allowlist miss, or the target
    /// resolved to a blocked/private/metadata IP). Recorded to the
    /// tamper-evident audit chain so denials are non-repudiable — allowed egress
    /// gets an anchored receipt, but denials are only anchored via this chain.
    EgressDenied {
        tenant_id: String,
        agent_id: String,
        host: String,
        method: String,
        path: String,
        reason: String,
    },
}

impl AuditEvent {
    /// Stable string tag for the `event_type` SQL column. Mirrors
    /// the serde `tag` discriminator above so a SIEM query can match
    /// without re-parsing the JSON payload.
    pub fn event_type(&self) -> &'static str {
        match self {
            AuditEvent::AuthFailed { .. } => "auth_failed",
            AuditEvent::SignatureMismatch { .. } => "signature_mismatch",
            AuditEvent::CrossTenantAttempt { .. } => "cross_tenant_attempt",
            AuditEvent::PolicyViolation { .. } => "policy_violation",
            AuditEvent::AdminKeyRotated { .. } => "admin_key_rotated",
            AuditEvent::RateLimitTripped { .. } => "rate_limit_tripped",
            AuditEvent::EgressDenied { .. } => "egress_denied",
            AuditEvent::AdminAction { .. } => "admin_action",
        }
    }

    /// The tenant this event belongs to. Best-effort — events that have
    /// no tenant context (rate-limit trip on unauthenticated traffic)
    /// fall back to the default tenant. Operators querying per-tenant
    /// see those records under `default`.
    pub fn tenant_id(&self) -> String {
        match self {
            AuditEvent::CrossTenantAttempt { tenant_id, .. }
            | AuditEvent::PolicyViolation { tenant_id, .. }
            | AuditEvent::EgressDenied { tenant_id, .. }
            | AuditEvent::AdminAction { tenant_id, .. } => tenant_id.clone(),
            _ => "default".to_string(),
        }
    }
}

/// One audit-log row as returned from the in-DB store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub audit_id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub event: AuditEvent,
    pub timestamp: i64,
}

/// Query parameters for `GET /v1/admin/audit`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    /// Inclusive lower bound on `timestamp` (unix epoch seconds).
    pub since: Option<i64>,
    /// Inclusive upper bound on `timestamp` (unix epoch seconds).
    pub until: Option<i64>,
    /// Filter by event-type tag (one of [`AuditEvent::event_type`]).
    pub event_type: Option<String>,
    /// Page size cap. Default 200, max 1000.
    pub limit: Option<u32>,
}

/// Optional file-sink handle. Lazy-initialized from `init_audit_sink`.
static FILE_SINK: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();

/// Optional DB handle for audit persistence. When `None`, the record
/// helper still emits to tracing + the file sink — handy for unit
/// tests that don't spin up a SQLite DB.
static DB_SINK: OnceLock<Mutex<Option<Arc<DbHandle>>>> = OnceLock::new();

/// Serialises hash-chain appends. `DbHandle::lock()` draws from an r2d2 pool, so
/// two concurrent appends could read the same head and assign a duplicate `seq`,
/// breaking the chain. Audit writes are low-frequency security events, so a
/// process-wide lock around the read-head → insert step is the simplest correct
/// guard.
///
/// It is only *this* process, which is enough on SQLite (one writer) but not on
/// Postgres. There the UNIQUE index on `seq` catches a cross-process collision
/// and [`AUDIT_CHAIN_APPEND_ATTEMPTS`] re-reads the head.
static AUDIT_CHAIN_LOCK: Mutex<()> = Mutex::new(());

/// How many times an append re-reads the chain head after losing the `seq` race.
///
/// Only reachable on Postgres with concurrent writers; on SQLite
/// `AUDIT_CHAIN_LOCK` already made the first attempt the only one. Bounded
/// rather than unbounded so a genuinely broken constraint surfaces as a sink
/// failure instead of spinning inside audit middleware.
const AUDIT_CHAIN_APPEND_ATTEMPTS: usize = 4;

/// Count of audit-sink write failures (DB insert / file write / serialize).
/// A non-zero value means at least one security event may not have been durably
/// recorded. Surfaced in `/admin/health/detailed` so operators can alert; each
/// failure also emits a `tracing::error!` for SIEM. For regulated deployments,
/// treat a rising count as a health failure.
static AUDIT_SINK_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Number of audit-sink write failures since process start (health metric).
pub fn audit_sink_failure_count() -> u64 {
    AUDIT_SINK_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Record (and loudly log) a dropped audit event. Called from the sink writers
/// on every path where a configured sink fails to persist the event.
fn record_audit_sink_failure(sink: &str, detail: &str) {
    AUDIT_SINK_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::error!(
        target: "sauron::audit::security",
        sink,
        error = %detail,
        "AUDIT SINK WRITE FAILED — security event may not be durably recorded",
    );
}

/// Initialize file + DB sinks. Idempotent — calling twice is safe; the
/// second call replaces the previous sinks under their mutex.
///
/// `SAURON_AUDIT_LOG_PATH` controls the file sink. Absent / empty
/// disables the file sink.
pub fn init_audit_sink(db: Arc<DbHandle>) {
    let _ = ensure_security_audit_schema(&db);
    let cell = DB_SINK.get_or_init(|| Mutex::new(None));
    if let Ok(mut g) = cell.lock() {
        *g = Some(db);
    }
    let path = std::env::var("SAURON_AUDIT_LOG_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let cell = FILE_SINK.get_or_init(|| Mutex::new(None));
    if let Ok(mut g) = cell.lock() {
        *g = path.and_then(|p| {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
            {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::warn!(
                        target: "sauron::audit::security",
                        path = %p.display(),
                        err = %e,
                        "failed to open audit log file sink — continuing without it"
                    );
                    None
                }
            }
        });
    }
}

/// Create the `security_audit_log` table if missing. Idempotent — safe
/// to call on every process start.
/// SQLite-only, deliberately. Under Postgres this table and its hash-chain
/// columns come from `migrations/postgres/0007_security_audit_log.sql` and
/// `0014_audit_chain_and_schema_version.sql`; running `CREATE TABLE` /
/// `ALTER TABLE` from application code against Postgres would fight the
/// migration that already owns the schema. The sidecar still gets the table so
/// a Postgres deployment can be rolled back to SQLite without losing the shape.
pub fn ensure_security_audit_schema(db: &DbHandle) -> Result<(), rusqlite::Error> {
    let conn = db.lock_sqlite().map_err(|e| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
    })?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS security_audit_log (
            audit_id    TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL DEFAULT 'default',
            event_type  TEXT NOT NULL,
            event_json  TEXT NOT NULL,
            timestamp   INTEGER NOT NULL,
            -- H-2: tamper-evident hash chain. `seq` is monotonic; `entry_hash`
            -- is HMAC(key, seq|prev_hash|audit_id|tenant|type|json|ts); `prev_hash`
            -- links to the previous row. Editing/deleting/reordering any row
            -- breaks the chain for anyone holding the audit key.
            seq         INTEGER,
            prev_hash   TEXT,
            entry_hash  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_ts
            ON security_audit_log(tenant_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_security_audit_type_ts
            ON security_audit_log(event_type, timestamp);
        "#,
    )?;
    // Idempotent ALTERs for DBs whose security_audit_log was created (here or in
    // db.rs) before the hash chain landed. Must precede the seq index below.
    let _ = conn.execute("ALTER TABLE security_audit_log ADD COLUMN seq INTEGER", []);
    let _ = conn.execute(
        "ALTER TABLE security_audit_log ADD COLUMN prev_hash TEXT",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE security_audit_log ADD COLUMN entry_hash TEXT",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_audit_seq ON security_audit_log(seq)",
        [],
    );
    Ok(())
}

/// HMAC key for the audit hash chain. Sourced from `SAURON_AUDIT_HMAC_KEY`
/// (raw bytes); falls back to a fixed dev key when unset so dev/test still
/// produce a verifiable chain. In production this fallback is unreachable:
/// `runtime_mode::assert_production_enforcement_safe` refuses to boot without a
/// real key (without a secret key, a DB writer could recompute the chain after
/// editing a row).
fn audit_hmac_key() -> Vec<u8> {
    match std::env::var("SAURON_AUDIT_HMAC_KEY") {
        Ok(v) if !v.trim().is_empty() => v.into_bytes(),
        _ => b"SAURON_DEV_AUDIT_HMAC_KEY_v1".to_vec(),
    }
}

/// Compute `entry_hash = hex(HMAC-SHA256(key, seq|prev|audit_id|tenant|type|json|ts))`.
fn compute_entry_hash(
    key: &[u8],
    seq: i64,
    prev_hash: &str,
    audit_id: &str,
    tenant_id: &str,
    event_type: &str,
    event_json: &str,
    timestamp: i64,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(
        format!("{seq}|{prev_hash}|{audit_id}|{tenant_id}|{event_type}|{event_json}|{timestamp}")
            .as_bytes(),
    );
    hex::encode(mac.finalize().into_bytes())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn new_audit_id() -> String {
    // 16 bytes of OS randomness → 32-char hex. Avoids a uuid dep.
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Persist an event to the file sink. Best-effort; failures are logged
/// and swallowed so a full disk never bubbles up as a 5xx to the caller.
fn write_file_sink(line: &str) {
    let cell = FILE_SINK.get_or_init(|| Mutex::new(None));
    match cell.lock() {
        Ok(mut g) => {
            if let Some(file) = g.as_mut() {
                use std::io::Write;
                // A full disk / IO error means the event was NOT durably written
                // to the file sink — record it rather than silently dropping.
                if let Err(e) = writeln!(file, "{line}").and_then(|_| file.flush()) {
                    record_audit_sink_failure("file", &e.to_string());
                }
            }
        }
        Err(_) => record_audit_sink_failure("file", "sink mutex poisoned"),
    }
}

/// Persist an event to the DB sink (when one was wired up).
fn write_db_sink(record: &AuditRecord) {
    let cell = DB_SINK.get_or_init(|| Mutex::new(None));
    let db = match cell.lock() {
        Ok(g) => match g.as_ref() {
            Some(d) => Arc::clone(d),
            // No DB sink configured (e.g. unit tests) — not a failure.
            None => return,
        },
        Err(_) => {
            record_audit_sink_failure("db", "sink mutex poisoned");
            return;
        }
    };
    let mut conn = match db.lock() {
        Ok(c) => c,
        Err(e) => {
            record_audit_sink_failure("db", &format!("connection pool lock: {e}"));
            return;
        }
    };
    let event_json = match serde_json::to_string(&record.event) {
        Ok(s) => s,
        Err(e) => {
            record_audit_sink_failure("db", &format!("event serialize: {e}"));
            return;
        }
    };
    // H-2: append to the tamper-evident hash chain. `DbHandle::lock()` is a pool
    // checkout (not a global mutex), so the head-read → insert must be serialised
    // explicitly to keep `seq` monotonic and gap-free.
    //
    // The mutex only covers this process. Under Postgres — where more than one
    // process is the point — two appenders can read the same head and compute
    // the same `seq`. `uq_security_audit_seq` in
    // `migrations/postgres/0014_audit_chain_and_schema_version.sql` is UNIQUE
    // on `seq`, so the loser gets a unique violation rather than a silent fork,
    // and re-reads the head instead of dropping the event. The constraint is
    // the check; this retry is what turns "detected" into "recorded".
    let _chain = AUDIT_CHAIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let key = audit_hmac_key();
    for attempt in 0..AUDIT_CHAIN_APPEND_ATTEMPTS {
        let (last_seq, last_hash): (i64, String) =
            chain_head_raw(&mut conn.any_conn()).unwrap_or((0, "genesis".to_string()));
        let seq = last_seq + 1;
        let entry_hash = compute_entry_hash(
            &key,
            seq,
            &last_hash,
            &record.audit_id,
            &record.tenant_id,
            &record.event_type,
            &event_json,
            record.timestamp,
        );
        match conn.any_conn().execute(
            "INSERT INTO security_audit_log
         (audit_id, tenant_id, event_type, event_json, timestamp, seq, prev_hash, entry_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            sql_params![
                &record.audit_id,
                &record.tenant_id,
                &record.event_type,
                &event_json,
                record.timestamp,
                seq,
                &last_hash,
                &entry_hash
            ],
        ) {
            Ok(_) => return,
            Err(e) => {
                let msg = e.to_lowercase();
                let lost_the_race = msg.contains("unique") || msg.contains("duplicate key");
                if !lost_the_race || attempt + 1 == AUDIT_CHAIN_APPEND_ATTEMPTS {
                    record_audit_sink_failure("db", &format!("insert: {e}"));
                    return;
                }
            }
        }
    }
}

/// Verify the integrity of the security-audit hash chain. Walks rows in `seq`
/// order, recomputing each `entry_hash` and checking the `prev_hash` linkage.
/// Returns `Err(reason)` at the first inconsistency (edit, deletion, reorder).
/// Used by an admin verify endpoint / external auditor holding the audit key.
/// Current head of the keyed audit chain: `(seq, entry_hash)`, or `None` when
/// nothing has been logged yet.
///
/// The chain proves nobody edited the log *without the sealing key*. Whoever
/// holds that key — the operator — can rewrite history and re-seal it. Anchoring
/// this head into an external timestamp is what closes that: the head published
/// at time T cannot be changed after T, so any later rewrite contradicts a
/// commitment the operator does not control.
pub fn audit_chain_head(conn: &mut AnyConn<'_>) -> Option<(i64, String)> {
    chain_head_raw(conn).filter(|(_, hash)| !hash.is_empty())
}

/// The raw head row, shared by the append path and [`audit_chain_head`].
///
/// These were two copies of the same query with different fallbacks. They must
/// agree — the appender links to whatever this returns, and an anchor commits
/// it — so one of them drifting would break the chain silently.
fn chain_head_raw(conn: &mut AnyConn<'_>) -> Option<(i64, String)> {
    conn.query_row(
        "SELECT seq, entry_hash FROM security_audit_log
         WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1",
        sql_params![],
        |r| Ok((r.get_i64(0)?, r.get_string(1)?)),
    )
    .ok()
    .flatten()
}

pub fn verify_audit_chain(conn: &mut AnyConn<'_>) -> Result<u64, String> {
    let key = audit_hmac_key();
    let rows = conn
        .query_map(
            "SELECT seq, prev_hash, entry_hash, audit_id, tenant_id, event_type, event_json, timestamp
             FROM security_audit_log WHERE seq IS NOT NULL ORDER BY seq ASC",
            sql_params![],
            |r| {
                Ok((
                    r.get_i64(0)?,
                    r.get_string(1)?,
                    r.get_string(2)?,
                    r.get_string(3)?,
                    r.get_string(4)?,
                    r.get_string(5)?,
                    r.get_string(6)?,
                    r.get_i64(7)?,
                ))
            },
        )
        .map_err(|e| format!("query: {e}"))?;
    let mut expected_seq = 1i64;
    let mut prev = "genesis".to_string();
    let mut count = 0u64;
    // query_map already collected and propagated decode failures, so a row that
    // cannot be read aborts verification instead of being skipped — which for a
    // tamper-evidence check is the whole point.
    for (seq, prev_hash, entry_hash, audit_id, tenant_id, event_type, event_json, ts) in rows {
        if seq != expected_seq {
            return Err(format!(
                "seq gap: expected {expected_seq}, got {seq} (row deleted/reordered)"
            ));
        }
        if prev_hash != prev {
            return Err(format!("prev_hash mismatch at seq {seq} (chain broken)"));
        }
        let recomputed = compute_entry_hash(
            &key,
            seq,
            &prev_hash,
            &audit_id,
            &tenant_id,
            &event_type,
            &event_json,
            ts,
        );
        if recomputed != entry_hash {
            return Err(format!("entry_hash mismatch at seq {seq} (row tampered)"));
        }
        prev = entry_hash;
        expected_seq += 1;
        count += 1;
    }
    Ok(count)
}

/// Record one audit event to all configured sinks.
///
/// Always emits to the `sauron::audit::security` tracing target. Also
/// writes to the file + DB sinks when [`init_audit_sink`] has wired
/// them. Failures in any sink are logged-and-swallowed: the caller MUST
/// be able to record an event without blocking the request path.
pub fn record(event: AuditEvent) {
    let record = AuditRecord {
        audit_id: new_audit_id(),
        tenant_id: event.tenant_id(),
        event_type: event.event_type().to_string(),
        event,
        timestamp: unix_now(),
    };
    let json = serde_json::to_string(&record).unwrap_or_else(|_| {
        // Best-effort fallback if a future variant has a non-serializable field.
        format!(
            "{{\"audit_id\":\"{}\",\"event_type\":\"{}\",\"timestamp\":{}}}",
            record.audit_id, record.event_type, record.timestamp
        )
    });
    tracing::info!(
        target: "sauron::audit::security",
        audit_id = %record.audit_id,
        tenant_id = %record.tenant_id,
        event_type = %record.event_type,
        timestamp = record.timestamp,
        event_json = %json,
        "audit event"
    );
    write_file_sink(&json);
    write_db_sink(&record);
}

/// Query the in-DB store with tenant isolation.
///
/// Tenant `*` is special-cased to mean "no tenant filter" — but the
/// HTTP surface does NOT expose this. Only background tools (which
/// hold operator-global trust) should pass `*`.
pub fn query_audit_events(
    db: &DbHandle,
    tenant: &str,
    q: &AuditQuery,
) -> Result<Vec<AuditRecord>, String> {
    let mut conn = db
        .lock()
        .map_err(|e| format!("audit query: db lock: {e}"))?;
    let limit = q.limit.unwrap_or(200).min(1000) as i64;
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(i64::MAX);
    let event_type_filter = q.event_type.clone();

    // Filters are optional, so the placeholder numbers depend on which ones are
    // present. Building the argument list alongside the SQL numbers them from
    // its length instead of by hand — the previous version wrote "?3" or "?4"
    // for event_type depending on the tenant branch, and needed a four-arm match
    // at the end purely because `params!` takes a fixed arity.
    let mut sql = String::from(
        "SELECT audit_id, tenant_id, event_type, event_json, timestamp \
         FROM security_audit_log WHERE timestamp >= ?1 AND timestamp <= ?2",
    );
    let mut args: Vec<SqlValue> = vec![since.into(), until.into()];
    if tenant != "*" {
        args.push(tenant.into());
        sql.push_str(&format!(" AND tenant_id = ?{}", args.len()));
    }
    if let Some(ref et) = event_type_filter {
        args.push(et.as_str().into());
        sql.push_str(&format!(" AND event_type = ?{}", args.len()));
    }
    args.push(limit.into());
    sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{}", args.len()));

    conn.any_conn()
        .query_map(&sql, &args, |row| {
            let event_json = row.get_string(3)?;
            Ok(AuditRecord {
                audit_id: row.get_string(0)?,
                tenant_id: row.get_string(1)?,
                event_type: row.get_string(2)?,
                event: serde_json::from_str(&event_json).map_err(|e| format!("event_json: {e}"))?,
                timestamp: row.get_i64(4)?,
            })
        })
        .map_err(|e| format!("audit query: {e}"))
}

/// Axum middleware that records auth/policy failures after the handler
/// runs. Sits AFTER the auth layer so the tenant id is already
/// resolved on the request extensions, and the response status reveals
/// whether the handler accepted or rejected the call.
///
/// Mapping rules:
/// - 401, 407 → `AuthFailed`
/// - 403 → `AuthFailed` (forbidden = auth scope mismatch)
/// - Any other status passes through unaudited (admin queries on the
///   audit log itself are intentionally NOT logged to avoid recursion).
pub async fn audit_log_middleware(request: Request, next: Next) -> Response {
    // Snapshot identifying bits BEFORE the request is consumed.
    let path = request.uri().path().to_string();
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let response = next.run(request).await;
    let status = response.status().as_u16();

    // Suppress audit recursion: don't re-audit the audit-query endpoint.
    let is_audit_path = path.starts_with("/v1/admin/audit");
    if !is_audit_path && matches!(status, 401 | 403 | 407) {
        record(AuditEvent::AuthFailed {
            ip,
            path,
            reason: format!("http {status}"),
        });
    }
    response
}

/// HTTP handler: `GET /v1/admin/audit?since=X&until=Y&event_type=Z`.
///
/// Tenant-scoped via `Extension<TenantId>` (set by the existing tenancy
/// middleware). Admin-gated by being mounted under the admin router.
pub async fn admin_audit_handler(
    axum::Extension(tenant): axum::Extension<TenantId>,
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<axum::response::Json<Vec<AuditRecord>>, (axum::http::StatusCode, String)> {
    let db = {
        let st = state.read().map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("state lock: {e}"),
            )
        })?;
        Arc::clone(&st.db)
    };
    let rows = query_audit_events(&db, tenant.as_str(), &q)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(axum::response::Json(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fresh in-memory DbHandle backed by a unique temp file.
    /// Avoids `:memory:` because our DbHandle wraps an r2d2 pool that
    /// can't share an in-memory DB across connections.
    fn fresh_db() -> (Arc<DbHandle>, std::path::PathBuf) {
        // Each test gets a unique file so we never collide.
        let dir = std::env::temp_dir().join("sauron_audit_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!(
            "audit-{}-{}.sqlite",
            std::process::id(),
            new_audit_id(),
        ));
        let db = Arc::new(crate::db::open_db_at(path.to_str().unwrap(), 2));
        ensure_security_audit_schema(&db).expect("schema");
        (db, path)
    }

    // The audit sinks are OnceLock<Mutex<…>> globals because the
    // record() helper is called from any worker without a state
    // handle. Tests that exercise the global sinks must run
    // serialized so the DB pointer one test installs is the same one
    // observed by `record()` immediately after. A static mutex,
    // grabbed via a small helper, gives us that ordering without
    // requiring `cargo test -- --test-threads=1`.
    static SINK_TEST_GUARD: Mutex<()> = Mutex::new(());
    fn lock_sink_tests() -> std::sync::MutexGuard<'static, ()> {
        match SINK_TEST_GUARD.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
    fn reset_sinks_for_test() {
        // Clear any DB sink leftover from earlier tests in this binary.
        let cell = DB_SINK.get_or_init(|| Mutex::new(None));
        if let Ok(mut g) = cell.lock() {
            *g = None;
        }
        let cell = FILE_SINK.get_or_init(|| Mutex::new(None));
        if let Ok(mut g) = cell.lock() {
            *g = None;
        }
    }

    #[test]
    fn record_emits_to_tracing_and_db_when_wired() {
        let _g = lock_sink_tests();
        reset_sinks_for_test();
        let (db, _path) = fresh_db();
        init_audit_sink(Arc::clone(&db));
        record(AuditEvent::AuthFailed {
            ip: "1.2.3.4".into(),
            path: "/v1/policy/upload".into(),
            reason: "missing x-admin-key".into(),
        });
        // The OnceLock-backed sink is process-global so the row landed
        // in the DB we wired up.
        let rows = query_audit_events(
            &db,
            "default",
            &AuditQuery {
                event_type: Some("auth_failed".into()),
                ..Default::default()
            },
        )
        .expect("query");
        assert!(
            rows.iter().any(|r| matches!(
                &r.event,
                AuditEvent::AuthFailed { ip, .. } if ip == "1.2.3.4"
            )),
            "expected auth_failed row, got {rows:?}"
        );
    }

    #[test]
    fn audit_hash_chain_verifies_and_detects_tampering() {
        let _g = lock_sink_tests();
        reset_sinks_for_test();
        let (db, _path) = fresh_db();
        init_audit_sink(Arc::clone(&db));
        for i in 0..3 {
            record(AuditEvent::AuthFailed {
                ip: format!("10.0.0.{i}"),
                path: "/v1/admin".into(),
                reason: "test".into(),
            });
        }
        let mut conn = db.lock().unwrap();
        // Intact chain verifies.
        let n = verify_audit_chain(&mut conn.any_conn()).expect("chain should verify");
        assert!(n >= 3, "expected >=3 chained rows, got {n}");
        // Tamper a row's payload in place — verification must now fail.
        conn.any_conn()
            .execute(
                "UPDATE security_audit_log SET event_json = '{\"tampered\":true}' WHERE seq = 2",
                sql_params![],
            )
            .unwrap();
        let err = verify_audit_chain(&mut conn.any_conn()).expect_err("tampering must be detected");
        assert!(err.contains("seq 2"), "got: {err}");
    }

    #[test]
    fn file_sink_appends_jsonl_when_path_env_set() {
        let _g = lock_sink_tests();
        reset_sinks_for_test();
        let dir = std::env::temp_dir().join("sauron_audit_file_sink");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join(format!("audit-{}.jsonl", new_audit_id()));
        std::env::set_var("SAURON_AUDIT_LOG_PATH", file_path.to_str().unwrap());
        let (db, _p) = fresh_db();
        init_audit_sink(Arc::clone(&db));
        record(AuditEvent::AdminKeyRotated {
            key_fingerprint: "deadbeef".into(),
        });
        std::env::remove_var("SAURON_AUDIT_LOG_PATH");
        let content = std::fs::read_to_string(&file_path).expect("read sink");
        assert!(
            content.contains("admin_key_rotated"),
            "sink missing event tag: {content}"
        );
        assert!(content.contains("deadbeef"));
    }

    #[test]
    fn db_insert_and_tenant_scoped_query_round_trip() {
        let _g = lock_sink_tests();
        reset_sinks_for_test();
        let (db, _p) = fresh_db();
        init_audit_sink(Arc::clone(&db));
        record(AuditEvent::PolicyViolation {
            tenant_id: "acme".into(),
            agent_id: "agt_x".into(),
            policy_id: "pol_y".into(),
            check: "spend_cap".into(),
            reason: "over budget".into(),
        });
        record(AuditEvent::PolicyViolation {
            tenant_id: "globex".into(),
            agent_id: "agt_z".into(),
            policy_id: "pol_w".into(),
            check: "spend_cap".into(),
            reason: "over budget".into(),
        });
        let acme = query_audit_events(&db, "acme", &AuditQuery::default()).expect("acme");
        assert_eq!(acme.len(), 1);
        assert_eq!(acme[0].tenant_id, "acme");
        let globex = query_audit_events(&db, "globex", &AuditQuery::default()).expect("globex");
        assert_eq!(globex.len(), 1);
        assert_eq!(globex[0].tenant_id, "globex");
    }

    #[test]
    fn cross_tenant_query_isolation_blocks_leakage() {
        let _g = lock_sink_tests();
        reset_sinks_for_test();
        let (db, _p) = fresh_db();
        init_audit_sink(Arc::clone(&db));
        record(AuditEvent::CrossTenantAttempt {
            tenant_id: "tenant_a".into(),
            target_tenant: "tenant_b".into(),
            path: "/v1/policy/list".into(),
        });
        // Tenant A sees their own event.
        let a = query_audit_events(&db, "tenant_a", &AuditQuery::default()).expect("a");
        assert_eq!(a.len(), 1);
        // Tenant B sees NOTHING — the attempt was recorded against the
        // SOURCE tenant (the attacker), not the target.
        let b = query_audit_events(&db, "tenant_b", &AuditQuery::default()).expect("b");
        assert!(
            b.is_empty(),
            "tenant_b should not see tenant_a's event: {b:?}"
        );
        // Operator-global query (tenant=*) sees both.
        let all = query_audit_events(&db, "*", &AuditQuery::default()).expect("*");
        assert!(all.iter().any(|r| r.tenant_id == "tenant_a"));
    }

    #[test]
    fn malformed_event_json_rejected_on_deserialize() {
        // We test the boundary: a JSON blob that doesn't match any
        // variant is rejected by serde, NOT silently accepted.
        let bad = r#"{"type":"not_a_real_event","ip":"1.1.1.1"}"#;
        let parsed: Result<AuditEvent, _> = serde_json::from_str(bad);
        assert!(parsed.is_err(), "expected serde to reject unknown variant");

        // And: deny_unknown_fields means an extra key is also rejected.
        let extra = r#"{"type":"auth_failed","ip":"1.1.1.1","path":"/x","reason":"y","z":1}"#;
        let parsed: Result<AuditEvent, _> = serde_json::from_str(extra);
        assert!(parsed.is_err(), "expected serde to reject extra field");
    }
}
