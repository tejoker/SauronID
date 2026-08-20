use std::time::Duration;

use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::any_db::AnyConn;

/// Marker embedded in the `Debug` form of [`PoolTimeout`], and matched by the
/// HTTP panic handler in `main.rs` to answer 503 instead of 500.
///
/// It has to live in `Debug` rather than `Display` because `Result::unwrap`
/// formats with `Debug`, and the ~90 call sites that take a connection do so
/// with `.unwrap()`. r2d2's own error is no help here: it `Debug`-prints as
/// `Error(None)`, which is indistinguishable from any other panic.
pub const POOL_TIMEOUT_MARKER: &str = "sauron_db_pool_timeout";

/// Failure to take a pooled SQLite connection.
///
/// There is exactly one cause: every connection was busy for longer than
/// r2d2's connection timeout. That is load, not a fault — the correct answer
/// is "come back shortly", not "the server is broken". Wrapping r2d2's opaque
/// error gives the panic payload something the HTTP layer can recognise.
pub struct PoolTimeout(pub r2d2::Error);

impl std::fmt::Debug for PoolTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{POOL_TIMEOUT_MARKER}: {}", self.0)
    }
}

impl std::fmt::Display for PoolTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database connection pool exhausted: {}", self.0)
    }
}

impl std::error::Error for PoolTimeout {}

pub struct DbHandle {
    pool: Pool<SqliteConnectionManager>,
    /// Present when SAURON_DB_BACKEND=postgres and DATABASE_URL is set.
    ///
    /// Held ALONGSIDE the SQLite pool, not instead of it: 277 call sites still
    /// take `lock()` and speak rusqlite, so during the migration both are live
    /// and each converted call site moves to `any()`. When the last one moves,
    /// the SQLite pool becomes the dev-only default rather than a sidecar.
    pg_pool: Option<Pool<PostgresConnectionManager<PgTls>>>,
}

impl DbHandle {
    /// A pooled connection to the configured backend.
    ///
    /// Was the SQLite-only accessor; it is now an alias for [`conn`], which is
    /// what made the port atomic. Every call site acquires here, so pointing
    /// this one function at the dispatching guard moved all of them at once —
    /// and the compiler then found each site that still spoke rusqlite
    /// directly, because `DbConn` has no `query_row`/`execute` of its own.
    pub fn lock(&self) -> Result<DbConn, PoolTimeout> {
        self.conn()
    }

    /// A pooled *SQLite* connection, whatever backend is configured.
    ///
    /// Using this asserts "this does not work on Postgres and is not meant
    /// to". There are two such cases, both deliberate: schema initialisation
    /// (Postgres takes its schema from `migrations/postgres/`, not from
    /// `init_schema`) and SQLite's online backup API, which has no Postgres
    /// equivalent. Every caller says which one it is at the site.
    pub fn lock_sqlite(&self) -> Result<PooledConnection<SqliteConnectionManager>, PoolTimeout> {
        self.pool.get().map_err(PoolTimeout)
    }

    /// True when a Postgres pool is configured and `any()` will use it.
    pub fn is_postgres(&self) -> bool {
        self.pg_pool.is_some()
    }

    /// An owned connection to whichever backend is configured.
    ///
    /// This is what `lock()` should have been. `lock()` hands back a SQLite
    /// connection, and every call site that then says `.any_conn()` gets
    /// `AnyConn::Sqlite` from `impl AsAnyConn for rusqlite::Connection` — so the
    /// portable idiom reads as backend-agnostic while being pinned to SQLite.
    /// That is why `DbHandle::any()` had no callers and the whole dual-backend
    /// layer was unreachable.
    ///
    /// [`any()`] solves it with a closure, which is correct but requires every
    /// call site to be restructured around one. This returns a guard instead:
    /// the caller keeps its existing shape and only the acquisition line
    /// changes, because `DbConn::any_conn()` dispatches where the trait impl
    /// could not.
    ///
    /// The guard owns its pooled connection, so the pool lifetime stays here
    /// rather than leaking outward — the objection that motivated the closure.
    /// The cost is that callers need `let mut`, since the Postgres variant is
    /// borrowed mutably.
    pub fn conn(&self) -> Result<DbConn, PoolTimeout> {
        match &self.pg_pool {
            // `pool.get()` may open a connection or reap a broken one, and both
            // run the blocking driver — so the acquisition needs the same
            // treatment as a query.
            Some(pool) => Ok(DbConn::Postgres(Some(Box::new(
                crate::any_db::blocking(|| pool.get()).map_err(PoolTimeout)?,
            )))),
            None => Ok(DbConn::Sqlite(self.lock_sqlite()?)),
        }
    }
}

impl Drop for DbHandle {
    fn drop(&mut self) {
        // Dropping the r2d2 pool closes every idle Postgres client, and each
        // close runs the blocking driver. At process shutdown that happens on a
        // runtime thread, so it needs the same guard as a query.
        if let Some(pool) = self.pg_pool.take() {
            crate::any_db::blocking(move || drop(pool));
        }
    }
}

/// An owned pooled connection to whichever backend is configured.
///
/// Obtained from [`DbHandle::conn`]. Call [`DbConn::any_conn`] to get the
/// portable query surface; unlike the same-named method on
/// `rusqlite::Connection`, this one actually dispatches.
///
/// The Postgres client is boxed because it is roughly twice the size of the
/// SQLite guard, and every caller of [`DbHandle::conn`] would otherwise pay for
/// the larger variant on the stack — including the SQLite deployments, which
/// are all of them today.
pub enum DbConn {
    Sqlite(PooledConnection<SqliteConnectionManager>),
    /// `Option` only so [`Drop`] can take the client out and release it from a
    /// context where blocking is allowed; it is `Some` for the guard's whole
    /// usable life.
    Postgres(Option<Box<PooledConnection<PostgresConnectionManager<PgTls>>>>),
}

impl Drop for DbConn {
    fn drop(&mut self) {
        // Returning a pooled Postgres client can close it, and closing runs the
        // blocking driver's `block_on`. Dropping a guard at the end of an async
        // handler would then panic — the same failure as an unwrapped query,
        // arriving during unwind. Only the Postgres arm needs this; the SQLite
        // guard's drop is pure bookkeeping.
        if let DbConn::Postgres(slot) = self {
            if let Some(client) = slot.take() {
                use tokio::runtime::{Handle, RuntimeFlavor};
                match Handle::try_current() {
                    // Multi-thread runtime: hand the thread to the blocking
                    // driver for the duration of the close.
                    Ok(h) if h.runtime_flavor() != RuntimeFlavor::CurrentThread => {
                        tokio::task::block_in_place(move || drop(client));
                    }
                    // Current-thread runtime: `block_in_place` is unavailable and
                    // dropping inline runs the driver's `block_on` on the very
                    // thread driving the reactor, which panics with "cannot start
                    // a runtime from within a runtime". In a destructor that is
                    // not a catchable panic — it aborts the process. So the
                    // client goes to a plain OS thread, off the reactor, where
                    // the close can block as much as it likes.
                    Ok(_) => {
                        std::thread::spawn(move || drop(client));
                    }
                    // No runtime at all: nothing to block, so close inline.
                    Err(_) => drop(client),
                }
            }
        }
    }
}

impl DbConn {
    /// Portable query surface over the configured backend.
    ///
    /// `&mut self` because `AnyConn::Postgres` borrows the client mutably;
    /// the SQLite arm does not need it but the signature must cover both.
    pub fn any_conn(&mut self) -> AnyConn<'_> {
        match self {
            DbConn::Sqlite(c) => AnyConn::Sqlite(c),
            DbConn::Postgres(c) => {
                AnyConn::Postgres(c.as_mut().expect("guard used after its own Drop"))
            }
        }
    }

    /// The underlying SQLite connection, when that is the configured backend.
    ///
    /// An escape hatch for the paths not yet converted — schema initialisation,
    /// and the helpers still typed on `&rusqlite::Connection`. Returns `None`
    /// under Postgres rather than panicking, so a caller that still needs
    /// rusqlite has to say what it does about the other backend.
    pub fn sqlite(&self) -> Option<&rusqlite::Connection> {
        match self {
            DbConn::Sqlite(c) => Some(c),
            DbConn::Postgres(_) => None,
        }
    }

    pub fn backend(&self) -> crate::any_db::Backend {
        match self {
            DbConn::Sqlite(_) => crate::any_db::Backend::Sqlite,
            DbConn::Postgres(_) => crate::any_db::Backend::Postgres,
        }
    }
}

/// TLS connector for the blocking Postgres pool.
///
/// One concrete type for every `sslmode`, because `PostgresConnectionManager` is
/// generic over the connector and [`DbHandle`] has to name a single one.
/// `SslMode::Disable` simply never asks it for a session, so carrying the
/// connector costs nothing on a plaintext link.
pub type PgTls = tokio_postgres_rustls::MakeRustlsConnect;

/// Normalise libpq `sslmode` values that `tokio-postgres` does not parse.
///
/// `tokio-postgres` accepts only `disable`, `prefer` and `require`; the two
/// modes a managed provider actually hands you — `verify-ca` and `verify-full` —
/// are a parse ERROR. That error used to be swallowed into "staying on SQLite",
/// which is how a deployment could end up with `Repo` on Postgres (sqlx parses
/// them fine) and every `lock()` call site on the SQLite sidecar at the same
/// time: two backends, one process, silently.
///
/// Mapping them to `require` is safe in the strict direction. Under libpq
/// `require` encrypts but does NOT verify the chain; under rustls the
/// certificate is verified against the root store regardless, and the hostname
/// is checked in `TlsConnect::connect`. So `require` here is what libpq calls
/// `verify-full`, and promoting `verify-ca`/`verify-full` to it does not weaken
/// anything. The reverse mapping would, which is why it is not done.
fn normalise_sslmode(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    let mut rest = url;
    while let Some(at) = rest.to_ascii_lowercase().find("sslmode=") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "sslmode=".len()..];
        let stop = after.find(['&', '?', ' ']).unwrap_or(after.len());
        let value = after[..stop].to_ascii_lowercase();
        let mapped = match value.as_str() {
            "verify-ca" | "verify-full" => "require",
            other => other,
        };
        out.push_str("sslmode=");
        out.push_str(mapped);
        rest = &after[stop..];
    }
    out.push_str(rest);
    out
}

/// Build the Postgres pool when the deployment asks for it.
///
/// **The runtime must be multi-threaded.** `postgres` is the blocking driver, so
/// closing a connection calls `block_on`. On a current-thread runtime that runs
/// on the very thread driving the reactor and panics with "cannot start a
/// runtime from within a runtime" — and because the close happens in `Drop`,
/// it aborts the process instead of failing a request. `#[tokio::main]` is
/// multi-threaded by default, which is why the server is fine; anything
/// embedding this handle under `flavor = "current_thread"` is not.
///
/// `Ok(None)` means "this deployment did not ask for Postgres". Every other
/// failure is an `Err`: once `SAURON_DB_BACKEND=postgres` is set, falling back
/// to SQLite is not a degraded mode, it is a second database that `Repo` — which
/// builds its own sqlx pool from the same URL — is not using. The caller turns
/// this into a refusal to start.
fn open_pg_pool(pool_size: u32) -> Result<Option<Pool<PostgresConnectionManager<PgTls>>>, String> {
    let backend = std::env::var("SAURON_DB_BACKEND")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(backend.as_str(), "postgres" | "pg" | "postgresql") {
        return Ok(None);
    }
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => return Err("SAURON_DB_BACKEND=postgres but DATABASE_URL is unset".into()),
    };

    let normalised = normalise_sslmode(&url);
    let config = normalised
        .parse::<postgres::Config>()
        .map_err(|e| format!("DATABASE_URL is not a valid postgres config: {e}"))?;

    // rustls needs a process-wide crypto provider. Another dependency may have
    // installed one already (reqwest's platform verifier does), and a second
    // install is an error rather than a no-op — so an existing provider is the
    // success case, not a failure.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let (tls, cert_errors) = PgTls::with_native_certs().map_err(|errors| {
        format!(
            "no usable certificates in the system trust store, so a TLS connection to Postgres cannot be verified: {errors:?}"
        )
    })?;
    if !cert_errors.is_empty() {
        // Some roots failed to parse but others loaded. Worth saying out loud —
        // a thinned trust store is how "verified" quietly becomes "verified
        // against less than you thought".
        tracing::warn!(
            target: "sauron::db",
            errors = ?cert_errors,
            "some native root certificates could not be loaded"
        );
    }

    let ssl_mode = format!("{:?}", config.get_ssl_mode()).to_ascii_lowercase();
    let manager = PostgresConnectionManager::new(config, tls);
    let pool = Pool::builder()
        .max_size(pool_size)
        .connection_timeout(pool_timeout())
        .build(manager)
        .map_err(|e| format!("could not build the postgres pool: {e}"))?;

    tracing::info!(
        target: "sauron::db",
        pool_size,
        %ssl_mode,
        "postgres pool ready"
    );
    Ok(Some(pool))
}

/// Opens persistent SQLite (path from DATABASE_PATH, default ./sauron.db).
pub fn open_db() -> DbHandle {
    let path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./sauron.db".to_string());
    let pool_size: u32 = std::env::var("SAURON_DB_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|v| v.clamp(1, 64))
        .unwrap_or(16);
    open_db_at_with_timeout(&path, pool_size, pool_timeout())
}

/// How long a caller waits for a free connection before the request is shed.
///
/// r2d2's own default is 30 seconds, which is the wrong shape for a request
/// path: by the time a client has queued for half a minute it has usually given
/// up, and the queue behind it has grown the whole time. Shedding early with a
/// 503 and `Retry-After` is what lets load drain. The default stays 30s so this
/// change alters no existing deployment; lower it deliberately.
fn pool_timeout() -> Duration {
    let ms = std::env::var("SAURON_DB_POOL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(30_000)
        .clamp(100, 60_000);
    Duration::from_millis(ms)
}

/// Opens a SQLite database at the given path with the given pool size.
/// Exposed for tests + tooling that want to bypass the `DATABASE_PATH` env var.
pub fn open_db_at(path: &str, pool_size: u32) -> DbHandle {
    open_db_at_with_timeout(path, pool_size, pool_timeout())
}

/// As [`open_db_at`], with an explicit connection-acquisition timeout.
///
/// Separate entry point because the 503 load-shedding path is only reachable
/// once the pool is saturated, and a test that had to wait out the production
/// default would take 30 seconds to assert one status code.
pub fn open_db_at_with_timeout(path: &str, pool_size: u32, timeout: Duration) -> DbHandle {
    let mut handle = open_sqlite_only_with_timeout(path, pool_size, timeout);
    // Fail closed. A Postgres deployment whose blocking pool did not come up is
    // not "running on SQLite" — `Repo` builds its own sqlx pool from the same
    // URL and would still be on Postgres, so the process would serve two
    // databases at once and silently split the writes between them.
    handle.pg_pool = open_pg_pool(pool_size)
        .unwrap_or_else(|reason| panic!("[FATAL] SAURON_DB_BACKEND=postgres: {reason}"));
    handle
}

/// As [`open_db_at`], but never attaches a Postgres pool.
///
/// For callers that have already decided they are SQLite — chiefly tests that
/// build a `Repo::Sqlite` directly. `open_db_at` consults `SAURON_DB_BACKEND`
/// from the ambient environment, so under the Postgres CI job it returns a
/// handle whose `conn()` dispatches to Postgres. Pair that with a hard-coded
/// `Repo::Sqlite` and the halves disagree: methods that match on the enum arm
/// write through rusqlite while methods that go through `conn()` read from
/// Postgres. Writes land in one backend, reads come from the other — the same
/// split the FATAL above exists to prevent, reached from the other direction.
pub fn open_sqlite_only(path: &str, pool_size: u32) -> DbHandle {
    open_sqlite_only_with_timeout(path, pool_size, pool_timeout())
}

fn open_sqlite_only_with_timeout(path: &str, pool_size: u32, timeout: Duration) -> DbHandle {
    let manager = SqliteConnectionManager::file(path).with_init(|conn| {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            -- FULL makes a committed transaction durable across an OS crash
            -- or power loss. This costs latency but the audit/nonce ledgers
            -- are security state and must not acknowledge a losable commit.
            PRAGMA synchronous = FULL;
            ",
        )
    });

    // `build_unchecked`, not `build`: r2d2's `build` blocks until it has
    // established `max_size` connections and gives up after `connection_timeout`
    // — the same budget the request path uses to shed load. Those are different
    // jobs. `pool_exhaustion_503` deliberately passes a 200 ms timeout so a
    // saturated pool answers quickly, and on a busy machine that same 200 ms was
    // not always enough to open the file, so the pool failed to build and the
    // test panicked instead of exercising what it tests.
    //
    // Construction no longer waits for connections; the `pool.get()` immediately
    // below still runs `init_schema`, so a genuinely unusable path is still a
    // startup failure rather than a deferred surprise.
    let pool = Pool::builder()
        .max_size(pool_size)
        .connection_timeout(timeout)
        .build_unchecked(manager);

    {
        let conn = pool.get().unwrap_or_else(|e| {
            panic!(
                "cannot acquire SQLite connection for init at '{}': {}",
                path, e
            )
        });
        init_schema(&conn);
    }

    tracing::info!(target: "sauron::db", %path, pool_size, "SQLite opened");

    DbHandle { pool, pg_pool: None }
}

pub fn init_schema(conn: &Connection) {
    conn.execute_batch(
        r#"
        -- Partner sites (banks + retail).
        --
        -- There is deliberately no private-key column. Partners generate and
        -- retain their own ring key; the server receives a public key and a key
        -- image and never holds custody. The column that used to sit here only
        -- ever stored the constant "EXTERNAL_CUSTODY" and was never read back —
        -- dead storage whose name misdescribed the trust model to anyone
        -- reading the schema. Dropped for existing databases below.
        CREATE TABLE IF NOT EXISTS clients (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    UNIQUE NOT NULL,
            public_key_hex  TEXT    NOT NULL,
            key_image_hex   TEXT    NOT NULL,
            tokens_b        INTEGER NOT NULL DEFAULT 0,
            client_type     TEXT    NOT NULL CHECK(client_type IN ('FULL_KYC', 'ZKP_ONLY', 'BANK'))
        );
        CREATE TABLE IF NOT EXISTS client_tenant_bindings (
            client_name TEXT NOT NULL,
            tenant_id   TEXT NOT NULL,
            PRIMARY KEY (client_name, tenant_id)
        );

        -- Registered users
        CREATE TABLE IF NOT EXISTS users (
            key_image_hex   TEXT PRIMARY KEY,
            public_key_hex  TEXT NOT NULL,
            first_name      TEXT NOT NULL DEFAULT '',
            last_name       TEXT NOT NULL DEFAULT '',
            email           TEXT NOT NULL DEFAULT '',
            date_of_birth   TEXT NOT NULL DEFAULT '',
            nationality     TEXT NOT NULL DEFAULT ''
        );

        -- Passwordless production authentication. The credential is bound by
        -- the partner/bank-signed registration payload; SauronID stores only
        -- an Ed25519 public key. Challenges are one-use and short-lived.
        CREATE TABLE IF NOT EXISTS user_auth_credentials (
            key_image_hex          TEXT PRIMARY KEY,
            ed25519_public_key_b64u TEXT UNIQUE NOT NULL,
            created_at             INTEGER NOT NULL,
            -- Session revocation. The owner session is a stateless HMAC with a
            -- one-hour lifetime, so before this column existed a leaked session
            -- could not be shortened: nothing on the server was consulted, so
            -- there was nothing to change. The epoch is folded into the signed
            -- payload, so incrementing it invalidates every session ever issued
            -- for this owner on the next request.
            --
            -- Per-owner rather than per-session on purpose: the response to a
            -- suspected leak is "cut this owner off", and a per-session table
            -- would need a row per login for a capability that expires in an
            -- hour anyway. A single integer costs one indexed read on a row the
            -- session path already has to touch.
            session_epoch          INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS user_auth_challenges (
            challenge_id  TEXT PRIMARY KEY,
            tenant_id     TEXT NOT NULL,
            key_image_hex TEXT NOT NULL,
            nonce         TEXT NOT NULL,
            expires_at    INTEGER NOT NULL,
            used_at       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_user_auth_challenges_expiry
            ON user_auth_challenges(expires_at, used_at);
        CREATE TABLE IF NOT EXISTS user_auth_tenant_bindings (
            tenant_id    TEXT NOT NULL,
            key_image_hex TEXT NOT NULL,
            created_at   INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, key_image_hex)
        );

        -- Optional mapping from bank customer IDs to user key images
        CREATE TABLE IF NOT EXISTS bank_kyc_links (
            bank_customer_id TEXT PRIMARY KEY,
            user_key_image   TEXT NOT NULL,
            updated_at       INTEGER NOT NULL,
            metadata_json    TEXT NOT NULL DEFAULT '{}'
        );


        -- BabyJubJub ZKP credentials (cached after issuer claim)
        CREATE TABLE IF NOT EXISTS user_credentials (
            key_image_hex   TEXT PRIMARY KEY,
            credential_json TEXT NOT NULL,
            issued_at       INTEGER NOT NULL
        );


        -- User <-> client relationship
        CREATE TABLE IF NOT EXISTS user_registrations (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name        TEXT    NOT NULL,
            user_key_image_hex TEXT    NOT NULL,
            source             TEXT    NOT NULL DEFAULT 'register',
            timestamp          INTEGER NOT NULL,
            UNIQUE(client_name, user_key_image_hex, source)
        );


        -- AI agents delegated by human owners
        CREATE TABLE IF NOT EXISTS agents (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id         TEXT    UNIQUE NOT NULL,
            human_key_image  TEXT    NOT NULL,
            agent_checksum   TEXT    NOT NULL,
            intent_json      TEXT    NOT NULL DEFAULT '{}',
            assurance_level  TEXT    NOT NULL DEFAULT 'delegated_nonbank'
                                      CHECK(assurance_level IN ('delegated_bank','delegated_nonbank','autonomous_web3')),
            public_key_hex   TEXT    NOT NULL DEFAULT '',
            ring_key_image_hex TEXT   NOT NULL DEFAULT '',
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked          INTEGER NOT NULL DEFAULT 0
        );
        -- Agent VCs (self-sovereign KYA path)
        CREATE TABLE IF NOT EXISTS agent_vcs (
            agent_id        TEXT    PRIMARY KEY,
            vc_json         TEXT    NOT NULL,
            vc_hash         TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0
        );


        -- API usage billing (per-call metering)
        -- action: 'kyc_human' | 'kyc_agent' | 'zkp_login' | 'agent_register' | 'agent_vc_issue'
        CREATE TABLE IF NOT EXISTS api_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            is_agent    INTEGER NOT NULL DEFAULT 0,
            timestamp   INTEGER NOT NULL,
            meta        TEXT    NOT NULL DEFAULT '{}'
        );

        -- Merkle commitment ledger
        CREATE TABLE IF NOT EXISTS merkle_leaves (
            seq             INTEGER PRIMARY KEY AUTOINCREMENT,
            commitment_hex  TEXT    NOT NULL UNIQUE,
            registered_at   INTEGER NOT NULL
        );

        -- Anonymous request log
        CREATE TABLE IF NOT EXISTS requests_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            action_type TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'OK',
            detail      TEXT    NOT NULL DEFAULT ''
        );


        CREATE INDEX IF NOT EXISTS idx_agents_human_active ON agents (human_key_image, revoked, expires_at);
        CREATE INDEX IF NOT EXISTS idx_api_usage_client_ts ON api_usage (client_name, timestamp);

        -- A-JWT jti replay protection (server authoritative)
        CREATE TABLE IF NOT EXISTS ajwt_used_jtis (
            jti     TEXT PRIMARY KEY NOT NULL,
            exp     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ajwt_used_jtis_exp ON ajwt_used_jtis(exp);

        -- One-time PoP challenges for /agent/pop/challenge
        CREATE TABLE IF NOT EXISTS agent_pop_challenges (
            id          TEXT PRIMARY KEY NOT NULL,
            agent_id    TEXT NOT NULL,
            challenge   TEXT NOT NULL,
            exp         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_pop_challenges_exp ON agent_pop_challenges(exp);

        -- One-time attestation challenges issued before /agent/register.
        -- Binding the challenge to tenant, authenticated human and the exact
        -- Ed25519 PoP key prevents replaying a valid hardware quote for a
        -- different registration or swapping the runtime signing key.
        CREATE TABLE IF NOT EXISTS agent_attestation_challenges (
            id                  TEXT PRIMARY KEY NOT NULL,
            tenant_id           TEXT NOT NULL,
            human_key_image     TEXT NOT NULL,
            nonce               TEXT NOT NULL,
            pop_public_key_b64u TEXT NOT NULL,
            expires_at          INTEGER NOT NULL,
            used_at             INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_agent_attestation_challenges_exp
            ON agent_attestation_challenges(expires_at);

        -- Server-computed agent checksum inputs.
        -- Operators submit a structured config object at /agent/register; the server
        -- canonicalises it to JSON, computes SHA-256, and stores BOTH the raw inputs
        -- and the resulting checksum. Operator-supplied agent_checksum on the agents
        -- row is no longer trusted — it must equal the server-computed value or
        -- the registration is rejected.
        --
        -- agent_type drives required-fields validation (see agent.rs::validate_checksum_inputs).
        CREATE TABLE IF NOT EXISTS agent_checksum_inputs (
            agent_id          TEXT PRIMARY KEY NOT NULL,
            agent_type        TEXT NOT NULL,         -- llm | mcp_server | rule_bot | browser | openai_assistant | framework | custom
            inputs_canonical  TEXT NOT NULL,         -- canonical-JSON of the structured config
            computed_checksum TEXT NOT NULL,         -- sha256:<hex(SHA256(inputs_canonical))>
            version           INTEGER NOT NULL DEFAULT 1,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL
        );

        -- Append-only audit trail for every checksum rotation. Every accepted update
        -- adds a row with the previous and new checksum + caller-supplied reason.
        CREATE TABLE IF NOT EXISTS agent_checksum_audit (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id          TEXT NOT NULL,
            from_checksum     TEXT NOT NULL,
            to_checksum       TEXT NOT NULL,
            from_inputs_hash  TEXT NOT NULL,
            to_inputs_hash    TEXT NOT NULL,
            reason            TEXT NOT NULL DEFAULT '',
            actor             TEXT NOT NULL DEFAULT '',  -- session key_image_hex or admin
            ts                INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_checksum_audit_agent ON agent_checksum_audit(agent_id, ts);

        -- Agent egress log (Gap 2): every outbound call the agent makes to a
        -- third-party API SHOULD be reported here via POST /agent/egress/log.
        -- This is voluntary reporting today; operators are expected to enforce
        -- the constraint via container network policy (e.g. only allow the
        -- agent process to reach SauronID's outbound proxy port). Each row is
        -- included in the next agent-action anchor batch, making after-the-fact
        -- log tampering require forging Bitcoin and Solana attestations.
        CREATE TABLE IF NOT EXISTS agent_egress_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id      TEXT NOT NULL,
            target_host   TEXT NOT NULL,
            target_path   TEXT NOT NULL DEFAULT '',
            method        TEXT NOT NULL,
            body_hash_hex TEXT NOT NULL DEFAULT '',
            status_code   INTEGER NOT NULL DEFAULT 0,
            ts            INTEGER NOT NULL,
            allowed       INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_agent_egress_log_agent_ts ON agent_egress_log(agent_id, ts);

        -- One-use egress capabilities. Only the SHA-256 of the bearer token is
        -- stored. Every capability is bound to the exact tenant, agent,
        -- method, URL and pre-redaction request body hash.
        CREATE TABLE IF NOT EXISTS agent_egress_capabilities (
            token_hash_hex   TEXT PRIMARY KEY NOT NULL,
            tenant_id       TEXT NOT NULL,
            agent_id        TEXT NOT NULL,
            method          TEXT NOT NULL,
            url             TEXT NOT NULL,
            body_hash_hex   TEXT NOT NULL,
            action_receipt_id TEXT NOT NULL,
            expires_at      INTEGER NOT NULL,
            used_at         INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_agent_egress_capabilities_exp
            ON agent_egress_capabilities(expires_at);

        -- Per-call signature nonces: single-use replay protection for the
        -- DPoP-style call signature over body+method+path+ts+nonce.
        CREATE TABLE IF NOT EXISTS agent_call_nonces (
            agent_id    TEXT    NOT NULL,
            nonce       TEXT    NOT NULL,
            exp         INTEGER NOT NULL,
            PRIMARY KEY (agent_id, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_call_nonces_exp ON agent_call_nonces(exp);

        -- Cryptographic action leash: each agent action must present a ring
        -- signature over a canonical envelope with a one-time nonce.
        CREATE TABLE IF NOT EXISTS agent_action_nonces (
            nonce       TEXT PRIMARY KEY NOT NULL,
            agent_id    TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            expires_at  INTEGER NOT NULL,
            used_at     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_action_nonces_exp ON agent_action_nonces(expires_at);

        CREATE TABLE IF NOT EXISTS agent_action_receipts (
            receipt_id         TEXT PRIMARY KEY NOT NULL,
            action_hash        TEXT NOT NULL,
            agent_id           TEXT NOT NULL,
            ring_key_image_hex TEXT NOT NULL,
            policy_version     TEXT NOT NULL,
            ajwt_jti           TEXT NOT NULL,
            pop_jkt            TEXT NOT NULL DEFAULT '',
            status             TEXT NOT NULL,
            signature          TEXT NOT NULL,
            created_at         INTEGER NOT NULL,
            -- Anonymous ring path (phase 3): agent_id is '' for anon receipts;
            -- identity is replaced by ring_id + the per-ring key image. Both are
            -- also committed by action_hash, so they are tamper-evident.
            ring_id            TEXT,
            config_digest      TEXT,
            -- Hash chain over receipts, per tenant. `seq` is dense and
            -- monotonic; `prev_hash` is the chain hash of seq-1. Deleting or
            -- reordering a receipt breaks the successor's link, which a plain
            -- per-receipt signature cannot detect.
            seq                INTEGER NOT NULL DEFAULT 0,
            prev_hash          TEXT NOT NULL DEFAULT '',
            -- Which owner-signed grant authorised the action.
            owner_mandate_hash TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_agent_action_receipts_agent ON agent_action_receipts(agent_id, created_at);

        -- Phase 2 of the anonymous ring-policy redesign
        -- (docs/design/anonymous-ring-policy.md). A ring is a RULE; agents
        -- subscribe to many rings. `rule_json` carries allowed_actions +
        -- allowed_config_digests + per-ring budgets. Members are per-ring stealth
        -- pseudonym points (ring_pseudonym.rs) — NEVER master keys — so a
        -- DB-reader cannot link a member to an agent identity or across rings.
        CREATE TABLE IF NOT EXISTS rings (
            tenant_id   TEXT    NOT NULL DEFAULT 'default',
            ring_id     TEXT    NOT NULL,
            rule_json   TEXT    NOT NULL,
            version     INTEGER NOT NULL DEFAULT 1,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, ring_id)
        );
        CREATE TABLE IF NOT EXISTS ring_members (
            tenant_id        TEXT    NOT NULL DEFAULT 'default',
            ring_id          TEXT    NOT NULL,
            member_point_hex TEXT    NOT NULL,
            created_at       INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, ring_id, member_point_hex)
        );

        -- Phase 4: multi-unit usage ledger keyed on the per-ring KEY IMAGE (the
        -- pseudonym), never an agent identity. Tokens are authoritative; `usd` is
        -- derived from a per-model price map at record time. `usage_ledger` holds
        -- the running lifetime total per (ring, pseudonym); `usage_log` is the
        -- append-only event trail (anchorable). Budgets in RingRule.budgets are
        -- enforced per-pseudonym against the ledger.
        CREATE TABLE IF NOT EXISTS usage_ledger (
            tenant_id        TEXT    NOT NULL DEFAULT 'default',
            ring_id          TEXT    NOT NULL,
            key_image_hex    TEXT    NOT NULL,
            input_tokens     INTEGER NOT NULL DEFAULT 0,
            output_tokens    INTEGER NOT NULL DEFAULT 0,
            usd              REAL    NOT NULL DEFAULT 0,
            updated_at       INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, ring_id, key_image_hex)
        );
        CREATE TABLE IF NOT EXISTS usage_log (
            log_id           TEXT    PRIMARY KEY NOT NULL,
            tenant_id        TEXT    NOT NULL DEFAULT 'default',
            ring_id          TEXT    NOT NULL,
            key_image_hex    TEXT    NOT NULL,
            model_id         TEXT    NOT NULL,
            input_tokens     INTEGER NOT NULL DEFAULT 0,
            output_tokens    INTEGER NOT NULL DEFAULT 0,
            usd              REAL    NOT NULL DEFAULT 0,
            recorded_at      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_usage_log_ring ON usage_log(tenant_id, ring_id, key_image_hex, recorded_at);

        -- Strict, pre-Stripe payment authorization artifacts (single-use auth envelope).
        CREATE TABLE IF NOT EXISTS agent_payment_authorizations (
            auth_id        TEXT PRIMARY KEY NOT NULL,
            agent_id       TEXT NOT NULL,
            jti            TEXT NOT NULL UNIQUE,
            amount_minor   INTEGER NOT NULL,
            currency       TEXT NOT NULL,
            merchant_id    TEXT NOT NULL DEFAULT '',
            payment_ref    TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            expires_at     INTEGER NOT NULL,
            consumed       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_agent ON agent_payment_authorizations(agent_id, expires_at);
        CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_payment_ref ON agent_payment_authorizations(payment_ref);


        -- Bitcoin anchoring receipts for Merkle roots.
        -- Default provider is local mock: OP_RETURN payload + fake txid, no real BTC.
        CREATE TABLE IF NOT EXISTS bitcoin_merkle_anchors (
            anchor_id          TEXT PRIMARY KEY NOT NULL,
            merkle_root_hex    TEXT NOT NULL,
            provider           TEXT NOT NULL,
            network            TEXT NOT NULL,
            op_return_hex      TEXT NOT NULL,
            txid               TEXT NOT NULL,
            broadcast          INTEGER NOT NULL DEFAULT 0,
            no_real_money      INTEGER NOT NULL DEFAULT 1,
            created_at         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bitcoin_merkle_root ON bitcoin_merkle_anchors(merkle_root_hex);

        -- Agent-action anchor batches: periodic merkle commitment over the
        -- agent_action_receipts table, with cross-reference to the BTC OTS and
        -- Solana memo anchors that timestamp the same root. External auditors
        -- replay the merkle path from any receipt to `batch_root_hex` and verify
        -- the root via OTS / Solana Explorer.
        CREATE TABLE IF NOT EXISTS agent_action_anchors (
            anchor_id        TEXT PRIMARY KEY NOT NULL,
            batch_root_hex   TEXT NOT NULL,
            n_actions        INTEGER NOT NULL,
            from_receipt_id  TEXT NOT NULL,   -- inclusive
            to_receipt_id    TEXT NOT NULL,   -- inclusive
            from_created_at  INTEGER NOT NULL,
            to_created_at    INTEGER NOT NULL,
            btc_anchor_id    TEXT NOT NULL DEFAULT '',
            sol_anchor_id    TEXT NOT NULL DEFAULT '',
            anchor_status    TEXT NOT NULL DEFAULT 'pending',
            anchor_error     TEXT NOT NULL DEFAULT '',
            leaf_version     INTEGER NOT NULL DEFAULT 1,
            created_at       INTEGER NOT NULL,
            -- Head of the keyed audit chain at the moment this batch was sealed.
            -- Committed as an extra merkle leaf, so the external timestamp over
            -- batch_root_hex also fixes the audit log as of this point.
            audit_head_seq   INTEGER NOT NULL DEFAULT 0,
            audit_head_hash  TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_root ON agent_action_anchors(batch_root_hex);
        CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_range ON agent_action_anchors(from_created_at, to_created_at);

        -- Solana anchoring receipts for Merkle roots (Memo Program transactions).
        CREATE TABLE IF NOT EXISTS solana_merkle_anchors (
            anchor_id        TEXT PRIMARY KEY NOT NULL,
            merkle_root_hex  TEXT NOT NULL,
            network          TEXT NOT NULL,
            signature        TEXT NOT NULL UNIQUE,
            slot             INTEGER NOT NULL DEFAULT 0,
            confirmed        INTEGER NOT NULL DEFAULT 0,
            created_at       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_solana_merkle_root ON solana_merkle_anchors(merkle_root_hex);
        CREATE INDEX IF NOT EXISTS idx_solana_pending ON solana_merkle_anchors(confirmed, created_at);


        -- Opaque rate-limit buckets (SHA256-derived keys); sliding windows by window_id = floor(epoch/window).
        CREATE TABLE IF NOT EXISTS risk_rate_counters (
            bucket      TEXT NOT NULL,
            window_id   INTEGER NOT NULL,
            cnt         INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket, window_id)
        );
        CREATE INDEX IF NOT EXISTS idx_risk_rate_counters_window ON risk_rate_counters(window_id);

        -- Compliance screening overlays (sanctions / PEP / coarse risk tier) — server-side only.
        CREATE TABLE IF NOT EXISTS user_compliance_screening (
            key_image_hex   TEXT PRIMARY KEY NOT NULL,
            sanctions_tier  TEXT NOT NULL DEFAULT 'unknown',
            pep_flag        INTEGER NOT NULL DEFAULT 0,
            risk_tier       TEXT NOT NULL DEFAULT 'unknown',
            list_version    TEXT NOT NULL DEFAULT '',
            updated_at      INTEGER NOT NULL DEFAULT 0
        );

        -- Sprint 2: agent policy DSL store. raw_yaml round-trips back through the
        -- DSL parser → compiler on `PolicyStore::hydrate()` at startup.
        CREATE TABLE IF NOT EXISTS policies (
            policy_id   TEXT PRIMARY KEY,
            agent       TEXT NOT NULL,
            version     TEXT NOT NULL,
            raw_yaml    TEXT NOT NULL,
            created_at  BIGINT NOT NULL,
            updated_at  BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policies_agent ON policies(agent);

        -- Sprint 3 follow-up: server-side spend ledger. Closes the documented
        -- gap "Local budget can be tampered" (redteam A3). The SDK's in-memory
        -- BudgetTracker flushes periodically into `spend_log`; `spend_ledger`
        -- holds the running total per (policy_id, agent_id, period_start).
        -- POST /v1/policy/evaluate now looks up the authoritative value from
        -- this ledger when the request carries an `agent_id`.
        -- tenant_id is part of the KEY, not just a column. It was added as a
        -- column by the multi-tenant migration while the key stayed
        -- (policy_id, agent_id, period_start), which made the upsert conflict
        -- target tenant-blind: two tenants spending against the same logical
        -- (agent, policy, period) collapsed into ONE row owned by whichever
        -- wrote first. The non-owning tenant then read 0 and its budget cap
        -- never tripped, while the owning tenant absorbed spend it never made.
        -- `tenant-spend-ledger-race.ts` reproduces it; docs/multi-tenancy-audit.md
        -- has the numbers.
        CREATE TABLE IF NOT EXISTS spend_ledger (
            policy_id    TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            period_start BIGINT NOT NULL,        -- unix epoch, 0 = lifetime
            total_usd    REAL NOT NULL DEFAULT 0,
            last_updated BIGINT NOT NULL,
            tenant_id    TEXT NOT NULL DEFAULT 'default',
            PRIMARY KEY (tenant_id, policy_id, agent_id, period_start)
        );
        CREATE INDEX IF NOT EXISTS idx_spend_ledger_agent ON spend_ledger(agent_id);

        CREATE TABLE IF NOT EXISTS spend_log (
            log_id       TEXT PRIMARY KEY,           -- uuid
            policy_id    TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            action_id    TEXT,                       -- nullable; sdk-provided
            amount_usd   REAL NOT NULL,
            recorded_at  BIGINT NOT NULL,
            source       TEXT NOT NULL               -- 'sdk_flush' | 'server_recompute'
        );
        CREATE INDEX IF NOT EXISTS idx_spend_log_pa ON spend_log(policy_id, agent_id, recorded_at);

        -- Sprint 7: customer-side stat aggregation + ZK integrity.
        -- Holds per-tenant per-period claimed metric values together with the
        -- ZK proof that bound the claim to a Merkle-committed receipt set.
        -- Primary key is the idempotency tuple — same submission re-arriving
        -- overwrites in place via ON CONFLICT.
        CREATE TABLE IF NOT EXISTS customer_stats (
            tenant_id     TEXT NOT NULL DEFAULT 'default',
            agent_id      TEXT NOT NULL DEFAULT '',     -- '' for tenant-aggregate
            metric_id     TEXT NOT NULL,
            claimed_value INTEGER NOT NULL,             -- fixed-point ×1000
            n_records     INTEGER NOT NULL,
            period_start  INTEGER NOT NULL,
            period_end    INTEGER NOT NULL,
            merkle_root   TEXT NOT NULL,
            proof_b64     TEXT NOT NULL,
            vk_id         TEXT NOT NULL,
            checkpoint_id TEXT NOT NULL,
            submitted_at  INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, agent_id, metric_id, period_start)
        );
        CREATE INDEX IF NOT EXISTS idx_customer_stats_tenant_period
            ON customer_stats(tenant_id, period_start, period_end);
        CREATE INDEX IF NOT EXISTS idx_customer_stats_metric_period
            ON customer_stats(metric_id, period_start, period_end);
        -- Statement hashes for accepted stats proofs. Kept separate from
        -- agent_action_receipts because there is no agent-signed action
        -- envelope preimage for this synthetic record; mixing it into an
        -- action anchor would make complete transparent proofs impossible.
        CREATE TABLE IF NOT EXISTS stats_submission_receipts (
            statement_hash TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL,
            checkpoint_id  TEXT NOT NULL,
            metric_id      TEXT NOT NULL,
            submitted_at   INTEGER NOT NULL
        );

        -- Server-authoritative proof statements. Verification requests name a
        -- checkpoint; they never supply the trusted root directly. Rows are
        -- written only by the anchoring/checkpoint worker after finalization.
        CREATE TABLE IF NOT EXISTS zk_proof_checkpoints (
            checkpoint_id  TEXT PRIMARY KEY NOT NULL,
            tenant_id      TEXT NOT NULL,
            circuit        TEXT NOT NULL,
            merkle_root    TEXT NOT NULL,
            tree_size      INTEGER NOT NULL,
            anchor_id      TEXT NOT NULL,
            finalized_at   INTEGER NOT NULL,
            UNIQUE (tenant_id, circuit, anchor_id)
        );
        CREATE INDEX IF NOT EXISTS idx_zk_proof_checkpoints_lookup
            ON zk_proof_checkpoints(tenant_id, checkpoint_id, circuit);

        -- Sprint 8: operator-managed cohort definitions for DP-published
        -- cross-tenant benchmarks. Global (NOT tenant-scoped) — see
        -- docs/privacy-model.md "Publication pipeline".
        CREATE TABLE IF NOT EXISTS cohort_definitions (
            cohort_id              TEXT PRIMARY KEY,
            label                  TEXT NOT NULL,
            vendor                 TEXT,
            sector                 TEXT,
            tenant_ids_json        TEXT NOT NULL,
            k_anonymity_threshold  INTEGER NOT NULL DEFAULT 5,
            epsilon_per_metric     REAL NOT NULL,
            delta                  REAL NOT NULL,
            created_at             INTEGER NOT NULL,
            updated_at             INTEGER NOT NULL
        );

        -- S8 extension: persistent per-cohort per-metric ε ledger. Each
        -- publication checks remaining ε against the cohort's lifetime
        -- budget for the current regulatory cycle and refuses publication
        -- when the budget is exhausted. Operators rotate (reset) the
        -- budget per regulatory cycle through POST /v1/cohort/:id/budget/rotate.
        -- See docs/privacy-model.md § "Inter-period ε budget tracking".
        CREATE TABLE IF NOT EXISTS dp_budget_ledger (
            cohort_id     TEXT NOT NULL,
            metric_id     TEXT NOT NULL,
            cycle_start   INTEGER NOT NULL,
            epsilon_spent REAL NOT NULL DEFAULT 0,
            delta_spent   REAL NOT NULL DEFAULT 0,
            epsilon_cap   REAL NOT NULL,
            delta_cap     REAL NOT NULL,
            last_published INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (cohort_id, metric_id, cycle_start)
        );
        CREATE INDEX IF NOT EXISTS idx_dp_budget_cohort
            ON dp_budget_ledger(cohort_id, cycle_start);

        CREATE TABLE IF NOT EXISTS dp_budget_publications (
            publication_id TEXT PRIMARY KEY,
            cohort_id      TEXT NOT NULL,
            metric_id      TEXT NOT NULL,
            cycle_start    INTEGER NOT NULL,
            epsilon        REAL NOT NULL,
            delta          REAL NOT NULL,
            noise_scale    REAL NOT NULL,
            published_at   INTEGER NOT NULL,
            FOREIGN KEY (cohort_id, metric_id, cycle_start)
                REFERENCES dp_budget_ledger(cohort_id, metric_id, cycle_start)
        );
        CREATE INDEX IF NOT EXISTS idx_dp_pub_cohort
            ON dp_budget_publications(cohort_id, cycle_start);

        -- Sprint 13-14 Tier 2: Paillier homomorphic-encryption aggregations.
        -- One row per `(cohort_id, metric_id, period_start)` keyed by a
        -- stable `aggregation_id`. The server homomorphically sums customer
        -- ciphertexts in place and stores only the running ciphertext —
        -- per-customer values are never decrypted server-side.
        --
        -- NEEDS_CRYPTO_REVIEW: rotating `pk_id` mid-period without keying
        -- a new aggregation row will corrupt the running sum. Operators
        -- MUST treat the (cohort, metric, period) tuple as bound to a
        -- single public key for the lifetime of the row.

        -- S10: server-side agent → policy binding registry.
        -- One row per (tenant_id, agent_id); last-write-wins via UPSERT.
        -- Replaces the dashboard's localStorage binding so policy assignment
        -- survives across devices and is queryable by the evaluator.
        CREATE TABLE IF NOT EXISTS agent_policy_bindings (
            tenant_id  TEXT    NOT NULL DEFAULT 'default',
            agent_id   TEXT    NOT NULL,
            policy_id  TEXT    NOT NULL,
            bound_at   INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, agent_id)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_policy_bindings_policy
            ON agent_policy_bindings(tenant_id, policy_id);

        -- S12: security audit log. Tenant-scoped append-only trail of
        -- auth failures, signature mismatches, cross-tenant attempts,
        -- policy violations, admin-key rotations, and rate-limit trips.
        -- Surfaced via GET /v1/admin/audit (admin-gated, tenant-scoped).
        CREATE TABLE IF NOT EXISTS security_audit_log (
            audit_id    TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL DEFAULT 'default',
            event_type  TEXT NOT NULL,
            event_json  TEXT NOT NULL,
            timestamp   INTEGER NOT NULL,
            seq         INTEGER,
            prev_hash   TEXT NOT NULL DEFAULT '',
            entry_hash  TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_ts
            ON security_audit_log(tenant_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_security_audit_type_ts
            ON security_audit_log(event_type, timestamp);

        -- Sprint 19-20: periodic ZK audit reports. One row per generated
        -- report; signature column carries the operator HMAC over the
        -- canonical-form JSON (see `audit::report::sign_report`).
        CREATE TABLE IF NOT EXISTS audit_reports (
            report_id      TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL DEFAULT 'default',
            agent_ids_json TEXT NOT NULL,
            period_start   INTEGER NOT NULL,
            period_end     INTEGER NOT NULL,
            generated_at   INTEGER NOT NULL,
            report_json    TEXT NOT NULL,
            signature      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_reports_tenant
            ON audit_reports(tenant_id, generated_at);
        "#,
    )
    .expect("DB schema init failed");

    // ── spend_ledger: put tenant_id in the primary key on EXISTING databases ──
    //
    // SQLite cannot ALTER a primary key, so this is the twelve-step rebuild:
    // create the correctly-keyed table, copy, drop, rename. Guarded on the old
    // key still being in place so it runs once and is a no-op afterwards.
    //
    // NON-DESTRUCTIVE ON PURPOSE. Every existing row is copied verbatim, keeping
    // whatever tenant_id it already carries. What the rebuild CANNOT do is
    // un-merge a row whose total already absorbed another tenant's spend — that
    // information was never recorded separately. Such a row stays with the
    // tenant that owned it, i.e. over-counted rather than lost, which is the
    // conservative direction for a budget cap. The victim tenant starts
    // accumulating its own row correctly from here. An operator who needs the
    // historical split can rebuild it from spend_log, which WAS tenant-correct
    // throughout.
    {
        let needs_rebuild = conn
            .prepare("SELECT 1 FROM pragma_index_list('spend_ledger') LIMIT 0")
            .is_ok()
            && conn
                .prepare("PRAGMA table_info(spend_ledger)")
                .and_then(|mut st| {
                    let cols: Vec<(i64, String)> = st
                        .query_map([], |r| Ok((r.get::<_, i64>(5)?, r.get::<_, String>(1)?)))?
                        .filter_map(Result::ok)
                        .collect();
                    // pk column 5 is the 1-based position in the primary key.
                    let in_pk: Vec<&str> = cols
                        .iter()
                        .filter(|(pk, _)| *pk > 0)
                        .map(|(_, n)| n.as_str())
                        .collect();
                    Ok(!in_pk.is_empty() && !in_pk.contains(&"tenant_id"))
                })
                .unwrap_or(false);
        if needs_rebuild {
            let rebuilt = conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE spend_ledger__new (
                    policy_id    TEXT NOT NULL,
                    agent_id     TEXT NOT NULL,
                    period_start BIGINT NOT NULL,
                    total_usd    REAL NOT NULL DEFAULT 0,
                    last_updated BIGINT NOT NULL,
                    tenant_id    TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (tenant_id, policy_id, agent_id, period_start)
                );
                INSERT INTO spend_ledger__new
                    (policy_id, agent_id, period_start, total_usd, last_updated, tenant_id)
                SELECT policy_id, agent_id, period_start, total_usd, last_updated,
                       COALESCE(tenant_id, 'default')
                FROM spend_ledger;
                DROP TABLE spend_ledger;
                ALTER TABLE spend_ledger__new RENAME TO spend_ledger;
                CREATE INDEX IF NOT EXISTS idx_spend_ledger_agent ON spend_ledger(agent_id);
                CREATE INDEX IF NOT EXISTS idx_spend_ledger_tenant
                    ON spend_ledger(tenant_id, policy_id, agent_id);
                COMMIT;
                "#,
            );
            match rebuilt {
                Ok(()) => tracing::warn!(
                    target: "sauron::db",
                    "spend_ledger rebuilt with tenant_id in the primary key; \
                     pre-existing totals were copied as-is and may over-count the \
                     owning tenant (see docs/multi-tenancy-audit.md)"
                ),
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    panic!(
                        "[FATAL] spend_ledger tenant-key rebuild failed: {e}. \
                         Refusing to run with a tenant-blind spend ledger: cross-tenant \
                         writes would collapse into one row and a budget cap would not trip."
                    );
                }
            }
        }
    }

    // Migration-safe add for existing databases created before requested_claims_json existed.
    let _ = conn.execute(
        "ALTER TABLE clients ADD COLUMN tokens_b INTEGER NOT NULL DEFAULT 0",
        [],
    );
    // Drop the write-only clients.private_key_hex column. It held the literal
    // "EXTERNAL_CUSTODY" and nothing ever read it, but a NOT NULL column of
    // that name is what a security reviewer sees first, and the INSERT no
    // longer supplies it — so on a database created before this change the
    // insert would fail until the column goes. Ignoring the error is the
    // idempotency: on a fresh database there is nothing to drop.
    let _ = conn.execute("ALTER TABLE clients DROP COLUMN private_key_hex", []);
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN assurance_level TEXT NOT NULL DEFAULT 'delegated_nonbank'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN parent_agent_id TEXT DEFAULT NULL",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN pop_jkt TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN pop_public_key_b64u TEXT NOT NULL DEFAULT ''",
        [],
    );

    // S8 extension: ε ledger cycle defaults on cohort_definitions. All
    // optional; existing rows keep working untouched. cycle_seconds = NULL
    // → defaults to 90 days; epsilon_cap_per_cycle = NULL → epsilon_per_metric * 4;
    // delta_cap_per_cycle = NULL → delta * 4.
    let _ = conn.execute(
        "ALTER TABLE cohort_definitions ADD COLUMN cycle_seconds INTEGER",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE cohort_definitions ADD COLUMN epsilon_cap_per_cycle REAL",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE cohort_definitions ADD COLUMN delta_cap_per_cycle REAL",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE customer_stats ADD COLUMN checkpoint_id TEXT NOT NULL DEFAULT ''",
        [],
    );

    // OpenTimestamps: per-anchor partial proof bytes (calendar attestations).
    // Promoted to full Bitcoin proofs by the background upgrade task once the
    // calendar root is included in a block. Nullable; absent for legacy mock anchors.
    let _ = conn.execute(
        "ALTER TABLE bitcoin_merkle_anchors ADD COLUMN ots_receipt_blob BLOB",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE bitcoin_merkle_anchors ADD COLUMN ots_calendar_url TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE bitcoin_merkle_anchors ADD COLUMN ots_upgraded INTEGER NOT NULL DEFAULT 0",
        [],
    );

    // Session revocation epoch, for databases created before the column existed.
    // Bumping it invalidates every session already issued for that owner.
    let _ = conn.execute(
        "ALTER TABLE user_auth_credentials ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0",
        [],
    );

    // Hardware-attestation slot: TPM2 quote / AWS Nitro attestation document /
    // Apple Secure Enclave attestation. Stored verbatim; SauronID does not
    // cryptographically verify the attestation (see threat-model.md).
    let _ = conn.execute("ALTER TABLE agents ADD COLUMN attestation_blob TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN attestation_kind TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN ring_key_image_hex TEXT NOT NULL DEFAULT ''",
        [],
    );

    // M1 of TPM2-bound PoP key roadmap (docs/roadmap.md Plan 1):
    //   - attestation_pubkey_b64u — the AIK public key extracted from the
    //     hardware attestation (used as the trusted PoP key once M2 lands).
    //   - attestation_pcr_set — JSON-encoded PCR selection + canonical hash
    //     the operator expects the TPM2 quote to bind.
    //   - attestation_ek_cert_chain_pem — verbatim EK cert chain, used at
    //     verify time to walk to a known TPM-vendor root.
    // All nullable; existing rows keep working untouched.
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN attestation_pubkey_b64u TEXT",
        [],
    );
    let _ = conn.execute("ALTER TABLE agents ADD COLUMN attestation_pcr_set TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN attestation_ek_cert_chain_pem TEXT",
        [],
    );

    // Anonymous ring path (phase 3): receipts from the anon flow carry ring_id +
    // config_digest instead of an agent identity. Nullable; legacy rows untouched.
    let _ = conn.execute(
        "ALTER TABLE agent_action_receipts ADD COLUMN ring_id TEXT",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_receipts ADD COLUMN config_digest TEXT",
        [],
    );
    // Receipt hash chain. Existing rows keep seq = 0 / prev_hash = '' and stay
    // verifiable under the v2 signature; new receipts chain from seq 1 upward.
    // Owner-signed mandate: the grant, signed by the owner's own key.
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN owner_mandate_sig_b64u TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agents ADD COLUMN owner_mandate_hash TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_anchors ADD COLUMN audit_head_seq INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_anchors ADD COLUMN audit_head_hash TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_receipts ADD COLUMN seq INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_receipts ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_receipts ADD COLUMN owner_mandate_hash TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_anchors ADD COLUMN anchor_status TEXT NOT NULL DEFAULT 'pending'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_anchors ADD COLUMN anchor_error TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE agent_action_anchors ADD COLUMN leaf_version INTEGER NOT NULL DEFAULT 1",
        [],
    );
    let _ = conn.execute("ALTER TABLE security_audit_log ADD COLUMN seq INTEGER", []);
    let _ = conn.execute(
        "ALTER TABLE security_audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE security_audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''",
        [],
    );

    let run_revoke_migration = std::env::var("SAURON_REVOKE_LEGACY_DELEGATED_NONBANK")
        .map(|v| {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        })
        .unwrap_or(true);

    if run_revoke_migration {
        let revoked = conn
            .execute(
                "UPDATE agents SET revoked = 1 WHERE assurance_level = 'delegated_nonbank' AND revoked = 0",
                [],
            )
            .unwrap_or(0);
        if revoked > 0 {
            tracing::info!(
                target: "sauron::db",
                revoked,
                "migration revoked legacy delegated_nonbank agents"
            );
        }
    }

    let _ = conn.execute(
        "INSERT INTO user_compliance_screening (key_image_hex, sanctions_tier, pep_flag, risk_tier, list_version, updated_at)
         SELECT u.key_image_hex, 'unknown', 0, 'unknown', '', 0 FROM users u
         LEFT JOIN user_compliance_screening s ON s.key_image_hex = u.key_image_hex
         WHERE s.key_image_hex IS NULL",
        [],
    );

    // ─────────────────────────────────────────────────────────────────
    // Sprint 11 — multi-tenancy: add `tenant_id TEXT NOT NULL DEFAULT
    // 'default'` to every SCOPE'd table. Existing rows backfill to the
    // default tenant via the column DEFAULT, preserving backwards
    // compatibility for the 412-test suite + the live dashboard demo.
    //
    // The `ALTER TABLE … ADD COLUMN` statements are wrapped in `let _ =`
    // so a re-run on an already-migrated database is a no-op (SQLite
    // returns a duplicate-column error which we deliberately swallow).
    //
    // Tables intentionally NOT scoped here (see core/src/tenancy/mod.rs
    // for the audit rationale): users, clients, bank_kyc_links,
    // agent_pop_challenges, agent_call_nonces, ajwt_used_jtis,
    // agent_action_nonces, agent_vcs, api_usage, requests_log,
    // agent_checksum_inputs, agent_checksum_audit.
    let tenant_scoped_tables: &[&str] = &[
        "agents",
        "policies",
        "agent_action_receipts",
        "agent_action_anchors",
        "bitcoin_merkle_anchors",
        "solana_merkle_anchors",
        "agent_egress_log",
        "agent_payment_authorizations",
        "user_credentials",
        "user_registrations",
        "merkle_leaves",
        "risk_rate_counters",
        "spend_ledger",
        "spend_log",
    ];
    for tbl in tenant_scoped_tables {
        let _ = conn.execute(
            &format!("ALTER TABLE {tbl} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"),
            [],
        );
    }
    // Compatibility for databases created between passwordless-auth v1 and
    // the tenant-bound v2 protocol. New databases already have this column.
    let _ = conn.execute(
        "ALTER TABLE user_auth_challenges ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
        [],
    );
    // Existing single-tenant installations retain their clients in `default`;
    // new client enrollment writes an explicit authenticated tenant binding.
    let _ = conn.execute(
        "INSERT OR IGNORE INTO client_tenant_bindings (client_name, tenant_id)
         SELECT name, 'default' FROM clients",
        [],
    );

    // Enforce key uniqueness at the database boundary as well as in the
    // registration pre-check. This closes concurrent-register TOCTOU races.
    // Empty legacy values are excluded; production registration rejects them.
    for sql in [
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_active_public_key ON agents(tenant_id, public_key_hex) WHERE revoked = 0 AND public_key_hex != ''",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_active_ring_key_image ON agents(tenant_id, ring_key_image_hex) WHERE revoked = 0 AND ring_key_image_hex != ''",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_active_pop_key ON agents(tenant_id, pop_public_key_b64u) WHERE revoked = 0 AND pop_public_key_b64u IS NOT NULL AND pop_public_key_b64u != ''",
    ] {
        conn.execute(sql, [])
            .expect("active agent key uniqueness migration failed; revoke duplicate active keys before startup");
    }

    // Composite indexes that make every tenant-scoped query hit a single
    // partition. Idempotent via `IF NOT EXISTS`.
    let tenant_indexes: &[&str] = &[
        "CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id, human_key_image)",
        "CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id, policy_id)",
        "CREATE INDEX IF NOT EXISTS idx_agent_action_receipts_tenant ON agent_action_receipts(tenant_id, agent_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_tenant ON agent_action_anchors(tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bitcoin_merkle_anchors_tenant ON bitcoin_merkle_anchors(tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_solana_merkle_anchors_tenant ON solana_merkle_anchors(tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_agent_egress_log_tenant ON agent_egress_log(tenant_id, agent_id, ts)",
        "CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_tenant ON agent_payment_authorizations(tenant_id, agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_user_credentials_tenant ON user_credentials(tenant_id, key_image_hex)",
        "CREATE INDEX IF NOT EXISTS idx_user_registrations_tenant ON user_registrations(tenant_id, client_name)",
        "CREATE INDEX IF NOT EXISTS idx_merkle_leaves_tenant ON merkle_leaves(tenant_id, registered_at)",
        "CREATE INDEX IF NOT EXISTS idx_risk_rate_counters_tenant ON risk_rate_counters(tenant_id, bucket, window_id)",
        "CREATE INDEX IF NOT EXISTS idx_spend_ledger_tenant ON spend_ledger(tenant_id, policy_id, agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_spend_log_tenant ON spend_log(tenant_id, policy_id, agent_id, recorded_at)",
    ];
    for sql in tenant_indexes {
        conn.execute(sql, [])
            .expect("tenant index migration failed");
    }

    // Earlier releases made idempotent ALTERs by ignoring duplicate-column
    // errors. Never let that also hide a real migration failure: validate the
    // complete security-critical shape before recording the schema version.
    for (table, columns) in [
        (
            "agents",
            &["tenant_id", "pop_public_key_b64u", "ring_key_image_hex"] as &[&str],
        ),
        (
            "agent_payment_authorizations",
            &["tenant_id", "consumed"] as &[&str],
        ),
        (
            "user_credentials",
            &["tenant_id", "credential_json"] as &[&str],
        ),
        (
            "user_registrations",
            &["tenant_id", "user_key_image_hex"] as &[&str],
        ),
        ("merkle_leaves", &["tenant_id", "commitment_hex"] as &[&str]),
        (
            "security_audit_log",
            &["seq", "prev_hash", "entry_hash"] as &[&str],
        ),
    ] {
        // PRAGMA is SQLite-only introspection with no PostgreSQL equivalent
        // (that would be information_schema), and this check runs against the
        // SQLite schema bootstrap specifically. It stays on rusqlite.
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap_or_else(|e| panic!("cannot inspect migrated table {table}: {e}"));
        let present: std::collections::HashSet<String> = stmt
            .query_map([], |row| row.get(1))
            .unwrap_or_else(|e| panic!("cannot read migrated table {table}: {e}"))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("cannot decode migrated table {table}: {e}"));
        for column in columns {
            assert!(
                present.contains(*column),
                "database migration incomplete: {table}.{column} is missing"
            );
        }
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version INTEGER PRIMARY KEY,
             applied_at INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO schema_migrations(version, applied_at)
         VALUES (1, CAST(strftime('%s','now') AS INTEGER));",
    )
    .expect("schema version migration failed");
}

#[cfg(test)]
mod pool_timeout_tests {
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
}

#[cfg(test)]
mod durability_tests {
    use super::*;

    #[test]
    fn persistent_connections_use_full_synchronous_durability() {
        let path = std::env::temp_dir().join(format!(
            "sauron-durability-{}-{}.sqlite",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let db = open_db_at(path.to_str().unwrap(), 1);
        let conn = db.lock_sqlite().expect("connection");
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .expect("read synchronous pragma");
        assert_eq!(synchronous, 2, "SQLite synchronous must be FULL");
        drop(conn);
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}

#[cfg(test)]
mod pg_tls_tests {
    use super::normalise_sslmode;

    /// The two modes a managed provider actually hands you. `tokio-postgres`
    /// rejects both at parse time, and that rejection used to mean "silently run
    /// on SQLite while `Repo` runs on Postgres".
    #[test]
    fn verify_modes_are_promoted_to_require() {
        for url in [
            "postgres://u:p@host/db?sslmode=verify-full",
            "postgres://u:p@host/db?sslmode=verify-ca",
            "postgres://u:p@host/db?sslmode=VERIFY-FULL",
        ] {
            let out = normalise_sslmode(url);
            assert!(out.ends_with("sslmode=require"), "{url} -> {out}");
            assert!(out.parse::<postgres::Config>().is_ok(), "{out}");
        }
    }

    /// Modes `tokio-postgres` already understands must survive untouched — in
    /// particular `disable`, because silently promoting it to `require` would
    /// break every plaintext local deployment.
    #[test]
    fn understood_modes_are_left_alone() {
        for mode in ["disable", "prefer", "require"] {
            let url = format!("postgres://u:p@host/db?sslmode={mode}");
            assert_eq!(normalise_sslmode(&url), url);
        }
    }

    /// The rewrite must not eat the rest of the query string, and must cope with
    /// `sslmode` appearing anywhere in it.
    #[test]
    fn other_parameters_are_preserved() {
        let out = normalise_sslmode(
            "postgres://u:p@host/db?application_name=sauron&sslmode=verify-full&connect_timeout=5",
        );
        assert_eq!(
            out,
            "postgres://u:p@host/db?application_name=sauron&sslmode=require&connect_timeout=5"
        );
        assert!(out.parse::<postgres::Config>().is_ok());

        // No sslmode at all: unchanged, and still parses. tokio-postgres then
        // defaults to `prefer`.
        let plain = "postgres://u:p@host/db";
        assert_eq!(normalise_sslmode(plain), plain);
    }

    /// A URL with no `sslmode` defaults to `prefer`, which negotiates TLS when
    /// the server offers it. The old code could not have done this at all.
    #[test]
    fn the_default_mode_still_attempts_tls() {
        let cfg: postgres::Config = "postgres://u:p@host/db".parse().unwrap();
        assert!(matches!(
            cfg.get_ssl_mode(),
            postgres::config::SslMode::Prefer
        ));
    }
}
