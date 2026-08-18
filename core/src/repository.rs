//! Storage-backend abstraction for SauronID.
//!
//! **Status:** Phase 3 in progress. The full Postgres swap is a multi-week task;
//! this module is the migration template. New code SHOULD use this repository
//! API; existing code continues to call rusqlite directly until ported.
//!
//! ## Backends
//!
//! - **`Sqlite` (default)** — wraps the existing `r2d2 + rusqlite` pool, no
//!   behaviour change. The single-node SQLite path remains operational.
//! - **`Postgres` (opt-in)** — sqlx `PgPool`, real connection pooling,
//!   replication-friendly. Activated by `SAURON_DB_BACKEND=postgres` plus
//!   `DATABASE_URL=postgres://…`. Only modules ported to the repository API
//!   honour this backend; ported list grows incrementally.
//!
//! ## What `Repo` still owns
//!
//! | Table                      | Notes                                                  |
//! |----------------------------|--------------------------------------------------------|
//! | `agent_call_nonces`        | Migration template. Serializable txn wrapper (M1).     |
//! | `ajwt_used_jtis`           | M1. Parked: the live consume is `ajwt_support`.        |
//! | `agent_pop_challenges`     | M2. Parked: the live path is `ajwt_support`.           |
//! | `agent_payment_*`          | M2. FOR UPDATE + RETURNING authorize consume.          |
//! | `credential_codes`         | M3. claim flag flip with TOCTOU guard.                 |
//! | `agents`                   | M3. lookup + insert + revoke.                          |
//! | `agent_checksum_*`         | M3. checksum input + audit trail.                      |
//! | `users`                    | M3. upsert + registration lookup.                      |
//! | `spend_*`                  | server-authoritative spend ledger.                     |
//!
//! ## Two pools, and what was removed from between them
//!
//! Under Postgres this process holds two pools: the sqlx one below, and the
//! blocking one every `DbHandle::lock()` site uses. That is the migration state,
//! not a design — but a table written through BOTH is the hazard it creates,
//! because the two have different isolation and no transaction spans them.
//!
//! An audit found eight `Repo` methods that duplicated a live `AnyConn` path
//! for the same table while having no caller at all: `risk_increment`,
//! `prune_call_nonces`, `prune_pop_challenges`, `insert_bitcoin_anchor`,
//! `insert_solana_anchor`, `insert_merkle_leaf`, `agent_action_receipt_exists`
//! and `consume_bank_attestation_nonce`. They were the ported-but-never-wired
//! half, and deleting them took the both-pools-write-this set from six tables to
//! three. The consent-token family went with the `/kyc/*` routes it served.
//!
//! Of the three that remain, `agent_call_nonces` is not a conflict — `Repo`
//! claims, the GC in `state.rs` only deletes rows that have already expired.
//! `ajwt_used_jtis` and `agent_pop_challenges` genuinely have two live-capable
//! writers, and are kept deliberately: the `Repo` halves are the landing zone
//! the deferred M2 call-site sweep points at, named in the TODOs in `agent.rs`
//! and `main.rs`. Delete those and the sweep loses its destination.
//!
//! ## Serializable transactions (M1)
//!
//! TOCTOU-sensitive paths (single-use nonce consume, JTI claim, rate-window
//! increment-and-check) run under explicit serializable isolation:
//!
//! - **SQLite**: `BEGIN IMMEDIATE TRANSACTION` acquires the writer lock for the
//!   life of the transaction. Combined with `journal_mode = WAL` + `busy_timeout`
//!   this gives single-writer serializable semantics for the wrapped block.
//! - **Postgres**: `BEGIN ISOLATION LEVEL SERIALIZABLE` with `SQLSTATE 40001`
//!   (`serialization_failure`) retry — up to 3 attempts with exponential backoff
//!   (10ms, 40ms, 90ms). The outer caller never observes the retry.
//!
//! `INSERT … ON CONFLICT DO NOTHING / DO UPDATE` is atomic at any isolation
//! level (the conflict resolution is in-statement), so the helpers below use
//! `INSERT` row-count + uniqueness for replay detection. The serializable
//! wrapper is belt-and-braces: even if a future helper adds a `SELECT … WHERE
//! flag = 0` followed by `UPDATE`, it cannot be torn by a concurrent reader.
//!
//! ## Why incremental
//!
//! 12 source files reference `rusqlite::` directly across ~80 call sites.
//! Atomic swap risks correctness regressions on the security-critical TOCTOU
//! patterns we just fixed. Incremental port lets us rerun the 9-scenario
//! invariant suite after each module migrates and catch regressions early.
//!
//! ## Pattern for porting a module
//!
//! 1. Add a function on `Repo` that takes the high-level intent
//!    (e.g. `claim_call_nonce(agent_id, nonce, exp)`).
//! 2. Implement it for both backends inside the same function — match on
//!    `&self.kind` and dispatch to either rusqlite or sqlx.
//! 3. Update callers from raw SQL to `state.repo.claim_call_nonce(...)`.
//! 4. Run `bash run-all.sh` (default + enforce mode).

use std::sync::Arc;

use crate::db::DbHandle;
use crate::tenancy::DEFAULT_TENANT;

/// The repository's own backend split, older than and separate from
/// [`crate::db::DbConn`].
///
/// Both variants are selected from the same `SAURON_DB_BACKEND`, so
/// `Repo::Sqlite` exists only when `DbHandle` has no Postgres pool either. That
/// is why every `Repo::Sqlite(db)` arm below takes `db.lock_sqlite()` rather
/// than the dispatching `db.lock()`: it is already the SQLite half of a
/// two-armed match, and the Postgres half is the sqlx code next to it. Making
/// those arms dispatch would give Postgres two independent routes to the same
/// table — sqlx here and `AnyConn` there — which is the split the port exists
/// to remove.
#[derive(Clone)]
pub enum Repo {
    Sqlite(Arc<DbHandle>),
    Postgres(sqlx::PgPool),
}

/// A registered user row, for the read paths that previously did ad-hoc
/// `SELECT … FROM users WHERE key_image_hex = ?`. All columns are `NOT NULL`
/// (schema default `''`), so plain `String` is safe.
#[derive(Clone, Debug)]
pub struct UserRow {
    pub public_key_hex: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub date_of_birth: String,
    pub nationality: String,
}

#[derive(Debug)]
pub enum RepoError {
    Backend(String),
    Replay(String),
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Backend(s) => write!(f, "{s}"),
            RepoError::Replay(s) => write!(f, "{s}"),
        }
    }
}

impl Repo {
    /// Build a Repo from environment configuration.
    ///
    /// `SAURON_DB_BACKEND=postgres` selects the sqlx Postgres path and requires
    /// `DATABASE_URL`. Anything else (including unset) selects the existing
    /// SQLite path, preserving full backwards compatibility.
    pub async fn from_env(sqlite: Arc<DbHandle>) -> Result<Self, String> {
        let backend = std::env::var("SAURON_DB_BACKEND")
            .unwrap_or_else(|_| "sqlite".to_string())
            .to_ascii_lowercase();
        match backend.as_str() {
            "postgres" | "pg" | "postgresql" => {
                let url = std::env::var("DATABASE_URL").map_err(|_| {
                    "DATABASE_URL must be set when SAURON_DB_BACKEND=postgres".to_string()
                })?;
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(
                        std::env::var("SAURON_PG_POOL_SIZE")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(16u32),
                    )
                    .connect(&url)
                    .await
                    .map_err(|e| format!("postgres connect: {e}"))?;
                tracing::info!(target: "sauron::repo", backend = "postgres", "repository pool ready");
                // This used to warn that the port was partial and most tables
                // still used the SQLite sidecar. That stopped being true when
                // `DbHandle::lock()` began returning the dispatching guard; the
                // sidecar now only carries what `lock_sqlite()` names, which is
                // schema bootstrap and the backup tooling. Leaving the warning
                // would have operators discount a message that is no longer
                // describing their deployment.
                //
                // The claim is held by `core/tests/postgres_backend_drift.sh`,
                // which fails if a registration lands in the sidecar.
                Ok(Repo::Postgres(pool))
            }
            _ => {
                tracing::info!(target: "sauron::repo", backend = "sqlite", "repository on legacy rusqlite path");
                Ok(Repo::Sqlite(sqlite))
            }
        }
    }

    pub fn is_postgres(&self) -> bool {
        matches!(self, Repo::Postgres(_))
    }

    // ─── txn_serializable ──────────────────────────────────────────────────
    //
    // Run an SQLite operation under `BEGIN IMMEDIATE TRANSACTION` (writer lock
    // for the life of the txn — single-writer serialisable semantics in WAL
    // mode). The closure receives the pooled connection; it MUST NOT spawn
    // sub-tasks that touch the DB pool (they would deadlock on the writer lock).
    //
    // For TOCTOU-sensitive single-statement operations (`INSERT … ON CONFLICT`)
    // the IMMEDIATE-TX wrapper is belt-and-braces — the statement is already
    // atomic. The wrapper matters when the closure reads-then-writes.
    pub fn txn_immediate_sqlite<F, T>(&self, f: F) -> Result<T, RepoError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, RepoError>,
    {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")
                    .map_err(|e| RepoError::Backend(format!("begin immediate: {e}")))?;
                let res = f(&conn);
                match res {
                    Ok(v) => {
                        conn.execute_batch("COMMIT;")
                            .map_err(|e| RepoError::Backend(format!("commit: {e}")))?;
                        Ok(v)
                    }
                    Err(e) => {
                        let _ = conn.execute_batch("ROLLBACK;");
                        Err(e)
                    }
                }
            }
            Repo::Postgres(_) => Err(RepoError::Backend(
                "txn_immediate_sqlite called on Postgres backend".into(),
            )),
        }
    }

    // Run a Postgres operation under `BEGIN ISOLATION LEVEL SERIALIZABLE`,
    // retrying on `SQLSTATE 40001` (serialisation_failure) up to 3 attempts
    // with exponential backoff (10 / 40 / 90 ms). Any other error aborts.
    //
    // The closure receives a mutable `sqlx::Transaction<Postgres>` and SHOULD
    // run all of its statements via that handle; sqlx returns `?` errors as
    // `sqlx::Error`. Callers map domain errors via the `mapper` arg so the
    // retry loop can tell a TOCTOU collision (Replay) from a transient
    // serialisation failure (retry) from a hard backend error (abort).
    pub async fn txn_serializable_pg<F, T>(&self, mut f: F) -> Result<T, RepoError>
    where
        for<'c> F: FnMut(
            &'c mut sqlx::Transaction<'static, sqlx::Postgres>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, RepoError>> + Send + 'c>,
        >,
    {
        let pool = match self {
            Repo::Postgres(p) => p.clone(),
            Repo::Sqlite(_) => {
                return Err(RepoError::Backend(
                    "txn_serializable_pg called on SQLite backend".into(),
                ));
            }
        };
        let mut last_err: Option<RepoError> = None;
        for attempt in 0..3u32 {
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| RepoError::Backend(format!("postgres begin: {e}")))?;
            // Upgrade to SERIALIZABLE for this txn (Postgres default is READ COMMITTED).
            if let Err(e) = sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *tx)
                .await
            {
                let _ = tx.rollback().await;
                return Err(RepoError::Backend(format!("postgres set isolation: {e}")));
            }
            let inner = f(&mut tx).await;
            match inner {
                Ok(val) => match tx.commit().await {
                    Ok(()) => return Ok(val),
                    Err(sqlx::Error::Database(db_err))
                        if db_err.code().as_deref() == Some("40001") =>
                    {
                        last_err = Some(RepoError::Backend(format!(
                            "serialisation_failure on commit (attempt {})",
                            attempt + 1
                        )));
                    }
                    Err(e) => {
                        return Err(RepoError::Backend(format!("postgres commit: {e}")));
                    }
                },
                Err(e) => {
                    // Roll back; only retry if the error came from SQLSTATE 40001.
                    let _ = tx.rollback().await;
                    let retryable = matches!(&e, RepoError::Backend(s) if s.contains("40001") || s.contains("serialization_failure"));
                    if !retryable {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
            // Backoff: 10ms, 40ms, 90ms — total <150ms across 3 attempts.
            let backoff_ms =
                10u64 + (attempt as u64) * 30 + (attempt as u64) * (attempt as u64) * 10;
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
        }
        Err(last_err.unwrap_or_else(|| {
            RepoError::Backend("serialisable retry exhausted with no error captured".into())
        }))
    }

    // ─── agent_call_nonces ─────────────────────────────────────────────────
    //
    // Atomic single-use insert under serializable isolation. Errors with
    // `RepoError::Replay` when the same (agent_id, nonce) pair has already
    // been consumed — this is the security property: a captured per-call
    // signature cannot be replayed.

    pub async fn consume_call_nonce(
        &self,
        agent_id: &str,
        nonce: &str,
        exp: i64,
    ) -> Result<(), RepoError> {
        if nonce.is_empty() {
            return Err(RepoError::Backend("missing call nonce".into()));
        }
        if nonce.len() > 128 {
            return Err(RepoError::Backend(
                "call nonce too long (max 128 chars)".into(),
            ));
        }
        match self {
            Repo::Sqlite(_) => {
                let agent_id = agent_id.to_string();
                let nonce = nonce.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "INSERT INTO agent_call_nonces (agent_id, nonce, exp) VALUES (?1, ?2, ?3)",
                        rusqlite::params![agent_id, nonce, exp],
                    )
                    .map_err(|e| {
                        let s = e.to_string();
                        if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                            RepoError::Replay("call nonce replay (already used)".into())
                        } else {
                            RepoError::Backend(s)
                        }
                    })?;
                    Ok(())
                })
            }
            Repo::Postgres(_) => {
                let agent_id = agent_id.to_string();
                let nonce = nonce.to_string();
                self.txn_serializable_pg(move |tx| {
                    let agent_id = agent_id.clone();
                    let nonce = nonce.clone();
                    Box::pin(async move {
                        let result = sqlx::query(
                            "INSERT INTO agent_call_nonces (agent_id, nonce, exp) VALUES ($1, $2, $3)",
                        )
                        .bind(&agent_id)
                        .bind(&nonce)
                        .bind(exp)
                        .execute(&mut **tx)
                        .await;
                        match result {
                            Ok(_) => Ok(()),
                            Err(sqlx::Error::Database(db_err))
                                if db_err.is_unique_violation() =>
                            {
                                Err(RepoError::Replay(
                                    "call nonce replay (already used)".into(),
                                ))
                            }
                            Err(sqlx::Error::Database(db_err))
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                Err(RepoError::Backend("40001 serialization_failure".into()))
                            }
                            Err(e) => Err(RepoError::Backend(format!(
                                "postgres insert call nonce: {e}"
                            ))),
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── ajwt_used_jtis ────────────────────────────────────────────────────
    //
    // Single-use JTI claim under serializable isolation. Atomic INSERT; unique
    // constraint on `jti` is the replay detector. The wrapper protects against
    // future read-then-write helpers (e.g. "claim if not used AND not expired").
    pub async fn consume_ajwt_jti(&self, jti: &str, exp: i64) -> Result<(), RepoError> {
        if jti.is_empty() {
            return Err(RepoError::Backend("missing jti".into()));
        }
        if jti.len() > 256 {
            return Err(RepoError::Backend("jti too long (max 256 chars)".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let jti = jti.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "INSERT INTO ajwt_used_jtis (jti, exp) VALUES (?1, ?2)",
                        rusqlite::params![jti, exp],
                    )
                    .map_err(|e| {
                        let s = e.to_string();
                        if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                            RepoError::Replay("A-JWT jti replay (token already used)".into())
                        } else {
                            RepoError::Backend(s)
                        }
                    })?;
                    Ok(())
                })
            }
            Repo::Postgres(_) => {
                let jti = jti.to_string();
                self.txn_serializable_pg(move |tx| {
                    let jti = jti.clone();
                    Box::pin(async move {
                        let result =
                            sqlx::query("INSERT INTO ajwt_used_jtis (jti, exp) VALUES ($1, $2)")
                                .bind(&jti)
                                .bind(exp)
                                .execute(&mut **tx)
                                .await;
                        match result {
                            Ok(_) => Ok(()),
                            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                                Err(RepoError::Replay(
                                    "A-JWT jti replay (token already used)".into(),
                                ))
                            }
                            Err(sqlx::Error::Database(db_err))
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                Err(RepoError::Backend("40001 serialization_failure".into()))
                            }
                            Err(e) => Err(RepoError::Backend(format!("postgres insert jti: {e}"))),
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── M2: agent_pop_challenges ──────────────────────────────────────────
    //
    // Low-risk module: one-time PoP challenges with GC-on-expiry. Take helper
    // is single-row delete-by-id with a freshness check; the SQLite path keeps
    // its existing INSERT/DELETE flow via `ajwt_support::insert_pop_challenge`
    // and `ajwt_support::take_pop_challenge` (those wrap in `BEGIN IMMEDIATE`
    // for safety even though the operations are intrinsically atomic).

    /// Insert a one-time PoP challenge after GC. Returns the stored `exp`.
    pub async fn insert_pop_challenge(
        &self,
        id: &str,
        agent_id: &str,
        challenge: &str,
        now: i64,
        ttl_secs: i64,
    ) -> Result<i64, RepoError> {
        let exp = now + ttl_secs;
        match self {
            Repo::Sqlite(_) => {
                let id = id.to_string();
                let agent_id = agent_id.to_string();
                let challenge = challenge.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "DELETE FROM agent_pop_challenges WHERE exp < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                    conn.execute(
                        "INSERT INTO agent_pop_challenges (id, agent_id, challenge, exp) \
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![id, agent_id, challenge, exp],
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                    Ok(exp)
                })
            }
            Repo::Postgres(_) => {
                let id = id.to_string();
                let agent_id = agent_id.to_string();
                let challenge = challenge.to_string();
                self.txn_serializable_pg(move |tx| {
                    let id = id.clone();
                    let agent_id = agent_id.clone();
                    let challenge = challenge.clone();
                    Box::pin(async move {
                        sqlx::query("DELETE FROM agent_pop_challenges WHERE exp < $1")
                            .bind(now)
                            .execute(&mut **tx)
                            .await
                            .map_err(|e| RepoError::Backend(format!("pg pop gc: {e}")))?;
                        sqlx::query(
                            "INSERT INTO agent_pop_challenges (id, agent_id, challenge, exp) \
                             VALUES ($1, $2, $3, $4)",
                        )
                        .bind(&id)
                        .bind(&agent_id)
                        .bind(&challenge)
                        .bind(exp)
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg pop insert: {e}")))?;
                        Ok(exp)
                    })
                })
                .await
            }
        }
    }

    /// Take (load + delete) a one-time PoP challenge under a serializable txn.
    /// Returns Err(`Replay`) when the challenge is missing, expired, or bound
    /// to a different agent. Postgres uses `FOR UPDATE` + conditional DELETE
    /// `RETURNING` to guarantee at most one taker.
    pub async fn take_pop_challenge(
        &self,
        challenge_id: &str,
        expected_agent_id: &str,
        now: i64,
    ) -> Result<String, RepoError> {
        match self {
            Repo::Sqlite(_) => {
                let challenge_id = challenge_id.to_string();
                let expected_agent_id = expected_agent_id.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let (challenge, agent_id, exp): (String, String, i64) = conn
                        .query_row(
                            "SELECT challenge, agent_id, exp FROM agent_pop_challenges WHERE id = ?1",
                            rusqlite::params![challenge_id],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .map_err(|_| RepoError::Replay(
                            "unknown or expired pop_challenge_id".into(),
                        ))?;
                    if agent_id != expected_agent_id {
                        return Err(RepoError::Replay(
                            "pop challenge does not match agent".into(),
                        ));
                    }
                    if exp < now {
                        let _ = conn.execute(
                            "DELETE FROM agent_pop_challenges WHERE id = ?1",
                            rusqlite::params![challenge_id],
                        );
                        return Err(RepoError::Replay("pop challenge expired".into()));
                    }
                    let rows = conn
                        .execute(
                            "DELETE FROM agent_pop_challenges WHERE id = ?1",
                            rusqlite::params![challenge_id],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    if rows == 0 {
                        return Err(RepoError::Replay(
                            "pop challenge already taken".into(),
                        ));
                    }
                    Ok(challenge)
                })
            }
            Repo::Postgres(_) => {
                let challenge_id = challenge_id.to_string();
                let expected_agent_id = expected_agent_id.to_string();
                self.txn_serializable_pg(move |tx| {
                    let challenge_id = challenge_id.clone();
                    let expected_agent_id = expected_agent_id.clone();
                    Box::pin(async move {
                        // FOR UPDATE locks the row for the txn's life; the
                        // conditional DELETE … RETURNING below is what proves
                        // we are the sole taker.
                        let row: Option<(String, String, i64)> = sqlx::query_as(
                            "SELECT challenge, agent_id, exp FROM agent_pop_challenges \
                             WHERE id = $1 FOR UPDATE",
                        )
                        .bind(&challenge_id)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg pop select: {e}")))?;
                        let (challenge, agent_id, exp) = match row {
                            Some(t) => t,
                            None => {
                                return Err(RepoError::Replay(
                                    "unknown or expired pop_challenge_id".into(),
                                ))
                            }
                        };
                        if agent_id != expected_agent_id {
                            return Err(RepoError::Replay(
                                "pop challenge does not match agent".into(),
                            ));
                        }
                        if exp < now {
                            let _ = sqlx::query("DELETE FROM agent_pop_challenges WHERE id = $1")
                                .bind(&challenge_id)
                                .execute(&mut **tx)
                                .await;
                            return Err(RepoError::Replay("pop challenge expired".into()));
                        }
                        let result: Option<(String,)> = sqlx::query_as(
                            "DELETE FROM agent_pop_challenges WHERE id = $1 RETURNING challenge",
                        )
                        .bind(&challenge_id)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg pop delete: {e}")))?;
                        match result {
                            Some(_) => Ok(challenge),
                            None => Err(RepoError::Replay("pop challenge already taken".into())),
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── M2: bank_attestation_nonces ───────────────────────────────────────
    //
    // UNIQUE-key consume. Primary key (provider_id, nonce) is the replay
    // detector; INSERT failing with UNIQUE violation maps to RepoError::Replay.

    // ─── M2: consent_log token consume ─────────────────────────────────────
    //
    // The TOCTOU pattern: mark `token_used=1` only if the row currently has
    // `token_used=0 AND revoked=0 AND not expired`. Postgres uses
    // `SELECT … FOR UPDATE` to lock the row, then conditional UPDATE …
    // RETURNING to confirm the flag actually flipped. The RETURNING row count
    // is the authoritative TOCTOU oracle: only one txn can flip 0→1.
    //
    // Returns the consent record (user_key_image, site_name, issuing_agent_id,
    // requested_claims_json) on success. Error variants distinguish replay
    // (already used / revoked / expired) from backend.

    // ─── consent_log read / grant / list / revoke ──────────────────────────
    //
    // Creation + token consume are handled by insert_pending_consent /
    // consume_consent_token above. These cover the remaining handler paths so
    // the whole consent_log lifecycle is on one backend.

    /// user_key_image for a live, unused consent token scoped to a site.
    pub async fn resolve_consent_user(
        &self,
        tenant_id: &str,
        consent_token: &str,
        site_name: &str,
        now: i64,
    ) -> Result<Option<String>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(conn
                    .query_row(
                        "SELECT user_key_image FROM consent_log \
                         WHERE tenant_id = ?1 AND consent_token = ?2 AND site_name = ?3 AND token_used = 0 AND revoked = 0 \
                         AND (consent_expires_at = 0 OR consent_expires_at > ?4)",
                        rusqlite::params![tenant_id, consent_token, site_name, now],
                        |r| r.get::<_, String>(0),
                    )
                    .ok())
            }
            Repo::Postgres(pool) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT user_key_image FROM consent_log \
                     WHERE tenant_id = $1 AND consent_token = $2 AND site_name = $3 AND token_used = 0 AND revoked = 0 \
                     AND (consent_expires_at = 0 OR consent_expires_at > $4)",
                )
                .bind(tenant_id)
                .bind(consent_token)
                .bind(site_name)
                .bind(now)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg resolve_consent_user: {e}")))?;
                Ok(row.map(|t| t.0))
            }
        }
    }

    /// A user's consent history: (request_id, site_name, granted_at, token_used, revoked).
    pub async fn list_user_consents(
        &self,
        tenant_id: &str,
        user_key_image: &str,
    ) -> Result<Vec<(String, String, i64, i64, i64)>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut stmt = conn
                    .prepare(
                        "SELECT request_id, site_name, granted_at, token_used, revoked \
                         FROM consent_log WHERE tenant_id = ?1 AND user_key_image = ?2 \
                         ORDER BY granted_at DESC LIMIT 100",
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map(rusqlite::params![tenant_id, user_key_image], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                    })
                    .map_err(|e| RepoError::Backend(e.to_string()))?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Repo::Postgres(pool) => {
                // token_used/revoked are int4; cast for the same reason as in
                // consume_consent_token above.
                let rows: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(
                    "SELECT request_id, site_name, granted_at, token_used::BIGINT, revoked::BIGINT \
                     FROM consent_log WHERE tenant_id = $1 AND user_key_image = $2 \
                     ORDER BY granted_at DESC LIMIT 100",
                )
                .bind(tenant_id)
                .bind(user_key_image)
                .fetch_all(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg list_user_consents: {e}")))?;
                Ok(rows)
            }
        }
    }

    /// Revoke a user's consent by request id. Returns rows affected.
    pub async fn revoke_consent(
        &self,
        tenant_id: &str,
        request_id: &str,
        user_key_image: &str,
    ) -> Result<u64, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let n = conn
                    .execute(
                        "UPDATE consent_log SET revoked = 1 \
                         WHERE tenant_id = ?1 AND request_id = ?2 AND user_key_image = ?3",
                        rusqlite::params![tenant_id, request_id, user_key_image],
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(n as u64)
            }
            Repo::Postgres(pool) => {
                let res = sqlx::query(
                    "UPDATE consent_log SET revoked = 1 \
                     WHERE tenant_id = $1 AND request_id = $2 AND user_key_image = $3",
                )
                .bind(tenant_id)
                .bind(request_id)
                .bind(user_key_image)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg revoke_consent: {e}")))?;
                Ok(res.rows_affected())
            }
        }
    }

    // ─── M2: agent_payment_authorizations ──────────────────────────────────
    //
    // Same TOCTOU pattern as consent_log: flip `consumed=0 → 1` only once.
    // Postgres uses FOR UPDATE + RETURNING; SQLite uses BEGIN IMMEDIATE +
    // conditional UPDATE.

    /// Which agent obtained this authorization, if it exists in `tenant_id`.
    ///
    /// Consume is authorised by ownership, not just by holding the id: within a
    /// tenant every signed agent knows the id format, so without this check one
    /// agent could redeem another's authorization. Returns `None` when the row
    /// does not exist or belongs to a different tenant — the caller answers 404
    /// either way, so a cross-tenant probe cannot distinguish the two.
    pub async fn payment_authorization_agent(
        &self,
        tenant_id: &str,
        auth_id: &str,
    ) -> Result<Option<String>, RepoError> {
        if auth_id.is_empty() {
            return Err(RepoError::Backend("missing auth_id".into()));
        }
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.query_row(
                    "SELECT agent_id FROM agent_payment_authorizations \
                     WHERE tenant_id = ?1 AND auth_id = ?2",
                    rusqlite::params![tenant_id, auth_id],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(RepoError::Backend(other.to_string())),
                })
            }
            Repo::Postgres(pool) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT agent_id FROM agent_payment_authorizations \
                     WHERE tenant_id = $1 AND auth_id = $2",
                )
                .bind(tenant_id)
                .bind(auth_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg payment_authorization_agent: {e}")))?;
                Ok(row.map(|r| r.0))
            }
        }
    }

    pub async fn consume_payment_authorization(
        &self,
        tenant_id: &str,
        auth_id: &str,
        now: i64,
    ) -> Result<(), RepoError> {
        if auth_id.is_empty() {
            return Err(RepoError::Backend("missing auth_id".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let auth_id = auth_id.to_string();
                let tenant_id = tenant_id.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let rows = conn
                        .execute(
                            "UPDATE agent_payment_authorizations SET consumed = 1 \
                             WHERE tenant_id = ?1 AND auth_id = ?2 AND consumed = 0 AND expires_at > ?3",
                            rusqlite::params![tenant_id, auth_id, now],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    if rows == 0 {
                        return Err(RepoError::Replay(
                            "Authorization already consumed or expired".into(),
                        ));
                    }
                    Ok(())
                })
            }
            Repo::Postgres(_) => {
                let auth_id = auth_id.to_string();
                let tenant_id = tenant_id.to_string();
                self.txn_serializable_pg(move |tx| {
                    let auth_id = auth_id.clone();
                    let tenant_id = tenant_id.clone();
                    Box::pin(async move {
                        let claimed: Option<(String,)> = sqlx::query_as(
                            "UPDATE agent_payment_authorizations SET consumed = 1 \
                             WHERE tenant_id = $1 AND auth_id = $2 AND consumed = 0 AND expires_at > $3 \
                             RETURNING auth_id",
                        )
                        .bind(&tenant_id)
                        .bind(&auth_id)
                        .bind(now)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| match e {
                            sqlx::Error::Database(ref db_err)
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                RepoError::Backend("40001 serialization_failure".into())
                            }
                            _ => RepoError::Backend(format!("pg payauth consume: {e}")),
                        })?;
                        if claimed.is_none() {
                            return Err(RepoError::Replay(
                                "Authorization already consumed or expired".into(),
                            ));
                        }
                        Ok(())
                    })
                })
                .await
            }
        }
    }

    /// Insert a new single-use payment authorization. Unique on `auth_id` and
    /// `jti` — uniqueness violations surface as `RepoError::Replay`.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_payment_authorization(
        &self,
        tenant_id: &str,
        auth_id: &str,
        agent_id: &str,
        jti: &str,
        amount_minor: i64,
        currency: &str,
        merchant_id: &str,
        payment_ref: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO agent_payment_authorizations (auth_id, agent_id, jti, \
                     amount_minor, currency, merchant_id, payment_ref, created_at, \
                     expires_at, consumed, tenant_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10)",
                    rusqlite::params![
                        auth_id,
                        agent_id,
                        jti,
                        amount_minor,
                        currency,
                        merchant_id,
                        payment_ref,
                        created_at,
                        expires_at,
                        tenant_id,
                    ],
                )
                .map_err(|e| {
                    let s = e.to_string();
                    if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                        RepoError::Replay("payment authorization already exists".into())
                    } else {
                        RepoError::Backend(s)
                    }
                })?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                let res = sqlx::query(
                    "INSERT INTO agent_payment_authorizations (auth_id, agent_id, jti, \
                     amount_minor, currency, merchant_id, payment_ref, created_at, \
                     expires_at, consumed, tenant_id) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $10)",
                )
                .bind(auth_id)
                .bind(agent_id)
                .bind(jti)
                .bind(amount_minor)
                .bind(currency)
                .bind(merchant_id)
                .bind(payment_ref)
                .bind(created_at)
                .bind(expires_at)
                .bind(tenant_id)
                .execute(pool)
                .await;
                match res {
                    Ok(_) => Ok(()),
                    Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(
                        RepoError::Replay("payment authorization already exists".into()),
                    ),
                    Err(e) => Err(RepoError::Backend(format!("pg insert payment auth: {e}"))),
                }
            }
        }
    }

    // ─── M3: credential_codes ─────────────────────────────────────────────
    //
    // Single-use `claimed` flag flip — exact mirror of M2 payment_auth pattern.

    /// Attempt to flip credential_codes.claimed 0→1 for the given key image.
    /// Returns Ok(true) if this caller won the race, Ok(false) if the row
    /// was already claimed (caller should re-check `user_credentials`).
    pub async fn claim_credential_code(
        &self,
        tenant_id: &str,
        key_image_hex: &str,
    ) -> Result<bool, RepoError> {
        if key_image_hex.is_empty() {
            return Err(RepoError::Backend("missing key_image_hex".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let key = key_image_hex.to_string();
                let tenant_id = tenant_id.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let rows = conn
                        .execute(
                            "UPDATE credential_codes SET claimed = 1 \
                             WHERE tenant_id = ?1 AND key_image_hex = ?2 AND claimed = 0",
                            rusqlite::params![tenant_id, key],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    Ok(rows == 1)
                })
            }
            Repo::Postgres(_) => {
                let key = key_image_hex.to_string();
                let tenant_id = tenant_id.to_string();
                self.txn_serializable_pg(move |tx| {
                    let key = key.clone();
                    let tenant_id = tenant_id.clone();
                    Box::pin(async move {
                        let claimed: Option<(String,)> = sqlx::query_as(
                            "UPDATE credential_codes SET claimed = 1 \
                             WHERE tenant_id = $1 AND key_image_hex = $2 AND claimed = 0 \
                             RETURNING key_image_hex",
                        )
                        .bind(&tenant_id)
                        .bind(&key)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| match e {
                            sqlx::Error::Database(ref db_err)
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                RepoError::Backend("40001 serialization_failure".into())
                            }
                            _ => RepoError::Backend(format!("pg credential claim: {e}")),
                        })?;
                        Ok(claimed.is_some())
                    })
                })
                .await
            }
        }
    }

    /// Release a previously claimed credential code so the user can retry.
    /// Used on the failure paths in the /credential/claim flow.
    pub async fn release_credential_code(
        &self,
        tenant_id: &str,
        key_image_hex: &str,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "UPDATE credential_codes SET claimed = 0 \
                     WHERE tenant_id = ?1 AND key_image_hex = ?2 AND claimed = 1",
                    rusqlite::params![tenant_id, key_image_hex],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "UPDATE credential_codes SET claimed = 0 \
                     WHERE tenant_id = $1 AND key_image_hex = $2 AND claimed = 1",
                )
                .bind(tenant_id)
                .bind(key_image_hex)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg release credential: {e}")))?;
                Ok(())
            }
        }
    }

    /// Look up the pre-auth code + subject DID for a credential request.
    pub async fn select_credential_code(
        &self,
        tenant_id: &str,
        key_image_hex: &str,
    ) -> Result<Option<(String, String)>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let row = conn
                    .query_row(
                        "SELECT pre_auth_code, subject_did FROM credential_codes \
                         WHERE tenant_id = ?1 AND key_image_hex = ?2",
                        rusqlite::params![tenant_id, key_image_hex],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .ok();
                Ok(row)
            }
            Repo::Postgres(pool) => {
                let row: Option<(String, String)> = sqlx::query_as(
                    "SELECT pre_auth_code, subject_did FROM credential_codes \
                     WHERE tenant_id = $1 AND key_image_hex = $2",
                )
                .bind(tenant_id)
                .bind(key_image_hex)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg sel credential code: {e}")))?;
                Ok(row)
            }
        }
    }

    // ─── M3: users + user_credentials + user_registrations ────────────────

    /// Returns true if a user row exists for the key image.
    pub async fn user_exists(&self, key_image_hex: &str) -> Result<bool, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let n: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
                        rusqlite::params![key_image_hex],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                Ok(n > 0)
            }
            Repo::Postgres(pool) => {
                let row: (i64,) =
                    sqlx::query_as("SELECT COUNT(*)::BIGINT FROM users WHERE key_image_hex = $1")
                        .bind(key_image_hex)
                        .fetch_one(pool)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg user_exists: {e}")))?;
                Ok(row.0 > 0)
            }
        }
    }

    /// Upsert a user row (idempotent — re-registration overrides metadata).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_user(
        &self,
        key_image_hex: &str,
        public_key_hex: &str,
        first_name: &str,
        last_name: &str,
        email: &str,
        date_of_birth: &str,
        nationality: &str,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO users (key_image_hex, public_key_hex, first_name, last_name, \
                     email, date_of_birth, nationality) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                     ON CONFLICT(key_image_hex) DO UPDATE SET \
                       public_key_hex = excluded.public_key_hex, \
                       first_name = excluded.first_name, \
                       last_name = excluded.last_name, \
                       email = excluded.email, \
                       date_of_birth = excluded.date_of_birth, \
                       nationality = excluded.nationality",
                    rusqlite::params![
                        key_image_hex,
                        public_key_hex,
                        first_name,
                        last_name,
                        email,
                        date_of_birth,
                        nationality
                    ],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO users (key_image_hex, public_key_hex, first_name, last_name, \
                     email, date_of_birth, nationality) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) \
                     ON CONFLICT (key_image_hex) DO UPDATE SET \
                       public_key_hex = EXCLUDED.public_key_hex, \
                       first_name = EXCLUDED.first_name, \
                       last_name = EXCLUDED.last_name, \
                       email = EXCLUDED.email, \
                       date_of_birth = EXCLUDED.date_of_birth, \
                       nationality = EXCLUDED.nationality",
                )
                .bind(key_image_hex)
                .bind(public_key_hex)
                .bind(first_name)
                .bind(last_name)
                .bind(email)
                .bind(date_of_birth)
                .bind(nationality)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg upsert user: {e}")))?;
                Ok(())
            }
        }
    }

    /// Full user row by key image, or `None` if absent. Covers the scattered
    /// per-key reads (nationality / public_key / names).
    pub async fn get_user(&self, key_image_hex: &str) -> Result<Option<UserRow>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let row = conn
                    .query_row(
                        "SELECT public_key_hex, first_name, last_name, email, date_of_birth, nationality \
                         FROM users WHERE key_image_hex = ?1",
                        rusqlite::params![key_image_hex],
                        |r| {
                            Ok(UserRow {
                                public_key_hex: r.get(0)?,
                                first_name: r.get(1)?,
                                last_name: r.get(2)?,
                                email: r.get(3)?,
                                date_of_birth: r.get(4)?,
                                nationality: r.get(5)?,
                            })
                        },
                    )
                    .ok();
                Ok(row)
            }
            Repo::Postgres(pool) => {
                let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
                    "SELECT public_key_hex, first_name, last_name, email, date_of_birth, nationality \
                     FROM users WHERE key_image_hex = $1",
                )
                .bind(key_image_hex)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg get_user: {e}")))?;
                Ok(row.map(
                    |(public_key_hex, first_name, last_name, email, date_of_birth, nationality)| {
                        UserRow {
                            public_key_hex,
                            first_name,
                            last_name,
                            email,
                            date_of_birth,
                            nationality,
                        }
                    },
                ))
            }
        }
    }

    /// All user public keys, for startup ring-group reconstruction.
    pub async fn all_user_pubkeys(&self) -> Result<Vec<String>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut stmt = conn
                    .prepare("SELECT public_key_hex FROM users")
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| RepoError::Backend(e.to_string()))?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Repo::Postgres(pool) => {
                let rows: Vec<(String,)> = sqlx::query_as("SELECT public_key_hex FROM users")
                    .fetch_all(pool)
                    .await
                    .map_err(|e| RepoError::Backend(format!("pg all_user_pubkeys: {e}")))?;
                Ok(rows.into_iter().map(|t| t.0).collect())
            }
        }
    }

    /// All merkle commitments in insertion order, for startup ledger reconstruction.
    pub async fn all_merkle_commitments(&self) -> Result<Vec<String>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut stmt = conn
                    .prepare("SELECT commitment_hex FROM merkle_leaves ORDER BY seq ASC")
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| RepoError::Backend(e.to_string()))?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Repo::Postgres(pool) => {
                let rows: Vec<(String,)> =
                    sqlx::query_as("SELECT commitment_hex FROM merkle_leaves ORDER BY seq ASC")
                        .fetch_all(pool)
                        .await
                        .map_err(|e| {
                            RepoError::Backend(format!("pg all_merkle_commitments: {e}"))
                        })?;
                Ok(rows.into_iter().map(|t| t.0).collect())
            }
        }
    }

    /// Total registered users (admin metric).
    pub async fn count_users(&self) -> Result<i64, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let n: i64 = conn
                    .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                    .unwrap_or(0);
                Ok(n)
            }
            Repo::Postgres(pool) => {
                let row: (i64,) = sqlx::query_as("SELECT COUNT(*)::BIGINT FROM users")
                    .fetch_one(pool)
                    .await
                    .map_err(|e| RepoError::Backend(format!("pg count_users: {e}")))?;
                Ok(row.0)
            }
        }
    }

    /// All users for the admin listing: (key_image_hex, first, last, nationality).
    pub async fn list_users(&self) -> Result<Vec<(String, String, String, String)>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut stmt = conn
                    .prepare("SELECT key_image_hex, first_name, last_name, nationality FROM users")
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                    .map_err(|e| RepoError::Backend(e.to_string()))?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Repo::Postgres(pool) => {
                let rows: Vec<(String, String, String, String)> = sqlx::query_as(
                    "SELECT key_image_hex, first_name, last_name, nationality FROM users",
                )
                .fetch_all(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg list_users: {e}")))?;
                Ok(rows)
            }
        }
    }

    /// Users registered against one site (admin per-site view). Returns
    /// (first, last, email, nationality, source, timestamp), newest first.
    pub async fn list_site_users(
        &self,
        client_name: &str,
    ) -> Result<Vec<(String, String, String, String, String, i64)>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut stmt = conn
                    .prepare(
                        "SELECT u.first_name, u.last_name, u.email, u.nationality, r.source, r.timestamp \
                         FROM user_registrations r \
                         JOIN users u ON u.key_image_hex = r.user_key_image_hex \
                         WHERE r.client_name = ?1 \
                         ORDER BY r.timestamp DESC LIMIT 500",
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map(rusqlite::params![client_name], |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    })
                    .map_err(|e| RepoError::Backend(e.to_string()))?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Repo::Postgres(pool) => {
                let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
                    "SELECT u.first_name, u.last_name, u.email, u.nationality, r.source, r.timestamp \
                     FROM user_registrations r \
                     JOIN users u ON u.key_image_hex = r.user_key_image_hex \
                     WHERE r.client_name = $1 \
                     ORDER BY r.timestamp DESC LIMIT 500",
                )
                .bind(client_name)
                .fetch_all(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg list_site_users: {e}")))?;
                Ok(rows)
            }
        }
    }

    /// Cache the issuer-minted VC for a user (idempotent upsert by key image).
    pub async fn upsert_user_credential(
        &self,
        tenant_id: &str,
        key_image_hex: &str,
        credential_json: &str,
        issued_at: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let changed = conn.execute(
                    "INSERT INTO user_credentials (key_image_hex, credential_json, issued_at, tenant_id) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT(key_image_hex) DO UPDATE SET credential_json=excluded.credential_json, issued_at=excluded.issued_at \
                     WHERE user_credentials.tenant_id=excluded.tenant_id",
                    rusqlite::params![key_image_hex, credential_json, issued_at, tenant_id],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                if changed == 0 {
                    return Err(RepoError::Backend(
                        "credential key image already belongs to another tenant".into(),
                    ));
                }
                Ok(())
            }
            Repo::Postgres(pool) => {
                let result = sqlx::query(
                    "INSERT INTO user_credentials (key_image_hex, credential_json, issued_at, tenant_id) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (key_image_hex) DO UPDATE SET \
                       credential_json = EXCLUDED.credential_json, \
                       issued_at = EXCLUDED.issued_at \
                     WHERE user_credentials.tenant_id = EXCLUDED.tenant_id",
                )
                .bind(key_image_hex)
                .bind(credential_json)
                .bind(issued_at)
                .bind(tenant_id)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg upsert user cred: {e}")))?;
                if result.rows_affected() == 0 {
                    return Err(RepoError::Backend(
                        "credential key image already belongs to another tenant".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Fetch the cached VC, if any.
    pub async fn select_user_credential(
        &self,
        tenant_id: &str,
        key_image_hex: &str,
    ) -> Result<Option<String>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let row = conn
                    .query_row(
                        "SELECT credential_json FROM user_credentials WHERE tenant_id = ?1 AND key_image_hex = ?2",
                        rusqlite::params![tenant_id, key_image_hex],
                        |r| r.get::<_, String>(0),
                    )
                    .ok();
                Ok(row)
            }
            Repo::Postgres(pool) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT credential_json FROM user_credentials WHERE tenant_id = $1 AND key_image_hex = $2",
                )
                .bind(tenant_id)
                .bind(key_image_hex)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg sel user cred: {e}")))?;
                Ok(row.map(|t| t.0))
            }
        }
    }

    /// Append a user_registration row (idempotent — `INSERT OR IGNORE`).
    pub async fn insert_user_registration(
        &self,
        tenant_id: &str,
        client_name: &str,
        user_key_image_hex: &str,
        source: &str,
        timestamp: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp, tenant_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![client_name, user_key_image_hex, source, timestamp, tenant_id],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO user_registrations (client_name, user_key_image_hex, source, timestamp, tenant_id) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                )
                .bind(client_name)
                .bind(user_key_image_hex)
                .bind(source)
                .bind(timestamp)
                .bind(tenant_id)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg insert registration: {e}")))?;
                Ok(())
            }
        }
    }

    // ─── M3: merkle_leaves ────────────────────────────────────────────────

    // ─── M4: anchor tables (bitcoin / solana) ──────────────────────────────
    //
    // NOTE on autoincrement parity: SQLite's `INTEGER PRIMARY KEY AUTOINCREMENT`
    // produces a strictly monotonic gap-free sequence per table. Postgres's
    // `BIGSERIAL` (the canonical port) is *not* gap-free — the sequence
    // advances on rollback as well as commit. Callers must not assume the
    // primary-key id is a contiguous count of historical rows. Both anchor
    // tables here use TEXT `anchor_id` as the public reference, so this is
    // an internal-only concern.

    // ─── M4: agent_action_receipts ─────────────────────────────────────────

    // ─── Sprint 3+: spend ledger ───────────────────────────────────────────
    //
    // Server-authoritative spend total per (policy_id, agent_id, period_start).
    // Closes redteam A3 ("Local budget can be tampered"): the SDK keeps an
    // in-memory `BudgetTracker` for local pre-checks, but every recorded spend
    // is flushed to `spend_log` and atomically aggregated into `spend_ledger`.
    // POST /v1/policy/evaluate looks up the authoritative total here when
    // the caller supplies an `agent_id`.
    //
    // Both backends run the INSERT + UPSERT under a serializable wrapper so a
    // concurrent flush from a parallel SDK instance cannot tear the running
    // total.

    /// Record a single spend event: append to `spend_log` and atomically add
    /// `amount_usd` to the matching `spend_ledger` row (lifetime period =
    /// `period_start = 0` by default — pass an explicit value to track a
    /// daily/weekly/etc. window).
    ///
    /// Returns the freshly assigned `log_id`. `source` is one of
    /// `"sdk_flush"` (default for client-driven flushes) or
    /// `"server_recompute"` (reserved for future reconciliation jobs).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_spend(
        &self,
        policy_id: &str,
        agent_id: &str,
        action_id_opt: Option<&str>,
        amount_usd: f64,
        source: &str,
        now: i64,
    ) -> Result<String, RepoError> {
        Self::record_spend_with_period(
            self,
            policy_id,
            agent_id,
            action_id_opt,
            amount_usd,
            source,
            0, // lifetime period
            now,
        )
        .await
    }

    /// Tenant-scoped variant of [`record_spend`]. Multi-tenant call sites
    /// (Sprint 11) pass the resolved tenant id; legacy call sites continue
    /// to use [`record_spend`] which defaults to the `"default"` tenant.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_spend_tenant(
        &self,
        tenant_id: &str,
        policy_id: &str,
        agent_id: &str,
        action_id_opt: Option<&str>,
        amount_usd: f64,
        source: &str,
        now: i64,
    ) -> Result<String, RepoError> {
        self.record_spend_with_period_tenant(
            tenant_id,
            policy_id,
            agent_id,
            action_id_opt,
            amount_usd,
            source,
            0,
            now,
        )
        .await
    }

    /// Same as [`record_spend`] but with an explicit `period_start`. Useful
    /// for daily/weekly accounting windows.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_spend_with_period(
        &self,
        policy_id: &str,
        agent_id: &str,
        action_id_opt: Option<&str>,
        amount_usd: f64,
        source: &str,
        period_start: i64,
        now: i64,
    ) -> Result<String, RepoError> {
        self.record_spend_with_period_tenant(
            DEFAULT_TENANT,
            policy_id,
            agent_id,
            action_id_opt,
            amount_usd,
            source,
            period_start,
            now,
        )
        .await
    }

    /// Tenant-scoped variant of [`record_spend_with_period`].
    #[allow(clippy::too_many_arguments)]
    pub async fn record_spend_with_period_tenant(
        &self,
        tenant_id: &str,
        policy_id: &str,
        agent_id: &str,
        action_id_opt: Option<&str>,
        amount_usd: f64,
        source: &str,
        period_start: i64,
        now: i64,
    ) -> Result<String, RepoError> {
        if policy_id.is_empty() || agent_id.is_empty() {
            return Err(RepoError::Backend("missing policy_id or agent_id".into()));
        }
        if !amount_usd.is_finite() {
            return Err(RepoError::Backend("amount_usd must be finite".into()));
        }
        if source != "sdk_flush" && source != "server_recompute" {
            return Err(RepoError::Backend(format!(
                "unknown spend source '{source}'"
            )));
        }
        let log_id = format!("splog_{}", uuid_like_hex());
        let tenant_id_owned = tenant_id.to_string();
        match self {
            Repo::Sqlite(_) => {
                let policy_id = policy_id.to_string();
                let agent_id = agent_id.to_string();
                let action_id = action_id_opt.map(|s| s.to_string());
                let source = source.to_string();
                let log_id_cloned = log_id.clone();
                let tenant_inner = tenant_id_owned.clone();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "INSERT INTO spend_log (log_id, policy_id, agent_id, action_id, \
                         amount_usd, recorded_at, source, tenant_id) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![
                            log_id_cloned,
                            policy_id,
                            agent_id,
                            action_id,
                            amount_usd,
                            now,
                            source,
                            tenant_inner,
                        ],
                    )
                    .map_err(|e| RepoError::Backend(format!("spend_log insert: {e}")))?;
                    conn.execute(
                        "INSERT INTO spend_ledger \
                         (policy_id, agent_id, period_start, total_usd, last_updated, tenant_id) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                         ON CONFLICT(policy_id, agent_id, period_start) DO UPDATE SET \
                           total_usd = total_usd + ?4, \
                           last_updated = ?5",
                        rusqlite::params![
                            policy_id,
                            agent_id,
                            period_start,
                            amount_usd,
                            now,
                            tenant_inner,
                        ],
                    )
                    .map_err(|e| RepoError::Backend(format!("spend_ledger upsert: {e}")))?;
                    Ok(())
                })?;
                Ok(log_id)
            }
            Repo::Postgres(_) => {
                let policy_id = policy_id.to_string();
                let agent_id = agent_id.to_string();
                let action_id = action_id_opt.map(|s| s.to_string());
                let source = source.to_string();
                let log_id_cloned = log_id.clone();
                let tenant_inner = tenant_id_owned.clone();
                self.txn_serializable_pg(move |tx| {
                    let policy_id = policy_id.clone();
                    let agent_id = agent_id.clone();
                    let action_id = action_id.clone();
                    let source = source.clone();
                    let log_id_inner = log_id_cloned.clone();
                    let tenant_inner = tenant_inner.clone();
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO spend_log (log_id, policy_id, agent_id, action_id, \
                             amount_usd, recorded_at, source, tenant_id) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        )
                        .bind(&log_id_inner)
                        .bind(&policy_id)
                        .bind(&agent_id)
                        .bind(action_id.as_deref())
                        .bind(amount_usd)
                        .bind(now)
                        .bind(&source)
                        .bind(&tenant_inner)
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| match e {
                            sqlx::Error::Database(ref db_err)
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                RepoError::Backend("40001 serialization_failure".into())
                            }
                            _ => RepoError::Backend(format!("pg spend_log insert: {e}")),
                        })?;
                        sqlx::query(
                            "INSERT INTO spend_ledger \
                             (policy_id, agent_id, period_start, total_usd, last_updated, tenant_id) \
                             VALUES ($1, $2, $3, $4, $5, $6) \
                             ON CONFLICT (policy_id, agent_id, period_start) DO UPDATE SET \
                               total_usd = spend_ledger.total_usd + EXCLUDED.total_usd, \
                               last_updated = EXCLUDED.last_updated",
                        )
                        .bind(&policy_id)
                        .bind(&agent_id)
                        .bind(period_start)
                        .bind(amount_usd)
                        .bind(now)
                        .bind(&tenant_inner)
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| match e {
                            sqlx::Error::Database(ref db_err)
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                RepoError::Backend("40001 serialization_failure".into())
                            }
                            _ => RepoError::Backend(format!("pg spend_ledger upsert: {e}")),
                        })?;
                        Ok(())
                    })
                })
                .await?;
                Ok(log_id)
            }
        }
    }

    /// Return the authoritative spend total for one period (default lifetime
    /// when `period_start == 0`). Missing row returns `Ok(0.0)`.
    ///
    /// Back-compat shim: uses the `"default"` tenant. New callers should
    /// prefer [`Self::get_spend_total_tenant`].
    pub async fn get_spend_total(
        &self,
        policy_id: &str,
        agent_id: &str,
        period_start: i64,
    ) -> Result<f64, RepoError> {
        self.get_spend_total_tenant(DEFAULT_TENANT, policy_id, agent_id, period_start)
            .await
    }

    /// Tenant-scoped variant of [`get_spend_total`].
    pub async fn get_spend_total_tenant(
        &self,
        tenant_id: &str,
        policy_id: &str,
        agent_id: &str,
        period_start: i64,
    ) -> Result<f64, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let row: Option<f64> = conn
                    .query_row(
                        "SELECT total_usd FROM spend_ledger \
                         WHERE policy_id = ?1 AND agent_id = ?2 AND period_start = ?3 \
                           AND tenant_id = ?4",
                        rusqlite::params![policy_id, agent_id, period_start, tenant_id],
                        |r| r.get::<_, f64>(0),
                    )
                    .ok();
                Ok(row.unwrap_or(0.0))
            }
            Repo::Postgres(pool) => {
                let row: Option<(f64,)> = sqlx::query_as(
                    "SELECT total_usd FROM spend_ledger \
                     WHERE policy_id = $1 AND agent_id = $2 AND period_start = $3 \
                       AND tenant_id = $4",
                )
                .bind(policy_id)
                .bind(agent_id)
                .bind(period_start)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg spend total: {e}")))?;
                Ok(row.map(|t| t.0).unwrap_or(0.0))
            }
        }
    }

    /// Return the (last_updated, log_count) sidecar pair for a ledger row.
    /// Used by `GET /v1/agents/:agent_id/spend` to enrich the response.
    /// Back-compat shim — defaults to the `"default"` tenant.
    pub async fn get_spend_meta(
        &self,
        policy_id: &str,
        agent_id: &str,
        period_start: i64,
    ) -> Result<(i64, i64), RepoError> {
        self.get_spend_meta_tenant(DEFAULT_TENANT, policy_id, agent_id, period_start)
            .await
    }

    /// Tenant-scoped variant of [`get_spend_meta`].
    pub async fn get_spend_meta_tenant(
        &self,
        tenant_id: &str,
        policy_id: &str,
        agent_id: &str,
        period_start: i64,
    ) -> Result<(i64, i64), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let last_updated: i64 = conn
                    .query_row(
                        "SELECT last_updated FROM spend_ledger \
                         WHERE policy_id = ?1 AND agent_id = ?2 AND period_start = ?3 \
                           AND tenant_id = ?4",
                        rusqlite::params![policy_id, agent_id, period_start, tenant_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0);
                let log_count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM spend_log \
                         WHERE policy_id = ?1 AND agent_id = ?2 AND tenant_id = ?3",
                        rusqlite::params![policy_id, agent_id, tenant_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0);
                Ok((last_updated, log_count))
            }
            Repo::Postgres(pool) => {
                let lu: Option<(i64,)> = sqlx::query_as(
                    "SELECT last_updated FROM spend_ledger \
                     WHERE policy_id = $1 AND agent_id = $2 AND period_start = $3 \
                       AND tenant_id = $4",
                )
                .bind(policy_id)
                .bind(agent_id)
                .bind(period_start)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg ledger meta: {e}")))?;
                let cnt: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*)::BIGINT FROM spend_log \
                     WHERE policy_id = $1 AND agent_id = $2 AND tenant_id = $3",
                )
                .bind(policy_id)
                .bind(agent_id)
                .bind(tenant_id)
                .fetch_one(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg log count: {e}")))?;
                Ok((lu.map(|t| t.0).unwrap_or(0), cnt.0))
            }
        }
    }

    /// Recent rows of `spend_log` for the given (policy_id, agent_id), newest
    /// first. `limit` is clamped to 1000. Back-compat shim — defaults to
    /// the `"default"` tenant.
    pub async fn list_spend_log(
        &self,
        policy_id: &str,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<SpendLogEntry>, RepoError> {
        self.list_spend_log_tenant(DEFAULT_TENANT, policy_id, agent_id, limit)
            .await
    }

    /// Tenant-scoped variant of [`list_spend_log`].
    pub async fn list_spend_log_tenant(
        &self,
        tenant_id: &str,
        policy_id: &str,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<SpendLogEntry>, RepoError> {
        let limit = limit.clamp(1, 1000);
        match self {
            Repo::Sqlite(db) => {
                let conn = db
                    .lock_sqlite()
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut stmt = conn
                    .prepare(
                        "SELECT log_id, policy_id, agent_id, action_id, amount_usd, \
                         recorded_at, source FROM spend_log \
                         WHERE policy_id = ?1 AND agent_id = ?2 AND tenant_id = ?3 \
                         ORDER BY recorded_at DESC LIMIT ?4",
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![policy_id, agent_id, tenant_id, limit],
                        |r| {
                            Ok(SpendLogEntry {
                                log_id: r.get(0)?,
                                policy_id: r.get(1)?,
                                agent_id: r.get(2)?,
                                action_id: r.get(3)?,
                                amount_usd: r.get(4)?,
                                recorded_at: r.get(5)?,
                                source: r.get(6)?,
                            })
                        },
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row.map_err(|e| RepoError::Backend(e.to_string()))?);
                }
                Ok(out)
            }
            Repo::Postgres(pool) => {
                let rows: Vec<(String, String, String, Option<String>, f64, i64, String)> =
                    sqlx::query_as(
                        "SELECT log_id, policy_id, agent_id, action_id, amount_usd, \
                         recorded_at, source FROM spend_log \
                         WHERE policy_id = $1 AND agent_id = $2 AND tenant_id = $3 \
                         ORDER BY recorded_at DESC LIMIT $4",
                    )
                    .bind(policy_id)
                    .bind(agent_id)
                    .bind(tenant_id)
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(|e| RepoError::Backend(format!("pg spend log list: {e}")))?;
                Ok(rows
                    .into_iter()
                    .map(
                        |(
                            log_id,
                            policy_id,
                            agent_id,
                            action_id,
                            amount_usd,
                            recorded_at,
                            source,
                        )| {
                            SpendLogEntry {
                                log_id,
                                policy_id,
                                agent_id,
                                action_id,
                                amount_usd,
                                recorded_at,
                                source,
                            }
                        },
                    )
                    .collect())
            }
        }
    }
}

/// One row of `spend_log` returned by [`Repo::list_spend_log`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpendLogEntry {
    /// `splog_<hex>` identifier.
    pub log_id: String,
    /// Policy this spend was charged against.
    pub policy_id: String,
    /// Agent that recorded the spend.
    pub agent_id: String,
    /// Optional action id from the SDK side (free-form).
    pub action_id: Option<String>,
    /// USD amount (positive for spend, zero/negative tolerated for corrections
    /// via `record_spend_with_period`; the public HTTP route rejects negatives
    /// outright).
    pub amount_usd: f64,
    /// Unix-epoch seconds at which the spend was recorded.
    pub recorded_at: i64,
    /// `sdk_flush` or `server_recompute`.
    pub source: String,
}

/// Generate a 32-hex-char id without pulling in the `uuid` crate.
///
/// Combines high-resolution wall time with a per-call PID + nanosecond
/// scramble. Collision probability is negligible at the spend-ledger
/// volume we expect (<1 row/ms even under aggressive flushes).
fn uuid_like_hex() -> String {
    use sha2::{Digest, Sha256};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let counter = SPEND_LOG_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
    let mut h = Sha256::new();
    h.update(nanos.to_be_bytes());
    h.update(pid.to_be_bytes());
    h.update(counter.to_be_bytes());
    let hash = h.finalize();
    hex::encode(&hash[..16])
}

static SPEND_LOG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;

    /// Build a unique-path Repo::Sqlite for parallel test isolation.
    fn build_test_repo(test_name: &str) -> Repo {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path =
            std::env::temp_dir().join(format!("sauron-repo-test-{pid}-{nanos}-{test_name}.db"));
        // Ensure clean slate.
        let _ = std::fs::remove_file(&path);
        let handle = open_db_at(path.to_str().unwrap(), 2);
        Repo::Sqlite(Arc::new(handle))
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_repo_consume_call_nonce_first_use_succeeds() {
        let repo = build_test_repo("first_use_ok");
        rt().block_on(async {
            let r = repo
                .consume_call_nonce("agent-1", "nonce-abc", 9_999_999_999)
                .await;
            assert!(r.is_ok(), "first use must succeed: {r:?}");
        });
    }

    #[test]
    fn test_repo_consume_call_nonce_replay_rejected() {
        let repo = build_test_repo("replay_rejected");
        rt().block_on(async {
            repo.consume_call_nonce("agent-1", "nonce-xyz", 9_999_999_999)
                .await
                .expect("first insert ok");
            let r2 = repo
                .consume_call_nonce("agent-1", "nonce-xyz", 9_999_999_999)
                .await;
            match r2 {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay error, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_call_nonce_rejects_empty_nonce() {
        let repo = build_test_repo("empty_nonce");
        rt().block_on(async {
            let r = repo.consume_call_nonce("agent-1", "", 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("missing")),
                other => panic!("expected Backend missing-nonce, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_call_nonce_rejects_oversized_nonce() {
        let repo = build_test_repo("oversize_nonce");
        rt().block_on(async {
            let huge = "a".repeat(129);
            let r = repo.consume_call_nonce("agent-1", &huge, 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("too long")),
                other => panic!("expected Backend too-long, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_is_postgres_false_for_sqlite_backend() {
        let repo = build_test_repo("not_postgres");
        assert!(!repo.is_postgres());
    }

    // ─── M1 new helpers ───────────────────────────────────────────────────

    #[test]
    fn test_repo_consume_ajwt_jti_first_use_ok() {
        let repo = build_test_repo("ajwt_first_ok");
        rt().block_on(async {
            let r = repo.consume_ajwt_jti("jti-1", 9_999_999_999).await;
            assert!(r.is_ok(), "first jti claim ok: {r:?}");
        });
    }

    #[test]
    fn test_repo_consume_ajwt_jti_replay_rejected() {
        let repo = build_test_repo("ajwt_replay");
        rt().block_on(async {
            repo.consume_ajwt_jti("jti-replay", 9_999_999_999)
                .await
                .expect("first ok");
            let r = repo.consume_ajwt_jti("jti-replay", 9_999_999_999).await;
            match r {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_ajwt_jti_rejects_empty() {
        let repo = build_test_repo("ajwt_empty");
        rt().block_on(async {
            let r = repo.consume_ajwt_jti("", 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("missing")),
                other => panic!("expected Backend missing, got: {other:?}"),
            }
        });
    }

    // ─── M2: agent_pop_challenges ─────────────────────────────────────────

    #[test]
    fn test_repo_pop_insert_then_take_returns_challenge() {
        let repo = build_test_repo("pop_insert_take");
        rt().block_on(async {
            let exp = repo
                .insert_pop_challenge("pch_1", "agent-1", "chal-abc", 1_000, 300)
                .await
                .expect("insert ok");
            assert_eq!(exp, 1_300);
            let got = repo
                .take_pop_challenge("pch_1", "agent-1", 1_001)
                .await
                .expect("take ok");
            assert_eq!(got, "chal-abc");
        });
    }

    #[test]
    fn test_repo_pop_take_twice_replays() {
        let repo = build_test_repo("pop_take_twice");
        rt().block_on(async {
            repo.insert_pop_challenge("pch_2", "agent-1", "chal", 1_000, 300)
                .await
                .unwrap();
            repo.take_pop_challenge("pch_2", "agent-1", 1_001)
                .await
                .unwrap();
            match repo.take_pop_challenge("pch_2", "agent-1", 1_001).await {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay on second take, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_pop_take_wrong_agent_rejected() {
        let repo = build_test_repo("pop_take_wrong_agent");
        rt().block_on(async {
            repo.insert_pop_challenge("pch_3", "agent-A", "chal", 1_000, 300)
                .await
                .unwrap();
            match repo.take_pop_challenge("pch_3", "agent-B", 1_001).await {
                Err(RepoError::Replay(s)) => assert!(s.contains("match agent")),
                other => panic!("expected Replay match agent, got: {other:?}"),
            }
        });
    }

    // ─── M2: bank_attestation_nonces ──────────────────────────────────────

    // ─── M2: consent_log ──────────────────────────────────────────────────

    // ─── M2: agent_payment_authorizations ─────────────────────────────────

    #[test]
    fn test_repo_payment_auth_insert_then_consume_once() {
        let repo = build_test_repo("payauth_insert_consume");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "default",
                "payauth_1",
                "agent-1",
                "jti-1",
                1000,
                "EUR",
                "M1",
                "ref_1",
                1_000,
                9_999_999_999,
            )
            .await
            .expect("insert ok");
            repo.consume_payment_authorization("default", "payauth_1", 1_001)
                .await
                .expect("first consume ok");
        });
    }

    #[test]
    fn test_repo_payment_authorization_is_tenant_bound() {
        let repo = build_test_repo("payauth_tenant");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "victim",
                "payauth_tenant",
                "agent-1",
                "jti-tenant",
                1000,
                "EUR",
                "M1",
                "ref_tenant",
                1_000,
                9_999_999_999,
            )
            .await
            .unwrap();
            assert!(matches!(
                repo.consume_payment_authorization("attacker", "payauth_tenant", 1_001)
                    .await,
                Err(RepoError::Replay(_))
            ));
            assert!(repo
                .consume_payment_authorization("victim", "payauth_tenant", 1_001)
                .await
                .is_ok());
        });
    }

    /// Ownership, not just possession of the id. `/agent/payment/consume`
    /// authorises on this, so a wrong answer here lets one signed agent redeem
    /// another's authorization.
    #[test]
    fn test_repo_payment_authorization_agent_lookup_is_scoped() {
        let repo = build_test_repo("payauth_owner");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "default",
                "payauth_owner",
                "agent-owner",
                "jti-owner",
                1000,
                "EUR",
                "M1",
                "ref_owner",
                1_000,
                9_999_999_999,
            )
            .await
            .unwrap();
            assert_eq!(
                repo.payment_authorization_agent("default", "payauth_owner")
                    .await
                    .unwrap(),
                Some("agent-owner".to_string())
            );
            // Another tenant must not even learn that the row exists.
            assert_eq!(
                repo.payment_authorization_agent("other", "payauth_owner")
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                repo.payment_authorization_agent("default", "payauth_missing")
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn test_repo_payment_auth_double_consume_rejected() {
        let repo = build_test_repo("payauth_double");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "default",
                "payauth_2",
                "agent-1",
                "jti-2",
                1000,
                "EUR",
                "M1",
                "ref_2",
                1_000,
                9_999_999_999,
            )
            .await
            .unwrap();
            repo.consume_payment_authorization("default", "payauth_2", 1_001)
                .await
                .unwrap();
            match repo
                .consume_payment_authorization("default", "payauth_2", 1_001)
                .await
            {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_payment_auth_duplicate_insert_replays() {
        let repo = build_test_repo("payauth_dup_insert");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "default",
                "payauth_3",
                "agent-1",
                "jti-3",
                1000,
                "EUR",
                "M1",
                "ref_3",
                1_000,
                9_999_999_999,
            )
            .await
            .unwrap();
            match repo
                .insert_payment_authorization(
                    "default",
                    "payauth_3",
                    "agent-2",
                    "jti-3b",
                    2000,
                    "EUR",
                    "M1",
                    "ref_3b",
                    1_000,
                    9_999_999_999,
                )
                .await
            {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay on PK conflict, got: {other:?}"),
            }
        });
    }

    // ─── M3: credential_codes ─────────────────────────────────────────────

    fn seed_credential_code(repo: &Repo, key_image: &str) {
        if let Repo::Sqlite(db) = repo {
            let conn = db.lock_sqlite().unwrap();
            conn.execute(
                "INSERT INTO credential_codes (key_image_hex, pre_auth_code, subject_did, issued_at, claimed) \
                 VALUES (?1, 'pac_1', 'did:test:1', 1000, 0)",
                rusqlite::params![key_image],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_repo_credential_code_first_claim_wins() {
        let repo = build_test_repo("cred_first_claim");
        rt().block_on(async {
            seed_credential_code(&repo, "ki-A");
            assert!(repo.claim_credential_code("default", "ki-A").await.unwrap());
            assert!(
                !repo.claim_credential_code("default", "ki-A").await.unwrap(),
                "second claim must lose the race"
            );
        });
    }

    #[test]
    fn test_repo_credential_code_release_allows_retry() {
        let repo = build_test_repo("cred_release_retry");
        rt().block_on(async {
            seed_credential_code(&repo, "ki-B");
            assert!(repo.claim_credential_code("default", "ki-B").await.unwrap());
            repo.release_credential_code("default", "ki-B")
                .await
                .unwrap();
            assert!(
                repo.claim_credential_code("default", "ki-B").await.unwrap(),
                "after release, claim should succeed again"
            );
        });
    }

    #[test]
    fn test_repo_select_credential_code_returns_pair() {
        let repo = build_test_repo("cred_select_pair");
        rt().block_on(async {
            seed_credential_code(&repo, "ki-C");
            let row = repo
                .select_credential_code("default", "ki-C")
                .await
                .unwrap();
            let (pac, did) = row.expect("row present");
            assert_eq!(pac, "pac_1");
            assert_eq!(did, "did:test:1");
            assert!(repo
                .select_credential_code("default", "ki-missing")
                .await
                .unwrap()
                .is_none());
        });
    }

    // ─── M3: users + user_credentials + user_registrations ────────────────

    #[test]
    fn test_repo_users_upsert_idempotent() {
        let repo = build_test_repo("users_upsert");
        rt().block_on(async {
            assert!(!repo.user_exists("ki-1").await.unwrap());
            repo.upsert_user("ki-1", "pk", "A", "B", "a@b.c", "1990-01-01", "FR")
                .await
                .unwrap();
            assert!(repo.user_exists("ki-1").await.unwrap());
            // Upsert with new last_name overrides.
            repo.upsert_user("ki-1", "pk", "A", "Z", "a@b.c", "1990-01-01", "FR")
                .await
                .unwrap();
            assert!(repo.user_exists("ki-1").await.unwrap());
        });
    }

    #[test]
    fn test_repo_user_credential_upsert_and_select() {
        let repo = build_test_repo("ucred_upsert_sel");
        rt().block_on(async {
            assert!(repo
                .select_user_credential("default", "ki-2")
                .await
                .unwrap()
                .is_none());
            repo.upsert_user_credential("default", "ki-2", "{\"v\":1}", 1_000)
                .await
                .unwrap();
            assert_eq!(
                repo.select_user_credential("default", "ki-2")
                    .await
                    .unwrap(),
                Some("{\"v\":1}".to_string())
            );
        });
    }

    #[test]
    fn test_repo_user_credential_is_tenant_bound() {
        let repo = build_test_repo("user_cred_tenant");
        rt().block_on(async {
            repo.upsert_user_credential("victim", "ki-shared", "{\"v\":1}", 1_000)
                .await
                .unwrap();
            assert!(repo
                .select_user_credential("attacker", "ki-shared")
                .await
                .unwrap()
                .is_none());
            assert!(repo
                .upsert_user_credential("attacker", "ki-shared", "{\"v\":2}", 2_000)
                .await
                .is_err());
            assert_eq!(
                repo.select_user_credential("victim", "ki-shared")
                    .await
                    .unwrap(),
                Some("{\"v\":1}".into())
            );
        });
    }

    #[test]
    fn test_repo_user_registration_insert_idempotent() {
        let repo = build_test_repo("ureg_idem");
        rt().block_on(async {
            repo.insert_user_registration("default", "bank-A", "ki-3", "bank_webhook", 1_000)
                .await
                .unwrap();
            // Same triple must be silently ignored, not error.
            repo.insert_user_registration("default", "bank-A", "ki-3", "bank_webhook", 2_000)
                .await
                .unwrap();
        });
    }

    // ─── M3: merkle_leaves ────────────────────────────────────────────────

    // ─── M4: anchor tables ────────────────────────────────────────────────

    // ─── M4: agent_action_receipts ────────────────────────────────────────

    // ─── Sprint 3+: spend ledger ──────────────────────────────────────────

    #[test]
    fn test_repo_spend_record_increments_ledger() {
        let repo = build_test_repo("spend_record_inc");
        rt().block_on(async {
            let id = repo
                .record_spend("pol_A", "agent-1", Some("act-1"), 10.0, "sdk_flush", 100)
                .await
                .expect("record ok");
            assert!(id.starts_with("splog_"), "log id prefix: {id}");
            let total = repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap();
            assert!((total - 10.0).abs() < 1e-9, "total = {total}");

            repo.record_spend("pol_A", "agent-1", None, 2.5, "sdk_flush", 101)
                .await
                .unwrap();
            let total2 = repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap();
            assert!((total2 - 12.5).abs() < 1e-9, "total2 = {total2}");

            let log = repo.list_spend_log("pol_A", "agent-1", 100).await.unwrap();
            assert_eq!(log.len(), 2, "two log rows present");
            // Newest first by recorded_at DESC.
            assert!(log[0].recorded_at >= log[1].recorded_at);
        });
    }

    #[test]
    fn test_repo_spend_record_isolates_by_policy_agent_period() {
        let repo = build_test_repo("spend_iso");
        rt().block_on(async {
            repo.record_spend("pol_A", "agent-1", None, 5.0, "sdk_flush", 100)
                .await
                .unwrap();
            repo.record_spend("pol_A", "agent-2", None, 7.0, "sdk_flush", 100)
                .await
                .unwrap();
            repo.record_spend("pol_B", "agent-1", None, 11.0, "sdk_flush", 100)
                .await
                .unwrap();
            assert_eq!(
                repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap(),
                5.0
            );
            assert_eq!(
                repo.get_spend_total("pol_A", "agent-2", 0).await.unwrap(),
                7.0
            );
            assert_eq!(
                repo.get_spend_total("pol_B", "agent-1", 0).await.unwrap(),
                11.0
            );
            // Unknown lookup -> 0.
            assert_eq!(
                repo.get_spend_total("pol_X", "agent-X", 0).await.unwrap(),
                0.0
            );
        });
    }

    #[test]
    fn test_repo_spend_get_total_aggregates_periods_separately() {
        let repo = build_test_repo("spend_periods");
        rt().block_on(async {
            // Lifetime + per-day periods are independent rows under the PK.
            repo.record_spend_with_period("pol_A", "agent-1", None, 4.0, "sdk_flush", 0, 100)
                .await
                .unwrap();
            repo.record_spend_with_period(
                "pol_A",
                "agent-1",
                None,
                9.0,
                "sdk_flush",
                1_700_000_000,
                1_700_000_500,
            )
            .await
            .unwrap();
            assert_eq!(
                repo.get_spend_total("pol_A", "agent-1", 0).await.unwrap(),
                4.0
            );
            assert_eq!(
                repo.get_spend_total("pol_A", "agent-1", 1_700_000_000)
                    .await
                    .unwrap(),
                9.0
            );
        });
    }

    #[test]
    fn test_repo_spend_rejects_non_finite_amount() {
        let repo = build_test_repo("spend_nan");
        rt().block_on(async {
            match repo
                .record_spend("pol_A", "agent-1", None, f64::NAN, "sdk_flush", 100)
                .await
            {
                Err(RepoError::Backend(s)) => assert!(s.contains("finite")),
                other => panic!("expected finite-amount error, got: {other:?}"),
            }
            match repo
                .record_spend("pol_A", "agent-1", None, f64::INFINITY, "sdk_flush", 100)
                .await
            {
                Err(RepoError::Backend(s)) => assert!(s.contains("finite")),
                other => panic!("expected finite-amount error, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_spend_rejects_unknown_source() {
        let repo = build_test_repo("spend_bad_source");
        rt().block_on(async {
            match repo
                .record_spend("pol_A", "agent-1", None, 1.0, "bogus", 100)
                .await
            {
                Err(RepoError::Backend(s)) => assert!(s.contains("source")),
                other => panic!("expected unknown-source error, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_spend_list_clamps_limit() {
        let repo = build_test_repo("spend_list_limit");
        rt().block_on(async {
            for i in 0..5 {
                repo.record_spend("pol_A", "agent-1", None, 1.0, "sdk_flush", 100 + i)
                    .await
                    .unwrap();
            }
            let rows = repo.list_spend_log("pol_A", "agent-1", 2).await.unwrap();
            assert_eq!(rows.len(), 2, "limit honoured");

            // Over-cap limit clamps to 1000 (we only have 5 rows; just assert it doesn't error).
            let rows = repo
                .list_spend_log("pol_A", "agent-1", 1_000_000)
                .await
                .unwrap();
            assert_eq!(rows.len(), 5);
        });
    }
}
