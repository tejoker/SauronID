//! The same Rust code, the same SQL, both backends — identical results.
//!
//! `sql_translate`'s unit tests pin the text of each rewrite and
//! `sql_translation_differential.py` pins that the rewritten SQL returns the
//! same rows. This pins the layer the call sites will actually use: bind a
//! parameter through `SqlValue`, read a column through `AnyRow`, and get the
//! same answer whichever backend is underneath.
//!
//! Skipped unless SAURON_TEST_PG_URL is set, so the default `cargo test` run
//! needs no database.

use sauron_core::any_db::{AnyConn, SqlValue};
use sauron_core::sql_params;

// `legacy_seq` is nullable on purpose: it models `agent_action_receipts.seq`,
// which is NULL for rows written before the receipt chain existed. See the
// ordering scenario in `exercise`.
const DDL_SQLITE: &str = "CREATE TABLE t (
    id TEXT PRIMARY KEY NOT NULL,
    tenant TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    legacy_seq INTEGER,
    flag INTEGER NOT NULL DEFAULT 0,
    amount REAL NOT NULL DEFAULT 0,
    note TEXT
)";
const DDL_PG: &str = "CREATE TABLE t (
    id TEXT PRIMARY KEY NOT NULL,
    tenant TEXT NOT NULL,
    seq BIGINT NOT NULL DEFAULT 0,
    legacy_seq BIGINT,
    flag BIGINT NOT NULL DEFAULT 0,
    amount DOUBLE PRECISION NOT NULL DEFAULT 0,
    note TEXT
)";

/// One scenario, run against whatever connection it is handed. Written once so
/// the two backends cannot drift by accident.
fn exercise(conn: &mut AnyConn<'_>) -> Vec<String> {
    let mut out = Vec::new();

    conn.execute(
        "INSERT INTO t (id, tenant, seq, flag, amount, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        sql_params!["a", "default", 1i64, true, 1.5f64, "first"],
    )
    .expect("insert a");

    // NULL through the same binding path.
    conn.execute(
        "INSERT INTO t (id, tenant, seq, flag, amount, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            SqlValue::from("b"),
            SqlValue::from("default"),
            SqlValue::from(2i64),
            SqlValue::from(false),
            SqlValue::from(2.5f64),
            SqlValue::Null,
        ],
    )
    .expect("insert b");

    // Duplicate key must be dropped, not error, on both.
    let ignored = conn
        .execute(
            "INSERT OR IGNORE INTO t (id, tenant, seq, flag, amount, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            sql_params!["a", "default", 99i64, true, 9.0f64, "dupe"],
        )
        .expect("insert or ignore");
    out.push(format!("rows_from_ignored_duplicate={ignored}"));

    let one = conn
        .query_row(
            "SELECT id, seq, flag, amount, note FROM t WHERE id = ?1",
            sql_params!["a"],
            |r| {
                Ok(format!(
                    "id={} seq={} flag={} amount={} note={:?}",
                    r.get_string(0)?,
                    r.get_i64(1)?,
                    r.get_bool(2)?,
                    r.get_f64(3)?,
                    r.get_opt_string(4)?
                ))
            },
        )
        .expect("query_row a")
        .expect("row a exists");
    out.push(one);

    let null_note = conn
        .query_row("SELECT note FROM t WHERE id = ?1", sql_params!["b"], |r| {
            Ok(format!("note={:?}", r.get_opt_string(0)?))
        })
        .expect("query_row b")
        .expect("row b exists");
    out.push(null_note);

    // Missing row is None, not an error.
    let missing = conn
        .query_row("SELECT id FROM t WHERE id = ?1", sql_params!["nope"], |r| {
            r.get_string(0)
        })
        .expect("query_row missing");
    out.push(format!("missing_is_none={}", missing.is_none()));

    let listed = conn
        .query_map(
            "SELECT id, IFNULL(seq, 0) FROM t WHERE tenant = ?1 ORDER BY seq ASC",
            sql_params!["default"],
            |r| Ok(format!("{}:{}", r.get_string(0)?, r.get_i64(1)?)),
        )
        .expect("query_map");
    out.push(listed.join(","));

    let affected = conn
        .execute(
            "UPDATE t SET note = ?1 WHERE id = ?2",
            sql_params!["edited", "a"],
        )
        .expect("update");
    out.push(format!("updated={affected}"));

    // Picking a chain head over a column that is NULL on legacy rows.
    //
    // `ORDER BY legacy_seq DESC` does NOT mean the same thing on both backends:
    // SQLite sorts NULLs first ascending, so they land LAST descending, while
    // PostgreSQL defaults to NULLS FIRST for DESC and would return the legacy
    // row as the head. Coalescing in the ORDER BY removes the difference rather
    // than depending on either engine's default, and coalescing in the SELECT
    // keeps a NULL from reaching a typed getter, which is an error.
    //
    // This is the exact shape of `agent_action::next_chain_position_any`, where
    // getting it wrong would either restart a tenant's receipt chain at seq 1 or
    // fail every write on a database holding pre-chain receipts.
    conn.execute(
        "INSERT INTO t (id, tenant, legacy_seq, note) VALUES (?1, ?2, ?3, ?4)",
        &[
            SqlValue::from("legacy"),
            SqlValue::from("chain"),
            SqlValue::Null,
            SqlValue::from("pre-chain row"),
        ],
    )
    .expect("insert legacy");
    conn.execute(
        "INSERT INTO t (id, tenant, legacy_seq, note) VALUES (?1, ?2, ?3, ?4)",
        sql_params!["chained", "chain", 5i64, "chained row"],
    )
    .expect("insert chained");

    let head = conn
        .query_row(
            "SELECT id, IFNULL(legacy_seq, 0) FROM t WHERE tenant = ?1
             ORDER BY IFNULL(legacy_seq, 0) DESC LIMIT 1",
            sql_params!["chain"],
            |r| Ok(format!("{}@{}", r.get_string(0)?, r.get_i64(1)?)),
        )
        .expect("query_row chain head")
        .expect("chain head exists");
    out.push(format!("chain_head={head}"));

    // And the coalesced NULL reads as 0 rather than erroring.
    let legacy = conn
        .query_row(
            "SELECT IFNULL(legacy_seq, 0) FROM t WHERE id = ?1",
            sql_params!["legacy"],
            |r| r.get_i64(0),
        )
        .expect("query_row legacy")
        .expect("legacy row exists");
    out.push(format!("legacy_seq_coalesced={legacy}"));

    out
}

#[test]
fn sqlite_and_postgres_agree_through_the_same_code() {
    let sqlite = rusqlite::Connection::open_in_memory().expect("sqlite");
    sqlite.execute_batch(DDL_SQLITE).expect("sqlite ddl");
    let sqlite_out = exercise(&mut AnyConn::Sqlite(&sqlite));

    let Ok(url) = std::env::var("SAURON_TEST_PG_URL") else {
        eprintln!("SAURON_TEST_PG_URL unset — SQLite half only");
        assert!(!sqlite_out.is_empty());
        return;
    };

    let mut client =
        postgres::Client::connect(&url, postgres::NoTls).expect("connect to test postgres");
    client
        .batch_execute("DROP TABLE IF EXISTS t")
        .expect("drop");
    client.batch_execute(DDL_PG).expect("pg ddl");
    let pg_out = exercise(&mut AnyConn::Postgres(&mut client));

    assert_eq!(
        sqlite_out, pg_out,
        "the same code produced different results per backend"
    );
}
