//! Does the `AnyConn` idiom return exactly what `Repo` returns?
//!
//! `Repo` and `AnyConn` are the two database layers this codebase carries. The
//! plan is to retire `Repo`'s non-transactional half by moving those call sites
//! onto `AnyConn`, which already speaks both dialects through `sql_translate`.
//! That plan is only safe if the two layers agree on every row, and "they look
//! like the same query" is not evidence.
//!
//! So this runs both against the SAME database and asserts equality. It is the
//! gate on the port, not a description of it: while it passes, moving a call
//! site is a mechanical change with a proof behind it; if it ever fails, the
//! method it names is not portable and belongs with the six transactional ones.
//!
//! Deliberately NOT covered here: `consume_call_nonce`, `consume_ajwt_jti`,
//! `consume_payment_authorization`, `take_pop_challenge`,
//! `insert_pop_challenge` and `record_spend_with_period`. Those do not differ
//! by dialect — they differ by CONCURRENCY STRATEGY. Postgres uses
//! `SERIALIZABLE` plus `SELECT … FOR UPDATE` row locks with a 40001 retry;
//! SQLite uses a coarse `BEGIN IMMEDIATE` writer lock. `AnyConn::transaction()`
//! issues a plain `BEGIN`, which is READ COMMITTED on Postgres with no retry
//! and no row locking, and `sql_translate` cannot emit `FOR UPDATE` at all.
//! Porting them onto `AnyConn` as it stands would silently downgrade the
//! atomic single-use guarantee behind attacks A2, A3 and A11 — it would
//! compile, and most tests would still pass. They stay in `Repo` until
//! `AnyConn` grows an equivalent primitive.

use sauron_core::repository::Repo;
use sauron_core::sql_params;
use std::sync::Arc;

/// A fresh SQLite-backed handle plus a `Repo` sharing it, so both layers read
/// and write one database and any disagreement is theirs, not the fixture's.
fn fixture() -> (Arc<sauron_core::db::DbHandle>, Repo, std::path::PathBuf) {
    let dir = std::env::temp_dir().join("sauron_repo_equiv");
    let _ = std::fs::create_dir_all(&dir);
    // A per-test file passed DIRECTLY to `open_db_at`, not through
    // `DATABASE_PATH`. `#[tokio::test]` runs these in parallel threads of one
    // process, and an env var is process-global: setting it per test let one
    // test's rows show up in another's COUNT(*) and made the count assertions
    // fail in whichever order the scheduler picked.
    let path = dir.join(format!(
        "equiv-{}-{:?}.db",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let db = Arc::new(sauron_core::db::open_db_at(
        path.to_str().expect("utf-8 path"),
        4,
    ));
    let repo = Repo::Sqlite(Arc::clone(&db));
    (db, repo, path)
}

fn seed_user(db: &Arc<sauron_core::db::DbHandle>, ki: &str, pk: &str, email: &str) {
    let mut c = db.lock().expect("conn");
    c.any_conn()
        .execute(
            "INSERT OR REPLACE INTO users \
             (key_image_hex, public_key_hex, first_name, last_name, email, date_of_birth, nationality) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            sql_params![&ki, &pk, &"Ada", &"Lovelace", &email, &"1815-12-10", &"GBR"],
        )
        .expect("seed user");
}

#[tokio::test]
async fn get_user_agrees() {
    let (db, repo, _p) = fixture();
    seed_user(&db, "ki_get", "pk_get", "ada@example.test");

    let via_repo = repo.get_user("ki_get").await.expect("repo").expect("row");

    let via_anyconn = {
        let mut c = db.lock().expect("conn");
        c.any_conn()
            .query_row(
                "SELECT public_key_hex, first_name, last_name, email, date_of_birth, nationality \
                 FROM users WHERE key_image_hex = ?1",
                sql_params![&"ki_get"],
                |r| {
                    Ok((
                        r.get_string(0)?,
                        r.get_string(1)?,
                        r.get_string(2)?,
                        r.get_string(3)?,
                        r.get_string(4)?,
                        r.get_string(5)?,
                    ))
                },
            )
            .expect("anyconn")
            .expect("row")
    };

    assert_eq!(via_repo.public_key_hex, via_anyconn.0);
    assert_eq!(via_repo.first_name, via_anyconn.1);
    assert_eq!(via_repo.last_name, via_anyconn.2);
    assert_eq!(via_repo.email, via_anyconn.3);
    assert_eq!(via_repo.date_of_birth, via_anyconn.4);
    assert_eq!(via_repo.nationality, via_anyconn.5);
}

#[tokio::test]
async fn get_user_agrees_on_the_missing_row() {
    // The interesting half: `Ok(None)` and not an error, from both layers.
    let (db, repo, _p) = fixture();
    assert!(repo.get_user("absent").await.expect("repo").is_none());
    let mut c = db.lock().expect("conn");
    let row = c
        .any_conn()
        .query_row(
            "SELECT public_key_hex FROM users WHERE key_image_hex = ?1",
            sql_params![&"absent"],
            |r| r.get_string(0),
        )
        .expect("anyconn");
    assert!(row.is_none(), "both layers report absence as Ok(None)");
}

#[tokio::test]
async fn user_exists_agrees() {
    let (db, repo, _p) = fixture();
    seed_user(&db, "ki_ex", "pk_ex", "ex@example.test");

    for (ki, expected) in [("ki_ex", true), ("nope", false)] {
        let via_repo = repo.user_exists(ki).await.expect("repo");
        let via_anyconn = {
            let mut c = db.lock().expect("conn");
            c.any_conn()
                .query_row(
                    "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
                    sql_params![&ki],
                    |r| r.get_i64(0),
                )
                .expect("anyconn")
                .unwrap_or(0)
                > 0
        };
        assert_eq!(via_repo, expected, "repo disagrees with the fixture");
        assert_eq!(
            via_anyconn, via_repo,
            "AnyConn disagrees with Repo for {ki}"
        );
    }
}

#[tokio::test]
async fn count_users_agrees() {
    let (db, repo, _p) = fixture();
    for i in 0..3 {
        seed_user(
            &db,
            &format!("ki_c{i}"),
            &format!("pk_c{i}"),
            "c@example.test",
        );
    }
    let via_repo = repo.count_users().await.expect("repo");
    let via_anyconn = {
        let mut c = db.lock().expect("conn");
        c.any_conn()
            .query_row("SELECT COUNT(*) FROM users", sql_params![], |r| {
                r.get_i64(0)
            })
            .expect("anyconn")
            .unwrap_or(0)
    };
    assert_eq!(via_repo, 3, "fixture seeded three users");
    assert_eq!(via_anyconn, via_repo);
}

#[tokio::test]
async fn all_user_pubkeys_agrees_including_order() {
    // Order matters: the caller feeds these into a ring group, and a different
    // order is a different ring.
    let (db, repo, _p) = fixture();
    for i in 0..4 {
        seed_user(
            &db,
            &format!("ki_p{i}"),
            &format!("pk_p{i}"),
            "p@example.test",
        );
    }
    let via_repo = repo.all_user_pubkeys().await.expect("repo");
    let via_anyconn = {
        let mut c = db.lock().expect("conn");
        c.any_conn()
            .query_map("SELECT public_key_hex FROM users", sql_params![], |r| {
                r.get_string(0)
            })
            .expect("anyconn")
    };
    assert_eq!(via_repo.len(), 4);
    assert_eq!(via_anyconn, via_repo, "same rows in the same order");
}

#[tokio::test]
async fn upsert_user_then_both_layers_read_it_back_identically() {
    // Write through Repo, read through both. Catches a write that lands in a
    // shape only its own reader understands.
    let (db, repo, _p) = fixture();
    repo.upsert_user(
        "ki_up",
        "pk_up",
        "Grace",
        "Hopper",
        "grace@example.test",
        "1906-12-09",
        "USA",
    )
    .await
    .expect("repo upsert");

    let via_repo = repo.get_user("ki_up").await.expect("repo").expect("row");
    let via_anyconn = {
        let mut c = db.lock().expect("conn");
        c.any_conn()
            .query_row(
                "SELECT public_key_hex, first_name, nationality FROM users \
                 WHERE key_image_hex = ?1",
                sql_params![&"ki_up"],
                |r| Ok((r.get_string(0)?, r.get_string(1)?, r.get_string(2)?)),
            )
            .expect("anyconn")
            .expect("row")
    };
    assert_eq!(via_anyconn.0, via_repo.public_key_hex);
    assert_eq!(via_anyconn.1, via_repo.first_name);
    assert_eq!(via_anyconn.2, via_repo.nationality);

    // And upsert is idempotent through both readers.
    repo.upsert_user(
        "ki_up",
        "pk_up2",
        "Grace",
        "Hopper",
        "grace@example.test",
        "1906-12-09",
        "USA",
    )
    .await
    .expect("repo re-upsert");
    assert_eq!(
        repo.count_users().await.expect("repo"),
        1,
        "upsert, not insert"
    );
}

#[tokio::test]
async fn insert_user_registration_is_idempotent_through_both_layers() {
    // The dialect case: Repo's SQLite arm writes `INSERT OR IGNORE`, its
    // Postgres arm writes `ON CONFLICT DO NOTHING` by hand, and
    // `sql_translate::rewrite_insert_or` turns the former into the latter. So a
    // ported call site can write the SQLite form and get identical behaviour.
    let (db, repo, _p) = fixture();
    for _ in 0..2 {
        repo.insert_user_registration("default", "client_a", "ki_reg", "test", 1_700_000_000)
            .await
            .expect("repo insert_user_registration");
    }
    let rows = {
        let mut c = db.lock().expect("conn");
        c.any_conn()
            .query_row(
                "SELECT COUNT(*) FROM user_registrations WHERE user_key_image_hex = ?1",
                sql_params![&"ki_reg"],
                |r| r.get_i64(0),
            )
            .expect("anyconn")
            .unwrap_or(0)
    };
    assert_eq!(rows, 1, "second insert ignored, not duplicated");

    // Pin the rewrite itself, so this stays true if someone edits the translator.
    let translated = sauron_core::sql_translate::to_postgres(
        "INSERT OR IGNORE INTO user_registrations (a) VALUES (?1)",
    );
    assert!(
        translated.contains("ON CONFLICT DO NOTHING"),
        "the SQLite form a ported site writes must still translate: {translated}"
    );
    assert!(
        !translated.contains("OR IGNORE"),
        "translated: {translated}"
    );
}
