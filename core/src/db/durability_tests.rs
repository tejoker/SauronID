//! Extracted verbatim from the inline `mod durability_tests` that `db.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

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
