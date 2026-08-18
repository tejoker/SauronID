//! How much of the core can actually reach Postgres. Measured, not estimated.
//!
//! ## What this used to measure, and why it changed
//!
//! Before the call-site sweep there was exactly one function that could
//! construct `AnyConn::Postgres` — `DbHandle::any()` — and it had **zero
//! callers**, verified by renaming it and watching nothing fail to compile.
//! Everything else got its `AnyConn` from `impl AsAnyConn for
//! rusqlite::Connection`, which hard-returns `AnyConn::Sqlite` whatever the
//! configuration says:
//!
//! ```ignore
//! let db = st.db.lock().unwrap();
//! db.any_conn().query_row(..);   // read as portable; always SQLite
//! ```
//!
//! So the old measure was "statements written in the portable idiom but pinned
//! to SQLite", counted by grepping `any_conn()`. That number is now
//! meaningless in the other direction: `DbHandle::lock()` returns a `DbConn`,
//! and `DbConn::any_conn()` dispatches, so the *same* grep now counts mostly
//! portable statements. A count that means opposite things before and after the
//! change it is supposed to track is worse than no count.
//!
//! ## What it measures now
//!
//! The sweep inverted the default: dispatching is what you get, and staying on
//! SQLite is what you have to ask for, by name, via `DbHandle::lock_sqlite()`.
//! So the honest measure of "cannot reach Postgres" is that opt-out, and it is
//! small enough to enumerate rather than count. Each entry below is a claim
//! that the code there does not work on Postgres and is not meant to.
//!
//! These tests exist so the figure in `docs/production-readiness.md` comes from
//! the build rather than from reading, and so re-pinning a call site forces the
//! claim to move with the code.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Files allowed to opt out of dispatch, and why.
///
/// `repository.rs` dominates the count and is not a gap: `Repo` is an older,
/// separate dual-backend split whose `Repo::Sqlite(db)` arms are the SQLite
/// half of a two-armed match, with sqlx Postgres code in the other half. Both
/// arms are chosen from the same `SAURON_DB_BACKEND`, so a `Repo::Sqlite` arm
/// only ever runs when there is no Postgres pool at all. Making those dispatch
/// would give Postgres two independent routes to one table.
///
/// Update together with the figure in docs/production-readiness.md.
const SQLITE_ONLY: &[(&str, usize, &str)] = &[
    (
        "repository.rs",
        34,
        "the SQLite half of Repo's own backend match; the Postgres half is sqlx",
    ),
    (
        "db.rs",
        2,
        "the dispatcher itself — it has to be able to name the SQLite pool",
    ),
    (
        "audit/store.rs",
        1,
        "ensure_audit_reports_schema; Postgres takes this table from migrations/postgres/0008",
    ),
    (
        "middleware/audit_log.rs",
        1,
        "ensure_security_audit_schema; Postgres takes this table from migrations/postgres/0007+0014",
    ),
];

fn core_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("readable dir") {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `lock_sqlite()` uses in production code, per file.
///
/// Test modules are excluded: a fixture asserting on the SQLite database it
/// just created is not a deployment that cannot use Postgres. Comments are
/// stripped first — this counts call sites, and the doc comments explaining why
/// a site is SQLite-only name the function too. Counting those made adding an
/// explanation look like adding an opt-out.
fn sqlite_only_sites() -> BTreeMap<String, usize> {
    let mut files = Vec::new();
    rust_files(&core_src(), &mut files);
    assert!(!files.is_empty(), "no sources under core/src");

    let mut by_file = BTreeMap::new();
    for f in files {
        let src = std::fs::read_to_string(&f).expect("readable source");
        let body = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src[..],
        };
        let code: String = body
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let n = code.matches("lock_sqlite()").count();
        if n > 0 {
            by_file.insert(
                f.strip_prefix(core_src())
                    .unwrap_or(&f)
                    .to_string_lossy()
                    .to_string(),
                n,
            );
        }
    }
    by_file
}

#[test]
fn the_sqlite_only_opt_outs_are_exactly_the_documented_ones() {
    let found = sqlite_only_sites();
    let expected: BTreeMap<String, usize> = SQLITE_ONLY
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), *n))
        .collect();

    if found != expected {
        let mut report = String::new();
        for (file, n) in &found {
            match expected.get(file) {
                Some(e) if e == n => {}
                Some(e) => report.push_str(&format!("    {file}: {n} (documented {e})\n")),
                None => report.push_str(&format!("    {file}: {n} (NOT documented)\n")),
            }
        }
        for file in expected.keys() {
            if !found.contains_key(file) {
                report.push_str(&format!("    {file}: 0 (documented, now gone)\n"));
            }
        }
        panic!(
            "the set of SQLite-only opt-outs moved:\n{report}\n\
             Every `lock_sqlite()` asserts \"this does not work on Postgres and is \
             not meant to\". Adding one is a deliberate act: record it in \
             SQLITE_ONLY with the reason, and update the figure in \
             docs/production-readiness.md in the same commit. Removing one is the \
             port progressing — do the same."
        );
    }
}

#[test]
fn acquisition_dispatches_by_default() {
    // The inversion the sweep is: `lock()` — what ~92 call sites call — hands
    // back the dispatching guard, so a call site reaches Postgres by doing
    // nothing special. If this ever goes back to returning a SQLite connection,
    // every one of those sites silently re-pins and the count above still reads
    // zero, because they are not spelled `lock_sqlite()`.
    let db = std::fs::read_to_string(core_src().join("db.rs")).expect("db.rs");
    let lock = db
        .find("pub fn lock(&self)")
        .expect("DbHandle::lock is gone; the whole sweep routes through it");
    let body = &db[lock..(lock + 200).min(db.len())];
    assert!(
        body.contains("self.conn()"),
        "DbHandle::lock no longer delegates to conn(). It is the single point \
         that made the port atomic; re-pinning it silently un-ports every call \
         site. Got:\n{body}"
    );
    assert!(
        db.contains("pub fn conn(&self)"),
        "the dispatching constructor is gone"
    );
    assert!(
        db.contains("pub enum DbConn"),
        "the dispatching guard is gone"
    );
    assert!(
        db.contains("pub fn any<T>"),
        "DbHandle::any is gone — still the right shape for an async call site"
    );
}

#[test]
fn the_pinned_form_still_cannot_reach_postgres() {
    // `AsAnyConn for rusqlite::Connection` is what made the portable idiom read
    // as backend-agnostic while being SQLite. It is still SQLite-only, and that
    // is correct: what it borrows really is a rusqlite connection. What changed
    // is that call sites no longer obtain one — they hold a `DbConn`.
    let src = std::fs::read_to_string(core_src().join("any_db.rs")).expect("any_db.rs");
    let start = src
        .find("impl AsAnyConn for rusqlite::Connection")
        .expect("AsAnyConn impl moved; re-check what any_conn() dispatches on");
    let body = &src[start..(start + 220).min(src.len())];
    assert!(
        body.contains("AnyConn::Sqlite"),
        "AsAnyConn for rusqlite::Connection no longer hard-returns Sqlite; if it \
         dispatches now, this file needs re-deriving from scratch."
    );
}

#[test]
fn nothing_outside_db_rs_constructs_a_postgres_connection() {
    // A call site that built its own would be a dispatch path nobody counts.
    let mut files = Vec::new();
    rust_files(&core_src(), &mut files);
    let stray: Vec<String> = files
        .iter()
        .filter(|f| f.file_name().unwrap() != "db.rs" && f.file_name().unwrap() != "any_db.rs")
        .filter(|f| {
            std::fs::read_to_string(f)
                .unwrap_or_default()
                .contains("AnyConn::Postgres(&mut")
        })
        .map(|f| f.to_string_lossy().to_string())
        .collect();
    assert!(
        stray.is_empty(),
        "AnyConn::Postgres constructed outside db.rs, so Postgres reach is no \
         longer a property of one file: {stray:?}"
    );
}

#[test]
fn blocking_postgres_calls_are_confined_to_any_db() {
    // The synchronous `postgres` driver drives a private Tokio runtime with
    // `block_on`, which panics on a thread already running tasks — and every
    // call site is inside an async handler. `any_db::blocking` is the guard.
    // If a Postgres call appears anywhere else, it is a panic waiting for the
    // first request that reaches it.
    let any_db = std::fs::read_to_string(core_src().join("any_db.rs")).expect("any_db.rs");
    assert!(
        any_db.contains("block_in_place"),
        "any_db no longer defers blocking Postgres calls; async handlers will panic"
    );
    let db = std::fs::read_to_string(core_src().join("db.rs")).expect("db.rs");
    for needed in ["impl Drop for DbConn", "impl Drop for DbHandle"] {
        assert!(
            db.contains(needed),
            "{needed} is gone — releasing a Postgres client closes it, and \
             closing blocks, so the drop has to run where blocking is allowed"
        );
    }
}

#[test]
fn every_upsert_names_its_conflict_target() {
    // `sql_translate` rewrites `INSERT OR REPLACE` only when the statement
    // already carries an explicit `ON CONFLICT`; the bare form is left untouched
    // on purpose, so that Postgres rejects it rather than the translator
    // guessing an upsert key and silently changing what a rollback undoes.
    //
    // The consequence is that a bare `INSERT OR REPLACE` is a syntax error under
    // SAURON_DB_BACKEND=postgres — "syntax error at or near OR" — at whatever
    // moment that code path first runs. Two shipped in the port: the
    // bank_kyc_links link in `/bank/register`, and the agents seed in
    // `/dev/leash/demo`. Neither was covered by the empirical suite, because the
    // bank flow was flag-gated off and the dev route is not mounted in prod.
    // `/bank/register` has since been deleted with the rest of the banking
    // surface; the check stays, because the class of bug is not specific to it.
    //
    // Grep found them once. This keeps them found.
    let mut files = Vec::new();
    rust_files(&core_src(), &mut files);

    let mut bare = Vec::new();
    for f in files {
        if f.file_name().unwrap() == "sql_translate.rs" {
            continue; // its own fixtures are the bare form, deliberately
        }
        let src = std::fs::read_to_string(&f).expect("readable source");
        for (off, _) in src.match_indices("INSERT OR REPLACE INTO") {
            // The conflict clause follows within the same statement; 1600 chars
            // clears the longest column list in the tree with room to spare.
            let window = &src[off..(off + 1600).min(src.len())];
            if !window.contains("ON CONFLICT") {
                let line = src[..off].matches('\n').count() + 1;
                bare.push(format!("{}:{}", f.display(), line));
            }
        }
    }

    assert!(
        bare.is_empty(),
        "INSERT OR REPLACE without an explicit ON CONFLICT target is valid \
         SQLite and a syntax error on Postgres. Give each one a conflict target \
         and the update list that reproduces replace semantics:\n  {}",
        bare.join("\n  ")
    );
}
