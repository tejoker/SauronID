//! How much of the core can actually reach Postgres. Measured, not estimated.
//!
//! `SAURON_DB_BACKEND=postgres` builds a Postgres pool, and ~189 statements are
//! written in the portable `AnyConn` idiom against a dialect translator that
//! handles both engines. It is easy to read that as "mostly ported". It is not.
//!
//! There is exactly one function that can construct `AnyConn::Postgres`:
//! `DbHandle::any()`. Everything else obtains its `AnyConn` from
//! `impl AsAnyConn for rusqlite::Connection`, which hard-returns
//! `AnyConn::Sqlite` whatever the configuration says:
//!
//! ```ignore
//! st.db.any(|conn| conn.query_row(..))?;   // dispatches
//!
//! let db = st.db.lock().unwrap();
//! db.any_conn().query_row(..)?;            // never dispatches — always SQLite
//! ```
//!
//! At the time of writing `DbHandle::any()` has **zero callers** — verified by
//! renaming it and observing that nothing fails to compile. So outside
//! `repository.rs`, which holds its own Postgres pool, no part of the core
//! reaches Postgres at all. The abstraction is finished and unplugged.
//!
//! An audit of this repository initially reported "59% ported" by counting the
//! portable idiom as evidence of portability. These tests exist so the number
//! comes from the build rather than from reading, and so the day someone wires
//! dispatch up, the claim in `docs/production-readiness.md` is forced to move
//! with it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Statements written in the portable idiom but pinned to SQLite.
/// Update together with the figure in docs/production-readiness.md.
const EXPECTED_PINNED: usize = 189;
/// Tolerance for incidental refactors; a real sweep moves this far more.
const SLACK: usize = 5;

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

fn pinned_sites() -> (usize, BTreeMap<String, usize>) {
    let mut files = Vec::new();
    rust_files(&core_src(), &mut files);
    assert!(!files.is_empty(), "no sources under core/src");

    let mut total = 0;
    let mut by_file = BTreeMap::new();
    for f in files {
        // any_db.rs defines the trait; db.rs defines the dispatcher. Counting
        // them would measure the plumbing rather than its users.
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if name == "any_db.rs" || name == "db.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&f).expect("readable source");
        let body = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src[..],
        };
        let n = body.matches("any_conn()").count();
        if n > 0 {
            total += n;
            by_file.insert(
                f.strip_prefix(core_src())
                    .unwrap_or(&f)
                    .to_string_lossy()
                    .to_string(),
                n,
            );
        }
    }
    (total, by_file)
}

#[test]
fn sqlite_pinned_statement_count_matches_the_documented_figure() {
    let (pinned, by_file) = pinned_sites();
    if pinned.abs_diff(EXPECTED_PINNED) > SLACK {
        let mut worst: Vec<_> = by_file.into_iter().collect();
        worst.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let listing = worst
            .iter()
            .take(10)
            .map(|(f, n)| format!("    {n:3}  {f}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "SQLite-pinned statement count moved: {pinned} (documented {EXPECTED_PINNED}).\n\
             Update this constant and docs/production-readiness.md in the same commit,\n\
             so the claim and the code cannot disagree.\n\nLargest:\n{listing}"
        );
    }
}

#[test]
fn the_pinned_form_cannot_reach_postgres() {
    // The premise of the count above. If someone gives this trait a dispatching
    // implementation, that is the fix — but the coverage figure then means
    // something different and must be re-derived, not silently inherited.
    let src = std::fs::read_to_string(core_src().join("any_db.rs")).expect("any_db.rs");
    let start = src
        .find("impl AsAnyConn for rusqlite::Connection")
        .expect("AsAnyConn impl moved; re-check what any_conn() dispatches on");
    let body = &src[start..(start + 220).min(src.len())];
    assert!(
        body.contains("AnyConn::Sqlite"),
        "AsAnyConn for rusqlite::Connection no longer hard-returns Sqlite. If it \
         dispatches now, rewrite this test — the pinned count is no longer the \
         right measure of Postgres reach."
    );
}

#[test]
fn the_only_dispatcher_is_still_the_one_we_think_it_is() {
    // `DbHandle::any` is the sole constructor of AnyConn::Postgres outside
    // repository.rs. Its caller count is the real Postgres coverage number, and
    // today it is zero. This asserts the constructor still exists and is still
    // the only one, so "wire up dispatch" remains a single well-defined task.
    let db = std::fs::read_to_string(core_src().join("db.rs")).expect("db.rs");
    assert!(
        db.contains("pub fn any<T>"),
        "DbHandle::any is gone — if dispatch moved elsewhere, update these tests"
    );
    assert!(
        db.contains("AnyConn::Postgres"),
        "DbHandle::any no longer constructs the Postgres variant"
    );

    // Count constructions, not match arms. `AnyConn::Postgres(client) => {` in
    // any_db.rs is a pattern binding; the construction passes a borrow of a
    // pooled client, so `&mut` inside the parentheses is the discriminator.
    let mut files = Vec::new();
    rust_files(&core_src(), &mut files);
    let constructors: usize = files
        .iter()
        .map(|f| {
            std::fs::read_to_string(f)
                .unwrap_or_default()
                .matches("AnyConn::Postgres(&mut")
                .count()
        })
        .sum();
    assert_eq!(
        constructors, 1,
        "expected exactly one place to construct AnyConn::Postgres (DbHandle::any); \
         found {constructors}. More than one means Postgres reach is no longer a \
         single switch and this test needs rewriting."
    );
}
