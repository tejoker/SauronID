//! Extracted verbatim from the inline `mod pg_tls_tests` that `db.rs` used to
//! carry. `use super::*` still reaches the parent module's private items.

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
