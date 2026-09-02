//! The registration ceiling counts the right agents.
//!
//! `register_agent` refuses when a tenant's active agent count has reached the
//! deployment licence ceiling. The comparison is trivial; the query is not, and
//! two of its properties are load-bearing commercially and for isolation:
//!
//!   * it is **scoped to one tenant**, so one customer's agents never consume
//!     another's ceiling on a shared deployment, and
//!   * it **excludes revoked agents**, so the remediation the refusal offers
//!     ("revoke an unused agent") actually frees a slot.
//!
//! The handler itself cannot be invoked headlessly — it needs a session header,
//! the rate limiter and ring bookkeeping — so this asserts on the storage layer
//! using the exact SQL the handler runs, in the same style as
//! `multi_tenancy.rs`.

use sauron_core::licence::{Entitlement, FREE_TIER_MAX_AGENTS};

/// Byte-for-byte the predicate in `agent::handlers::register_agent`. If the two
/// ever diverge, this test is worthless — keep them together.
const CEILING_COUNT_SQL: &str =
    "SELECT COUNT(*) FROM agents WHERE revoked = 0 AND tenant_id = ?1";

fn build_db(name: &str) -> sauron_core::db::DbHandle {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-lic-{pid}-{nanos}-{name}.db"));
    let _ = std::fs::remove_file(&path);
    sauron_core::db::open_sqlite_only(path.to_str().unwrap(), 2)
}

fn seed_agent(db: &sauron_core::db::DbHandle, tenant: &str, agent_id: &str, revoked: i64) {
    let conn = db.lock_sqlite().unwrap();
    conn.execute(
        "INSERT INTO agents
         (agent_id, human_key_image, agent_checksum, issued_at, expires_at, revoked, tenant_id)
         VALUES (?1, ?2, 'checksum', 0, 9999999999, ?3, ?4)",
        rusqlite::params![agent_id, format!("ki-{agent_id}"), revoked, tenant],
    )
    .unwrap();
}

fn active_count(db: &sauron_core::db::DbHandle, tenant: &str) -> i64 {
    let conn = db.lock_sqlite().unwrap();
    conn.query_row(CEILING_COUNT_SQL, rusqlite::params![tenant], |r| r.get(0))
        .unwrap()
}

#[test]
fn the_ceiling_is_counted_per_tenant_not_per_deployment() {
    let db = build_db("per_tenant");
    for i in 0..5 {
        seed_agent(&db, "tenant_a", &format!("agt_a_{i}"), 0);
    }
    seed_agent(&db, "tenant_b", "agt_b_0", 0);

    assert_eq!(active_count(&db, "tenant_a"), 5);
    assert_eq!(
        active_count(&db, "tenant_b"),
        1,
        "tenant_a's five agents must not consume tenant_b's ceiling"
    );

    let free = Entitlement::FreeTier { reason: "test" };
    assert!(
        active_count(&db, "tenant_a") >= free.max_agents(),
        "tenant_a is over the free-tier ceiling and must be refused"
    );
    assert!(
        active_count(&db, "tenant_b") < free.max_agents(),
        "tenant_b is under it and must still be allowed"
    );
}

#[test]
fn revoking_an_agent_frees_a_slot_because_the_count_excludes_revoked() {
    let db = build_db("revoked_frees");
    for i in 0..FREE_TIER_MAX_AGENTS {
        seed_agent(&db, "tenant_a", &format!("agt_{i}"), 0);
    }
    let free = Entitlement::FreeTier { reason: "test" };
    assert_eq!(active_count(&db, "tenant_a"), free.max_agents());
    assert!(
        active_count(&db, "tenant_a") >= free.max_agents(),
        "at the ceiling, the next registration is refused"
    );

    {
        let conn = db.lock_sqlite().unwrap();
        conn.execute(
            "UPDATE agents SET revoked = 1 WHERE agent_id = 'agt_0'",
            [],
        )
        .unwrap();
    }

    assert!(
        active_count(&db, "tenant_a") < free.max_agents(),
        "the refusal tells the operator to revoke an unused agent — that has to work"
    );
}

#[test]
fn a_licensed_ceiling_admits_more_than_the_free_tier() {
    let db = build_db("licensed_ceiling");
    for i in 0..10 {
        seed_agent(&db, "tenant_a", &format!("agt_{i}"), 0);
    }
    let licensed = Entitlement::Licensed { max_agents: 50, licensee: "ACME SA".into() };
    let free = Entitlement::FreeTier { reason: "test" };
    let count = active_count(&db, "tenant_a");

    assert!(count >= free.max_agents(), "ten agents exceed the free tier");
    assert!(
        count < licensed.max_agents(),
        "and are admitted under a 50-agent licence — this is what the customer pays for"
    );
}
