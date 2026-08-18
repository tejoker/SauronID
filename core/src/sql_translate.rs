//! SQLite → PostgreSQL statement translation.
//!
//! The Postgres port stalled because it was attempted table by table: `Repo`
//! grew 50 hand-written methods covering 3 of 55 tables, while 277 call sites
//! elsewhere kept talking to rusqlite directly. Porting those one at a time is
//! 277 units of work, each an opportunity for a subtle behaviour change.
//!
//! This takes the other route: keep the SQL the call sites already write, and
//! translate it once, here. The translation is small because the codebase uses a
//! narrow SQLite dialect — numbered placeholders, `INSERT OR IGNORE/REPLACE`,
//! `IFNULL`, and `BEGIN IMMEDIATE`.
//!
//! What this deliberately does NOT do: parse SQL. A real parser would be more
//! correct and far more code; every rule below is a targeted rewrite with a test
//! pinning it, and anything unrecognised passes through untouched so Postgres
//! reports the error rather than this module guessing.

/// Rewrite a SQLite statement for PostgreSQL.
///
/// Idempotent for statements containing none of the constructs below, so it is
/// safe to apply unconditionally.
pub fn to_postgres(sql: &str) -> String {
    let mut out = rewrite_placeholders(sql);
    out = rewrite_insert_or(&out);
    out = rewrite_functions(&out);
    out = rewrite_transactions(&out);
    out
}

/// `?1` → `$1`. Both are 1-indexed and positional, so the mapping is direct.
///
/// Careful with string literals: a `?1` inside quotes is data, not a
/// placeholder. This walks the statement tracking quote state rather than doing
/// a blind replace.
fn rewrite_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                out.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                out.push(c);
            }
            '?' if !in_single && !in_double => {
                if chars.peek().is_some_and(|n| n.is_ascii_digit()) {
                    out.push('$');
                } else {
                    // A bare `?` is SQLite's anonymous placeholder, which has no
                    // positional Postgres equivalent. Leave it: Postgres will
                    // reject it loudly instead of this silently renumbering.
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// `INSERT OR IGNORE` / `INSERT OR REPLACE` → `ON CONFLICT` forms.
///
/// `OR IGNORE` maps cleanly to `ON CONFLICT DO NOTHING`. `OR REPLACE` does not:
/// Postgres needs an explicit conflict target and update list, which cannot be
/// derived without the schema. Those are rewritten to `DO NOTHING` ONLY when the
/// statement already carries an explicit `ON CONFLICT`; otherwise the `OR
/// REPLACE` is left in place so the statement fails visibly rather than
/// silently changing upsert semantics into a no-op.
fn rewrite_insert_or(sql: &str) -> String {
    let trimmed = sql.trim_start();
    let lowered = trimmed.to_ascii_lowercase();

    if lowered.starts_with("insert or ignore into") {
        let rest = &trimmed["insert or ignore into".len()..];
        let stmt = format!("INSERT INTO{rest}");
        if stmt.to_ascii_lowercase().contains("on conflict") {
            return stmt;
        }
        return format!(
            "{} ON CONFLICT DO NOTHING",
            stmt.trim_end_matches(';').trim_end()
        );
    }

    if lowered.starts_with("insert or replace into") && lowered.contains("on conflict") {
        let rest = &trimmed["insert or replace into".len()..];
        return format!("INSERT INTO{rest}");
    }

    sql.to_string()
}

/// SQLite scalar functions with different Postgres spellings.
fn rewrite_functions(sql: &str) -> String {
    let mut out = replace_ascii_case_insensitive(sql, "IFNULL(", "COALESCE(");
    out = replace_ascii_case_insensitive(
        &out,
        "strftime('%s','now')",
        "EXTRACT(EPOCH FROM now())::bigint",
    );
    out = replace_ascii_case_insensitive(
        &out,
        "strftime('%s', 'now')",
        "EXTRACT(EPOCH FROM now())::bigint",
    );
    out
}

/// SQLite's write-lock hint has no Postgres equivalent; plain `BEGIN` is the
/// closest, and the isolation the Postgres paths actually want is set per
/// transaction by the caller (`Repo` already uses SERIALIZABLE where it matters).
fn rewrite_transactions(sql: &str) -> String {
    let mut out = replace_ascii_case_insensitive(sql, "BEGIN IMMEDIATE TRANSACTION", "BEGIN");
    out = replace_ascii_case_insensitive(&out, "BEGIN IMMEDIATE", "BEGIN");
    out
}

/// Case-insensitive literal replace, preserving everything else byte for byte.
fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let hay_lower = haystack.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut idx = 0;
    while let Some(found) = hay_lower[idx..].find(&needle_lower) {
        let start = idx + found;
        out.push_str(&haystack[idx..start]);
        out.push_str(replacement);
        idx = start + needle.len();
    }
    out.push_str(&haystack[idx..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_become_dollar_numbers() {
        assert_eq!(
            to_postgres("SELECT a FROM t WHERE b = ?1 AND c = ?2"),
            "SELECT a FROM t WHERE b = $1 AND c = $2"
        );
        // Double digits must survive: ?10 is one placeholder, not ?1 then 0.
        assert_eq!(
            to_postgres("INSERT INTO t VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"),
            "INSERT INTO t VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"
        );
    }

    #[test]
    fn question_marks_inside_literals_are_data_not_placeholders() {
        assert_eq!(
            to_postgres("SELECT ?1 WHERE msg = 'what?1 is this'"),
            "SELECT $1 WHERE msg = 'what?1 is this'"
        );
        assert_eq!(
            to_postgres(r#"SELECT "col?1" FROM t WHERE x = ?1"#),
            r#"SELECT "col?1" FROM t WHERE x = $1"#
        );
    }

    #[test]
    fn anonymous_placeholder_is_left_alone_to_fail_loudly() {
        // Renumbering these silently would change which argument binds where.
        assert_eq!(
            to_postgres("SELECT a FROM t WHERE b = ?"),
            "SELECT a FROM t WHERE b = ?"
        );
    }

    #[test]
    fn insert_or_ignore_becomes_on_conflict_do_nothing() {
        assert_eq!(
            to_postgres("INSERT OR IGNORE INTO t (a, b) VALUES (?1, ?2)"),
            "INSERT INTO t (a, b) VALUES ($1, $2) ON CONFLICT DO NOTHING"
        );
        // Already has a conflict clause: don't append a second one.
        let already = "INSERT OR IGNORE INTO t (a) VALUES (?1) ON CONFLICT(a) DO NOTHING";
        assert_eq!(
            to_postgres(already),
            "INSERT INTO t (a) VALUES ($1) ON CONFLICT(a) DO NOTHING"
        );
    }

    #[test]
    fn insert_or_replace_without_a_conflict_target_is_not_silently_downgraded() {
        // Turning this into DO NOTHING would convert an upsert into a no-op —
        // the row simply would not update, with no error. Left alone so
        // Postgres rejects it and a human decides the conflict target.
        let sql = "INSERT OR REPLACE INTO t (a, b) VALUES (?1, ?2)";
        assert!(to_postgres(sql).to_ascii_uppercase().contains("OR REPLACE"));
    }

    #[test]
    fn insert_or_replace_with_an_explicit_conflict_clause_is_translated() {
        let sql = "INSERT OR REPLACE INTO t (a, b) VALUES (?1, ?2) \
                   ON CONFLICT(a) DO UPDATE SET b = excluded.b";
        assert_eq!(
            to_postgres(sql),
            "INSERT INTO t (a, b) VALUES ($1, $2) ON CONFLICT(a) DO UPDATE SET b = excluded.b"
        );
    }

    #[test]
    fn ifnull_and_strftime_get_postgres_spellings() {
        assert_eq!(
            to_postgres("SELECT IFNULL(seq, 0), ifnull(prev_hash, '') FROM t"),
            "SELECT COALESCE(seq, 0), COALESCE(prev_hash, '') FROM t"
        );
        assert_eq!(
            to_postgres("SELECT strftime('%s','now')"),
            "SELECT EXTRACT(EPOCH FROM now())::bigint"
        );
    }

    #[test]
    fn begin_immediate_becomes_plain_begin() {
        assert_eq!(to_postgres("BEGIN IMMEDIATE TRANSACTION;"), "BEGIN;");
        assert_eq!(to_postgres("BEGIN IMMEDIATE"), "BEGIN");
    }

    #[test]
    fn statements_with_nothing_to_translate_pass_through_unchanged() {
        for sql in [
            "SELECT COUNT(*) FROM agents",
            "DELETE FROM agent_action_nonces WHERE expires_at < $1",
            "UPDATE agents SET revoked = 1 WHERE agent_id = $1",
        ] {
            assert_eq!(to_postgres(sql), sql, "must be idempotent: {sql}");
        }
    }

    #[test]
    fn translation_is_idempotent() {
        let sql = "INSERT OR IGNORE INTO t (a) VALUES (?1)";
        let once = to_postgres(sql);
        assert_eq!(to_postgres(&once), once);
    }

    /// Real statements lifted from the codebase, so the rules are pinned against
    /// what actually ships rather than invented examples.
    #[test]
    fn real_statements_from_this_codebase() {
        let receipts = "INSERT OR REPLACE INTO agent_action_receipts \
             (receipt_id, action_hash, agent_id) VALUES (?1, ?2, ?3) \
             ON CONFLICT(receipt_id) DO UPDATE SET action_hash = excluded.action_hash";
        assert_eq!(
            to_postgres(receipts),
            "INSERT INTO agent_action_receipts \
             (receipt_id, action_hash, agent_id) VALUES ($1, $2, $3) \
             ON CONFLICT(receipt_id) DO UPDATE SET action_hash = excluded.action_hash"
        );

        let nonce =
            "INSERT INTO agent_action_nonces (nonce, agent_id, action_hash, expires_at, used_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)";
        assert_eq!(
            to_postgres(nonce),
            "INSERT INTO agent_action_nonces (nonce, agent_id, action_hash, expires_at, used_at) \
             VALUES ($1, $2, $3, $4, $5)"
        );

        let creds = "INSERT OR IGNORE INTO user_auth_credentials \
                     (key_image_hex, ed25519_public_key_b64u, created_at) VALUES (?1, ?2, ?3)";
        assert_eq!(
            to_postgres(creds),
            "INSERT INTO user_auth_credentials \
             (key_image_hex, ed25519_public_key_b64u, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING"
        );

        let chain = "SELECT tenant_id, receipt_id, IFNULL(seq, 0), IFNULL(prev_hash, '') \
                     FROM agent_action_receipts WHERE receipt_id = ?1";
        assert_eq!(
            to_postgres(chain),
            "SELECT tenant_id, receipt_id, COALESCE(seq, 0), COALESCE(prev_hash, '') \
             FROM agent_action_receipts WHERE receipt_id = $1"
        );
    }
}
