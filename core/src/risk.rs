//! Sliding-window rate limits keyed by opaque server-side buckets (hashed material).
//! In **development** runtimes, limits default to **disabled** (0) unless env is set.
//! In production-like runtimes, sane defaults apply unless overridden by env.

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use crate::runtime_mode::is_development_runtime;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hash_bucket(prefix: &[u8], parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    h.update(prefix);
    for p in parts {
        h.update(b"|");
        h.update(p);
    }
    hex::encode(&h.finalize()[..24])
}

// Every bucket folds `tenant_id` into the hash as its first component so
// counters are isolated per tenant. Without it, buckets collide on
// `human_key_image` / `agent_id` / `site` across tenants and one tenant can
// exhaust another tenant's rate-limit budget (cross-tenant DoS). Callers pass
// the request-scoped tenant (defaulting to `"default"` for legacy single-tenant
// traffic), so the isolation is transparent to existing deployments.
pub fn bucket_kyc_retrieve(tenant_id: &str, site: &str, user_key_image: &str) -> String {
    hash_bucket(
        b"kyc_retrieve",
        &[
            tenant_id.as_bytes(),
            site.as_bytes(),
            user_key_image.as_bytes(),
        ],
    )
}

pub fn bucket_agent_kyc_consent(tenant_id: &str, site: &str, user_key_image: &str) -> String {
    hash_bucket(
        b"agent_kyc_consent",
        &[
            tenant_id.as_bytes(),
            site.as_bytes(),
            user_key_image.as_bytes(),
        ],
    )
}

pub fn bucket_payment_authorize(tenant_id: &str, agent_id: &str) -> String {
    hash_bucket(
        b"payment_authorize",
        &[tenant_id.as_bytes(), agent_id.as_bytes()],
    )
}

pub fn bucket_agent_vc_issue(tenant_id: &str, human_key_image: &str) -> String {
    hash_bucket(
        b"agent_vc_issue",
        &[tenant_id.as_bytes(), human_key_image.as_bytes()],
    )
}

pub fn bucket_agent_register(tenant_id: &str, human_key_image: &str) -> String {
    hash_bucket(
        b"agent_register",
        &[tenant_id.as_bytes(), human_key_image.as_bytes()],
    )
}

pub fn bucket_agent_verify(tenant_id: &str, agent_id: &str) -> String {
    hash_bucket(
        b"agent_verify",
        &[tenant_id.as_bytes(), agent_id.as_bytes()],
    )
}

pub fn bucket_egress_capability(tenant_id: &str, agent_id: &str) -> String {
    hash_bucket(
        b"egress_capability",
        &[tenant_id.as_bytes(), agent_id.as_bytes()],
    )
}

fn parse_limit(name: &str, production_default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(if is_development_runtime() {
            0
        } else {
            production_default
        })
        .max(0)
}

pub fn window_secs() -> i64 {
    std::env::var("SAURON_RISK_WINDOW_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(60)
        .clamp(10, 3600)
}

/// Increment counter for this bucket/window. Returns `Err` if over limit after increment.
///
/// Wrapped in `BEGIN IMMEDIATE TRANSACTION` so the INSERT-ON-CONFLICT +
/// post-increment SELECT pair runs under the SQLite writer lock — counter
/// read cannot be torn by a concurrent increment. On Postgres callers SHOULD
/// route through `Repo::risk_increment` which runs the same pair under
/// `ISOLATION LEVEL SERIALIZABLE` with retry.
pub fn check_and_increment(
    db: &Connection,
    bucket: &str,
    now: i64,
    max_per_window: i64,
) -> Result<(), String> {
    if max_per_window <= 0 {
        return Ok(());
    }
    if bucket.len() > 128 {
        return Err("risk: internal bucket key too long".into());
    }
    let w = window_secs();
    let window_id = now / w;

    db.execute_batch("BEGIN IMMEDIATE TRANSACTION;")
        .map_err(|e| format!("risk: begin immediate: {e}"))?;
    let inner = (|| -> Result<i64, String> {
        db.any_conn().execute(
            "INSERT INTO risk_rate_counters (bucket, window_id, cnt) VALUES (?1, ?2, 1)
             ON CONFLICT(bucket, window_id) DO UPDATE SET cnt = cnt + 1",
            sql_params![&bucket, &window_id],
        )
        .map_err(|e| format!("risk: db error: {e}"))?;
        let cnt: i64 = db.any_conn().require(
            "SELECT cnt FROM risk_rate_counters WHERE bucket = ?1 AND window_id = ?2",
            sql_params![&bucket, &window_id],
            |r| r.get(0),
            || "risk: read cnt: row vanished".to_string(),
        )?;
        Ok(cnt)
    })();
    let cnt = match inner {
        Ok(c) => {
            db.execute_batch("COMMIT;")
                .map_err(|e| format!("risk: commit: {e}"))?;
            c
        }
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK;");
            return Err(e);
        }
    };

    if cnt > max_per_window {
        return Err("risk: rate limit exceeded".into());
    }

    // Best-effort GC of stale windows (bounded work per request, outside txn).
    let _ = db.any_conn().execute(
        "DELETE FROM risk_rate_counters WHERE window_id < ?1",
        sql_params![&window_id - 120],
    );

    Ok(())
}

pub fn limit_kyc_retrieve() -> i64 {
    parse_limit("SAURON_RISK_KYC_RETRIEVE_PER_WINDOW", 120)
}

pub fn limit_agent_kyc_consent() -> i64 {
    parse_limit("SAURON_RISK_AGENT_KYC_CONSENT_PER_WINDOW", 60)
}

pub fn limit_payment_authorize() -> i64 {
    parse_limit("SAURON_RISK_PAYMENT_AUTHORIZE_PER_WINDOW", 30)
}

pub fn limit_agent_vc_issue() -> i64 {
    parse_limit("SAURON_RISK_AGENT_VC_ISSUE_PER_WINDOW", 20)
}

pub fn limit_agent_register() -> i64 {
    // L3: in production we still default to 20/window. In dev the global
    // `parse_limit` floor is 0 (= unlimited) which leaves /agent/register
    // wide open during local runs — anyone scripting a registration flood
    // can saturate TPM-attestation parsing. Apply a 60/window floor (which
    // matches the 60s default window → ~1 register/sec/human) in dev too.
    // Env var still overrides, including to a higher value, or to 0 if
    // operator explicitly wants no cap.
    let parsed = parse_limit("SAURON_RISK_AGENT_REGISTER_PER_WINDOW", 20);
    if std::env::var("SAURON_RISK_AGENT_REGISTER_PER_WINDOW").is_ok() {
        // Operator explicitly set it — honour it as-is (parse_limit clamps to >= 0).
        parsed
    } else if parsed == 0 {
        // No env override and parse_limit returned the dev fallback (0).
        // Apply the new safe default.
        60
    } else {
        parsed
    }
}

pub fn limit_agent_verify() -> i64 {
    parse_limit("SAURON_RISK_AGENT_VERIFY_PER_WINDOW", 300)
}

pub fn limit_egress_capability() -> i64 {
    parse_limit("SAURON_RISK_EGRESS_CAPABILITY_PER_WINDOW", 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_isolated_per_tenant() {
        // Same human key image under two tenants must produce different
        // buckets — otherwise tenant A exhausting its quota starves tenant B.
        let a = bucket_agent_register("tenant_a", "hki");
        let b = bucket_agent_register("tenant_b", "hki");
        assert_ne!(a, b, "cross-tenant bucket collision");
        // Deterministic within a tenant.
        assert_eq!(a, bucket_agent_register("tenant_a", "hki"));
    }

    #[test]
    fn every_bucket_kind_separates_tenants() {
        assert_ne!(
            bucket_kyc_retrieve("t1", "site", "uki"),
            bucket_kyc_retrieve("t2", "site", "uki")
        );
        assert_ne!(
            bucket_payment_authorize("t1", "agent"),
            bucket_payment_authorize("t2", "agent")
        );
        assert_ne!(
            bucket_agent_verify("t1", "agent"),
            bucket_agent_verify("t2", "agent")
        );
        assert_ne!(
            bucket_egress_capability("t1", "agent"),
            bucket_egress_capability("t2", "agent")
        );
    }
}
