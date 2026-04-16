//! Sliding-window rate limits keyed by opaque server-side buckets (hashed material).
//! In **development** runtimes, limits default to **disabled** (0) unless env is set.
//! In production-like runtimes, sane defaults apply unless overridden by env.

use crate::runtime_mode::is_development_runtime;
use rusqlite::{params, Connection};
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

pub fn bucket_kyc_retrieve(site: &str, user_key_image: &str) -> String {
    hash_bucket(b"kyc_retrieve", &[site.as_bytes(), user_key_image.as_bytes()])
}

pub fn bucket_agent_kyc_consent(site: &str, user_key_image: &str) -> String {
    hash_bucket(b"agent_kyc_consent", &[site.as_bytes(), user_key_image.as_bytes()])
}

pub fn bucket_payment_authorize(agent_id: &str) -> String {
    hash_bucket(b"payment_authorize", &[agent_id.as_bytes()])
}

pub fn bucket_agent_vc_issue(human_key_image: &str) -> String {
    hash_bucket(b"agent_vc_issue", &[human_key_image.as_bytes()])
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

    db.execute(
        "INSERT INTO risk_rate_counters (bucket, window_id, cnt) VALUES (?1, ?2, 1)
         ON CONFLICT(bucket, window_id) DO UPDATE SET cnt = cnt + 1",
        params![bucket, window_id],
    )
    .map_err(|e| format!("risk: db error: {e}"))?;

    let cnt: i64 = db
        .query_row(
            "SELECT cnt FROM risk_rate_counters WHERE bucket = ?1 AND window_id = ?2",
            params![bucket, window_id],
            |r| r.get(0),
        )
        .map_err(|e| format!("risk: read cnt: {e}"))?;

    if cnt > max_per_window {
        return Err("risk: rate limit exceeded".into());
    }

    // Best-effort GC of stale windows (bounded work per request).
    let _ = db.execute(
        "DELETE FROM risk_rate_counters WHERE window_id < ?1",
        params![window_id - 120],
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
