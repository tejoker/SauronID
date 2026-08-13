//! Phase 4 of the anonymous ring-policy redesign: multi-unit usage ledger.
//! See `docs/design/anonymous-ring-policy.md`.
//!
//! Tracks **tokens and money** per ring pseudonym (the per-ring key image), not
//! per agent identity — so accounting works under the anonymous model. Tokens
//! are authoritative; `usd` is derived from a per-model price map at record
//! time, which makes it provider-agnostic: online providers report usage,
//! local runtimes (vLLM / llama.cpp / Ollama) report counts, and a model with
//! no price entry simply has `usd = 0` while its tokens are still tracked.
//!
//! Budgets in `RingRule.budgets` are enforced per-pseudonym against the ledger
//! (see `agent_action::validate_anon_action`).
//!
//! Honesty boundary: token counts are host/gateway-reported (same class as the
//! config digest). The ledger + append-only `usage_log` make them tamper-evident
//! and anchorable; they become authoritative only when an in-path inference
//! gateway counts them (see `docs/ideas/blackbox-encrypted-inference.md`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    extract::{Extension, Json, Path, State},
    http::StatusCode,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::any_db::{AnyRowGet, AsAnyConn};
use crate::sql_params;
use crate::rings::RingBudgets;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

/// Per-model price, USD per 1,000 tokens.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelPrice {
    #[serde(default)]
    pub in_per_1k: f64,
    #[serde(default)]
    pub out_per_1k: f64,
}

/// Running totals for one ring pseudonym.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UsageTotals {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub usd: f64,
}

/// Load the per-model price map from `SAURON_MODEL_PRICES` (JSON object of
/// `model_id -> {in_per_1k, out_per_1k}`). Empty when unset/invalid.
fn load_price_map() -> HashMap<String, ModelPrice> {
    std::env::var("SAURON_MODEL_PRICES")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Pure money derivation from a price map. Unknown model → 0 (tokens still
/// tracked). Kept separate from env loading so it is unit-testable.
pub fn usd_from_prices(
    prices: &HashMap<String, ModelPrice>,
    model_id: &str,
    in_tokens: i64,
    out_tokens: i64,
) -> f64 {
    match prices.get(model_id) {
        Some(p) => {
            (in_tokens as f64 / 1000.0) * p.in_per_1k + (out_tokens as f64 / 1000.0) * p.out_per_1k
        }
        None => 0.0,
    }
}

/// Derive USD for a usage event using the env-configured price map.
pub fn derive_usd(model_id: &str, in_tokens: i64, out_tokens: i64) -> f64 {
    usd_from_prices(&load_price_map(), model_id, in_tokens, out_tokens)
}

/// Current lifetime totals for a ring pseudonym (zero when none recorded yet).
pub fn get_usage(
    db: &Connection,
    tenant_id: &str,
    ring_id: &str,
    key_image_hex: &str,
) -> Result<UsageTotals, String> {
    let row = db.any_conn()
        .query_row(
            "SELECT input_tokens, output_tokens, usd FROM usage_ledger
             WHERE tenant_id = ?1 AND ring_id = ?2 AND key_image_hex = ?3",
            sql_params![&tenant_id, &ring_id, &key_image_hex],
            |r| {
                Ok(UsageTotals {
                    input_tokens: r.get(0)?,
                    output_tokens: r.get(1)?,
                    usd: r.get(2)?,
                })
            },
        )
        .ok()
        .flatten();
    Ok(row.unwrap_or_default())
}

/// Returns `Some(reason)` if the totals already exceed any budget the ring caps.
/// `None` budgets are unlimited.
pub fn budget_exceeded(totals: &UsageTotals, budgets: &RingBudgets) -> Option<String> {
    if let Some(cap) = budgets.usd {
        if totals.usd > cap {
            return Some(format!("usd {:.4} > cap {:.4}", totals.usd, cap));
        }
    }
    if let Some(cap) = budgets.input_tokens {
        if totals.input_tokens > cap {
            return Some(format!(
                "input_tokens {} > cap {}",
                totals.input_tokens, cap
            ));
        }
    }
    if let Some(cap) = budgets.output_tokens {
        if totals.output_tokens > cap {
            return Some(format!(
                "output_tokens {} > cap {}",
                totals.output_tokens, cap
            ));
        }
    }
    None
}

/// Record a usage event against the ring pseudonym that owns a receipt. Appends
/// to `usage_log` and atomically accumulates `usage_ledger`. Returns the new
/// totals. Requires an anon-ring receipt (legacy receipts have no `ring_id`).
pub fn record_usage(
    db: &Connection,
    receipt_id: &str,
    model_id: &str,
    in_tokens: i64,
    out_tokens: i64,
    now: i64,
) -> Result<(String, String, UsageTotals), (StatusCode, String)> {
    if in_tokens < 0 || out_tokens < 0 {
        return Err((StatusCode::BAD_REQUEST, "token counts must be >= 0".into()));
    }
    let (tenant_id, ring_id_opt, key_image): (String, Option<String>, String) =
        db.any_conn().require(
            "SELECT tenant_id, ring_id, ring_key_image_hex FROM agent_action_receipts
             WHERE receipt_id = ?1",
            sql_params![receipt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            || (StatusCode::NOT_FOUND, "receipt not found".to_string()),
        )?;
    let ring_id = ring_id_opt.filter(|s| !s.is_empty()).ok_or((
        StatusCode::BAD_REQUEST,
        "usage recording requires an anon-ring receipt (ring_id missing)".to_string(),
    ))?;

    let usd = derive_usd(model_id, in_tokens, out_tokens);
    let log_id = format!("ul_{}", crate::ajwt_support::random_hex_32());
    db.any_conn().execute(
        "INSERT INTO usage_log
         (log_id, tenant_id, ring_id, key_image_hex, model_id, input_tokens, output_tokens, usd, recorded_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        sql_params![&log_id, &tenant_id, &ring_id, &key_image, &model_id, &in_tokens, &out_tokens, &usd, &now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    db.any_conn().execute(
        "INSERT INTO usage_ledger
         (tenant_id, ring_id, key_image_hex, input_tokens, output_tokens, usd, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(tenant_id, ring_id, key_image_hex) DO UPDATE SET
            input_tokens  = usage_ledger.input_tokens  + excluded.input_tokens,
            output_tokens = usage_ledger.output_tokens + excluded.output_tokens,
            usd           = usage_ledger.usd           + excluded.usd,
            updated_at    = excluded.updated_at",
        sql_params![&tenant_id, &ring_id, &key_image, &in_tokens, &out_tokens, &usd, &now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let totals = get_usage(db, &tenant_id, &ring_id, &key_image)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((ring_id, key_image, totals))
}

/// Per-pseudonym totals for a whole ring (operator view).
pub fn list_ring_usage(
    db: &Connection,
    tenant_id: &str,
    ring_id: &str,
) -> Result<Vec<(String, UsageTotals)>, String> {
    db.any_conn()
        .query_map(
            "SELECT key_image_hex, input_tokens, output_tokens, usd FROM usage_ledger
             WHERE tenant_id = ?1 AND ring_id = ?2 ORDER BY key_image_hex",
            sql_params![tenant_id, ring_id],
            |r| {
                Ok((
                    r.get::<String>(0)?,
                    UsageTotals {
                        input_tokens: r.get(1)?,
                        output_tokens: r.get(2)?,
                        usd: r.get(3)?,
                    },
                ))
            },
        )
        .map_err(|e| format!("query list_ring_usage: {e}"))
}

// ─── HTTP handlers ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RecordUsageRequest {
    pub receipt_id: String,
    #[serde(default)]
    pub model_id: String,
    #[serde(default)]
    pub input_tokens: i64,
    #[serde(default)]
    pub output_tokens: i64,
    /// Single-use nonce, covered by the signature.
    pub nonce: String,
    /// LSAG signature over [`canonical_usage_report_json`] against the ring's
    /// member set. Proves the reporter holds the same per-ring key that produced
    /// the receipt — without it this endpoint is an unauthenticated write into
    /// the budget ledger.
    pub ring_signature: crate::ring::RingSignature,
}

/// Fixed-field canonical JSON for signed usage reports (byte parity across
/// implementations — do not replace with `Value::to_string()`).
pub fn canonical_usage_report_json(
    receipt_id: &str,
    model_id: &str,
    input_tokens: i64,
    output_tokens: i64,
    nonce: &str,
) -> String {
    use crate::agent_action::json_str;
    format!(
        "{{\"receipt_id\":{},\"model_id\":{},\"input_tokens\":{},\"output_tokens\":{},\"nonce\":{}}}",
        json_str(receipt_id),
        json_str(model_id),
        input_tokens,
        output_tokens,
        json_str(nonce),
    )
}

/// Authorise a usage report: the reporter must prove membership of the ring that
/// owns the receipt, with the *same* key image the receipt was issued to, and
/// each report is single-use.
///
/// Token counts stay host-reported (see the module honesty boundary) — this
/// closes forgery and third-party ledger poisoning, not under-reporting.
pub fn verify_usage_report(
    db: &Connection,
    req: &RecordUsageRequest,
    now: i64,
) -> Result<(), (StatusCode, String)> {
    if req.nonce.trim().len() < 16 || req.nonce.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "nonce must be 16..128 chars".into(),
        ));
    }
    let (tenant_id, ring_id, receipt_key_image): (String, Option<String>, String) =
        db.any_conn().require(
            "SELECT tenant_id, ring_id, ring_key_image_hex FROM agent_action_receipts
             WHERE receipt_id = ?1",
            sql_params![&req.receipt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            || (StatusCode::NOT_FOUND, "receipt not found".to_string()),
        )?;
    let ring_id = ring_id.filter(|s| !s.is_empty()).ok_or((
        StatusCode::BAD_REQUEST,
        "usage recording requires an anon-ring receipt (ring_id missing)".to_string(),
    ))?;

    // The signature must come from the pseudonym the receipt was issued to, not
    // merely from some member of the ring — otherwise any member could bill
    // another member's budget.
    let key_image_hex = hex::encode(req.ring_signature.key_image.compress().as_bytes());
    if key_image_hex != receipt_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "usage report signed by a different ring pseudonym than the receipt".into(),
        ));
    }

    let members = crate::rings::list_member_points(db, &tenant_id, &ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if members.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "ring has no members".into()));
    }
    let canonical = canonical_usage_report_json(
        &req.receipt_id,
        &req.model_id,
        req.input_tokens,
        req.output_tokens,
        &req.nonce,
    );
    if !crate::ring::verify(canonical.as_bytes(), &members, &req.ring_signature) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "usage report signature verification failed".into(),
        ));
    }

    // Single-use, in the same table and idiom as action nonces: the UNIQUE
    // violation IS the check. Consumed only after the signature verifies.
    // ponytail: a 30-day window, not forever — long enough that a captured
    // report cannot be replayed once the row ages out of any realistic session.
    db.any_conn().execute(
        "INSERT INTO agent_action_nonces (nonce, agent_id, action_hash, expires_at, used_at)
         VALUES (?1, '', ?2, ?3, ?4)",
        sql_params![
            format!("usage|{key_image_hex}|{}", req.nonce),
            &req.receipt_id,
            now + 30 * 24 * 3600,
            &now
        ],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::UNAUTHORIZED, "usage report replay".to_string())
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;
    Ok(())
}

/// POST /agent/usage — report token usage for a prior anon action receipt.
pub async fn record_usage_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(req): Json<RecordUsageRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !crate::rings::anon_rings_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anonymous rings are disabled (set SAURON_ANON_RINGS=1)".into(),
        ));
    }
    let now = crate::agent_action::now_secs();
    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
    verify_usage_report(&db, &req, now)?;
    let (ring_id, key_image, totals) = record_usage(
        &db,
        &req.receipt_id,
        &req.model_id,
        req.input_tokens,
        req.output_tokens,
        now,
    )?;
    Ok(Json(json!({
        "ring_id": ring_id,
        "key_image_hex": key_image,
        "input_tokens": totals.input_tokens,
        "output_tokens": totals.output_tokens,
        "usd": totals.usd,
    })))
}

/// GET /admin/rings/{ring_id}/usage — authenticated-tenant usage totals.
pub async fn ring_usage_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(ring_id): Path<String>,
    Extension(tenant): Extension<crate::tenancy::TenantId>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !crate::rings::anon_rings_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anonymous rings are disabled (set SAURON_ANON_RINGS=1)".into(),
        ));
    }
    let st = state.read_or_recover();
    let db = st.db.lock().unwrap();
    let rows = list_ring_usage(&db, tenant.as_str(), &ring_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(ki, t)| {
            json!({ "key_image_hex": ki, "input_tokens": t.input_tokens, "output_tokens": t.output_tokens, "usd": t.usd })
        })
        .collect();
    Ok(Json(json!({ "ring_id": ring_id, "pseudonyms": out })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn);
        conn
    }

    fn insert_anon_receipt(
        db: &Connection,
        receipt_id: &str,
        ring_id: Option<&str>,
        key_image: &str,
    ) {
        db.execute(
            "INSERT INTO agent_action_receipts
             (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at, ring_id, config_digest, tenant_id)
             VALUES (?1,'ah','',?2,'ring:r:v1','','','verified','sig',1,?3,'',?4)",
            params![receipt_id, key_image, ring_id, "default"],
        )
        .unwrap();
    }

    /// Build ring "r" with `a` + a decoy, and return the request-signing pieces.
    fn ring_fixture(db: &Connection) -> (curve25519_dalek::scalar::Scalar, String) {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        use sha2::Digest;
        let scalar = |seed: &[u8]| {
            let mut h = sha2::Sha512::new();
            h.update(seed);
            Scalar::from_hash(h)
        };
        let pub_hex =
            |s: &Scalar| hex::encode((s * RISTRETTO_BASEPOINT_TABLE).compress().as_bytes());
        let (t, a) = (scalar(b"usage-trapdoor"), scalar(b"usage-agent"));
        crate::rings::upsert_ring(db, "default", "r", &crate::rings::RingRule::default(), 1)
            .unwrap();
        crate::rings::subscribe(db, "default", &t, &pub_hex(&a), "r", 1).unwrap();
        crate::rings::subscribe(db, "default", &t, &pub_hex(&scalar(b"usage-decoy")), "r", 1)
            .unwrap();
        let big_t = &t * RISTRETTO_BASEPOINT_TABLE;
        let shared = crate::ring_pseudonym::shared_secret_agent(&a, &big_t);
        let id = crate::ring_pseudonym::agent_ring_identity(&a, &shared, "r");
        let key_image = hex::encode(id.key_image().compress().as_bytes());
        (a, key_image)
    }

    fn signed_report(
        db: &Connection,
        a: &curve25519_dalek::scalar::Scalar,
        receipt_id: &str,
        nonce: &str,
        in_tokens: i64,
    ) -> RecordUsageRequest {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
        use sha2::Digest;
        let mut h = sha2::Sha512::new();
        h.update(b"usage-trapdoor");
        let t = curve25519_dalek::scalar::Scalar::from_hash(h);
        let big_t = &t * RISTRETTO_BASEPOINT_TABLE;
        let shared = crate::ring_pseudonym::shared_secret_agent(a, &big_t);
        let id = crate::ring_pseudonym::agent_ring_identity(a, &shared, "r");
        let members = crate::rings::list_member_points(db, "default", "r").unwrap();
        let idx = members.iter().position(|p| *p == id.public).unwrap();
        let canonical = canonical_usage_report_json(receipt_id, "local-model", in_tokens, 0, nonce);
        RecordUsageRequest {
            receipt_id: receipt_id.into(),
            model_id: "local-model".into(),
            input_tokens: in_tokens,
            output_tokens: 0,
            nonce: nonce.into(),
            ring_signature: crate::ring::sign(canonical.as_bytes(), &members, &id, idx),
        }
    }

    #[test]
    fn usage_report_requires_the_receipt_pseudonym_and_is_single_use() {
        let db = mem_db();
        let (a, key_image) = ring_fixture(&db);
        insert_anon_receipt(&db, "ar_signed", Some("r"), &key_image);

        // Genuine holder of the receipt's per-ring key.
        let req = signed_report(&db, &a, "ar_signed", "nonce-usage-0000001", 100);
        verify_usage_report(&db, &req, 1).expect("receipt pseudonym accepted");

        // Same report again — replay refused.
        let err = verify_usage_report(&db, &req, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert!(err.1.contains("replay"), "got: {}", err.1);

        // Tampering with the counts after signing invalidates the report.
        let mut tampered = signed_report(&db, &a, "ar_signed", "nonce-usage-0000002", 100);
        tampered.input_tokens = 0;
        let err = verify_usage_report(&db, &tampered, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // A third party who knows the receipt id cannot bill it: no signature.
        let stranger = signed_report(&db, &a, "ar_signed", "nonce-usage-0000003", 5);
        insert_anon_receipt(&db, "ar_other", Some("r"), "kimg_someone_else");
        let mut wrong_receipt = stranger;
        wrong_receipt.receipt_id = "ar_other".into();
        let err = verify_usage_report(&db, &wrong_receipt, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert!(err.1.contains("different ring pseudonym"), "got: {}", err.1);
    }

    #[test]
    fn usd_derivation_uses_price_map_and_zero_for_unknown() {
        let mut prices = HashMap::new();
        prices.insert(
            "claude-opus-4-8".to_string(),
            ModelPrice {
                in_per_1k: 0.015,
                out_per_1k: 0.075,
            },
        );
        // 2000 in, 1000 out → 2*0.015 + 1*0.075 = 0.105
        let usd = usd_from_prices(&prices, "claude-opus-4-8", 2000, 1000);
        assert!((usd - 0.105).abs() < 1e-9, "got {usd}");
        // Local / unknown model → tokens tracked elsewhere, usd 0.
        assert_eq!(usd_from_prices(&prices, "local-llama", 9999, 9999), 0.0);
    }

    #[test]
    fn budget_exceeded_respects_caps_and_unlimited() {
        let totals = UsageTotals {
            input_tokens: 1500,
            output_tokens: 10,
            usd: 2.0,
        };
        // Unlimited everywhere.
        assert!(budget_exceeded(&totals, &RingBudgets::default()).is_none());
        // Under all caps.
        assert!(budget_exceeded(
            &totals,
            &RingBudgets {
                usd: Some(5.0),
                input_tokens: Some(2000),
                output_tokens: Some(100)
            }
        )
        .is_none());
        // Over the token cap.
        assert!(budget_exceeded(
            &totals,
            &RingBudgets {
                usd: None,
                input_tokens: Some(1000),
                output_tokens: None
            }
        )
        .is_some());
    }

    #[test]
    fn record_usage_accumulates_and_keys_on_pseudonym() {
        let db = mem_db();
        insert_anon_receipt(&db, "ar_1", Some("ring:r"), "kimg_abc");
        let (ring_id, ki, t1) = record_usage(&db, "ar_1", "local-model", 100, 50, 1).unwrap();
        assert_eq!(ring_id, "ring:r");
        assert_eq!(ki, "kimg_abc");
        assert_eq!(
            t1,
            UsageTotals {
                input_tokens: 100,
                output_tokens: 50,
                usd: 0.0
            }
        );
        // Second event accumulates on the same pseudonym.
        let (_, _, t2) = record_usage(&db, "ar_1", "local-model", 10, 5, 2).unwrap();
        assert_eq!(
            t2,
            UsageTotals {
                input_tokens: 110,
                output_tokens: 55,
                usd: 0.0
            }
        );
        assert_eq!(get_usage(&db, "default", "ring:r", "kimg_abc").unwrap(), t2);
    }

    #[test]
    fn record_usage_rejects_legacy_receipt_and_unknown_receipt() {
        let db = mem_db();
        // Legacy receipt: ring_id NULL.
        insert_anon_receipt(&db, "ar_legacy", None, "ki");
        let err = record_usage(&db, "ar_legacy", "m", 1, 1, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // Unknown receipt.
        let err = record_usage(&db, "ar_missing", "m", 1, 1, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
