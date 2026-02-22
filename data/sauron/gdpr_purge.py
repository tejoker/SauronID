"""
GDPR Data Retention Purge — Sauron
====================================
Anonymizes PII for EU/EEA residents whose last Sauron authentication
exceeds RETENTION_DAYS (365 days).  Non-EU/EEA users (China, USA, UK…)
are exempt — GDPR applies only to EU/EEA residents.

IMPORTANT
---------
  • personas.csv  — NEVER touched.  Read-only synthetic source of truth.
  • users.csv     — The writable user registry.  PII fields are nulled here.
  • sauron/data/sauron_users.parquet — is_anonymized flag + gdpr_purge_date
  • sauron/data/gdpr_log.parquet     — Audit trail, one row per run

Run manually:
    python sauron/gdpr_purge.py
"""

from __future__ import annotations

import logging
from datetime import date, timedelta
from pathlib import Path

import polars as pl

logger = logging.getLogger(__name__)

# ── Paths ────────────────────────────────────────────────────────────────────
_HERE        = Path(__file__).parent
DATA         = _HERE / "data"
ROOT         = _HERE.parent
USERS_CSV    = ROOT / "users.csv"          # writable – GDPR modifies this
USERS_FILE   = DATA / "sauron_users.parquet"
LOG_FILE     = DATA / "gdpr_log.parquet"

# ── Policy ───────────────────────────────────────────────────────────────────
RETENTION_DAYS = 365

# EU 27 member states + EEA (Norway, Iceland, Liechtenstein)
# Includes both ISO codes and the shorthand codes used in personas/users.csv
EU_EEA_COUNTRIES: set[str] = {
    # EU 27 — ISO alpha-2 and common variants
    "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi",
    "fr", "de", "gr", "hu", "ie", "ire", "it", "lv", "lt",
    "lu", "mt", "nl", "pl", "pt", "ro", "sk", "si", "es",
    "se", "swe",
    # EEA (non-EU)
    "no", "is", "li",
}

# PII columns to wipe in users.csv
PII_FIELDS = ["first_name", "last_name", "email", "address"]


# ─────────────────────────────────────────────────────────────────────────────
def run_purge() -> dict:
    """
    Execute GDPR purge for EU/EEA residents only.
    Returns a summary dict.
    """
    today   = date.today()
    cutoff  = str(today - timedelta(days=RETENTION_DAYS))
    today_s = str(today)

    if not USERS_FILE.exists():
        logger.error("sauron_users.parquet not found — run build_data.py first")
        return {"error": "sauron_users.parquet missing"}

    if not USERS_CSV.exists():
        logger.error("users.csv not found")
        return {"error": "users.csv missing"}

    users = pl.read_parquet(USERS_FILE)

    if "country" not in users.schema:
        logger.error("sauron_users.parquet has no 'country' column — run build_data.py")
        return {"error": "sauron_users missing country column"}

    eu_mask      = pl.col("country").is_in(list(EU_EEA_COUNTRIES))
    eu_eea_total = int(users.filter(eu_mask).height)

    # EU/EEA + inactive + not yet anonymized
    new_mask = (
        eu_mask &
        (pl.col("last_auth_date") < cutoff) &
        (pl.col("is_anonymized") == False)
    )
    to_purge     = users.filter(new_mask)
    purge_ids    = to_purge["persona_id"].to_list()
    newly_purged = len(purge_ids)

    logger.info(
        "GDPR purge: %d newly eligible EU/EEA users (cutoff %s, EU/EEA scope %d)",
        newly_purged, cutoff, eu_eea_total,
    )

    if newly_purged > 0:
        # Anonymize in users.csv ONLY (personas.csv is never touched)
        uf = pl.read_csv(USERS_CSV)
        exprs = []
        for field in PII_FIELDS:
            if field in uf.schema:
                exprs.append(
                    pl.when(pl.col("id").is_in(purge_ids))
                    .then(pl.lit("ANONYMIZED"))
                    .otherwise(pl.col(field))
                    .alias(field)
                )
        if exprs:
            uf = uf.with_columns(exprs)
            uf.write_csv(USERS_CSV)
            logger.info("  anonymized %d rows in users.csv", newly_purged)

        # Update sauron_users.parquet flags
        users = users.with_columns([
            pl.when(pl.col("persona_id").is_in(purge_ids))
              .then(pl.lit(True))
              .otherwise(pl.col("is_anonymized"))
              .alias("is_anonymized"),
            pl.when(pl.col("persona_id").is_in(purge_ids))
              .then(pl.lit(today_s))
              .otherwise(pl.col("gdpr_purge_date"))
              .alias("gdpr_purge_date"),
        ])
        users.write_parquet(USERS_FILE)

    # Totals
    users_fresh      = pl.read_parquet(USERS_FILE)
    total_anonymized = int(users_fresh.filter(pl.col("is_anonymized")).height)
    eligible_still   = int(
        users_fresh.filter(
            eu_mask &
            (pl.col("last_auth_date") < cutoff) &
            (pl.col("is_anonymized") == False)
        ).height
    )

    # Audit log
    entry = pl.DataFrame({
        "run_date":           [today_s],
        "newly_purged":       [newly_purged],
        "total_anonymized":   [total_anonymized],
        "eligible_remaining": [eligible_still],
        "eu_eea_scope":       [eu_eea_total],
    })
    if LOG_FILE.exists():
        existing = pl.read_parquet(LOG_FILE)
        log = pl.concat([existing, entry], how="diagonal")
    else:
        log = entry
    log.write_parquet(LOG_FILE)

    result = {
        "run_date":           today_s,
        "newly_purged":       newly_purged,
        "total_anonymized":   total_anonymized,
        "eligible_remaining": eligible_still,
        "eu_eea_scope":       eu_eea_total,
    }
    logger.info("GDPR purge complete: %s", result)
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(run_purge())
