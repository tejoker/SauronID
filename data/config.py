"""
config.py — single source of truth for data generation scale.

Change N_PERSONAS here and run build_all.py to regenerate
everything (data, ML models, scores, dashboard stats).
"""

N_PERSONAS  = 10_000   # number of synthetic personas
N_COMPANIES = 50       # number of merchant companies (fixed; scale personas instead)

# How many personas to seed into Sauron backend (via HTTP API).
# Set lower for fast dev iterations, higher for realistic data.
N_SEED_USERS = 200     # default: first 200 personas

# Base customer ranges are proportional to N_PERSONAS.
# At 1 000 personas: startup 10-80, sme 80-300, enterprise 300-900.
# The ratio stays constant so transaction density per persona is stable.
_BASE = N_PERSONAS / 1_000
SIZE_RANGE = {
    "startup":    (int(10  * _BASE), int(80  * _BASE)),
    "sme":        (int(80  * _BASE), int(300 * _BASE)),
    "enterprise": (int(300 * _BASE), int(900 * _BASE)),
}

# ---------------------------------------------------------------------------
# Sauron client type mapping
# ---------------------------------------------------------------------------
# Maps (category, size_tier) → Sauron client_type.
# FULL_KYC (full_identification) = companies doing KYC AND querying ZKP proofs
# ZKP_ONLY (non_regulated_acquirer) = companies querying proofs only
def sauron_client_type(category: str, size_tier: str) -> str:
    """Assign FULL_KYC or ZKP_ONLY based on category & size."""
    if category == "investment":
        return "FULL_KYC"
    if category in ("tech", "travel") and size_tier == "enterprise":
        return "FULL_KYC"
    return "ZKP_ONLY"

# ---------------------------------------------------------------------------
# Country → ISO nationality code (used by Sauron users)
# ---------------------------------------------------------------------------
COUNTRY_TO_NATIONALITY = {
    "usa":   "US",
    "china": "CN",
    "fr":    "FR",
    "uk":    "GB",
    "ire":   "IE",
    "swe":   "SE",
}

# ---------------------------------------------------------------------------
# Generation → date_of_birth range (year bounds, inclusive)
# All users are adults (≥18 in 2026).
# ---------------------------------------------------------------------------
GENERATION_DOB_RANGE = {
    "gen_z":      (1997, 2008),   # 18-29 in 2026
    "millennial": (1981, 1996),   # 30-45 in 2026
    "boomer":     (1946, 1964),   # 62-80 in 2026
}
