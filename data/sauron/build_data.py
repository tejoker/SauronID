"""
Sauron synthetic data builder.
Outputs:
  sauron/data/clients.parquet
  sauron/data/credit_ledger.parquet
  sauron/data/verifications.parquet
  sauron/data/ring_snapshots.parquet
  sauron/data/anomaly_events.parquet
  sauron/data/sauron_users.parquet
"""
import os
import random
import sys
import numpy as np
import polars as pl
from datetime import date, timedelta

ROOT = os.environ.get("DATA_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(OUT, exist_ok=True)

# Allow importing config from parent directory (or DATA_DIR in Docker)
sys.path.insert(0, ROOT)
from config import sauron_client_type

random.seed(42)
rng = np.random.default_rng(42)

# ── Constants ────────────────────────────────────────────────────────────────
START_DATE = date(2024, 1, 1)
END_DATE   = date(2025, 12, 31)
DAYS       = (END_DATE - START_DATE).days + 1

# Map companies.csv category → Sauron sector label
CATEGORY_TO_SECTOR = {
    "investment":  "investment",
    "tech":        "technology",
    "lifestyle":   "lifestyle",
    "food_living": "retail",
    "travel":      "travel",
}

# Assign a realistic home country per category (round-robin by row index)
COUNTRY_POOLS = {
    "investment":  ["France", "Germany", "UK", "Switzerland", "Luxembourg",
                    "Netherlands", "Italy", "Spain", "Sweden", "Ireland"],
    "tech":        ["USA", "UK", "Sweden", "Germany", "Ireland", "France",
                    "USA", "Netherlands", "USA", "UK"],
    "lifestyle":   ["France", "UK", "Italy", "Germany", "Spain",
                    "France", "UK", "Netherlands", "Italy", "Spain"],
    "food_living": ["UK", "France", "Germany", "Netherlands", "Ireland",
                    "UK", "France", "Germany", "Spain", "Italy"],
    "travel":      ["UK", "France", "Germany", "Spain", "Netherlands",
                    "Sweden", "UK", "France", "Italy", "Germany"],
}


# Map Sauron client_type to analytics type labels
SAURON_TYPE_TO_ANALYTICS = {
    "FULL_KYC":  "full_identification",
    "ZKP_ONLY":  "non_regulated_acquirer",
}

def assign_type(category: str, size_tier: str) -> str:
    """
    Harmonized type assignment using the same logic as config.sauron_client_type.
    Returns FULL_KYC or ZKP_ONLY (matching the Sauron backend model).
    """
    return sauron_client_type(category, size_tier)

RINGS = [
    ("ring_adult",       "Age 18+ verified",       "Users confirmed to be over 18"),
    ("ring_social",      "Social identity",         "Users with verified social presence"),
    ("ring_financial",   "Financial eligible",      "Users cleared for financial products"),
    ("ring_healthcare",  "Healthcare eligible",     "Users cleared for medical platforms"),
    ("ring_gaming",      "Gaming age-gate",         "Users verified for gaming platforms (13+)"),
    ("ring_crypto",      "Crypto AML cleared",      "Users passing AML checks for crypto"),
]

# ── 1. Clients (sourced from companies.csv) ───────────────────────────────────
print("Building clients…")
companies = pl.read_csv(os.path.join(ROOT, "companies.csv"))
rows = []
for i, row in enumerate(companies.iter_rows(named=True)):
    category  = row["category"]
    size_tier = row["size_tier"]
    # Use client_type from CSV if available, otherwise compute it
    c_type    = row.get("client_type", None) or assign_type(category, size_tier)
    sector    = CATEGORY_TO_SECTOR[category]
    pool      = COUNTRY_POOLS[category]
    country   = pool[i % len(pool)]
    # FULL_KYC join earlier, ZKP_ONLY later
    if c_type == "FULL_KYC":
        join = START_DATE + timedelta(days=int(rng.integers(0, 90)))
    else:
        join = START_DATE + timedelta(days=int(rng.integers(60, 270)))
    rows.append((row["company_id"], row["name"], c_type, sector, country, join.isoformat()))

clients = pl.DataFrame(
    rows,
    schema=["client_id","name","type","sector","country","join_date"],
    orient="row"
)
clients.write_parquet(f"{OUT}/clients.parquet")
type_counts = clients["type"].value_counts().sort("count", descending=True)
print(f"  {len(clients)} clients")
for r in type_counts.iter_rows(named=True):
    print(f"    {r['type']}: {r['count']}")


# ── Credit economy constants ────────────────────────────────────────────────
CREDIT_A_PER_KYC = 1.0    # 1 Credit A earned per full KYC completed
KYC_USD_PER_HEAD = 2.00   # $2/KYC (1 Credit A = 5B × $0.40)
TOTAL_FIELDS     = 80     # total identity fields in a Sauron ring profile
BASE_B_RATE      = 10.0   # Credit B cost to access all 80 fields in one request
CREDIT_B_USD     = 0.40   # 1 Credit B = $0.40 USD (Sauron sale price)
EXCHANGE_A_TO_B  = 5.0    # Platform: 1 Credit A converts to 5 Credit B

all_dates = [START_DATE + timedelta(days=d) for d in range(DAYS)]

# ── Persona Sauron registration dates (beta(2,4) adoption curve) ────────────
# Used for: verification scheduling, ring enrollment
print("Computing persona Sauron join dates…")
personas_csv_path = os.path.join(ROOT, "personas.csv")
_personas_raw = pl.read_csv(personas_csv_path)
N_PERSONAS = len(_personas_raw)

# Beta(2,4) adoption curve → slow start, peak ~month 8, long tail
_beta_samples = rng.beta(2, 4, size=N_PERSONAS)
persona_sauron_join: dict[int, date] = {}
for idx, pid in enumerate(_personas_raw["id"].to_list()):
    offset_days = int(_beta_samples[idx] * DAYS)
    persona_sauron_join[pid] = START_DATE + timedelta(days=offset_days)

# ── 2. Verifications (persona-driven) ────────────────────────────────────────
print("Building verifications…")

# Separate issuers and acquirers
full_id_clients = [r for r in clients.iter_rows(named=True) if r["type"] == "FULL_KYC"]
acquirer_clients = [r for r in clients.iter_rows(named=True) if r["type"] == "ZKP_ONLY"]

# Assign each persona round-robin to a full_identification issuer
persona_to_issuer: dict[int, int] = {}
all_pids = _personas_raw["id"].to_list()
for idx, pid in enumerate(all_pids):
    if full_id_clients:
        issuer = full_id_clients[idx % len(full_id_clients)]
        persona_to_issuer[pid] = issuer["client_id"]

client_join_map = {r["client_id"]: date.fromisoformat(r["join_date"]) for r in clients.iter_rows(named=True)}

verify_rows = []

# --- KYC events (issuer side): persona-driven hard cap ---
# Each persona gets 1 initial KYC + annual re-KYC
for pid, issuer_cid in persona_to_issuer.items():
    issuer_join = client_join_map[issuer_cid]
    p_join = persona_sauron_join[pid]
    # Initial KYC: within 60 days of max(issuer live, persona Sauron join)
    earliest = max(issuer_join, p_join)
    kyc_date = earliest + timedelta(days=int(rng.integers(0, 61)))
    if kyc_date > END_DATE:
        continue

    # Failure rate declines from 18% → 8% over 24 months (maturity effect)
    months_since_start = (kyc_date - START_DATE).days / 30.0
    fail_rate = 0.18 - (0.10 * min(months_since_start / 24.0, 1.0))
    failed = 1 if rng.random() < fail_rate else 0
    n_fields_req = TOTAL_FIELDS
    cred_a = round(CREDIT_A_PER_KYC, 2) if not failed else 0.0

    verify_rows.append((issuer_cid, kyc_date.isoformat(), 1, 0, 1,
                        failed, n_fields_req, cred_a, 0.0, 1, 0))

    # Annual re-KYC on every 365-day anniversary within the data window
    rekyc_date = kyc_date + timedelta(days=365)
    while rekyc_date <= END_DATE:
        months_since = (rekyc_date - START_DATE).days / 30.0
        fail_rate_re = 0.18 - (0.10 * min(months_since / 24.0, 1.0))
        failed_re = 1 if rng.random() < fail_rate_re else 0
        cred_a_re = round(CREDIT_A_PER_KYC, 2) if not failed_re else 0.0
        verify_rows.append((issuer_cid, rekyc_date.isoformat(), 1, 0, 1,
                            failed_re, TOTAL_FIELDS, cred_a_re, 0.0, 0, 1))
        rekyc_date += timedelta(days=365)

# --- Attribute queries (acquirer side): onboarding-driven ---
# Each acquirer serves 5-30% of the user base, queries Sauron once at user onboarding
for acq in acquirer_clients:
    acq_cid = acq["client_id"]
    acq_join = client_join_map[acq_cid]
    # What fraction of users does this acquirer serve?
    user_share = float(rng.uniform(0.05, 0.30))
    n_users_served = max(1, int(N_PERSONAS * user_share))
    # Pick which personas (deterministic per acquirer)
    acq_rng = np.random.default_rng(acq_cid * 7919)
    served_indices = acq_rng.choice(N_PERSONAS, size=n_users_served, replace=False)

    for si in served_indices:
        pid = all_pids[si]
        # Query happens when persona joins Sauron or acquirer goes live, whichever is later
        p_join = persona_sauron_join[pid]
        query_date = max(acq_join, p_join) + timedelta(days=int(rng.integers(0, 31)))
        if query_date > END_DATE:
            continue

        n_fields_req = int(rng.integers(1, TOTAL_FIELDS))
        cred_b = round((n_fields_req / TOTAL_FIELDS) * BASE_B_RATE, 2)

        verify_rows.append((acq_cid, query_date.isoformat(), 0, 1, 1,
                            0, n_fields_req, 0.0, cred_b, 0, 0))

verifications = pl.DataFrame(
    verify_rows,
    schema=["client_id","date","full_kyc","reduced","total","failed",
            "n_fields","credit_a_earned","credit_b_spent",
            "initial_kyc","rekyc"],
    orient="row"
).sort(["client_id","date"])
verifications.write_parquet(f"{OUT}/verifications.parquet")

# Stats
total_full = int(verifications["full_kyc"].sum())
total_red = int(verifications["reduced"].sum())
total_init = int(verifications["initial_kyc"].sum())
total_rekyc = int(verifications["rekyc"].sum())
print(f"  {len(verifications)} verification rows")
print(f"    Full KYC: {total_full:,} (initial: {total_init:,}, re-KYC: {total_rekyc:,})")
print(f"    Attribute queries: {total_red:,}")

# ── 3. Credit Ledger ────────────────────────────────────────────────────────
print("Building credit ledger…")
client_types = {r["client_id"]: r["type"]      for r in clients.iter_rows(named=True)}
client_join  = {r["client_id"]: date.fromisoformat(r["join_date"]) for r in clients.iter_rows(named=True)}

ledger_rows: list = []
bal_a: dict[int, float] = {}   # Credit A balance per client
bal_b: dict[int, float] = {}   # Credit B balance per client

# Acquirers start with an initial Credit B purchase on join date
for row in clients.iter_rows(named=True):
    cid_  = row["client_id"]
    ctype = row["type"]
    join  = date.fromisoformat(row["join_date"])
    if ctype == "ZKP_ONLY":
        # ZKP_ONLY consumers purchase Credit B to access proofs
        init_b = round(float(rng.uniform(200, 1000)), 2)
        bal_b[cid_] = init_b
        ledger_rows.append((cid_, join.isoformat(), "B", "purchase",
                            init_b, round(init_b * CREDIT_B_USD, 2), init_b))
    else:  # FULL_KYC — earns Credit A organically, starts at 0
        bal_a[cid_] = 0.0

# Walk verifications chronologically to emit credit events
for row in verifications.sort(["date","client_id"]).iter_rows(named=True):
    cid_  = row["client_id"]
    ctype = client_types[cid_]
    d_str = row["date"]

    if ctype == "FULL_KYC" and row["credit_a_earned"] > 0:
        earned = row["credit_a_earned"]
        bal_a[cid_] = bal_a.get(cid_, 0.0) + earned
        ledger_rows.append((cid_, d_str, "A", "kyc_earned",
                            earned, 0.0, round(bal_a[cid_], 2)))
        # Occasional A → B conversion (0.1% of days)
        if rng.random() < 0.001 and bal_a.get(cid_, 0.0) > 50:
            conv_a = round(float(rng.uniform(10, min(50, bal_a[cid_]))), 2)
            conv_b = round(conv_a * EXCHANGE_A_TO_B, 2)
            bal_a[cid_] -= conv_a
            bal_b[cid_]  = bal_b.get(cid_, 0.0) + conv_b
            ledger_rows.append((cid_, d_str, "A", "convert_to_B",
                                -conv_a, 0.0, round(bal_a[cid_], 2)))
            ledger_rows.append((cid_, d_str, "B", "convert_from_A",
                                conv_b, 0.0, round(bal_b[cid_], 2)))

    elif ctype == "ZKP_ONLY" and row["credit_b_spent"] > 0:
        spent = row["credit_b_spent"]
        cur   = bal_b.get(cid_, 0.0)
        # Auto top-up when balance runs low
        if cur - spent < 20:
            topup = round(float(rng.uniform(100, 500)), 2)
            bal_b[cid_] = cur + topup
            cur = bal_b[cid_]
            ledger_rows.append((cid_, d_str, "B", "purchase",
                                topup, round(topup * CREDIT_B_USD, 2), round(cur, 2)))
        bal_b[cid_] = cur - spent
        ledger_rows.append((cid_, d_str, "B", "verify_spent",
                            -round(spent, 2), 0.0, round(bal_b[cid_], 2)))

credit_ledger = pl.DataFrame(
    ledger_rows,
    schema=["client_id","date","credit_type","event_type","amount","usd_value","balance_after"],
    orient="row"
).sort(["client_id","date"])
credit_ledger.write_parquet(f"{OUT}/credit_ledger.parquet")

# Summarise
a_total = credit_ledger.filter((pl.col("credit_type")=="A") & (pl.col("amount")>0))["amount"].sum()
b_total = credit_ledger.filter((pl.col("credit_type")=="B") & (pl.col("event_type")=="purchase"))["amount"].sum()
b_spent = credit_ledger.filter(pl.col("event_type")=="verify_spent")["amount"].abs().sum()
print(f"  {len(credit_ledger)} ledger entries")
print(f"    Credit A earned:  {a_total:,.0f}")
print(f"    Credit B purchased: {b_total:,.0f}")
print(f"    Credit B spent:   {b_spent:,.0f}")

# ── 4. Ring snapshots (monthly, anchored to persona registration) ─────────────
print("Building ring snapshots…")

ring_rows = []
ring_base = {
    "ring_adult":      0,
    "ring_social":     0,
    "ring_financial":  0,
    "ring_healthcare": 0,
    "ring_gaming":     0,
    "ring_crypto":     0,
}

# Ring enrollment: persona_sauron_join + 0-45 day delay
ring_enrollment: dict[str, list[date]] = {rn: [] for rn, _, _ in RINGS}
for pid in all_pids:
    p_join = persona_sauron_join[pid]
    # Each persona enrolls in 2-4 random rings
    n_rings = int(rng.integers(2, 5))
    chosen = rng.choice(len(RINGS), size=min(n_rings, len(RINGS)), replace=False)
    for ri in chosen:
        ring_name = RINGS[ri][0]
        enroll_date = p_join + timedelta(days=int(rng.integers(0, 46)))
        if enroll_date <= END_DATE:
            ring_enrollment[ring_name].append(enroll_date)

d = date(2024, 1, 1)
while d <= END_DATE:
    months_elapsed = (d.year - 2024) * 12 + d.month - 1
    for ring_id, (ring_name, label, desc) in enumerate(RINGS):
        base = ring_base[ring_name]
        # Count enrollments up to this month
        enrolled = sum(1 for ed in ring_enrollment[ring_name] if ed <= d)
        count = base + enrolled
        ring_rows.append((ring_name, label, d.isoformat(), count))
    # advance one month
    if d.month == 12:
        d = date(d.year + 1, 1, 1)
    else:
        d = date(d.year, d.month + 1, 1)

ring_snapshots = pl.DataFrame(
    ring_rows,
    schema=["ring_id","ring_label","date","member_count"],
    orient="row"
)
ring_snapshots.write_parquet(f"{OUT}/ring_snapshots.parquet")
print(f"  {len(ring_snapshots)} ring snapshot rows")

# ── 5. Anomaly events ────────────────────────────────────────────────────────
print("Building anomaly events…")

ANOMALY_TYPES = [
    ("spike_verifications",  "high",   "Verification volume spike: {n}x above baseline"),
    ("low_balance",          "medium", "Token balance critically low: {n} tokens remaining"),
    ("high_failure_rate",    "high",   "Verification failure rate {n}% exceeds threshold"),
    ("rapid_token_burn",     "medium", "Tokens consumed {n}x faster than 30-day average"),
    ("dormancy_break",       "low",    "Client resumed activity after {n} days of inactivity"),
    ("unusual_hour_pattern", "low",    "Unusual verification pattern detected off-hours"),
]

anomaly_rows = []
for row in clients.iter_rows(named=True):
    cid_  = row["client_id"]
    ctype = row["type"]
    join  = date.fromisoformat(row["join_date"])
    # Each client gets 2-8 anomalies across the period
    n_anomalies = int(rng.integers(2, 9))
    for _ in range(n_anomalies):
        atype_idx = rng.integers(0, len(ANOMALY_TYPES))
        atype, severity, tmpl = ANOMALY_TYPES[atype_idx]
        days_offset = int(rng.integers(0, DAYS))
        ev_date = (START_DATE + timedelta(days=days_offset))
        if ev_date < join:
            ev_date = join + timedelta(days=int(rng.integers(1, 30)))
        n_val = int(rng.integers(2, 20))
        msg = tmpl.format(n=n_val)
        anomaly_rows.append((cid_, ev_date.isoformat(), atype, severity, msg))

anomalies = pl.DataFrame(
    anomaly_rows,
    schema=["client_id","date","anomaly_type","severity","message"],
    orient="row"
).sort("date", descending=True)
anomalies.write_parquet(f"{OUT}/anomaly_events.parquet")
print(f"  {len(anomalies)} anomaly events")

# ── 6. Sauron users (GDPR retention tracking) ────────────────────────────────
# One row per persona. last_auth_date drives GDPR purge eligibility.
# personas.csv is the read-only synthetic source of truth.
# users.csv is the writable copy that GDPR actually modifies.
# Distribution (today ≈ 2026-02-22, cutoff = 1 year back):
#   65% active    → last_auth within last 12 months
#   15% borderline→ last_auth 12-18 months ago (just over threshold, EU only)
#   20% inactive  → last_auth >18 months ago (EU eligible for purge)
personas_df = pl.read_csv(os.path.join(ROOT, "personas.csv"))
n_personas  = len(personas_df)

rng_u = np.random.default_rng(99)
today_u = date(2026, 2, 22)

def _rand_date(lo: date, hi: date, n: int) -> list[str]:
    span = (hi - lo).days
    offsets = rng_u.integers(0, max(span, 1), size=n)
    return [(lo + timedelta(days=int(o))).isoformat() for o in offsets]

n_active      = int(n_personas * 0.65)
n_borderline  = int(n_personas * 0.15)
n_inactive    = n_personas - n_active - n_borderline

last_auth_dates = (
    _rand_date(date(2025, 2, 22), date(2025, 12, 31), n_active) +
    _rand_date(date(2024, 8, 22), date(2025, 2, 21), n_borderline) +
    _rand_date(date(2022, 1, 1),  date(2024, 8, 21), n_inactive)
)
rng_u.shuffle(last_auth_dates)

created_dates = _rand_date(date(2021, 1, 1), date(2024, 1, 1), n_personas)

sauron_users = pl.DataFrame({
    "persona_id":      personas_df["id"].to_list(),
    "country":         personas_df["country"].to_list(),   # needed for EU/EEA filter
    "created_at":      created_dates,
    "last_auth_date":  last_auth_dates,
    "is_anonymized":   [False] * n_personas,
    "gdpr_purge_date": [None]  * n_personas,
}, schema={
    "persona_id":      pl.Int64,
    "country":         pl.Utf8,
    "created_at":      pl.Utf8,
    "last_auth_date":  pl.Utf8,
    "is_anonymized":   pl.Boolean,
    "gdpr_purge_date": pl.Utf8,
})

sauron_users.write_parquet(f"{OUT}/sauron_users.parquet")

# Bootstrap users.csv from personas.csv if it doesn't exist
users_csv_path = os.path.join(ROOT, "users.csv")
if not os.path.exists(users_csv_path):
    import shutil
    shutil.copy2(personas_csv_path, users_csv_path)
    print(f"  Bootstrapped {users_csv_path} from personas.csv")

# Reset the GDPR audit log on full rebuild (fresh state)
gdpr_log_path = os.path.join(OUT, "gdpr_log.parquet")
if os.path.exists(gdpr_log_path):
    os.remove(gdpr_log_path)

EU_EEA = {"at","be","bg","hr","cy","cz","dk","ee","fi","fr","de","gr","hu",
           "ie","ire","it","lv","lt","lu","mt","nl","pl","pt","ro","sk","si",
           "es","se","swe","no","is","li"}
n_eu_eligible = sauron_users.filter(
    pl.col("country").is_in(list(EU_EEA)) &
    (pl.col("last_auth_date") < str(today_u - timedelta(days=365)))
).height
print(f"  {n_personas} sauron users generated — {n_eu_eligible} EU/EEA users eligible for GDPR purge (non-EU exempt)")

print("\nAll done. Files in:", OUT)
