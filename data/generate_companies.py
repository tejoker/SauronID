"""
generate_companies.py
Generates two CSVs:
  companies.csv      - 50 fictional companies (10 per expense category)
  company_trends.csv - monthly trend index + estimated customer count for each
                       company across 12 months, with event markers

All companies serve all 6 countries.
Trend shapes are defined per category; individual companies add Gaussian noise
so each curve is unique.

Volume is scaled proportionally to N_PERSONAS (set in config.py).
At 1 000 personas: startup 10-80, sme 80-300, enterprise 300-900.
Ranges scale linearly so transaction density per persona stays constant.
"""

import csv
import os
import random
import math
from config import SIZE_RANGE, sauron_client_type

random.seed(7)

DIR = os.path.dirname(__file__)
COMPANIES_CSV = os.path.join(DIR, "companies.csv")
TRENDS_CSV    = os.path.join(DIR, "company_trends.csv")

# ---------------------------------------------------------------------------
# Company roster: (name, category, size_tier)
# Mix of realistic-sounding and generic fictional brand names
# ---------------------------------------------------------------------------
COMPANIES_DATA = [
    # --- Tech ---
    ("NexaCloud",      "tech", "enterprise"),
    ("Pixelwave",      "tech", "sme"),
    ("ByteForge",      "tech", "sme"),
    ("GridStack",      "tech", "startup"),
    ("Fluxio",         "tech", "sme"),
    ("SyncPath",       "tech", "startup"),
    ("Orbitly",        "tech", "enterprise"),
    ("VaultNet",       "tech", "sme"),
    ("Crestdesk",      "tech", "enterprise"),
    ("Luminary Tech",  "tech", "startup"),
    # --- Lifestyle ---
    ("Aura Living",    "lifestyle", "sme"),
    ("Chroma Style",   "lifestyle", "startup"),
    ("Bloom & Co",     "lifestyle", "enterprise"),
    ("Velvet Lane",    "lifestyle", "sme"),
    ("Driftwood",      "lifestyle", "sme"),
    ("Nomad Wear",     "lifestyle", "startup"),
    ("CasaVerde",      "lifestyle", "enterprise"),
    ("Lumis Home",     "lifestyle", "sme"),
    ("KINETIC",        "lifestyle", "enterprise"),
    ("Pure Form",      "lifestyle", "startup"),
    # --- Food/Living ---
    ("TableRoot",      "food_living", "enterprise"),
    ("FreshGrid",      "food_living", "sme"),
    ("Nourish & Co",   "food_living", "sme"),
    ("HomeMarket",     "food_living", "enterprise"),
    ("DailyBasket",    "food_living", "startup"),
    ("PantryBox",      "food_living", "sme"),
    ("GreenTree Foods","food_living", "enterprise"),
    ("CityBite",       "food_living", "startup"),
    ("NestEats",       "food_living", "sme"),
    ("UrbanGrain",     "food_living", "startup"),
    # --- Travel ---
    ("Waybound",       "travel", "enterprise"),
    ("Skim Travel",    "travel", "sme"),
    ("Meridian Air",   "travel", "enterprise"),
    ("BluePath",       "travel", "sme"),
    ("Nomadex",        "travel", "startup"),
    ("SkyBridge",      "travel", "enterprise"),
    ("TerraRoute",     "travel", "sme"),
    ("WanderlustCo",   "travel", "sme"),
    ("Crestline Travel","travel","startup"),
    ("Orbita",         "travel", "startup"),
    # --- Investment ---
    ("Fortio",         "investment", "enterprise"),
    ("Crestwealth",    "investment", "sme"),
    ("Pinnacle Capital","investment","enterprise"),
    ("NexaFund",       "investment", "sme"),
    ("EquiVault",      "investment", "startup"),
    ("Verdant Finance","investment", "sme"),
    ("HarborPlan",     "investment", "enterprise"),
    ("StellarInvest",  "investment", "startup"),
    ("TrustPath",      "investment", "sme"),
    ("ApexWealth",     "investment", "startup"),
]

# Base monthly customers per size tier (drawn uniformly)
# SIZE_RANGE is imported from config.py and scales with N_PERSONAS

# ---------------------------------------------------------------------------
# Seasonal trend index per category (12 months, Jan=index 0)
# Values represent a multiplier on base volume; 1.0 = average month.
# ---------------------------------------------------------------------------
CATEGORY_TREND = {
    #           Jan   Feb   Mar   Apr   May   Jun   Jul   Aug   Sep   Oct   Nov   Dec
    "tech":    [0.80, 0.78, 0.88, 0.90, 0.95, 0.98, 1.00, 1.02, 1.05, 1.10, 1.55, 1.80],
    "lifestyle":[1.10, 0.85, 0.80, 0.90, 1.05, 1.30, 1.50, 1.45, 0.85, 0.90, 1.35, 1.60],
    "food_living":[1.05,0.95, 0.95, 1.00, 1.00, 1.00, 1.02, 1.02, 0.98, 0.98, 1.03, 1.15],
    "travel":  [1.20, 0.90, 0.95, 1.05, 1.15, 1.40, 1.80, 1.75, 0.75, 0.70, 0.95, 1.50],
    "investment":[1.35,1.00, 1.00, 1.25, 0.95, 0.85, 0.80, 0.82, 0.95, 1.15, 1.20, 1.10],
}

# Event markers: (month_idx, label)  month_idx is 0-based
EVENT_MARKERS = {
    1:  "New Year resolution",
    4:  "Tax season",
    7:  "Summer peak",
    8:  "Summer peak",
    11: "Black Friday",
    12: "Christmas/Holiday",
    13: "Winter holiday travel",   # mapped to month 1 (Dec index 11 + Jan index 0)
}

MONTH_EVENTS = {
    # month number (1-12): event label
    1:  "New Year",
    4:  "Tax season",
    7:  "Summer peak",
    8:  "Summer peak",
    11: "Black Friday",
    12: "Christmas / Holiday",
}

# Category-specific event overrides
CATEGORY_EVENTS = {
    "tech":        {11: "Black Friday", 12: "Holiday gifting"},
    "lifestyle":   {7: "Summer fashion", 8: "Summer fashion", 11: "Black Friday", 12: "Christmas"},
    "food_living": {12: "Christmas feasting"},
    "travel":      {1: "Winter getaways", 7: "Summer holidays", 8: "Summer holidays", 12: "Ski season"},
    "investment":  {1: "New Year portfolios", 4: "Tax-loss harvesting", 10: "Year-end planning", 11: "Year-end planning"},
}

NOISE_SIGMA = 0.10   # 10% standard deviation on the trend index per company-month

# Countries (all companies serve all)
ALL_COUNTRIES = ["usa", "china", "fr", "uk", "ire", "swe"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sample_base_customers(size_tier: str) -> int:
    lo, hi = SIZE_RANGE[size_tier]
    return random.randint(lo, hi)


def add_noise(index: float, sigma: float = NOISE_SIGMA) -> float:
    """Apply multiplicative Gaussian noise; clamp to [0.1, 4.0]."""
    noisy = index * random.gauss(1.0, sigma)
    return round(max(0.1, min(4.0, noisy)), 4)


def get_event(category: str, month: int) -> str:
    """Return event label for (category, month) or empty string."""
    cat_events = CATEGORY_EVENTS.get(category, {})
    return cat_events.get(month, "")

# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate():
    companies = []
    for idx, (name, category, size_tier) in enumerate(COMPANIES_DATA, start=1):
        companies.append({
            "company_id":             idx,
            "name":                   name,
            "category":               category,
            "size_tier":              size_tier,
            "client_type":            sauron_client_type(category, size_tier),
            "countries_served":       ";".join(ALL_COUNTRIES),
            "base_monthly_customers": sample_base_customers(size_tier),
        })

    # Write companies.csv
    with open(COMPANIES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "company_id", "name", "category", "size_tier", "client_type",
            "countries_served", "base_monthly_customers",
        ])
        writer.writeheader()
        writer.writerows(companies)
    print(f"Written {len(companies)} companies → {COMPANIES_CSV}")

    # Generate monthly trends
    trend_rows = []
    for company in companies:
        cid      = company["company_id"]
        category = company["category"]
        base     = company["base_monthly_customers"]
        cat_curve = CATEGORY_TREND[category]

        for month in range(1, 13):
            base_index  = cat_curve[month - 1]
            noisy_index = add_noise(base_index)
            estimated   = round(base * noisy_index)
            event       = get_event(category, month)
            trend_rows.append({
                "company_id":         cid,
                "company_name":       company["name"],
                "category":           category,
                "month":              month,
                "trend_index":        noisy_index,
                "estimated_customers": estimated,
                "event_marker":       event,
            })

    with open(TRENDS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "company_id", "company_name", "category", "month",
            "trend_index", "estimated_customers", "event_marker",
        ])
        writer.writeheader()
        writer.writerows(trend_rows)
    print(f"Written {len(trend_rows)} trend rows → {TRENDS_CSV}")

    # Summary per category
    print()
    from collections import defaultdict, Counter
    by_cat = defaultdict(list)
    for c in companies:
        by_cat[c["category"]].append(c)
    for cat, rows in sorted(by_cat.items()):
        counts = {"startup": 0, "sme": 0, "enterprise": 0}
        for r in rows:
            counts[r["size_tier"]] += 1
        sizes = " | ".join(f"{k}: {v}" for k, v in counts.items())
        avg_base = sum(r["base_monthly_customers"] for r in rows) // len(rows)
        print(f"  {cat:12s}  {sizes}   avg base: {avg_base} customers/mo")

    # Sauron client type summary
    type_counts = Counter(c["client_type"] for c in companies)
    print()
    print("Sauron client type distribution:")
    for t, v in sorted(type_counts.items()):
        names = [c["name"] for c in companies if c["client_type"] == t]
        print(f"  {t:10s}: {v:2d}  ({', '.join(names[:5])}{'...' if len(names) > 5 else ''})")


if __name__ == "__main__":
    generate()
