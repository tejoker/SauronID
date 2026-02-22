"""
generate_expenses.py
Generates expenses.csv: monthly expense allocation distributions per synthetic
user segment (country × wealth_tier × generation).

Each row gives, for 5 categories, the mean % and std % of monthly income:
  Food/Living, Tech, Lifestyle, Travel, Investment

Monthly income is derived from net worth using a wealth-tier-specific factor
(income_factor): monthly_income ≈ net_worth / income_factor

Example: bottom_50 Gen Z USA → median net worth $10,222 / 10 ≈ $1,022/month
         90% of $1,022 = ~$920 on Food/Living — realistic.

Investment is wealth-gated: only available to top_25 and above. bottom_50
have investment_mean=0, investment_std=0.

All means are renormalised to sum exactly to 100% after applying deltas.
"""

import csv
import os

# ---------------------------------------------------------------------------
# Net worth → implied monthly income conversion factor per wealth tier
# monthly_income = net_worth / income_factor
# ---------------------------------------------------------------------------
INCOME_FACTOR = {
    "bottom_50":  10,
    "top_25":     25,
    "top_10":     80,
    "top_1":     200,
}

# ---------------------------------------------------------------------------
# Baseline expense split (millennial, USA) — means and stds in % of income
# Categories: food_living, tech, lifestyle, travel, investment
# bottom_50: investment is 0 (wealth-gated)
# ---------------------------------------------------------------------------
BASE = {
    #             food  tech  life  trav  invest
    "bottom_50": {
        "mean": [77.0,  6.0, 10.0,  5.0,   2.0],
        "std":  [ 8.0,  2.0,  3.0,  2.0,   1.0],
    },
    "top_25": {
        "mean": [45.0, 10.0, 20.0, 10.0,  15.0],
        "std":  [ 6.0,  3.0,  4.0,  3.0,   4.0],
    },
    "top_10": {
        "mean": [32.0, 13.0, 20.0, 15.0,  20.0],
        "std":  [ 5.0,  3.0,  4.0,  4.0,   5.0],
    },
    "top_1": {
        "mean": [20.0, 10.0, 20.0, 15.0,  35.0],
        "std":  [ 4.0,  3.0,  4.0,  4.0,   5.0],
    },
}

CATEGORIES = ["food_living", "tech", "lifestyle", "travel", "investment"]

# ---------------------------------------------------------------------------
# Country deltas applied to means [food, tech, life, trav, invest]
# USA is baseline (all zeros). Deltas are renormalised after application.
# ---------------------------------------------------------------------------
COUNTRY_DELTAS = {
    "usa":   [ 0.0,  0.0,  0.0,  0.0,  0.0],
    "uk":    [-3.0,  0.0, +3.0,  0.0,  0.0],
    "fr":    [+3.0, -2.0, +1.0, +1.0, -3.0],
    "ire":   [-2.0,  0.0, +2.0,  0.0,  0.0],
    "swe":   [-4.0, +3.0, +1.0,  0.0,  0.0],
    "china": [+2.0, +4.0, -1.0, -3.0, -2.0],
}

# ---------------------------------------------------------------------------
# Generation deltas applied to means [food, tech, life, trav, invest]
# millennial is baseline. Deltas are renormalised after application.
# ---------------------------------------------------------------------------
GENERATION_DELTAS = {
    "millennial": [ 0.0,  0.0,  0.0,  0.0,  0.0],
    "gen_z":      [-3.0, +3.0, +4.0, -2.0, -2.0],
    "boomer":     [-1.0, -4.0, -2.0, +3.0, +4.0],
}

COUNTRIES    = list(COUNTRY_DELTAS.keys())
WEALTH_TIERS = list(BASE.keys())
GENERATIONS  = list(GENERATION_DELTAS.keys())

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "expenses.csv")

FIELDNAMES = (
    ["country", "wealth_tier", "generation", "income_factor"]
    + [f"{c}_mean_pct" for c in CATEGORIES]
    + [f"{c}_std_pct"  for c in CATEGORIES]
)


def apply_deltas(base_means: list[float], *delta_lists) -> list[float]:
    """Sum base means with all provided delta vectors, clamp negatives to 0."""
    result = list(base_means)
    for deltas in delta_lists:
        result = [m + d for m, d in zip(result, deltas)]
    return [max(0.0, v) for v in result]


def renormalise(means: list[float], is_bottom_50: bool) -> list[float]:
    """
    Renormalise means to sum to 100%.
    For bottom_50: investment index (4) is forced to 0 first (wealth-gated).
    """
    if is_bottom_50:
        means[4] = 0.0
    total = sum(means)
    if total == 0:
        return means
    return [round(v * 100.0 / total, 2) for v in means]


def fix_rounding(means: list[float]) -> list[float]:
    """Ensure means sum to exactly 100.00 by adjusting the largest component."""
    diff = round(100.0 - sum(means), 2)
    max_idx = means.index(max(means))
    means[max_idx] = round(means[max_idx] + diff, 2)
    return means


def generate_rows() -> list[dict]:
    rows = []
    for country in COUNTRIES:
        c_delta = COUNTRY_DELTAS[country]
        for wealth_tier in WEALTH_TIERS:
            base_means = list(BASE[wealth_tier]["mean"])
            base_stds  = list(BASE[wealth_tier]["std"])
            is_b50     = wealth_tier == "bottom_50"
            factor     = INCOME_FACTOR[wealth_tier]

            for generation in GENERATIONS:
                g_delta = GENERATION_DELTAS[generation]

                # Apply country + generation deltas to means
                means = apply_deltas(base_means, c_delta, g_delta)
                means = renormalise(means, is_b50)
                means = fix_rounding(means)

                # Stds are kept per-tier (not shifted by country/generation)
                # but zeroed for investment if bottom_50
                stds = list(base_stds)
                if is_b50:
                    stds[4] = 0.0

                row = {
                    "country":      country,
                    "wealth_tier":  wealth_tier,
                    "generation":   generation,
                    "income_factor": factor,
                }
                for i, cat in enumerate(CATEGORIES):
                    row[f"{cat}_mean_pct"] = means[i]
                    row[f"{cat}_std_pct"]  = stds[i]

                rows.append(row)
    return rows


def main():
    rows = generate_rows()
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written {len(rows)} rows to {OUTPUT_FILE}")
    print(f"Segments: {len(COUNTRIES)} countries × {len(WEALTH_TIERS)} tiers × {len(GENERATIONS)} generations")
    print()
    print("income_factor meaning: monthly_income = net_worth / income_factor")
    for tier, factor in INCOME_FACTOR.items():
        print(f"  {tier:12s} ÷ {factor}")


if __name__ == "__main__":
    main()
