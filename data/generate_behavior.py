"""
generate_behavior.py
Generates behavior.csv: internet expense frequency distributions and monthly
spend envelopes for synthetic users, segmented by country, wealth tier, and generation.

Frequency meaning:
  once     - high friction, consolidates all spending into a single transaction
  sometimes- low-moderate friction, a few transactions per month
  often    - moderate-low friction, several transactions per week
  always   - no friction, pays many times per day/week without hesitation

Total monthly spend budget is the same across frequencies for a given segment;
frequency reflects behaviour pattern, not total amount.
"""

import csv
import os

# ---------------------------------------------------------------------------
# Base probability distributions per wealth tier (millennial as neutral baseline)
# Shape: [p_once, p_sometimes, p_often, p_always]
# ---------------------------------------------------------------------------
BASE_DISTRIBUTIONS = {
    "bottom_50": [0.40, 0.35, 0.18, 0.07],
    "top_25":    [0.22, 0.33, 0.28, 0.17],
    "top_10":    [0.12, 0.23, 0.33, 0.32],
    "top_1":     [0.05, 0.15, 0.30, 0.50],
}

# ---------------------------------------------------------------------------
# Generation modifiers: delta applied to [once, sometimes, often, always]
# Gen Z  -> shifts toward always (lower friction)
# Boomer -> shifts toward once   (higher friction)
# Millennial is the baseline (no shift)
# Deltas are renormalised after application to ensure sum == 1.0
# ---------------------------------------------------------------------------
GENERATION_SHIFTS = {
    "millennial": [ 0.00,  0.00,  0.00,  0.00],
    "gen_z":      [-0.08, -0.02,  0.04,  0.06],
    "boomer":     [+0.08,  0.02, -0.04, -0.06],
}

# ---------------------------------------------------------------------------
# Monthly spend envelopes in USD (low, mid, high) per wealth tier (USA base)
# These represent the total monthly internet spend budget, NOT per-transaction.
# ---------------------------------------------------------------------------
USD_SPEND = {
    "bottom_50": (5,   15,   30),
    "top_25":    (30,  60,  100),
    "top_10":    (100, 200, 400),
    "top_1":     (400, 800, 2000),
}

# ---------------------------------------------------------------------------
# Country purchasing-power multipliers relative to USA = 1.0
# ---------------------------------------------------------------------------
COUNTRY_MULTIPLIERS = {
    "usa":   1.00,
    "uk":    0.90,
    "fr":    0.80,
    "ire":   0.85,
    "swe":   0.95,
    "china": 0.40,
}

COUNTRIES    = list(COUNTRY_MULTIPLIERS.keys())
WEALTH_TIERS = list(BASE_DISTRIBUTIONS.keys())
GENERATIONS  = list(GENERATION_SHIFTS.keys())

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "behavior.csv")
FIELDNAMES  = [
    "country", "wealth_tier", "generation",
    "p_once", "p_sometimes", "p_often", "p_always",
    "monthly_spend_low_usd", "monthly_spend_mid_usd", "monthly_spend_high_usd",
]


def apply_generation_shift(base: list[float], shift: list[float]) -> list[float]:
    """Apply a delta shift to a base distribution and renormalise to sum to 1."""
    shifted = [max(0.0, b + s) for b, s in zip(base, shift)]
    total = sum(shifted)
    return [round(v / total, 2) for v in shifted]


def adjust_last(probs: list[float]) -> list[float]:
    """Fix floating-point rounding so probabilities sum exactly to 1.00."""
    diff = round(1.0 - sum(probs), 2)
    probs[-1] = round(probs[-1] + diff, 2)
    return probs


def compute_spend(wealth_tier: str, multiplier: float) -> tuple[int, int, int]:
    low, mid, high = USD_SPEND[wealth_tier]
    return (
        round(low  * multiplier),
        round(mid  * multiplier),
        round(high * multiplier),
    )


def generate_rows() -> list[dict]:
    rows = []
    for country in COUNTRIES:
        multiplier = COUNTRY_MULTIPLIERS[country]
        for wealth_tier in WEALTH_TIERS:
            base = BASE_DISTRIBUTIONS[wealth_tier]
            spend_low, spend_mid, spend_high = compute_spend(wealth_tier, multiplier)
            for generation in GENERATIONS:
                shift = GENERATION_SHIFTS[generation]
                probs = apply_generation_shift(base, shift)
                probs = adjust_last(probs)
                rows.append({
                    "country":                country,
                    "wealth_tier":            wealth_tier,
                    "generation":             generation,
                    "p_once":                 probs[0],
                    "p_sometimes":            probs[1],
                    "p_often":                probs[2],
                    "p_always":               probs[3],
                    "monthly_spend_low_usd":  spend_low,
                    "monthly_spend_mid_usd":  spend_mid,
                    "monthly_spend_high_usd": spend_high,
                })
    return rows


def main():
    rows = generate_rows()
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Written {len(rows)} rows to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
