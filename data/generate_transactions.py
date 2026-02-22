"""
generate_transactions.py
========================
Generates synthetic transaction data from personas × company_trends.
All heavy computation uses NumPy; I/O and output use Polars + Parquet (zstd).

Output: transactions.parquet
Schema:
  transaction_id  int32
  company_id      int16
  customer_id     int32    (persona id)
  timestamp       datetime[ms]  (year 2025)
  amount_usd      float32
  is_fraud        bool
  fraud_type      str      (null | "account_takeover" | "amount_anomaly" | "velocity")
"""

import os
import numpy as np
import polars as pl
from datetime import datetime

SEED = 42
RNG  = np.random.default_rng(SEED)
ROOT = os.path.dirname(os.path.abspath(__file__))

# ── Fraud parameters
FRAUD_RATE   = 0.002                     # 0.2% of total transactions
FRAUD_SPLIT  = [0.34, 0.33, 0.33]       # takeover / anomaly / velocity

# ── Transactions per customer visit, by internet_frequency
FREQ_TXN = {
    "once":      (1, 1),
    "sometimes": (2, 4),
    "often":     (5, 10),
    "always":   (10, 20),
}

CATEGORIES     = ["food_living", "tech", "lifestyle", "travel", "investment"]
DAYS_IN_MONTH  = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]   # 2025


# ─────────────────────────────────────────────────────────
# Load CSVs with Polars (fast, typed)
# ─────────────────────────────────────────────────────────
def load_data():
    personas = pl.read_csv(os.path.join(ROOT, "personas.csv")).with_columns([
        pl.col("id").cast(pl.Int32),
        *[pl.col(f"{c}_usd").cast(pl.Float32) for c in CATEGORIES],
    ])
    companies = pl.read_csv(os.path.join(ROOT, "companies.csv")).with_columns(
        pl.col("company_id").cast(pl.Int16)
    )
    trends = pl.read_csv(os.path.join(ROOT, "company_trends.csv")).with_columns([
        pl.col("company_id").cast(pl.Int16),
        pl.col("month").cast(pl.Int8),
        pl.col("estimated_customers").cast(pl.Int32),
        pl.col("trend_index").cast(pl.Float32),
    ])
    return personas, companies, trends


# ─────────────────────────────────────────────────────────
# Build NumPy lookup tables for hot-path sampling
# ─────────────────────────────────────────────────────────
def build_lookups(personas: pl.DataFrame):
    p_ids  = personas["id"].to_numpy().astype(np.int32)
    p_freq = personas["internet_frequency"].to_list()
    # float32 spend arrays, one per category
    cat_spend = {
        c: personas[f"{c}_usd"].to_numpy().astype(np.float32)
        for c in CATEGORIES
    }
    # per-category normalised sampling weights
    cat_weights = {}
    for cat, arr in cat_spend.items():
        w     = np.maximum(arr, 0.0)
        total = w.sum()
        cat_weights[cat] = w / total if total > 0 else np.full(len(arr), 1.0 / len(arr))
    return p_ids, p_freq, cat_spend, cat_weights


# ─────────────────────────────────────────────────────────
# Fast vectorised timestamp generation (ms since epoch)
# ─────────────────────────────────────────────────────────
def random_timestamps(n: int, month: int) -> np.ndarray:
    """n timestamps distributed across 2025-{month}, business-hour-biased."""
    base      = int(datetime(2025, month, 1).timestamp() * 1000)
    days      = DAYS_IN_MONTH[month - 1]
    day_ms    = 86_400_000
    # Hours: normal around 13:00, σ=3h, clipped 0–23
    hours     = (RNG.standard_normal(n) * 3.0 + 13.0).clip(0, 23).astype(np.int32)
    day_off   = RNG.integers(0, days, size=n)
    min_off   = RNG.integers(0, 60, size=n)
    return (base + day_off * day_ms + hours * 3_600_000 + min_off * 60_000).astype(np.int64)


# ─────────────────────────────────────────────────────────
# Main generation loop
# ─────────────────────────────────────────────────────────
def generate(personas, companies, trends):
    p_ids, p_freq, cat_spend, cat_weights = build_lookups(personas)
    n_personas = len(p_ids)

    co_to_cat: dict[int, str] = {
        row["company_id"]: row["category"]
        for row in companies.iter_rows(named=True)
    }

    # Pre-allocate accumulator lists (avoids repeated list.append overhead in tight loop)
    txn_ids:   list[int]   = []
    co_ids:    list[int]   = []
    cust_ids:  list[int]   = []
    ts_ms:     list[int]   = []
    amounts:   list[float] = []
    txn_id = 0

    for row in trends.iter_rows(named=True):
        co_id  = int(row["company_id"])
        month  = int(row["month"])
        n_cust = int(row["estimated_customers"])
        cat    = co_to_cat.get(co_id)
        if not cat or n_cust == 0:
            continue

        # Sample n_cust persona indices (vectorised, O(n_cust))
        sampled = RNG.choice(n_personas, size=n_cust, replace=True, p=cat_weights[cat])

        for idx in sampled:
            pid        = int(p_ids[idx])
            freq       = p_freq[idx]
            lo, hi     = FREQ_TXN.get(freq, (1, 3))
            n_txn      = int(RNG.integers(lo, hi + 1))

            # Monthly spend at this company: random share [30 %, 70 %] of category spend
            mo_spend  = float(cat_spend[cat][idx])
            if mo_spend <= 0.0:
                mo_spend = 1.0
            share     = float(RNG.uniform(0.3, 0.7))
            per_txn   = max(0.5, mo_spend * share / n_txn)

            ts = random_timestamps(n_txn, month)
            # Vectorised amounts with ±15 % Gaussian noise
            noise  = 1.0 + 0.15 * RNG.standard_normal(n_txn)
            amts   = np.maximum(0.5, (per_txn * noise).astype(np.float32))

            for t in range(n_txn):
                txn_ids.append(txn_id)
                co_ids.append(co_id)
                cust_ids.append(pid)
                ts_ms.append(int(ts[t]))
                amounts.append(float(amts[t]))
                txn_id += 1

    return txn_ids, co_ids, cust_ids, ts_ms, amounts


# ─────────────────────────────────────────────────────────
# Fraud injection — pure NumPy, no Python loops over arrays
# ─────────────────────────────────────────────────────────
def inject_fraud(
    txn_ids: list, co_ids: list, cust_ids: list, ts_ms: list, amounts: list
):
    n       = len(amounts)
    n_fraud = max(1, int(n * FRAUD_RATE))

    n_take  = int(n_fraud * FRAUD_SPLIT[0])
    n_anom  = int(n_fraud * FRAUD_SPLIT[1])
    n_vel   = n_fraud - n_take - n_anom

    is_fraud  = np.zeros(n, dtype=np.bool_)
    ftype     = np.full(n, None, dtype=object)
    amt_arr   = np.array(amounts, dtype=np.float32)
    cust_arr  = np.array(cust_ids, dtype=np.int32)
    ts_arr    = np.array(ts_ms, dtype=np.int64)
    co_arr    = np.array(co_ids, dtype=np.int16)

    all_idx   = np.arange(n)

    # ── Account takeover: ×8–15
    idx_take  = RNG.choice(all_idx, size=n_take, replace=False)
    multiplier = RNG.uniform(8, 15, size=n_take).astype(np.float32)
    amt_arr[idx_take] *= multiplier
    is_fraud[idx_take] = True
    ftype[idx_take]    = "account_takeover"

    # ── Amount anomaly: customer_mean × U(8, 12)
    used       = set(idx_take.tolist())
    remaining  = all_idx[~np.isin(all_idx, idx_take)]
    idx_anom   = RNG.choice(remaining, size=n_anom, replace=False)

    # Compute per-customer mean with numpy scatter
    unique_c, inv = np.unique(cust_arr, return_inverse=True)
    sums   = np.zeros(len(unique_c), dtype=np.float64)
    counts = np.zeros(len(unique_c), dtype=np.int32)
    np.add.at(sums, inv, amt_arr.astype(np.float64))
    np.add.at(counts, inv, 1)
    means  = (sums / np.maximum(counts, 1)).astype(np.float32)      # per unique customer
    # Map back: cust_arr[i] → its mean
    cust_mean_full = means[inv]                                      # len = n
    scale = RNG.uniform(8, 12, size=n_anom).astype(np.float32)
    amt_arr[idx_anom]   = cust_mean_full[idx_anom] * scale
    is_fraud[idx_anom]  = True
    ftype[idx_anom]     = "amount_anomaly"

    # ── Velocity: clone bursts (4–7 copies within 4h) for n_vel/6 base transactions
    used2       = set(idx_take.tolist()) | set(idx_anom.tolist())
    free_mask   = ~np.isin(all_idx, list(used2))
    free_idx    = all_idx[free_mask]
    n_bursts    = max(1, n_vel // 6)
    burst_src   = RNG.choice(free_idx, size=min(n_bursts, len(free_idx)), replace=False)

    # Mark source rows as fraud
    is_fraud[burst_src] = True
    ftype[burst_src]    = "velocity"

    # Build burst rows as numpy arrays, then extend
    extra_txn_ids = []
    extra_co      = []
    extra_cust    = []
    extra_ts      = []
    extra_amt     = []
    extra_fraud   = []
    extra_ftype   = []
    next_id       = int(txn_ids[-1]) + 1 if txn_ids else 0

    for src_i in burst_src:
        burst_n   = int(RNG.integers(4, 8))
        base_ts   = int(ts_arr[src_i])
        offsets   = RNG.integers(0, 4 * 3_600_000, size=burst_n)
        for b in range(burst_n):
            extra_txn_ids.append(next_id)
            extra_co.append(int(co_arr[src_i]))
            extra_cust.append(int(cust_arr[src_i]))
            extra_ts.append(base_ts + int(offsets[b]))
            extra_amt.append(float(amt_arr[src_i]))
            extra_fraud.append(True)
            extra_ftype.append("velocity")
            next_id += 1

    # Concat base arrays + extras
    all_txn_ids  = list(map(int, txn_ids))   + extra_txn_ids
    all_co_ids   = co_arr.tolist()            + extra_co
    all_cust_ids = cust_arr.tolist()          + extra_cust
    all_ts_ms    = ts_arr.tolist()            + extra_ts
    all_amounts  = amt_arr.tolist()           + extra_amt
    all_fraud    = is_fraud.tolist()          + extra_fraud
    all_ftype    = ftype.tolist()             + extra_ftype

    return all_txn_ids, all_co_ids, all_cust_ids, all_ts_ms, all_amounts, all_fraud, all_ftype


# ─────────────────────────────────────────────────────────
# Assemble Polars DataFrame and write Parquet
# ─────────────────────────────────────────────────────────
def write_parquet(txn_ids, co_ids, cust_ids, ts_ms, amounts, is_fraud, ftype, out_path):
    df = pl.DataFrame({
        "transaction_id": pl.Series(np.array(txn_ids, dtype=np.int32)),
        "company_id":     pl.Series(np.array(co_ids,  dtype=np.int16)),
        "customer_id":    pl.Series(np.array(cust_ids, dtype=np.int32)),
        "timestamp":      pl.Series(np.array(ts_ms, dtype=np.int64)).cast(pl.Datetime("ms")),
        "amount_usd":     pl.Series(np.array(amounts, dtype=np.float32)),
        "is_fraud":       pl.Series(np.array(is_fraud, dtype=np.bool_)),
        "fraud_type":     pl.Series(ftype, dtype=pl.Utf8),
    }).sort("timestamp")   # monotonic order

    df.write_parquet(out_path, compression="zstd", statistics=True)
    return df


# ─────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────
def main():
    print("Loading CSVs…")
    personas, companies, trends = load_data()
    print(f"  Personas: {len(personas)}  Companies: {len(companies)}  Trend rows: {len(trends)}")

    print("Generating transactions…")
    txn_ids, co_ids, cust_ids, ts_ms, amounts = generate(personas, companies, trends)
    print(f"  Raw transactions: {len(txn_ids):,}")

    print("Injecting fraud…")
    txn_ids, co_ids, cust_ids, ts_ms, amounts, is_fraud, ftype = inject_fraud(
        txn_ids, co_ids, cust_ids, ts_ms, amounts
    )
    n_total = len(txn_ids)
    n_fraud = sum(is_fraud)
    print(f"  Total: {n_total:,}  Fraud: {n_fraud} ({n_fraud / n_total * 100:.3f}%)")
    by_type: dict[str, int] = {}
    for ft in ftype:
        if ft:
            by_type[ft] = by_type.get(ft, 0) + 1
    for k, v in sorted(by_type.items()):
        print(f"    {k}: {v:,}")

    out = os.path.join(ROOT, "transactions.parquet")
    print(f"Writing {out}…")
    df = write_parquet(txn_ids, co_ids, cust_ids, ts_ms, amounts, is_fraud, ftype, out)
    size_mb = os.path.getsize(out) / 1_048_576
    print(f"Done.  {len(df):,} rows  {size_mb:.2f} MB")
    print(df.schema)
    print(df.head(3))


if __name__ == "__main__":
    main()
