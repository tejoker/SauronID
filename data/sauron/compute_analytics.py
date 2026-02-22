"""
Sauron Analytics Engine — All Three Tiers
Outputs parquet files to sauron/data/
Run: python sauron/compute_analytics.py
"""

import warnings
warnings.filterwarnings("ignore")

import json
import numpy as np
import polars as pl
from datetime import date, timedelta
from pathlib import Path

# ── paths ──────────────────────────────────────────────────────────────────────
DATA = Path(__file__).parent / "data"

def _parse_dates(df: pl.DataFrame, col: str = "date") -> pl.DataFrame:
    """Cast string date column to Polars Date type."""
    if df[col].dtype == pl.Utf8 or df[col].dtype == pl.String:
        return df.with_columns(pl.col(col).str.to_date("%Y-%m-%d"))
    return df

def _d(v) -> date:
    """Normalise a Polars date value (may be datetime.date already) to datetime.date."""
    if isinstance(v, date):
        return v
    return date.fromisoformat(str(v)[:10])

def load_data():
    clients   = pl.read_parquet(DATA / "clients.parquet")
    tokens    = _parse_dates(pl.read_parquet(DATA / "credit_ledger.parquet"))
    verif     = _parse_dates(pl.read_parquet(DATA / "verifications.parquet"))
    rings     = _parse_dates(pl.read_parquet(DATA / "ring_snapshots.parquet"))
    return clients, tokens, verif, rings


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1
# ══════════════════════════════════════════════════════════════════════════════

def compute_runway(tokens: pl.DataFrame) -> pl.DataFrame:
    """
    Per-client: project balance to zero using last-60-day linear regression.
    Returns runway_days, projected_depletion (date string), burn_rate (tokens/day).
    """
    from sklearn.linear_model import LinearRegression

    today = date(2026, 1, 1)          # reference point (end of data)
    results = []

    for row in tokens.group_by("client_id").agg(
        pl.col("date").sort_by("date"),
        pl.col("balance_after").sort_by("date"),
        pl.col("amount").sum().alias("total_purchased"),
    ).iter_rows(named=True):
        cid    = row["client_id"]
        raw_dates = row["date"]
        bals   = row["balance_after"]

        dates = [date.fromisoformat(str(d)) if not isinstance(d, date) else d for d in raw_dates]

        if len(dates) < 2:
            results.append({"client_id": cid, "runway_days": 9999, "burn_rate": 0.0,
                             "projected_depletion": None, "current_balance": 0,
                             "total_purchased": row["total_purchased"]})
            continue

        # Keep last 60 days of observations
        date_nums = np.array([(d - dates[0]).days for d in dates], dtype=float)
        bals_arr  = np.array(bals, dtype=float)

        cutoff = date_nums[-1] - 60
        mask   = date_nums >= cutoff
        x      = date_nums[mask].reshape(-1, 1)
        y      = bals_arr[mask]

        if len(x) < 2 or y[-1] <= 0:
            results.append({"client_id": cid, "runway_days": 9999, "burn_rate": 0.0,
                             "projected_depletion": None,
                             "current_balance": int(bals[-1]),
                             "total_purchased": row["total_purchased"]})
            continue

        lr = LinearRegression().fit(x, y)
        slope = float(lr.coef_[0])   # tokens/day

        if slope >= 0:
            # balance is growing — no depletion forecast
            results.append({"client_id": cid, "runway_days": 9999, "burn_rate": float(-slope),
                             "projected_depletion": None,
                             "current_balance": int(bals[-1]),
                             "total_purchased": row["total_purchased"]})
            continue

        current_bal  = float(y[-1])
        days_to_zero = int(-current_bal / slope)
        days_to_zero = max(0, min(days_to_zero, 9999))
        depletion    = today + timedelta(days=days_to_zero)

        results.append({
            "client_id":           cid,
            "runway_days":         days_to_zero,
            "burn_rate":           round(float(-slope), 4),
            "projected_depletion": str(depletion),
            "current_balance":     int(bals[-1]),
            "total_purchased":     row["total_purchased"],
        })

    return pl.DataFrame(results)


def compute_bayesian_trust(verif: pl.DataFrame) -> pl.DataFrame:
    """
    Beta(2,2) prior updated by observations.
    trust_score = (2 + successes) / (4 + total_transactions)
    Also returns trust_ci_lo, trust_ci_hi (95% credible interval).
    """
    from scipy.stats import beta as beta_dist

    agg = (
        verif
        .group_by("client_id")
        .agg([
            pl.col("total").sum().alias("total_tx"),
            pl.col("failed").sum().alias("failed_tx"),
        ])
        .with_columns(
            (pl.col("total_tx") - pl.col("failed_tx")).alias("success_tx")
        )
    )

    rows = []
    for r in agg.iter_rows(named=True):
        a = 2 + r["success_tx"]
        b = 2 + r["failed_tx"]
        mean_val = a / (a + b)
        lo, hi   = beta_dist.ppf([0.025, 0.975], a, b)
        rows.append({
            "client_id":    r["client_id"],
            "trust_score":  round(mean_val, 4),
            "trust_ci_lo":  round(float(lo), 4),
            "trust_ci_hi":  round(float(hi), 4),
            "total_tx":     r["total_tx"],
            "failed_tx":    r["failed_tx"],
        })

    return pl.DataFrame(rows)


def compute_churn_risk(clients: pl.DataFrame, tokens: pl.DataFrame,
                       verif: pl.DataFrame, runway_df: pl.DataFrame) -> pl.DataFrame:
    """
    Logistic regression on: burn_rate_30d, days_since_last_purchase,
    runway_days, activity_ratio (last_30d vs prev_30d), failure_rate.
    Labels generated synthetically from threshold rules (semi-supervised).
    """
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    today_num = 365 * 2   # days from 2024-01-01 reference

    # ── token features ────────────────────────────────────────────────────────
    tok_feats = {}
    for row in tokens.group_by("client_id").agg(
        pl.col("date").sort_by("date"),
        pl.col("amount").sort_by("date"),
        pl.col("balance_after").sort_by("date"),
    ).iter_rows(named=True):
        cid   = row["client_id"]
        dates = row["date"]
        bals  = row["balance_after"]
        toks  = row["amount"]

        ref = date(2024, 1, 1)
        dates_parsed = [date.fromisoformat(str(d)) if not isinstance(d, date) else d for d in dates]
        dnums = np.array([(d - ref).days for d in dates_parsed], dtype=float)
        last_purchase = int(today_num - dnums[-1]) if len(dnums) > 0 else 999

        mask30 = dnums >= (today_num - 30)
        burn_30d = float(-np.polyfit(dnums[mask30], np.array(bals)[mask30], 1)[0]) if mask30.sum() >= 2 else 0.0

        tok_feats[cid] = {
            "days_since_purchase": last_purchase,
            "burn_rate_30d":       max(0.0, burn_30d),
        }

    # ── verif features ─────────────────────────────────────────────────────────
    verif_feats = {}
    for row in (
        verif
        .sort("date")
        .group_by("client_id")
        .agg([
            pl.col("total").sum().alias("total"),
            pl.col("failed").sum().alias("failed"),
            pl.col("date"),
            pl.col("total").alias("daily_total"),
        ])
        .iter_rows(named=True)
    ):
        cid   = row["client_id"]
        total = row["total"] or 1
        ref   = date(2024, 1, 1)
        dates = row["date"]
        daily = row["daily_total"]

        dnums = np.array([(d - ref).days for d in dates], dtype=float)
        vols  = np.array(daily, dtype=float)

        mask30 = dnums >= (today_num - 30)
        mask60 = (dnums >= (today_num - 60)) & (dnums < (today_num - 30))

        vol30 = float(vols[mask30].sum()) if mask30.sum() else 0.0
        vol60 = float(vols[mask60].sum()) if mask60.sum() else 1.0
        ratio = vol30 / max(vol60, 1.0)

        verif_feats[cid] = {
            "failure_rate":    row["failed"] / total,
            "activity_ratio":  ratio,
        }

    # ── assemble feature matrix ────────────────────────────────────────────────
    rdf = runway_df.to_dicts()
    runway_map = {r["client_id"]: r for r in rdf}

    X_rows, client_ids = [], []
    for row in clients.iter_rows(named=True):
        cid = row["client_id"]
        tf  = tok_feats.get(cid, {"days_since_purchase": 999, "burn_rate_30d": 0.0})
        vf  = verif_feats.get(cid, {"failure_rate": 0.0, "activity_ratio": 1.0})
        rm  = runway_map.get(cid, {"runway_days": 9999})

        X_rows.append([
            min(tf["days_since_purchase"], 365),
            tf["burn_rate_30d"],
            min(rm["runway_days"], 365),
            vf["activity_ratio"],
            vf["failure_rate"],
        ])
        client_ids.append(cid)

    X = np.array(X_rows, dtype=float)

    # Semi-supervised labels: churn if runway < 30d OR no purchase in 180d OR activity_ratio < 0.3
    y = ((X[:, 2] < 30) | (X[:, 0] > 180) | (X[:, 3] < 0.3)).astype(int)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Need at least both classes for LR
    if len(np.unique(y)) < 2:
        # fallback: use continuous heuristic
        churn_probs = np.clip(
            (365 - X[:, 2]) / 365 * 0.5 +
            (X[:, 0] / 365) * 0.3 +
            (1 - np.clip(X[:, 3], 0, 2) / 2) * 0.2,
            0.01, 0.99
        )
    else:
        lr = LogisticRegression(C=1.0, max_iter=500)
        lr.fit(Xs, y)
        churn_probs = lr.predict_proba(Xs)[:, 1]

    return pl.DataFrame({
        "client_id":  client_ids,
        "churn_risk": [round(float(p), 4) for p in churn_probs],
    })


def compute_health_scores(clients: pl.DataFrame, tokens: pl.DataFrame,
                           verif: pl.DataFrame, runway_df: pl.DataFrame,
                           trust_df: pl.DataFrame, churn_df: pl.DataFrame) -> pl.DataFrame:
    """
    Composite 0–100 score:
      35% runway_score (runway_days / 365 capped)
      30% activity_score (recent vol trend)
      20% reliability_score (1 - failure_rate)
      15% refill_regularity (std of gaps between purchases, inverted)
    """
    today_num = 365 * 2
    ref = date(2024, 1, 1)

    # runway score
    runway_map = {r["client_id"]: r for r in runway_df.to_dicts()}
    trust_map  = {r["client_id"]: r for r in trust_df.to_dicts()}
    churn_map  = {r["client_id"]: r for r in churn_df.to_dicts()}

    # activity score
    activity_map = {}
    for row in verif.sort("date").group_by("client_id").agg(
        pl.col("date"), pl.col("total").alias("daily_total")
    ).iter_rows(named=True):
        cid   = row["client_id"]
        raw_dates = row["date"]
        dates = [date.fromisoformat(str(d)) if not isinstance(d, date) else d for d in raw_dates]
        vols  = np.array(row["daily_total"], dtype=float)
        dnums = np.array([(d - ref).days for d in dates], dtype=float)
        if len(dnums) >= 14:
            mid = np.median(dnums)
            early = vols[dnums <= mid].mean() or 1
            late  = vols[dnums >  mid].mean() or 0
            activity_map[cid] = min(late / max(early, 1), 2.0) / 2.0
        else:
            activity_map[cid] = 0.5

    # reliability score
    reliability_map = {}
    for row in verif.group_by("client_id").agg(
        pl.col("total").sum(), pl.col("failed").sum()
    ).iter_rows(named=True):
        total = row["total"] or 1
        reliability_map[row["client_id"]] = 1.0 - (row["failed"] / total)

    # refill regularity
    regularity_map = {}
    for row in tokens.sort("date").group_by("client_id").agg(
        pl.col("date")
    ).iter_rows(named=True):
        dates = [(d - ref).days for d in row["date"]]
        if len(dates) >= 3:
            gaps = np.diff(sorted(dates))
            cv   = gaps.std() / (gaps.mean() + 1e-9)
            regularity_map[row["client_id"]] = float(np.exp(-cv))
        elif len(dates) == 1:
            regularity_map[row["client_id"]] = 0.5
        else:
            regularity_map[row["client_id"]] = 0.3

    results = []
    for row in clients.iter_rows(named=True):
        cid = row["client_id"]
        rm  = runway_map.get(cid, {"runway_days": 9999})
        runway_score      = min(rm["runway_days"], 365) / 365.0
        activity_score    = activity_map.get(cid, 0.5)
        reliability_score = reliability_map.get(cid, 0.95)
        regularity_score  = regularity_map.get(cid, 0.5)

        composite = (
            0.35 * runway_score +
            0.30 * activity_score +
            0.20 * reliability_score +
            0.15 * regularity_score
        ) * 100.0

        tm = trust_map.get(cid, {"trust_score": 0.9, "trust_ci_lo": 0.7, "trust_ci_hi": 1.0})
        cm = churn_map.get(cid, {"churn_risk": 0.1})

        results.append({
            "client_id":         cid,
            "health_score":      round(composite, 1),
            "runway_score":      round(runway_score * 100, 1),
            "activity_score":    round(activity_score * 100, 1),
            "reliability_score": round(reliability_score * 100, 1),
            "regularity_score":  round(regularity_score * 100, 1),
            "trust_score":       round(tm["trust_score"] * 100, 1),
            "trust_ci_lo":       round(tm["trust_ci_lo"] * 100, 1),
            "trust_ci_hi":       round(tm["trust_ci_hi"] * 100, 1),
            "churn_risk":        cm["churn_risk"],
        })

    return pl.DataFrame(results)


def detect_anomalies_ml(verif: pl.DataFrame, clients: pl.DataFrame) -> pl.DataFrame:
    """
    Isolation Forest on per-client daily (total, failed, full_kyc, reduced) features.
    Returns rows flagged as anomalous with anomaly_score.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    records = []

    for row in verif.group_by("client_id").agg(
        pl.col("date"),
        pl.col("total").alias("totals"),
        pl.col("failed").alias("faileds"),
        pl.col("full_kyc").alias("full_kycs"),
        pl.col("reduced").alias("reduceds"),
    ).iter_rows(named=True):
        cid   = row["client_id"]
        raw_dates = row["date"]
        dates = [date.fromisoformat(str(d)) if not isinstance(d, date) else d for d in raw_dates]
        n     = len(dates)

        if n < 10:
            continue

        X = np.column_stack([
            row["totals"],
            row["faileds"],
            row["full_kycs"],
            row["reduceds"],
        ]).astype(float)

        # rolling z-score features
        from scipy.ndimage import uniform_filter1d
        rolling_mean = uniform_filter1d(X[:, 0], size=7)
        rolling_std  = np.maximum(
            np.array([X[:, 0][max(0, i-7):i+1].std() for i in range(n)]),
            1e-6
        )
        z_score = (X[:, 0] - rolling_mean) / rolling_std

        X_feat = np.column_stack([
            X,
            z_score,
            rolling_mean,
        ])

        scaler = StandardScaler()
        X_s    = scaler.fit_transform(X_feat)

        clf = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        preds  = clf.fit_predict(X_s)
        scores = clf.score_samples(X_s)

        for i, (d, pred, score) in enumerate(zip(dates, preds, scores)):
            if pred == -1:
                total_val   = int(X[i, 0])
                failed_val  = int(X[i, 1])
                fail_rate   = failed_val / max(total_val, 1)
                severity    = "high" if score < -0.2 else ("medium" if score < -0.1 else "low")

                if total_val > rolling_mean[i] * 1.5:
                    anomaly_type = "volume_spike"
                    message      = f"Volume {total_val} is {total_val/max(rolling_mean[i],1):.1f}x rolling avg"
                elif total_val < rolling_mean[i] * 0.4:
                    anomaly_type = "volume_drop"
                    message      = f"Volume {total_val} dropped to {total_val/max(rolling_mean[i],1):.0%} of rolling avg"
                elif fail_rate > 0.3:
                    anomaly_type = "high_failure_rate"
                    message      = f"Failure rate {fail_rate:.0%} on {total_val} transactions"
                else:
                    anomaly_type = "statistical_outlier"
                    message      = f"Anomaly score {score:.3f} — unusual feature combination"

                records.append({
                    "client_id":    cid,
                    "date":         str(d),
                    "anomaly_type": anomaly_type,
                    "severity":     severity,
                    "anomaly_score": round(float(score), 4),
                    "total":        total_val,
                    "failed":       failed_val,
                    "message":      message,
                    "source":       "isolation_forest",
                })

    return pl.DataFrame(records) if records else pl.DataFrame({
        "client_id": [], "date": [], "anomaly_type": [], "severity": [],
        "anomaly_score": [], "total": [], "failed": [], "message": [], "source": [],
    })


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2
# ══════════════════════════════════════════════════════════════════════════════

def forecast_revenue(tokens: pl.DataFrame) -> pl.DataFrame:
    """
    XGBoost monthly platform revenue forecast (3 months ahead) with 80% CI.
    Uses platform-wide monthly token purchase aggregation.
    """
    import xgboost as xgb
    from sklearn.preprocessing import StandardScaler

    # aggregate monthly platform revenue (Credit B purchases only)
    monthly = (
        tokens
        .filter((pl.col("event_type") == "purchase") & (pl.col("credit_type") == "B"))
        .with_columns(pl.col("date").cast(pl.Utf8).str.slice(0, 7).alias("month"))
        .group_by("month")
        .agg(pl.col("usd_value").sum().alias("revenue"))
        .sort("month")
    )

    months  = monthly["month"].to_list()
    revenue = monthly["revenue"].to_numpy().astype(float)
    n       = len(revenue)

    if n < 6:
        return pl.DataFrame({"month": [], "revenue_forecast": [], "ci_lo": [], "ci_hi": [], "is_forecast": []})

    # build lag features
    def make_features(series, idx):
        lags = [series[max(0, idx-1)], series[max(0, idx-3)], series[max(0, idx-6)]]
        roll3 = series[max(0, idx-3):idx].mean() if idx >= 3 else series[:idx].mean()
        roll6 = series[max(0, idx-6):idx].mean() if idx >= 6 else series[:idx].mean()
        month_num = idx % 12
        return [lags[0], lags[1], lags[2], roll3, roll6, month_num]

    X_train, y_train = [], []
    for i in range(6, n):
        X_train.append(make_features(revenue, i))
        y_train.append(revenue[i])

    X = np.array(X_train, dtype=float)
    y = np.array(y_train, dtype=float)

    # mean model
    reg = xgb.XGBRegressor(n_estimators=100, max_depth=3, learning_rate=0.1,
                            random_state=42, verbosity=0)
    reg.fit(X, y)

    # quantile models for CI
    q10 = xgb.XGBRegressor(n_estimators=100, max_depth=3, learning_rate=0.1,
                             objective="reg:quantileerror", quantile_alpha=0.1,
                             random_state=42, verbosity=0)
    q90 = xgb.XGBRegressor(n_estimators=100, max_depth=3, learning_rate=0.1,
                             objective="reg:quantileerror", quantile_alpha=0.9,
                             random_state=42, verbosity=0)
    q10.fit(X, y)
    q90.fit(X, y)

    results = []
    # actual months
    for i, (m, r) in enumerate(zip(months, revenue)):
        results.append({"month": m, "revenue_actual": round(float(r), 2),
                        "revenue_forecast": None, "ci_lo": None, "ci_hi": None,
                        "is_forecast": False})

    # forecast 3 months ahead
    extended = list(revenue)
    last_month = months[-1]
    y_m, y_mo = int(last_month[:4]), int(last_month[5:7])

    for step in range(3):
        y_mo += 1
        if y_mo > 12:
            y_mo = 1
            y_m += 1
        next_month = f"{y_m:04d}-{y_mo:02d}"
        idx_next   = n + step
        feats = np.array([make_features(np.array(extended), idx_next)], dtype=float)

        pred = float(reg.predict(feats)[0])
        lo   = float(q10.predict(feats)[0])
        hi   = float(q90.predict(feats)[0])
        lo   = min(lo, pred)
        hi   = max(hi, pred)

        extended.append(pred)
        results.append({
            "month": next_month,
            "revenue_actual": None,
            "revenue_forecast": round(pred, 2),
            "ci_lo": round(lo, 2),
            "ci_hi": round(hi, 2),
            "is_forecast": True,
        })

    return pl.DataFrame(results)


def compute_cohorts(clients: pl.DataFrame, verif: pl.DataFrame) -> pl.DataFrame:
    """
    Group clients by join_month cohort.
    For each cohort, track normalized monthly verification volume (vol / cohort_size).
    """
    # join month
    coh_map = {
        r["client_id"]: r["join_date"][:7]
        for r in clients.iter_rows(named=True)
    }

    # cohort sizes
    from collections import defaultdict
    cohort_sizes = defaultdict(int)
    for v in coh_map.values():
        cohort_sizes[v] += 1

    # monthly verif per cohort
    records = []
    for row in (
        verif
        .with_columns(pl.col("date").cast(pl.Utf8).str.slice(0, 7).alias("month"))
        .group_by(["client_id", "month"])
        .agg(pl.col("total").sum().alias("vol"))
        .iter_rows(named=True)
    ):
        cid     = row["client_id"]
        cohort  = coh_map.get(cid)
        if cohort is None:
            continue
        records.append({
            "cohort":       cohort,
            "month":        row["month"],
            "vol":          row["vol"],
            "cohort_size":  cohort_sizes[cohort],
        })

    if not records:
        return pl.DataFrame({"cohort": [], "month": [], "vol_per_client": [], "cohort_size": []})

    df = pl.DataFrame(records)
    df = (
        df
        .group_by(["cohort", "month"])
        .agg([
            pl.col("vol").sum(),
            pl.col("cohort_size").first(),
        ])
        .with_columns(
            (pl.col("vol") / pl.col("cohort_size")).round(2).alias("vol_per_client")
        )
        .sort(["cohort", "month"])
    )
    return df


def fit_ring_curves(rings: pl.DataFrame) -> pl.DataFrame:
    """
    Fit logistic S-curve: f(t) = L / (1 + exp(-k*(t-t0)))
    per ring. Returns L, k, t0, saturation_pct, projected_saturation_date.
    """
    from scipy.optimize import curve_fit

    def logistic(t, L, k, t0):
        return L / (1 + np.exp(-k * (t - t0)))

    results = []

    for row in rings.sort("date").group_by("ring_id").agg(
        pl.col("ring_label").first(),
        pl.col("date"),
        pl.col("member_count"),
    ).iter_rows(named=True):
        ring_id    = row["ring_id"]
        ring_label = row["ring_label"]
        dates      = row["date"]
        counts     = np.array(row["member_count"], dtype=float)

        ref  = date(2024, 1, 1)
        t    = np.array([(_d(d) - ref).days for d in dates], dtype=float)

        if len(t) < 4 or counts.max() < 5:
            continue

        try:
            p0     = [counts.max() * 1.5, 0.02, t.mean()]
            bounds = ([counts.max() * 0.8, 0.001, t.min()],
                      [counts.max() * 10,  0.5,   t.max() + 365 * 2])
            popt, pcov = curve_fit(logistic, t, counts, p0=p0, bounds=bounds,
                                   maxfev=5000)
            L, k, t0 = popt
            perr     = np.sqrt(np.diag(pcov))

            sat_pct = (counts[-1] / L) * 100
            # project when 95% saturation is reached
            # 0.95*L = L/(1+exp(-k*(t-t0))) -> t = t0 - ln(1/0.95-1)/k
            t_95   = t0 - np.log(1 / 0.95 - 1) / k
            sat_date = str(ref + timedelta(days=int(t_95))) if 0 < t_95 < 365*5 + t.max() else None

            results.append({
                "ring_id":               ring_id,
                "ring_label":            ring_label,
                "L":                     round(float(L), 1),
                "k":                     round(float(k), 5),
                "t0":                    round(float(t0), 1),
                "L_err":                 round(float(perr[0]), 1),
                "k_err":                 round(float(perr[1]), 6),
                "current_count":         int(counts[-1]),
                "saturation_pct":        round(float(sat_pct), 1),
                "projected_saturation_date": sat_date,
            })
        except Exception:
            results.append({
                "ring_id":               ring_id,
                "ring_label":            ring_label,
                "L":                     float(counts.max() * 1.2),
                "k":                     0.02,
                "t0":                    float(t.mean()),
                "L_err":                 0.0,
                "k_err":                 0.0,
                "current_count":         int(counts[-1]),
                "saturation_pct":        round(counts[-1] / (counts.max() * 1.2) * 100, 1),
                "projected_saturation_date": None,
            })

    return pl.DataFrame(results) if results else pl.DataFrame({
        "ring_id": [], "ring_label": [], "L": [], "k": [], "t0": [],
        "L_err": [], "k_err": [], "current_count": [], "saturation_pct": [],
        "projected_saturation_date": [],
    })


# ══════════════════════════════════════════════════════════════════════════════
# TIER 3
# ══════════════════════════════════════════════════════════════════════════════

def compute_elasticity(tokens: pl.DataFrame, verif: pl.DataFrame) -> pl.DataFrame:
    """
    Price elasticity proxy: correlate monthly purchase volume (tokens) with time.
    Cross-elasticity: full_kyc vs reduced verification volumes.
    """
    from scipy import stats

    # Platform monthly Credit B purchase volume
    monthly_tok = (
        tokens
        .filter((pl.col("event_type") == "purchase") & (pl.col("credit_type") == "B"))
        .with_columns(pl.col("date").cast(pl.Utf8).str.slice(0, 7).alias("month"))
        .group_by("month")
        .agg(pl.col("amount").sum().alias("volume"))
        .sort("month")
    )

    t_tok    = np.arange(len(monthly_tok))
    vol_tok  = monthly_tok["volume"].to_numpy().astype(float)
    r_vol, p_vol = stats.pearsonr(t_tok, vol_tok)

    # Monthly full_kyc vs reduced
    monthly_verif = (
        verif
        .with_columns(pl.col("date").cast(pl.Utf8).str.slice(0, 7).alias("month"))
        .group_by("month")
        .agg([
            pl.col("full_kyc").sum(),
            pl.col("reduced").sum(),
        ])
        .sort("month")
    )

    fk = monthly_verif["full_kyc"].to_numpy().astype(float)
    rd = monthly_verif["reduced"].to_numpy().astype(float)

    if len(fk) >= 4:
        r_cross, p_cross = stats.pearsonr(fk, rd)
        # log-log slope as elasticity proxy
        lf = np.log(fk + 1)
        lr = np.log(rd + 1)
        slope, intercept, r_log, _, _ = stats.linregress(lf, lr)
    else:
        r_cross, p_cross, slope, r_log = 0.0, 1.0, 1.0, 0.0

    rows = [
        {"metric": "credit_b_volume_trend_r",    "value": round(float(r_vol),   4),   "p_value": round(float(p_vol), 4),   "description": "Pearson r between time and monthly Credit B purchase volume"},
        {"metric": "full_reduced_cross_r",       "value": round(float(r_cross), 4), "p_value": round(float(p_cross), 4), "description": "Cross-correlation: full_kyc vs reduced verifications"},
        {"metric": "log_log_elasticity_slope",   "value": round(float(slope), 4),   "p_value": None,                     "description": "Log-log slope (reduced ~ full_kyc): demand elasticity proxy"},
        {"metric": "log_log_r_squared",          "value": round(float(r_log**2), 4),"p_value": None,                     "description": "R² of log-log elasticity model"},
    ]
    return pl.DataFrame(rows)


def forecast_load(verif: pl.DataFrame) -> pl.DataFrame:
    """
    Weekly platform-wide verification load forecast (4 weeks ahead).
    Uses linear trend + 7-day seasonality decomposition.
    """
    from scipy.ndimage import uniform_filter1d
    from sklearn.linear_model import LinearRegression

    daily = (
        verif
        .group_by("date")
        .agg(pl.col("total").sum().alias("total"))
        .sort("date")
    )

    dates  = daily["date"].to_list()
    totals = daily["total"].to_numpy().astype(float)
    n      = len(totals)
    ref    = date(2024, 1, 1)
    t      = np.array([(d - ref).days for d in dates], dtype=float)

    if n < 14:
        return pl.DataFrame({"date": [], "load_forecast": [], "ci_lo": [], "ci_hi": [], "is_forecast": []})

    # Trend
    lr = LinearRegression().fit(t.reshape(-1, 1), totals)
    trend = lr.predict(t.reshape(-1, 1))
    residuals = totals - trend

    # Weekly seasonality (day-of-week average over residuals)
    dow_means = np.zeros(7)
    for i, d in enumerate(dates):
        dow = d.weekday()
        dow_means[dow] += residuals[i]
    dow_counts = np.zeros(7)
    for d in dates:
        dow_counts[d.weekday()] += 1
    dow_seasonality = dow_means / np.maximum(dow_counts, 1)

    # Residual std for CI
    seasonal_fitted = np.array([dow_seasonality[d.weekday()] for d in dates])
    final_resid = residuals - seasonal_fitted
    sigma = final_resid.std()

    results = []
    # Historical (last 30 days)
    for i in range(max(0, n-30), n):
        results.append({
            "date":           str(dates[i]),
            "load_actual":    int(totals[i]),
            "load_forecast":  None,
            "ci_lo":          None,
            "ci_hi":          None,
            "is_forecast":    False,
        })

    # Forecast 28 days
    last_t   = t[-1]
    last_date = dates[-1]
    for step in range(1, 29):
        fut_date  = last_date + timedelta(days=step)
        fut_t     = last_t + step
        trend_val = float(lr.predict([[fut_t]])[0])
        seas_val  = dow_seasonality[fut_date.weekday()]
        pred      = max(0, trend_val + seas_val)
        ci_factor = 1.645 * sigma * (1 + step / 56)   # widening CI
        results.append({
            "date":          str(fut_date),
            "load_actual":   None,
            "load_forecast": round(pred, 1),
            "ci_lo":         round(max(0, pred - ci_factor), 1),
            "ci_hi":         round(pred + ci_factor, 1),
            "is_forecast":   True,
        })

    return pl.DataFrame(results)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("Loading data...")
    clients, tokens, verif, rings = load_data()
    print(f"  clients={len(clients)}, tokens={len(tokens)}, verif={len(verif)}, rings={len(rings)}")

    # ── Tier 1 ──────────────────────────────────────────────────────────────
    print("\n[Tier 1] Computing runway forecast...")
    runway_df = compute_runway(tokens)
    runway_df.write_parquet(DATA / "runway_forecast.parquet")
    print(f"  -> {len(runway_df)} rows | runway_forecast.parquet")

    print("[Tier 1] Computing Bayesian trust scores...")
    trust_df = compute_bayesian_trust(verif)
    print(f"  -> {len(trust_df)} clients")

    print("[Tier 1] Computing churn risk...")
    churn_df = compute_churn_risk(clients, tokens, verif, runway_df)
    print(f"  -> {len(churn_df)} clients")

    print("[Tier 1] Computing composite health scores...")
    scores_df = compute_health_scores(clients, tokens, verif, runway_df, trust_df, churn_df)
    scores_df.write_parquet(DATA / "client_scores.parquet")
    print(f"  -> {len(scores_df)} rows | client_scores.parquet")

    print("[Tier 1] Running Isolation Forest anomaly detection...")
    anomalies_ml = detect_anomalies_ml(verif, clients)
    anomalies_ml.write_parquet(DATA / "anomalies_ml.parquet")
    print(f"  -> {len(anomalies_ml)} anomalies detected | anomalies_ml.parquet")

    # ── Tier 2 ──────────────────────────────────────────────────────────────
    print("\n[Tier 2] Forecasting platform revenue (XGBoost)...")
    revenue_df = forecast_revenue(tokens)
    revenue_df.write_parquet(DATA / "revenue_forecast.parquet")
    print(f"  -> {len(revenue_df)} rows | revenue_forecast.parquet")

    print("[Tier 2] Computing cohort analysis...")
    cohort_df = compute_cohorts(clients, verif)
    cohort_df.write_parquet(DATA / "cohort_analysis.parquet")
    print(f"  -> {len(cohort_df)} rows | cohort_analysis.parquet")

    print("[Tier 2] Fitting ring S-curves (scipy logistic)...")
    rings_df = fit_ring_curves(rings)
    rings_df.write_parquet(DATA / "ring_curves.parquet")
    print(f"  -> {len(rings_df)} rings fitted | ring_curves.parquet")

    # ── Tier 3 ──────────────────────────────────────────────────────────────
    print("\n[Tier 3] Computing verification demand elasticity...")
    elast_df = compute_elasticity(tokens, verif)
    elast_df.write_parquet(DATA / "elasticity.parquet")
    print(f"  -> {len(elast_df)} metrics | elasticity.parquet")

    print("[Tier 3] Forecasting verification load (28-day)...")
    load_df = forecast_load(verif)
    load_df.write_parquet(DATA / "load_forecast.parquet")
    print(f"  -> {len(load_df)} rows | load_forecast.parquet")

    # ── Summary ─────────────────────────────────────────────────────────────
    print("\nAll analytics computed successfully.")
    print("\nHealth score summary:")
    print(scores_df.select(["client_id","health_score","churn_risk","trust_score"]).sort("health_score"))

    print("\nAnomaly breakdown:")
    if len(anomalies_ml) > 0:
        print(anomalies_ml.group_by("severity").agg(pl.len().alias("count")))

    print("\nRing curves:")
    print(rings_df.select(["ring_label","L","saturation_pct","projected_saturation_date"]))


if __name__ == "__main__":
    main()
