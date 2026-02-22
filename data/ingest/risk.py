"""
ingest/risk.py
==============
Per-company risk engine combining:
  1. Per-company rolling z-score on amount_usd (30-day window)
     - 3σ → WATCH, 5σ → BLOCK
  2. XGBoost fraud classifier (pre-trained, one model per company)
  3. Auth anomaly detector
     - Burst of failed logins → WATCH / BLOCK

All state is in-memory (deque per company/user). Thread-safe for single
asyncio worker; no locking needed inside run_in_executor calls since each
call is sequential in the thread pool (maxWorkers=1 default or the caller
ensures one at a time per company — good enough for hackathon scale).
"""

import datetime
import json
import math
import os
import time
from collections import deque

import numpy as np
import xgboost as xgb

# ── Constants ─────────────────────────────────────────────────────────────
WINDOW_SECONDS   = 30 * 24 * 3600        # 30-day rolling window
WATCH_Z          = 3.0
BLOCK_Z          = 5.0

AUTH_WINDOW_S    = 300                   # 5-minute window for auth bursts
AUTH_WATCH_COUNT = 5                     # ≥5 failed logins → WATCH
AUTH_BLOCK_COUNT = 10                    # ≥10 failed logins → BLOCK

FEATURE_NAMES = [
    "amount_usd", "amount_z_co", "amount_z_cust", "amt_ratio_co",
    "velocity_1h", "velocity_24h", "days_since_last",
    "hour_of_day", "day_of_week", "month_sin", "month_cos",
]

HOUR_MS = 3_600_000
DAY_MS  = 86_400_000


# ── Rolling stats helper ──────────────────────────────────────────────────

class _RollingStats:
    """Maintain rolling mean and std over a time-windowed deque of floats."""

    def __init__(self, window_s: int):
        self._win   = window_s
        self._buf: deque[tuple[float, float]] = deque()  # (ts_s, value)
        self._sum   = 0.0
        self._sum2  = 0.0

    def _evict(self, now_s: float):
        cutoff = now_s - self._win
        while self._buf and self._buf[0][0] < cutoff:
            _, v = self._buf.popleft()
            self._sum  -= v
            self._sum2 -= v * v

    def push(self, value: float, ts_s: float | None = None) -> tuple[float, float]:
        """Add a value. Returns (mean, std) of the window after insertion."""
        now = ts_s if ts_s is not None else time.time()
        self._evict(now)
        self._buf.append((now, value))
        self._sum  += value
        self._sum2 += value * value
        n = len(self._buf)
        mean = self._sum / n
        var  = max(0.0, self._sum2 / n - mean * mean)
        std  = math.sqrt(var) if var > 0 else 1e-6
        return mean, std

    def z_score(self, value: float) -> float:
        n = len(self._buf)
        if n < 2:
            return 0.0
        mean = self._sum / n
        var  = max(0.0, self._sum2 / n - mean * mean)
        std  = math.sqrt(var) if var > 0 else 1e-6
        return (value - mean) / std


# ── RiskEngine ────────────────────────────────────────────────────────────

class RiskEngine:
    """
    Loads all XGBoost fraud models at startup.
    Maintains per-company rolling z-score state and per-user velocity state.
    """

    def __init__(self, model_dir: str, stats_dir: str):
        # company_id → xgb.Booster
        self._models: dict[int, xgb.Booster] = {}
        # company_id → {amount_mean, amount_std, best_threshold}
        self._co_stats: dict[int, dict] = {}
        # company_id → _RollingStats (tracks all amounts for the company)
        self._co_rolling: dict[int, _RollingStats] = {}
        # (company_id, user_id) → _RollingStats (customer-level amounts)
        self._cust_rolling: dict[tuple[int, int], _RollingStats] = {}
        # (company_id, user_id) → deque of timestamps (ms) for velocity — evicted at 24h
        self._cust_txn_ts: dict[tuple[int, int], deque] = {}
        # (company_id, user_id) → deque of timestamps (ms) for 1h velocity — evicted at 1h
        # Kept separate so vel_1h is O(1) (just len()) instead of O(n) scan over 24h deque.
        self._cust_txn_1h: dict[tuple[int, int], deque] = {}
        # (company_id, user_id) → last txn timestamp ms
        self._cust_last_ts: dict[tuple[int, int], int] = {}
        # (company_id, user_id) → deque of failed-auth timestamps (s)
        self._auth_failures: dict[tuple[int, int], deque] = {}

        self._load_models(model_dir, stats_dir)

    def _load_models(self, model_dir: str, stats_dir: str):
        loaded = 0
        for fname in os.listdir(model_dir):
            if not fname.endswith(".json") or fname == "stats.parquet":
                continue
            try:
                co_id = int(fname.replace("company_", "").replace(".json", ""))
            except ValueError:
                continue

            bst = xgb.Booster()
            bst.load_model(os.path.join(model_dir, fname))
            # nthread=1: for single-row inference the XGBoost thread-pool coordination
            # overhead exceeds the compute time. Measured 2.6x speedup (0.85ms → 0.33ms).
            bst.set_param("nthread", 1)
            self._models[co_id] = bst

            # Load per-company stats (amount_mean, amount_std, threshold)
            stats_path = os.path.join(stats_dir, fname)
            if os.path.exists(stats_path):
                with open(stats_path) as f:
                    raw = json.load(f)
                # stats JSON has nested structure; extract what we need
                self._co_stats[co_id] = {
                    "amount_mean":     raw.get("behavior", {}).get("monthly", {}).get("avg_txn_value", [0])[0],
                    "amount_std":      1.0,   # will be updated from rolling window
                    "best_threshold":  0.5,   # conservative default
                }
            loaded += 1

        self.n_models = loaded

    # ── Public entry point ─────────────────────────────────────────────

    def score(self, event: dict) -> dict:
        """
        Synchronous scoring function — called from run_in_executor.
        Returns a Decision dict.
        """
        co_id   = event["company_id"]
        user_id = event["user_id"]
        action  = event["action_type"]
        ts_ms   = event["timestamp_ms"]
        ts_s    = ts_ms / 1000.0
        amount  = float(event.get("amount_usd", 0.0))
        balance = event.get("credit_balance", -1.0)

        risk_level  = "PASS"
        reasons     = []
        fraud_score = 0.0
        is_fraud    = False
        z           = 0.0

        # ── Auth anomaly check ─────────────────────────────────────────
        if event.get("auth_failed"):
            key = (co_id, user_id)
            buf = self._auth_failures.setdefault(key, deque())
            buf.append(ts_s)
            # evict old entries outside AUTH_WINDOW_S
            cutoff = ts_s - AUTH_WINDOW_S
            while buf and buf[0] < cutoff:
                buf.popleft()

            n_failures = len(buf)
            if n_failures >= AUTH_BLOCK_COUNT:
                risk_level = "BLOCK"
                reasons.append(f"auth_burst:{n_failures}_in_{AUTH_WINDOW_S}s")
            elif n_failures >= AUTH_WATCH_COUNT:
                risk_level = "WATCH"
                reasons.append(f"auth_burst:{n_failures}_in_{AUTH_WINDOW_S}s")

        # ── Transaction scoring ────────────────────────────────────────
        if action == 1 and amount > 0:  # ACTION_TRANSACTION
            key = (co_id, user_id)

            # Company-level rolling stats
            co_roll = self._co_rolling.setdefault(co_id, _RollingStats(WINDOW_SECONDS))
            co_mean, co_std = co_roll.push(amount, ts_s)
            z = (amount - co_mean) / co_std

            # Z-score threshold check
            abs_z = abs(z)
            if abs_z >= BLOCK_Z:
                risk_level = "BLOCK"
                reasons.append(f"amount_z:{z:.1f}>=5σ")
            elif abs_z >= WATCH_Z:
                if risk_level == "PASS":
                    risk_level = "WATCH"
                reasons.append(f"amount_z:{z:.1f}>=3σ")

            # Customer-level rolling stats
            cust_roll = self._cust_rolling.setdefault(key, _RollingStats(WINDOW_SECONDS))
            c_mean, c_std = cust_roll.push(amount, ts_s)
            amount_z_cust = (amount - c_mean) / c_std

            # Velocity features — O(1) via two separate deques
            txn_buf = self._cust_txn_ts.setdefault(key, deque())
            txn_buf.append(ts_ms)
            # evict beyond 24h
            cutoff_24h = ts_ms - DAY_MS
            while txn_buf and txn_buf[0] < cutoff_24h:
                txn_buf.popleft()
            vel_24h = len(txn_buf)

            # 1h deque: maintained independently — evict at 1h boundary then append
            txn_1h = self._cust_txn_1h.setdefault(key, deque())
            txn_1h.append(ts_ms)
            cutoff_1h = ts_ms - HOUR_MS
            while txn_1h and txn_1h[0] < cutoff_1h:
                txn_1h.popleft()
            vel_1h = len(txn_1h)

            last_ts = self._cust_last_ts.get(key)
            days_since = (ts_ms - last_ts) / DAY_MS if last_ts else 30.0
            self._cust_last_ts[key] = ts_ms

            # Calendar features
            dt       = datetime.datetime.fromtimestamp(ts_s, tz=datetime.timezone.utc)
            hour     = float(dt.hour)
            dow      = float(dt.weekday())
            month    = float(dt.month)
            m_sin    = math.sin(2.0 * math.pi * month / 12.0)
            m_cos    = math.cos(2.0 * math.pi * month / 12.0)

            # Company-wide training-time mean (from stats)
            co_stat  = self._co_stats.get(co_id, {})
            train_mean = float(co_stat.get("amount_mean") or co_mean)

            amt_ratio_co   = amount / train_mean if train_mean > 0 else 1.0
            amount_z_co    = (amount - train_mean) / max(co_std, 1e-6)

            # XGBoost inference — inplace_predict avoids DMatrix heap allocation
            # (~5x faster per call; numerically identical to DMatrix.predict)
            bst = self._models.get(co_id)
            if bst is not None:
                X = np.array([[
                    amount,
                    amount_z_co,
                    amount_z_cust,
                    amt_ratio_co,
                    float(vel_1h),
                    float(vel_24h),
                    float(days_since),
                    hour,
                    dow,
                    m_sin,
                    m_cos,
                ]], dtype=np.float32)
                fraud_score = float(bst.inplace_predict(X)[0])
                threshold   = float(co_stat.get("best_threshold") or 0.5)
                is_fraud    = fraud_score >= threshold

                if is_fraud:
                    risk_level = "BLOCK"
                    reasons.append(f"model_fraud:{fraud_score:.3f}")

        return {
            "company_id":    co_id,
            "user_id":       user_id,
            "timestamp_ms":  ts_ms,
            "risk_level":    risk_level,
            "is_fraud":      is_fraud,
            "fraud_score":   round(fraud_score, 4),
            "z_score":       round(z, 3),
            "reason":        "; ".join(reasons) if reasons else "ok",
            "credit_balance": balance,
            "action_type":   action,
        }
