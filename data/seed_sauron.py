#!/usr/bin/env python3
"""
seed_sauron.py — Unified seeder for the Sauron Rust backend.

Reads companies.csv and personas.csv and seeds the Rust backend via HTTP API:
  1. POST /admin/clients     — create FULL_KYC / ZKP_ONLY clients from companies.csv
  2. POST /dev/register_user — register users with site_name → tokens_a incremented
  3. POST /dev/exchange + /dev/buy_tokens — populate token balances
  4. POST /data/{type}/{id}  — seed analytics data (stats, forecast, fraud)

Usage:
    python seed_sauron.py                           # default: all companies + N_SEED_USERS personas
    python seed_sauron.py --users 50                # override user count
    python seed_sauron.py --users 0                 # companies only
    python seed_sauron.py --server http://host:3001 # custom server URL
    python seed_sauron.py --all                     # seed ALL personas (may be slow)
"""

import csv
import hashlib
import math
import os
import random
import secrets
import sys
import time
import argparse
import json
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DIR)
from config import N_SEED_USERS, N_PERSONAS

DEFAULT_SERVER   = os.environ.get("SAURON_URL", "http://localhost:3001")
ADMIN_KEY        = os.environ.get("SAURON_ADMIN_KEY", "super_secret_hackathon_key")
COMPANIES_CSV    = os.path.join(DIR, "companies.csv")
PERSONAS_CSV     = os.path.join(DIR, "personas.csv")

# Deterministic password for seeded personas (dev only).
# Format: "pass_{persona_id}" so the CLI client can reproduce the OPRF.
def persona_password(persona_id: int) -> str:
    return f"pass_{persona_id}"


# ---------------------------------------------------------------------------
# Merkle Commitment helpers (client-side simulation)
# ---------------------------------------------------------------------------
def generate_commitment() -> tuple[str, str]:
    """
    Génère un couple (secret, commitment) pour la couche d'engagement Merkle.
    Le secret est un token aléatoire de 32 bytes (gardé par le client).
    Le commitment est SHA256(secret) encodé en hex (envoyé à Sauron).

    Returns:
        (secret_hex, commitment_hex)
    """
    secret_bytes = secrets.token_bytes(32)
    secret_hex = secret_bytes.hex()
    commitment_hex = hashlib.sha256(secret_bytes).hexdigest()
    return secret_hex, commitment_hex


# Stockage local des preuves Merkle pour la simulation.
# Format : {persona_email: {"secret": str, "commitment": str,
#                           "merkle_root": str, "merkle_proof": list[str],
#                           "leaf_index": int}}
_merkle_proofs_store: dict = {}


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only — no requests dependency)
# ---------------------------------------------------------------------------
def post_json(url: str, data: dict, headers: dict | None = None) -> dict | None:
    """POST JSON and return parsed response, or None on failure."""
    body = json.dumps(data).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        err_body = e.read().decode() if e.fp else ""
        return {"__error": e.code, "__body": err_body}
    except Exception as e:
        return {"__error": str(e)}


def get_json(url: str, headers: dict | None = None) -> dict | list | None:
    hdrs = {}
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs, method="GET")
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Wait for server
# ---------------------------------------------------------------------------
def wait_for_server(server: str, timeout: int = 60):
    print(f"Waiting for server at {server}...", end="", flush=True)
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            req = Request(f"{server}/admin/stats", headers={"x-admin-key": ADMIN_KEY})
            with urlopen(req, timeout=3):
                print(" ready.")
                return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    print(f"\nTIMEOUT after {timeout}s. Is the backend running on {server}?")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 1: Seed clients from companies.csv
# ---------------------------------------------------------------------------
def seed_clients(server: str) -> tuple[int, int]:
    """Returns (full_kyc_count, zkp_only_count)."""
    print("\n--- Seeding clients from companies.csv ---")
    if not os.path.exists(COMPANIES_CSV):
        print(f"  [SKIP] {COMPANIES_CSV} not found. Run generate_companies.py first.")
        return (0, 0)

    with open(COMPANIES_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        companies = list(reader)

    full, zkp = 0, 0
    for c in companies:
        name = c["name"]
        client_type = c.get("client_type", "ZKP_ONLY")
        resp = post_json(
            f"{server}/admin/clients",
            {"name": name, "client_type": client_type},
            headers={"x-admin-key": ADMIN_KEY},
        )
        if resp and "__error" not in resp:
            if client_type == "FULL_KYC":
                full += 1
            else:
                zkp += 1
            print(f"  ✓ {name} ({client_type})")
        else:
            err = resp.get("__body", resp.get("__error", "")) if resp else "no response"
            # Likely already exists — still count it.
            if "409" in str(err) or "CONFLICT" in str(err).upper() or "already" in str(err).lower():
                print(f"  ~ {name} ({client_type}) — already exists")
                if client_type == "FULL_KYC":
                    full += 1
                else:
                    zkp += 1
            else:
                print(f"  ✗ {name}: {err}")

    print(f"  → {full} FULL_KYC + {zkp} ZKP_ONLY = {full + zkp} clients")
    return (full, zkp)


# ---------------------------------------------------------------------------
# Step 2: Seed users from personas.csv (assigning each to a company)
# ---------------------------------------------------------------------------
def seed_users(server: str, limit: int) -> int:
    """Returns count of successfully registered users.
    
    Each persona is deterministically assigned to a company via round-robin
    so that `site_name` is always set and tokens_a gets incremented.
    """
    print(f"\n--- Seeding users from personas.csv (limit={limit}) ---")
    if limit <= 0:
        print("  [SKIP] --users 0")
        return 0

    if not os.path.exists(PERSONAS_CSV):
        print(f"  [SKIP] {PERSONAS_CSV} not found. Run generate_personas.py first.")
        return 0

    # Load companies for round-robin assignment
    company_names = []
    if os.path.exists(COMPANIES_CSV):
        with open(COMPANIES_CSV, encoding="utf-8") as f:
            company_names = [c["name"] for c in csv.DictReader(f)]

    with open(PERSONAS_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        personas = list(reader)

    actual = min(limit, len(personas))
    ok_count = 0
    t0 = time.time()

    for i, p in enumerate(personas[:actual]):
        # Assign each persona to a company via round-robin
        site = company_names[i % len(company_names)] if company_names else ""

        # [MERKLE] Générer un secret aléatoire et son commitment SHA256.
        secret_hex, commitment_hex = generate_commitment()

        payload = {
            "site_name":      site,
            "email":          p["email"],
            "password":       persona_password(int(p["id"])),
            "first_name":     p["first_name"],
            "last_name":      p["last_name"],
            "date_of_birth":  p.get("date_of_birth", ""),
            "nationality":    p.get("nationality", ""),
            "commitment":     commitment_hex,   # [MERKLE] envoi du commitment au backend
        }
        resp = post_json(f"{server}/dev/register_user", payload)
        if resp and "__error" not in resp:
            ok_count += 1
            # [MERKLE] Sauvegarder la preuve reçue (secret local + preuve serveur).
            _merkle_proofs_store[p["email"]] = {
                "secret":       secret_hex,
                "commitment":   commitment_hex,
                "merkle_root":  resp.get("merkle_root"),
                "merkle_proof": resp.get("merkle_proof", []),
                "leaf_index":   resp.get("leaf_index"),
            }
        else:
            err = resp.get("__body", resp.get("__error", "")) if resp else ""
            # Duplicate is OK.
            if "409" in str(err) or "already" in str(err).lower():
                ok_count += 1

        # Progress every 50 users.
        if (i + 1) % 50 == 0 or i + 1 == actual:
            elapsed = time.time() - t0
            rate = (i + 1) / max(elapsed, 0.01)
            eta = (actual - i - 1) / max(rate, 0.01)
            print(f"  [{i+1}/{actual}] {ok_count} ok — {rate:.0f} users/s — ETA {eta:.0f}s")

    elapsed = time.time() - t0
    print(f"  → {ok_count}/{actual} users registered in {elapsed:.1f}s")

    # [MERKLE] Résumé de la couche d'engagement.
    proofs_count = len(_merkle_proofs_store)
    if proofs_count > 0:
        sample = next(iter(_merkle_proofs_store.values()))
        last_root = sample.get("merkle_root", "N/A")
        # Cherche la dernière root enregistrée.
        for entry in _merkle_proofs_store.values():
            if entry.get("merkle_root"):
                last_root = entry["merkle_root"]
        print(f"  [MERKLE] {proofs_count} preuves stockées localement | dernière root={last_root}")

    return ok_count


# ---------------------------------------------------------------------------
# Step 3: Seed token operations (exchange + buy)
# ---------------------------------------------------------------------------
def seed_tokens(server: str):
    """Simulate realistic token activity for all companies.
    
    FULL_KYC companies: already earned tokens_a from user registrations.
      → exchange some tokens_a → tokens_b (rate: 1 A → 5 B)
    ZKP_ONLY companies: buy tokens_b directly (fiat simulation).
    """
    print("\n--- Seeding token operations ---")
    if not os.path.exists(COMPANIES_CSV):
        print(f"  [SKIP] {COMPANIES_CSV} not found.")
        return

    with open(COMPANIES_CSV, encoding="utf-8") as f:
        companies = list(csv.DictReader(f))

    rng = random.Random(42)
    exchanges_ok = 0
    buys_ok = 0

    for c in companies:
        name = c["name"]
        client_type = c.get("client_type", "ZKP_ONLY")

        if client_type == "FULL_KYC":
            # Get current token_a balance
            info = get_json(f"{server}/dev/client/{name}")
            if not info:
                continue
            tokens_a = info.get("tokens_a", 0)
            if tokens_a > 0:
                # Exchange 60-90% of tokens_a
                count = max(1, int(tokens_a * rng.uniform(0.6, 0.9)))
                resp = post_json(f"{server}/dev/exchange", {
                    "site_name": name,
                    "count": count,
                })
                if resp and "__error" not in resp:
                    exchanges_ok += 1
                    print(f"  ✓ {name} (FULL_KYC): exchanged {count}A → {count * 5}B")
                else:
                    err = resp.get("__body", resp.get("__error", "")) if resp else ""
                    print(f"  ✗ {name} exchange: {err}")
            # Also buy some extra tokens_b
            extra = rng.randint(20, 200)
            resp = post_json(f"{server}/dev/buy_tokens", {
                "site_name": name,
                "amount": extra,
            })
            if resp and "__error" not in resp:
                buys_ok += 1
        else:
            # ZKP_ONLY: buy tokens_b directly (their primary acquisition method)
            amount = rng.randint(100, 2000)
            resp = post_json(f"{server}/dev/buy_tokens", {
                "site_name": name,
                "amount": amount,
            })
            if resp and "__error" not in resp:
                buys_ok += 1
                print(f"  ✓ {name} (ZKP_ONLY): bought {amount}B")
            else:
                err = resp.get("__body", resp.get("__error", "")) if resp else ""
                print(f"  ✗ {name} buy_tokens: {err}")

    print(f"  → {exchanges_ok} exchanges, {buys_ok} token purchases")


# ---------------------------------------------------------------------------
# Step 4: Seed analytics data (stats, forecast, fraud)
# ---------------------------------------------------------------------------

MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

PRODUCTS_BY_CATEGORY = {
    "tech":        ["Starter Plan",    "Pro Plan",        "Business Plan",     "Enterprise Plan"],
    "lifestyle":   ["Basic Pass",      "Premium Pass",    "VIP Access",        "Elite Bundle"],
    "food_living": ["Meal Kit S",      "Meal Kit M",      "Meal Kit L",        "Premium Bundle"],
    "travel":      ["Economy",         "Business Class",  "Luxury Package",    "Concierge Service"],
    "investment":  ["Retail Account",  "Premium Account", "Wealth Suite",      "Advisory Service"],
}

COUNTRIES = ["usa", "china", "uk", "ire", "fr", "swe"]
GENERATIONS = ["millennial", "gen_z", "boomer"]
FRAUD_TYPES = ["card_testing", "account_takeover", "friendly_fraud", "identity_theft"]


def _gen_stats(company: dict, rng: random.Random) -> dict:
    """Generate deterministic stats JSON for one company."""
    cid = int(company["company_id"])
    category = company["category"]
    base_cust = int(company.get("base_monthly_customers", 500))
    products = PRODUCTS_BY_CATEGORY.get(category, PRODUCTS_BY_CATEGORY["tech"])

    # Monthly behavior
    monthly_labels = MONTH_NAMES[:]
    base_txn = rng.uniform(150, 500)
    monthly_atv = [round(base_txn * rng.uniform(0.9, 1.12), 2) for _ in range(12)]
    monthly_unique = [int(base_cust * rng.uniform(0.7, 1.3)) for _ in range(12)]
    monthly_new = [monthly_unique[0]] + [int(monthly_unique[i] * rng.uniform(0.05, 0.25)) for i in range(1, 12)]
    monthly_ret = [max(0, u - n) for u, n in zip(monthly_unique, monthly_new)]
    monthly_freq = [round(rng.uniform(8, 15), 2) for _ in range(12)]

    # Weekly behavior (52 weeks)
    weekly_labels = [f"W{w}" for w in range(1, 53)]
    weekly_atv = [round(base_txn * rng.uniform(0.85, 1.15), 2) for _ in range(52)]
    weekly_unique = [int(base_cust * rng.uniform(0.15, 0.35)) for _ in range(52)]
    weekly_new = [int(w * rng.uniform(0.05, 0.2)) for w in weekly_unique]
    weekly_ret = [max(0, u - n) for u, n in zip(weekly_unique, weekly_new)]
    weekly_freq = [round(rng.uniform(2, 4), 2) for _ in range(52)]

    # Revenue concentration
    total_rev = round(sum(atv * uc * freq for atv, uc, freq in
                          zip(monthly_atv, monthly_unique, monthly_freq)), 2)
    top10 = []
    for i in range(10):
        rev_share = rng.uniform(0.02, 0.08) * total_rev
        top10.append({
            "customer_id": rng.randint(100, 9999),
            "revenue": round(rev_share, 2),
            "txn_count": rng.randint(50, 500),
        })
    top10.sort(key=lambda x: -x["revenue"])

    # Decile distribution (Pareto-like: top decile gets ~40-55%)
    decile_shares = sorted([rng.uniform(1, 5) for _ in range(10)], reverse=True)
    decile_shares[0] *= rng.uniform(3, 5)  # top decile gets more
    total_s = sum(decile_shares)
    decile_pct = []
    cumul = 0.0
    for s in decile_shares:
        pct = s / total_s * 100
        cumul += pct
        decile_pct.append({"share": round(pct, 2), "cumulative": round(cumul, 2)})

    # Heatmap (7 days × 24 hours)
    heatmap_values = []
    for d in range(7):
        day_factor = 1.0 if d < 5 else 0.6  # weekends lower
        row = []
        for h in range(24):
            if 9 <= h <= 18:
                hour_factor = rng.uniform(0.8, 1.2)
            elif 6 <= h <= 21:
                hour_factor = rng.uniform(0.3, 0.6)
            else:
                hour_factor = rng.uniform(0.05, 0.15)
            row.append(int(base_cust * day_factor * hour_factor * rng.uniform(0.5, 1.5) / 10))
        heatmap_values.append(row)

    # Amount histogram (20 bins)
    p99 = base_txn * rng.uniform(3, 6)
    bin_edges = [round(i * p99 / 20, 2) for i in range(21)]
    # Bell-shaped distribution
    hist_counts = []
    for i in range(20):
        center_dist = abs(i - 8) / 10.0
        base_count = int(base_cust * rng.uniform(0.3, 1.5) * max(0.1, 1 - center_dist))
        hist_counts.append(base_count)

    # Product stats
    prod_rev = [round(total_rev * w, 2) for w in [0.1, 0.25, 0.35, 0.3]]
    prod_vol = [int(sum(hist_counts) * w) for w in [0.35, 0.30, 0.20, 0.15]]
    prod_avg = [round(r / max(v, 1), 2) for r, v in zip(prod_rev, prod_vol)]

    # Cross-sell matrix
    matrix = []
    for i in range(4):
        row = []
        for j in range(4):
            if i == j:
                row.append(1.0)
            else:
                row.append(round(rng.uniform(0.3, 0.95), 3))
        matrix.append(row)

    # Segmentation
    country_counts = {}
    for c in COUNTRIES:
        country_counts[c] = int(base_cust * rng.uniform(0.05, 0.4))
    gen_counts = {}
    for g in GENERATIONS:
        gen_counts[g] = int(base_cust * rng.uniform(0.2, 0.5))

    return {
        "company_id": cid,
        "category": category,
        "products": products,
        "behavior": {
            "monthly": {
                "labels": monthly_labels,
                "avg_txn_value": monthly_atv,
                "unique_customers": monthly_unique,
                "new_customers": monthly_new,
                "returning_customers": monthly_ret,
                "avg_frequency": monthly_freq,
            },
            "weekly": {
                "labels": weekly_labels,
                "avg_txn_value": weekly_atv,
                "unique_customers": weekly_unique,
                "new_customers": weekly_new,
                "returning_customers": weekly_ret,
                "avg_frequency": weekly_freq,
            },
        },
        "concentration": {
            "top10": top10,
            "decile_pct": decile_pct,
            "total_revenue": total_rev,
        },
        "heatmap": {
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "hours": list(range(24)),
            "values": heatmap_values,
        },
        "amount_hist": {
            "edges": bin_edges,
            "counts": hist_counts,
        },
        "products_stats": {
            "names": products,
            "revenue": prod_rev,
            "volume": prod_vol,
            "avg_amount": prod_avg,
        },
        "crosssell": {
            "products": products,
            "matrix": matrix,
        },
        "segmentation": {
            "country": dict(sorted(country_counts.items(), key=lambda x: -x[1])),
            "generation": dict(sorted(gen_counts.items(), key=lambda x: -x[1])),
        },
    }


def _gen_forecast(company: dict, rng: random.Random) -> dict:
    """Generate deterministic forecast data for one company."""
    cid = int(company["company_id"])
    base_cust = int(company.get("base_monthly_customers", 500))
    base_rev = base_cust * rng.uniform(200, 600)

    # Actuals: 12 months of historical data
    months_act = list(range(1, 13))
    revs_act = []
    vols_act = []
    for m in range(12):
        seasonal = 1.0 + 0.15 * math.sin(2 * math.pi * (m + 1) / 12.0)
        trend = 1.0 + m * rng.uniform(0.005, 0.02)
        rev = base_rev * seasonal * trend * rng.uniform(0.9, 1.1)
        vol = int(base_cust * seasonal * trend * rng.uniform(8, 15))
        revs_act.append(round(rev, 2))
        vols_act.append(vol)

    # Forecast: 3 months ahead
    fc_months = [1, 2, 3]  # next quarter
    rev_rmse = base_rev * rng.uniform(0.05, 0.15)
    vol_rmse = base_cust * rng.uniform(0.5, 2.0)
    fc_revs = []
    fc_vols = []
    for i in range(3):
        trend = 1.0 + 12 * rng.uniform(0.005, 0.02)
        seasonal = 1.0 + 0.15 * math.sin(2 * math.pi * (i + 1) / 12.0)
        fc_rev = base_rev * seasonal * trend * rng.uniform(0.95, 1.05)
        fc_vol = int(base_cust * seasonal * trend * rng.uniform(9, 14))
        fc_revs.append(round(fc_rev, 2))
        fc_vols.append(fc_vol)

    return {
        "company_id": cid,
        "n_horizon": 3,
        "actuals": {
            "months": months_act,
            "revenue": revs_act,
            "volume": vols_act,
        },
        "forecast": {
            "months": fc_months,
            "revenue": [round(v, 2) for v in fc_revs],
            "revenue_lo": [round(max(v - rev_rmse, 0), 2) for v in fc_revs],
            "revenue_hi": [round(v + rev_rmse, 2) for v in fc_revs],
            "volume": [round(v) for v in fc_vols],
            "volume_lo": [max(round(v - vol_rmse), 0) for v in fc_vols],
            "volume_hi": [round(v + vol_rmse) for v in fc_vols],
        },
        "stats": {
            "revenue_mean": round(sum(revs_act) / 12, 2),
            "revenue_max": round(max(revs_act), 2),
            "rev_rmse": round(rev_rmse, 2),
        },
    }


def _gen_fraud_summary(company: dict, rng: random.Random) -> dict:
    """Generate deterministic fraud summary for one company."""
    cid = int(company["company_id"])
    base_cust = int(company.get("base_monthly_customers", 500))
    n_total = int(base_cust * rng.uniform(8, 15) * 12)
    fraud_rate = rng.uniform(0.001, 0.01)
    n_actual = int(n_total * fraud_rate)
    n_alerts = int(n_actual * rng.uniform(1.2, 2.5))
    n_rule = int(n_actual * rng.uniform(0.5, 1.5))

    type_counts = {}
    for ft in FRAUD_TYPES:
        type_counts[ft] = rng.randint(0, max(1, n_actual // 3))

    return {
        "company_id": cid,
        "model_f1": round(rng.uniform(0.75, 0.95), 4),
        "threshold": round(rng.uniform(0.3, 0.7), 2),
        "n_train": int(n_total * 0.7),
        "n_test": int(n_total * 0.3),
        "n_fraud_train": int(n_actual * 0.7),
        "n_fraud_test": int(n_actual * 0.3),
        "n_recent_total": n_total,
        "n_recent_alerts": n_alerts,
        "n_recent_rule_flags": n_rule,
        "n_actual_fraud": n_actual,
        "fraud_rate_pct": round(fraud_rate * 100, 3),
        "fraud_type_counts": type_counts,
    }


def _gen_fraud_recent(company: dict, rng: random.Random) -> dict:
    """Generate deterministic recent fraud transactions for one company."""
    cid = int(company["company_id"])
    base_cust = int(company.get("base_monthly_customers", 500))
    n_txns = min(200, int(base_cust * rng.uniform(0.5, 2.0)))
    fraud_rate = rng.uniform(0.002, 0.01)

    transactions = []
    base_ts = 1735689600  # 2025-01-01
    for i in range(n_txns):
        is_fraud = rng.random() < fraud_rate
        fraud_prob = rng.uniform(0.6, 0.99) if is_fraud else rng.uniform(0.0, 0.3)
        fraud_alert = fraud_prob > 0.5
        transactions.append({
            "transaction_id": 100000 + cid * 1000 + i,
            "customer_id": rng.randint(1, base_cust),
            "timestamp": f"2025-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:00",
            "amount_usd": round(rng.uniform(5, 2000), 2),
            "is_fraud": is_fraud,
            "fraud_type": rng.choice(FRAUD_TYPES) if is_fraud else "",
            "rule_flag": is_fraud and rng.random() > 0.3,
            "fraud_prob": round(fraud_prob, 4),
            "fraud_alert": fraud_alert,
        })

    return {
        "company_id": cid,
        "count": len(transactions),
        "transactions": transactions,
    }


def seed_analytics(server: str):
    """Generate and seed all analytics data for all companies."""
    print("\n--- Seeding analytics data (stats, forecast, fraud) ---")
    if not os.path.exists(COMPANIES_CSV):
        print(f"  [SKIP] {COMPANIES_CSV} not found.")
        return

    with open(COMPANIES_CSV, encoding="utf-8") as f:
        companies = list(csv.DictReader(f))

    ok = 0
    for c in companies:
        cid = int(c["company_id"])
        rng = random.Random(cid * 31337)  # deterministic per company

        for data_type, gen_fn in [
            ("stats",         _gen_stats),
            ("forecast",      _gen_forecast),
            ("fraud_summary", _gen_fraud_summary),
            ("fraud_recent",  _gen_fraud_recent),
        ]:
            data = gen_fn(c, rng)
            resp = post_json(
                f"{server}/data/{data_type}/{cid}",
                {"data": data},
            )
            if resp and "__error" not in resp:
                ok += 1
            else:
                err = resp.get("__body", resp.get("__error", "")) if resp else ""
                print(f"  ✗ company {cid} / {data_type}: {err}")

        if cid % 10 == 0 or cid == len(companies):
            print(f"  [{cid}/{len(companies)}] {ok} records seeded")

    print(f"  → {ok} analytics records seeded for {len(companies)} companies")


# ---------------------------------------------------------------------------
# Step 5: Summary
# ---------------------------------------------------------------------------
def print_summary(server: str):
    print("\n--- Summary ---")
    stats = get_json(f"{server}/admin/stats", headers={"x-admin-key": ADMIN_KEY})
    if stats:
        print(f"  Users:     {stats.get('total_users', '?')}")
        print(f"  Clients:   {stats.get('total_clients', '?')}")
        print(f"  Tokens A:  {stats.get('total_tokens_a_issued', '?')}")
        print(f"  Rate A→B:  {stats.get('exchange_rate', '?')}")
    else:
        print("  (could not fetch stats)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Seed Sauron backend from generated CSVs")
    parser.add_argument("--server", default=DEFAULT_SERVER, help=f"Backend URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--users", type=int, default=N_SEED_USERS,
                        help=f"Number of personas to seed (default: {N_SEED_USERS})")
    parser.add_argument("--all", action="store_true", help="Seed all personas (overrides --users)")
    parser.add_argument("--no-wait", action="store_true", help="Skip server readiness check")
    args = parser.parse_args()

    user_limit = N_PERSONAS if args.all else args.users
    server = args.server.rstrip("/")

    print("=" * 60)
    print("  Sauron unified seeder")
    print(f"  Server:  {server}")
    print(f"  Users:   {user_limit} / {N_PERSONAS}")
    print("=" * 60)

    if not args.no_wait:
        wait_for_server(server)

    t0 = time.time()
    seed_clients(server)
    seed_users(server, user_limit)
    seed_tokens(server)
    seed_analytics(server)
    print_summary(server)

    total = time.time() - t0
    print(f"\n=== Seed complete in {total:.1f}s ===")


if __name__ == "__main__":
    main()
