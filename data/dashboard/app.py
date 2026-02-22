"""
dashboard/app.py
Standalone company analytics dashboard — completely separate from the KYC app.
Runs on port 8001.

Serves:
  GET /                          → selector UI
  GET /forecast                  → forecast.html
  GET /fraud                     → fraud.html
  GET /api/companies             → companies list
  GET /api/trends                → company_trends.csv as JSON
  GET /api/personas/summary      → aggregated stats from personas.csv
  GET /api/forecast/{id}         → forecast data for company (from DB)
  GET /api/fraud/summary/{id}    → fraud KPIs for company (from DB)
  GET /api/fraud/recent/{id}     → recent scored transactions (from DB)
  GET /api/stats/{id}            → precomputed analytics (from DB)

All analytics data is served from the Sauron Rust backend DB.
No more XGBoost models or JSON files.
"""

import csv
import json
import os
from collections import Counter
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.responses import HTMLResponse
from fastapi.security.api_key import APIKeyHeader
from fastapi.staticfiles import StaticFiles

DATA_DIR   = os.getenv("DATA_DIR", os.path.join(os.path.dirname(__file__), ".."))
SAURON_URL = os.getenv("SAURON_URL", "http://localhost:3001")

VALID_CATEGORIES = {"food_living", "tech", "lifestyle", "travel", "investment"}

app = FastAPI(title="Company Dashboard", version="3.0.0")
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

# ── Authentication ────────────────────────────────────────────────────────────
_API_KEY        = os.getenv("DASHBOARD_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Security(_api_key_header)):
    if not _API_KEY:
        raise HTTPException(status_code=503, detail="Dashboard API key not configured on server")
    if key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── Sauron backend proxy ─────────────────────────────────────────────────────
def _fetch_sauron(data_type: str, company_id: int) -> dict:
    """Fetch analytics data from the Sauron Rust backend."""
    url = f"{SAURON_URL}/data/{data_type}/{company_id}"
    try:
        req = Request(url, method="GET")
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 404:
            raise HTTPException(404, f"No {data_type} data for company {company_id}")
        raise HTTPException(502, f"Sauron backend error: {e.code}")
    except Exception as e:
        raise HTTPException(502, f"Cannot reach Sauron backend: {e}")


# ── CSV data cached at first load ─────────────────────────────────────────────
_companies_cache  : list[dict] | None = None
_trends_cache     : list[dict] | None = None
_personas_cache   : list[dict] | None = None


def _load_companies() -> list[dict]:
    global _companies_cache
    if _companies_cache is None:
        path = os.path.join(DATA_DIR, "companies.csv")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            _companies_cache = list(csv.DictReader(f))
    return _companies_cache


def _load_trends() -> list[dict]:
    global _trends_cache
    if _trends_cache is None:
        path = os.path.join(DATA_DIR, "company_trends.csv")
        if not os.path.exists(path):
            return []
        rows = []
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["month"]               = int(r["month"])
                r["trend_index"]         = float(r["trend_index"])
                r["estimated_customers"] = int(r["estimated_customers"])
                rows.append(r)
        _trends_cache = rows
    return _trends_cache


def _load_personas() -> list[dict]:
    global _personas_cache
    if _personas_cache is None:
        path = os.path.join(DATA_DIR, "personas.csv")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            _personas_cache = list(csv.DictReader(f))
    return _personas_cache


def _validate_company_id(company_id: int) -> int:
    if company_id <= 0:
        raise HTTPException(400, "company_id must be a positive integer")
    return company_id


# ── HTML pages (no auth required) ────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/forecast", response_class=HTMLResponse)
async def forecast_page():
    path = os.path.join(os.path.dirname(__file__), "static", "forecast.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/fraud", response_class=HTMLResponse)
async def fraud_page():
    path = os.path.join(os.path.dirname(__file__), "static", "fraud.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


# ── Data APIs (auth required) ─────────────────────────────────────────────────
@app.get("/api/companies", dependencies=[Depends(require_api_key)])
async def get_companies():
    return _load_companies()


@app.get("/api/trends", dependencies=[Depends(require_api_key)])
async def get_trends():
    return _load_trends()


def _persona_summary(rows: list[dict]) -> dict:
    categories = ["food_living", "tech", "lifestyle", "travel", "investment"]
    avg_spend  = {}
    for cat in categories:
        vals = [float(r[f"{cat}_usd"]) for r in rows if r.get(f"{cat}_usd")]
        avg_spend[cat] = round(sum(vals) / len(vals), 2) if vals else 0
    avg_net_worth = round(sum(float(r["net_worth_usd"]) for r in rows) / len(rows), 2) if rows else 0
    avg_income    = round(sum(float(r["monthly_income_usd"]) for r in rows) / len(rows), 2) if rows else 0
    return {
        "total":                 len(rows),
        "by_country":            dict(Counter(r["country"]           for r in rows)),
        "by_tier":               dict(Counter(r["wealth_tier"]        for r in rows)),
        "by_generation":         dict(Counter(r["generation"]         for r in rows)),
        "by_frequency":          dict(Counter(r["internet_frequency"] for r in rows)),
        "avg_monthly_spend_usd": avg_spend,
        "avg_net_worth_usd":     avg_net_worth,
        "avg_monthly_income_usd": avg_income,
    }


@app.get("/api/personas/summary", dependencies=[Depends(require_api_key)])
async def get_personas_summary():
    return _persona_summary(_load_personas())


@app.get("/api/personas/by_category/{category}", dependencies=[Depends(require_api_key)])
async def get_personas_by_category(category: str):
    if category not in VALID_CATEGORIES:
        raise HTTPException(400, f"Invalid category. Must be one of: {sorted(VALID_CATEGORIES)}")
    cats = list(VALID_CATEGORIES)
    def primary_cat(r: dict) -> str:
        return max(cats, key=lambda c: float(r.get(f"{c}_usd", 0)))
    filtered = [r for r in _load_personas() if primary_cat(r) == category]
    if not filtered:
        raise HTTPException(404, f"No personas found for category '{category}'")
    summary = _persona_summary(filtered)
    summary["category"] = category
    return summary


# ── Forecast API (from Sauron DB) ─────────────────────────────────────────────
@app.get("/api/forecast/{company_id}", dependencies=[Depends(require_api_key)])
async def get_forecast(company_id: int, n: int = 3):
    _validate_company_id(company_id)
    return _fetch_sauron("forecast", company_id)


# ── Fraud API (from Sauron DB) ────────────────────────────────────────────────
@app.get("/api/fraud/summary/{company_id}", dependencies=[Depends(require_api_key)])
async def get_fraud_summary(company_id: int):
    _validate_company_id(company_id)
    return _fetch_sauron("fraud_summary", company_id)


@app.get("/api/fraud/recent/{company_id}", dependencies=[Depends(require_api_key)])
async def get_fraud_recent(company_id: int, limit: int = 200):
    _validate_company_id(company_id)
    return _fetch_sauron("fraud_recent", company_id)


# ── Company Stats API (from Sauron DB) ────────────────────────────────────────
@app.get("/api/stats/{company_id}", dependencies=[Depends(require_api_key)])
async def get_company_stats(company_id: int):
    _validate_company_id(company_id)
    return _fetch_sauron("stats", company_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=True)
