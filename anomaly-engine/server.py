"""
SauronID Anomaly Detection API — FastAPI service (port 8010).

Endpoints:
  POST /score          — Risk score for a credential presentation
  POST /train          — Trigger model retraining
  GET  /model/status   — Model health and metrics
  POST /threat-response — Execute automated threat response
  GET  /health         — Service health check
"""

import os
import time
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from engine import RiskScoringEngine

app = FastAPI(title="SauronID Anomaly Detection Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Global engine instance ──────────────────────────────────────────

engine = RiskScoringEngine()
request_count = 0
high_risk_count = 0
start_time = time.time()


# ─── Models ──────────────────────────────────────────────────────────

class ScoreRequest(BaseModel):
    """Request to score a credential presentation."""
    ip_geo_distance_km: float = 0.0
    device_fingerprint_sim: float = 1.0
    request_velocity_1h: float = 1.0
    request_velocity_24h: float = 5.0
    hour_of_day: int = 12
    day_of_week: int = 2
    credential_age_days: float = 30.0
    acquirer_risk_score: float = 0.1
    amount_usd: float = 50.0
    is_new_device: int = 0
    # A-JWT specific
    agent_checksum: Optional[str] = None
    delegation_depth: int = 0
    workflow_violations: int = 0


class ScoreResponse(BaseModel):
    score: float
    level: str
    factors: List[str]
    signals: Dict[str, float]
    action: str
    latency_ms: float


class TrainRequest(BaseModel):
    """Request to retrain models with new data."""
    data_path: Optional[str] = None
    n_synthetic: int = 5000


class ThreatResponseRequest(BaseModel):
    """Automated threat response action."""
    action: str  # "block" | "step_up" | "allow"
    credential_hash: Optional[str] = None
    agent_checksum: Optional[str] = None
    reason: str = ""


# ─── Endpoints ───────────────────────────────────────────────────────

@app.post("/score", response_model=ScoreResponse)
async def score_transaction(req: ScoreRequest):
    """Score a credential presentation for risk."""
    global request_count, high_risk_count
    request_count += 1

    start = time.time()

    features = req.model_dump()
    # Add A-JWT-specific risk factors
    if req.workflow_violations > 0:
        features["request_velocity_1h"] += req.workflow_violations * 5

    result = engine.compute_risk_score(features)

    if result["level"] in ("high", "critical"):
        high_risk_count += 1

    latency = (time.time() - start) * 1000

    return ScoreResponse(
        score=result["score"],
        level=result["level"],
        factors=result["factors"],
        signals=result["signals"],
        action=result["action"],
        latency_ms=round(latency, 2),
    )


@app.post("/train")
async def train_models(req: TrainRequest):
    """Train or retrain the anomaly detection models."""
    try:
        # Generate synthetic training data
        n = req.n_synthetic
        rng = np.random.RandomState(42)

        df = pd.DataFrame({
            "ip_geo_distance_km": rng.exponential(50, n),
            "device_fingerprint_sim": rng.beta(8, 2, n),
            "request_velocity_1h": rng.poisson(3, n).astype(float),
            "request_velocity_24h": rng.poisson(15, n).astype(float),
            "hour_of_day": rng.randint(0, 24, n).astype(float),
            "day_of_week": rng.randint(0, 7, n).astype(float),
            "credential_age_days": rng.exponential(60, n),
            "acquirer_risk_score": rng.beta(2, 8, n),
            "amount_usd": rng.lognormal(4, 1.5, n),
            "is_new_device": rng.binomial(1, 0.1, n).astype(float),
        })

        # Train Isolation Forest
        if_stats = engine.if_model.train(df)
        engine.if_trained = True
        engine.if_model.save()

        # Train Autoencoder
        feature_cols = list(df.columns)
        engine.ae_model = __import__("models.autoencoder", fromlist=["AutoencoderModel"]).AutoencoderModel(
            input_dim=len(feature_cols)
        )
        ae_stats = engine.ae_model.train(df, feature_cols, epochs=30)
        engine.ae_trained = True
        engine.ae_model.save()

        return {
            "status": "trained",
            "isolation_forest": if_stats,
            "autoencoder": ae_stats,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/model/status")
async def model_status():
    """Get model health and metrics."""
    return {
        "isolation_forest": {
            "trained": engine.if_trained,
            "stats": engine.if_model.training_stats if engine.if_trained else None,
        },
        "autoencoder": {
            "trained": engine.ae_trained,
            "stats": engine.ae_model.training_stats if engine.ae_trained else None,
        },
        "engine": {
            "weights": engine.weights,
            "total_scored": request_count,
            "high_risk_count": high_risk_count,
            "uptime_seconds": round(time.time() - start_time, 1),
        },
    }


@app.post("/threat-response")
async def threat_response(req: ThreatResponseRequest):
    """Execute an automated threat response action."""
    # In production, this would trigger actual actions:
    # - "block": add to blocklist, revoke credential
    # - "step_up": require re-authentication
    # - "allow": log and continue
    action_log = {
        "action": req.action,
        "credential_hash": req.credential_hash,
        "agent_checksum": req.agent_checksum,
        "reason": req.reason,
        "timestamp": time.time(),
        "executed": True,
    }

    if req.action == "block":
        print(f"[THREAT] BLOCKING credential={req.credential_hash} reason={req.reason}")
    elif req.action == "step_up":
        print(f"[THREAT] STEP-UP AUTH required for credential={req.credential_hash}")
    else:
        print(f"[THREAT] ALLOW with monitoring for credential={req.credential_hash}")

    return action_log


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "SauronID Anomaly Detection Engine",
        "models_loaded": {
            "isolation_forest": engine.if_trained,
            "autoencoder": engine.ae_trained,
        },
        "uptime": round(time.time() - start_time, 1),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8010))
    print(f"\n[SauronID Anomaly Engine] Starting on port {port}")
    # Try to load pre-trained models
    engine.load_models()
    uvicorn.run(app, host="0.0.0.0", port=port)
