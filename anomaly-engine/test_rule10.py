"""
Rule 10 compliance check: anomaly models should score synthetic anomalies as risky.
"""

import numpy as np
import pandas as pd

from models.isolation_forest import IsolationForestModel


def build_training_data(n: int = 1500) -> pd.DataFrame:
    rng = np.random.RandomState(42)
    return pd.DataFrame(
        {
            "ip_geo_distance_km": rng.exponential(40, n),
            "device_fingerprint_sim": rng.beta(8, 2, n),
            "request_velocity_1h": rng.poisson(2, n).astype(float),
            "request_velocity_24h": rng.poisson(10, n).astype(float),
            "hour_of_day": rng.randint(7, 23, n).astype(float),
            "day_of_week": rng.randint(0, 7, n).astype(float),
            "credential_age_days": rng.exponential(90, n),
            "acquirer_risk_score": rng.beta(2, 8, n),
            "amount_usd": rng.lognormal(3.5, 0.6, n),
            "is_new_device": rng.binomial(1, 0.05, n).astype(float),
        }
    )


def main() -> None:
    model = IsolationForestModel(contamination=0.05, n_estimators=150)

    df = build_training_data()
    model.train(df)

    normal = {
        "ip_geo_distance_km": 15,
        "device_fingerprint_sim": 0.95,
        "request_velocity_1h": 2,
        "request_velocity_24h": 8,
        "hour_of_day": 14,
        "day_of_week": 2,
        "credential_age_days": 120,
        "acquirer_risk_score": 0.1,
        "amount_usd": 75,
        "is_new_device": 0,
        "delegation_depth": 0,
        "workflow_violations": 0,
    }

    anomaly = {
        "ip_geo_distance_km": 9500,
        "device_fingerprint_sim": 0.05,
        "request_velocity_1h": 80,
        "request_velocity_24h": 400,
        "hour_of_day": 3,
        "day_of_week": 6,
        "credential_age_days": 1,
        "acquirer_risk_score": 0.95,
        "amount_usd": 25000,
        "is_new_device": 1,
        "delegation_depth": 4,
        "workflow_violations": 3,
    }

    normal_score, normal_is_anomaly = model.score(normal)
    anomaly_score, anomaly_is_anomaly = model.score(anomaly)

    if anomaly_score >= normal_score:
        raise SystemExit(
            f"FAIL: expected anomaly score lower than normal (more anomalous). anomaly={anomaly_score:.4f}, normal={normal_score:.4f}"
        )

    if not anomaly_is_anomaly:
        raise SystemExit(
            "FAIL: synthetic anomaly was not flagged by IsolationForest"
        )

    if normal_is_anomaly:
        raise SystemExit("FAIL: baseline sample incorrectly flagged as anomaly")

    print("PASS: IsolationForest flags synthetic anomaly and accepts baseline sample")


if __name__ == "__main__":
    main()
