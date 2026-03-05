"""
SauronID Risk Scoring Engine — Combines ML models for dynamic risk assessment.

Orchestrates:
  1. Isolation Forest: broad anomaly detection on telemetry features
  2. Autoencoder: behavioral sequence reconstruction error
  3. Rule-based checks: impossible travel, velocity limits, known bad IPs

The final risk score is a weighted ensemble of all signals.
"""

import numpy as np
from typing import Dict, Any, Optional, List
from models.isolation_forest import IsolationForestModel
from models.autoencoder import AutoencoderModel

RISK_LEVELS = {
    "low": (0.0, 0.3),
    "medium": (0.3, 0.6),
    "high": (0.6, 0.85),
    "critical": (0.85, 1.0),
}

# Default weights for the ensemble
DEFAULT_WEIGHTS = {
    "isolation_forest": 0.35,
    "autoencoder": 0.35,
    "rules": 0.30,
}


class RiskScoringEngine:
    """
    Dynamic risk scoring engine combining multiple ML signals.

    Each credential presentation is scored in real-time.
    The score determines the automated threat response:
      - low (0-0.3):      Allow
      - medium (0.3-0.6):  Allow with monitoring
      - high (0.6-0.85):   Request step-up authentication
      - critical (0.85-1): Block transaction
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or DEFAULT_WEIGHTS
        self.if_model = IsolationForestModel()
        self.ae_model = AutoencoderModel()
        self.if_trained = False
        self.ae_trained = False

    def load_models(self, if_name: str = "isolation_forest", ae_name: str = "autoencoder") -> None:
        """Load pre-trained models from disk."""
        try:
            self.if_model.load(if_name)
            self.if_trained = True
            print(f"[ENGINE] Isolation Forest loaded: {if_name}")
        except Exception as e:
            print(f"[ENGINE] Warning: IF model not loaded: {e}")

        try:
            self.ae_model.load(ae_name)
            self.ae_trained = True
            print(f"[ENGINE] Autoencoder loaded: {ae_name}")
        except Exception as e:
            print(f"[ENGINE] Warning: AE model not loaded: {e}")

    def compute_risk_score(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute a risk score for a credential presentation.

        Args:
            transaction: Dict with telemetry features

        Returns:
            {
                score: float (0-1),
                level: "low"|"medium"|"high"|"critical",
                factors: [...],
                signals: { isolation_forest: ..., autoencoder: ..., rules: ... },
                action: "allow"|"monitor"|"step_up"|"block"
            }
        """
        signals = {}
        factors: List[str] = []

        # ─── Signal 1: Isolation Forest ─────────────────────────────
        if_score = 0.5  # neutral default
        if self.if_trained:
            raw_score, is_anomaly = self.if_model.score(transaction)
            # Normalize IF score from [-1, 1] to [0, 1] (1 = anomalous)
            if_score = max(0.0, min(1.0, (1.0 - raw_score) / 2.0))
            if is_anomaly:
                factors.append("Isolation Forest flagged as anomaly")
        signals["isolation_forest"] = if_score

        # ─── Signal 2: Autoencoder ──────────────────────────────────
        ae_score = 0.5  # neutral default
        if self.ae_trained:
            feature_cols = self.ae_model.training_stats.get("feature_cols", [])
            if feature_cols:
                error, is_anomaly = self.ae_model.score(transaction, feature_cols)
                # Normalize AE error relative to threshold
                threshold = self.ae_model.threshold or 1.0
                ae_score = min(1.0, error / (threshold * 3.0))
                if is_anomaly:
                    factors.append("Behavioral pattern deviates from baseline")
        signals["autoencoder"] = ae_score

        # ─── Signal 3: Rule-based checks ────────────────────────────
        rule_score = 0.0
        rule_factors = self._apply_rules(transaction)
        rule_score = min(1.0, len(rule_factors) * 0.25)
        factors.extend(rule_factors)
        signals["rules"] = rule_score

        # ─── Weighted ensemble ──────────────────────────────────────
        total_weight = sum(self.weights.values())
        final_score = (
            signals["isolation_forest"] * self.weights["isolation_forest"]
            + signals["autoencoder"] * self.weights["autoencoder"]
            + signals["rules"] * self.weights["rules"]
        ) / total_weight

        final_score = max(0.0, min(1.0, final_score))

        # Determine risk level
        level = "low"
        for lvl, (low, high) in RISK_LEVELS.items():
            if low <= final_score < high:
                level = lvl
                break
        if final_score >= 0.85:
            level = "critical"

        # Determine action
        actions = {
            "low": "allow",
            "medium": "monitor",
            "high": "step_up",
            "critical": "block",
        }

        return {
            "score": round(final_score, 4),
            "level": level,
            "factors": factors,
            "signals": {k: round(v, 4) for k, v in signals.items()},
            "action": actions[level],
        }

    def _apply_rules(self, tx: Dict[str, Any]) -> List[str]:
        """Rule-based anomaly checks."""
        factors = []

        # Impossible travel: > 500km in < 1h
        geo_dist = tx.get("ip_geo_distance_km", 0)
        if geo_dist > 500:
            factors.append(f"Impossible travel: {geo_dist:.0f}km from last location")

        # High velocity
        vel_1h = tx.get("request_velocity_1h", 0)
        if vel_1h > 20:
            factors.append(f"High velocity: {vel_1h} requests in 1h")

        # Unusual hour (2am - 5am local time)
        hour = tx.get("hour_of_day", 12)
        if 2 <= hour <= 5:
            factors.append(f"Unusual access hour: {hour}:00")

        # New device + high amount
        if tx.get("is_new_device", 0) and tx.get("amount_usd", 0) > 1000:
            factors.append("New device with high-value transaction")

        # Very new credential
        cred_age = tx.get("credential_age_days", 30)
        if cred_age < 1:
            factors.append("Credential less than 1 day old")

        return factors
