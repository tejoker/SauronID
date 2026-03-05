"""
SauronID Isolation Forest Model — High-dimensional anomaly detection.

Uses scikit-learn's IsolationForest to detect anomalous credential
presentations based on telemetry features:
  - IP geolocation distance (impossible travel detection)
  - Device fingerprint hash similarity
  - Request velocity (transactions per time window)
  - Time-of-day patterns
  - Credential age
  - Acquirer type encoding

Isolation Forests work by randomly partitioning the feature space.
Anomalies are "easy to isolate" — they require fewer splits to separate
from the rest of the data, resulting in shorter average path lengths.
"""

import numpy as np
import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, Optional, Tuple

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "saved_models")

FEATURES = [
    "ip_geo_distance_km",    # Distance from last known IP location
    "device_fingerprint_sim", # Similarity to known device (0-1)
    "request_velocity_1h",   # Requests in the last hour
    "request_velocity_24h",  # Requests in the last 24 hours
    "hour_of_day",           # 0-23
    "day_of_week",           # 0-6 (Monday=0)
    "credential_age_days",   # Days since credential was issued
    "acquirer_risk_score",   # Pre-assigned risk level of the acquirer (0-1)
    "amount_usd",            # Transaction amount in USD
    "is_new_device",         # Binary: first time seeing this device
]


class IsolationForestModel:
    """
    Isolation Forest for detecting anomalous credential presentations.
    
    Training:
        model = IsolationForestModel()
        model.train(telemetry_df)
        model.save("if_model_v1")
    
    Scoring:
        score = model.score(transaction_features)
        # score in [-1, 1]: -1 = very anomalous, 1 = very normal
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 200, random_state: int = 42):
        """
        Args:
            contamination: Expected proportion of anomalies (0.05 = 5%)
            n_estimators: Number of isolation trees
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1,  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = FEATURES
        self.training_stats: Dict[str, Any] = {}

    def train(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Train the Isolation Forest on telemetry data.
        
        Args:
            df: DataFrame with columns matching FEATURES
            
        Returns:
            Training statistics
        """
        # Validate features
        available = [f for f in self.feature_names if f in df.columns]
        if len(available) < 3:
            raise ValueError(f"Need at least 3 features. Available: {available}")

        X = df[available].fillna(0).values.astype(np.float64)

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train
        self.model.fit(X_scaled)
        self.is_trained = True
        self.feature_names = available

        # Compute training stats
        scores = self.model.score_samples(X_scaled)
        predictions = self.model.predict(X_scaled)

        self.training_stats = {
            "n_samples": len(df),
            "n_features": len(available),
            "features_used": available,
            "contamination": self.contamination,
            "n_anomalies_detected": int(np.sum(predictions == -1)),
            "anomaly_rate": float(np.mean(predictions == -1)),
            "score_mean": float(np.mean(scores)),
            "score_std": float(np.std(scores)),
            "score_min": float(np.min(scores)),
            "score_max": float(np.max(scores)),
        }

        return self.training_stats

    def score(self, features: Dict[str, float]) -> Tuple[float, bool]:
        """
        Score a single transaction.
        
        Args:
            features: Dict of feature_name → value
            
        Returns:
            (anomaly_score, is_anomaly)
            anomaly_score in [-1, 1]: negative = more anomalous
            is_anomaly: True if classified as anomaly
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        # Build feature vector
        x = np.array([[features.get(f, 0.0) for f in self.feature_names]], dtype=np.float64)
        x_scaled = self.scaler.transform(x)

        score = float(self.model.score_samples(x_scaled)[0])
        prediction = int(self.model.predict(x_scaled)[0])

        return score, prediction == -1

    def score_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score a batch of transactions."""
        if not self.is_trained:
            raise RuntimeError("Model not trained.")

        X = df[[f for f in self.feature_names if f in df.columns]].fillna(0).values.astype(np.float64)
        X_scaled = self.scaler.transform(X)

        scores = self.model.score_samples(X_scaled)
        predictions = self.model.predict(X_scaled)

        result = df.copy()
        result["if_score"] = scores
        result["if_anomaly"] = predictions == -1
        return result

    def save(self, name: str = "isolation_forest") -> str:
        """Save model to disk."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        path = os.path.join(MODEL_DIR, f"{name}.joblib")
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "training_stats": self.training_stats,
        }, path)
        return path

    def load(self, name: str = "isolation_forest") -> None:
        """Load model from disk."""
        path = os.path.join(MODEL_DIR, f"{name}.joblib")
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.training_stats = data["training_stats"]
        self.is_trained = True
