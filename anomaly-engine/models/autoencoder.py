"""
SauronID Autoencoder Model — Behavioral sequence reconstruction for anomaly detection.

Uses a PyTorch autoencoder trained on "normal" user behavior sequences.
When evaluating a new transaction, a high reconstruction error indicates
the behavior deviates from learned patterns — signaling potential:
  - Account takeover
  - Agent hijacking (prompt injection)
  - Credential theft
  - Synthetic identity usage

Architecture: [input_dim] → [64] → [32] → [16] → [32] → [64] → [input_dim]
The bottleneck (16 dims) forces the model to learn compressed representations
of normal behavior. Anomalous patterns cannot be compressed well, leading to
high reconstruction error.
"""

import numpy as np
import pandas as pd
import os
from typing import Dict, Any, Tuple, Optional

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "saved_models")


class BehaviorAutoencoder(nn.Module):
    """
    Symmetric autoencoder for behavioral pattern learning.
    """

    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 16),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.2),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)


class AutoencoderModel:
    """
    Autoencoder-based anomaly detector for behavioral sequences.

    Training:
        model = AutoencoderModel(input_dim=10)
        model.train(normal_behavior_df)
        model.save("ae_model_v1")

    Scoring:
        error, is_anomaly = model.score(transaction_features)
        # High error = anomalous behavior
    """

    def __init__(self, input_dim: int = 10, threshold_percentile: float = 95.0):
        """
        Args:
            input_dim: Number of input features
            threshold_percentile: Percentile of training errors to use as anomaly threshold
        """
        self.input_dim = input_dim
        self.threshold_percentile = threshold_percentile
        self.model = BehaviorAutoencoder(input_dim)
        self.threshold: float = 0.0
        self.is_trained = False
        self.training_stats: Dict[str, Any] = {}
        self.mean: Optional[np.ndarray] = None
        self.std: Optional[np.ndarray] = None

    def train(
        self,
        df: pd.DataFrame,
        feature_cols: list,
        epochs: int = 50,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
    ) -> Dict[str, Any]:
        """
        Train the autoencoder on normal behavior data.

        Args:
            df: DataFrame with behavioral features
            feature_cols: List of column names to use as features
            epochs: Training epochs
            batch_size: Batch size
            learning_rate: Adam learning rate

        Returns:
            Training statistics
        """
        # Prepare data
        X = df[feature_cols].fillna(0).values.astype(np.float32)

        # Normalize
        self.mean = X.mean(axis=0)
        self.std = X.std(axis=0) + 1e-8
        X_norm = (X - self.mean) / self.std

        dataset = TensorDataset(torch.FloatTensor(X_norm))
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.model.train()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate, weight_decay=1e-5)
        criterion = nn.MSELoss()

        loss_history = []
        for epoch in range(epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                output = self.model(batch)
                loss = criterion(output, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * len(batch)

            avg_loss = epoch_loss / len(X_norm)
            loss_history.append(avg_loss)

            if (epoch + 1) % 10 == 0:
                print(f"  [AE] Epoch {epoch+1}/{epochs} — loss: {avg_loss:.6f}")

        # Compute threshold from training data reconstruction errors
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_norm)
            reconstructed = self.model(X_tensor).numpy()
            errors = np.mean((X_norm - reconstructed) ** 2, axis=1)
            self.threshold = float(np.percentile(errors, self.threshold_percentile))

        self.is_trained = True
        self.training_stats = {
            "n_samples": len(df),
            "n_features": len(feature_cols),
            "feature_cols": feature_cols,
            "epochs": epochs,
            "final_loss": loss_history[-1],
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "error_mean": float(np.mean(errors)),
            "error_std": float(np.std(errors)),
            "error_max": float(np.max(errors)),
        }

        return self.training_stats

    def score(self, features: Dict[str, float], feature_cols: list) -> Tuple[float, bool]:
        """
        Score a single transaction by reconstruction error.

        Args:
            features: Dict of feature_name → value
            feature_cols: Ordered list of feature column names

        Returns:
            (reconstruction_error, is_anomaly)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        x = np.array([[features.get(f, 0.0) for f in feature_cols]], dtype=np.float32)
        x_norm = (x - self.mean) / self.std

        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.FloatTensor(x_norm)
            reconstructed = self.model(x_tensor).numpy()
            error = float(np.mean((x_norm - reconstructed) ** 2))

        return error, error > self.threshold

    def save(self, name: str = "autoencoder") -> str:
        """Save model to disk."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        path = os.path.join(MODEL_DIR, f"{name}.pt")
        torch.save({
            "model_state": self.model.state_dict(),
            "input_dim": self.input_dim,
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "mean": self.mean,
            "std": self.std,
            "training_stats": self.training_stats,
        }, path)
        return path

    def load(self, name: str = "autoencoder") -> None:
        """Load model from disk."""
        path = os.path.join(MODEL_DIR, f"{name}.pt")
        data = torch.load(path, map_location="cpu", weights_only=False)
        self.input_dim = data["input_dim"]
        self.model = BehaviorAutoencoder(self.input_dim)
        self.model.load_state_dict(data["model_state"])
        self.model.eval()
        self.threshold = data["threshold"]
        self.threshold_percentile = data["threshold_percentile"]
        self.mean = data["mean"]
        self.std = data["std"]
        self.training_stats = data["training_stats"]
        self.is_trained = True
