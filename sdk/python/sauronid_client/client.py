"""HTTP client for the SauronID core."""

from __future__ import annotations

import json
import time
import base64
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SauronIDError(RuntimeError):
    """Raised when the SauronID core rejects a request."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"SauronID HTTP {status}: {body}")


@dataclass
class SauronIDClient:
    """Thin HTTP client. Holds base URL and optional admin key.

    The admin key is required for `/admin/...` routes only. Per-call signing
    is handled by `SignedAgent` (see `agent.py`); this client deliberately
    does NOT cache agent secrets.
    """

    base_url: str
    admin_key: Optional[str] = None
    timeout: float = 10.0
    tenant_id: str = "default"

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")

    # ── low-level HTTP ────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        h = dict(headers or {})
        h.setdefault("x-sauron-tenant-id", self.tenant_id)
        if json_body is not None and "content-type" not in {k.lower() for k in h}:
            h["content-type"] = "application/json"
        body = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
        return requests.request(method, url, headers=h, data=body, timeout=self.timeout)

    def get_json(
        self, path: str, *, headers: Optional[Mapping[str, str]] = None
    ) -> Any:
        r = self._request("GET", path, headers=headers)
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        return r.json()

    def post_json(
        self,
        path: str,
        body: Mapping[str, Any],
        *,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        r = self._request("POST", path, json_body=body, headers=headers)
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        return r.json()

    def delete(
        self, path: str, *, headers: Optional[Mapping[str, str]] = None
    ) -> Any:
        r = self._request("DELETE", path, headers=headers)
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)
        return r.json() if r.text else {}

    # ── high-level helpers ────────────────────────────────────────────────

    def admin_headers(self) -> dict:
        if not self.admin_key:
            raise RuntimeError("admin_key not set on SauronIDClient")
        return {
            "x-admin-key": self.admin_key,
            "x-sauron-tenant-id": self.tenant_id,
        }

    def admin_stats(self) -> Any:
        return self.get_json("/admin/stats", headers=self.admin_headers())

    def health(self) -> bool:
        try:
            return self.get_json("/admin/stats", headers=self.admin_headers()) is not None
        except SauronIDError:
            return False

    def user_auth(self, email: str, password: str) -> dict:
        """Development-only legacy password authentication."""
        return self.post_json(
            "/user/auth", {"email": email, "password": password}
        )

    def user_auth_with_key(
        self, key_image_hex: str, private_key: Ed25519PrivateKey
    ) -> dict:
        """Authenticate with the production one-use Ed25519 challenge.

        The private key remains in the caller process. Its public half must
        have been bound to this key image during partner/bank registration.
        The returned session is cryptographically bound to ``tenant_id``.
        """
        challenge = self.post_json(
            "/user/auth/challenge", {"key_image_hex": key_image_hex}
        )
        payload = challenge.get("signing_payload_b64u", "")
        padded = payload + "=" * (-len(payload) % 4)
        try:
            signing_payload = base64.urlsafe_b64decode(padded)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("invalid authentication challenge payload") from exc
        signature = private_key.sign(signing_payload)
        signature_b64u = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        return self.post_json(
            "/user/auth/finish",
            {
                "challenge_id": challenge["challenge_id"],
                "key_image_hex": key_image_hex,
                "signature_b64u": signature_b64u,
            },
        )

    def submit_transparent_stats(
        self,
        *,
        checkpoint_id: str,
        metric_id: str,
        claimed_value: int,
        period_start: int,
        period_end: int,
        receipt_b64: str,
        agent_id: Optional[str] = None,
    ) -> dict:
        """Submit a ceremony-free native STARK stats receipt.

        Generate and independently verify ``receipt_b64`` with the pinned
        ``transparent-zk`` Rust tools. This method transports the receipt to
        the production endpoint; it does not replace local proof verification.
        """
        if metric_id not in {
            "success_rate",
            "error_rate",
            "tool_call_count",
            "cost_total",
        }:
            raise ValueError("metric_id is not implemented by sauron-stats-v1")
        if not checkpoint_id or not receipt_b64:
            raise ValueError("checkpoint_id and receipt_b64 are required")
        if period_start > period_end:
            raise ValueError("period_start must be <= period_end")
        if isinstance(claimed_value, bool) or not isinstance(claimed_value, int):
            raise TypeError("claimed_value must be a fixed-point integer")
        return self.post_json(
            "/v1/stats/submit-transparent",
            {
                "tenant_id": self.tenant_id,
                "agent_id_or_none": agent_id,
                "metric_id": metric_id,
                "claimed_value": claimed_value,
                "period_start": period_start,
                "period_end": period_end,
                "checkpoint_id": checkpoint_id,
                "program_id": "sauron-stats-v1",
                "receipt_b64": receipt_b64,
            },
            headers=self.admin_headers(),
        )

    # ── server time helper ───────────────────────────────────────────────

    @staticmethod
    def now_ms() -> int:
        return int(time.time() * 1000)
