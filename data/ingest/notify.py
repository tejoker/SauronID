"""
ingest/notify.py
================
Notification router — two channels:

1. SSE broadcast: all connected dashboard subscribers receive every
   WATCH / BLOCK decision as a JSON-encoded Server-Sent Event.

2. Webhook: per-company HTTP POST to a registered URL.
   Company webhook URLs are read from the environment:
       WEBHOOK_URL_<COMPANY_ID>=https://company-host.example.com/fraud-notify
   or from a JSON file at WEBHOOK_CONFIG_PATH (default: webhooks.json next to
   this file).

Both channels are fire-and-forget (non-blocking). Webhook failures are
logged but do not fail the main request.
"""

import asyncio
import json
import logging
import os
import time
from collections import defaultdict

import httpx

log = logging.getLogger("notify")

# ── Webhook config ────────────────────────────────────────────────────────

def _load_webhook_config() -> dict[int, str]:
    """
    Returns {company_id: webhook_url}.
    Reads from JSON file first, then overlays env vars.
    """
    config: dict[int, str] = {}

    config_path = os.getenv(
        "WEBHOOK_CONFIG_PATH",
        os.path.join(os.path.dirname(__file__), "webhooks.json"),
    )
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                raw = json.load(f)
            config = {int(k): v for k, v in raw.items()}
        except Exception as exc:
            log.warning("Could not load webhooks.json: %s", exc)

    # Env vars override file
    for key, val in os.environ.items():
        if key.startswith("WEBHOOK_URL_"):
            try:
                co_id = int(key[len("WEBHOOK_URL_"):])
                config[co_id] = val
            except ValueError:
                pass

    return config


# ── NotificationRouter ────────────────────────────────────────────────────

class NotificationRouter:
    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []
        self._webhooks: dict[int, str]         = _load_webhook_config()
        # reusable async HTTP client
        self._http = httpx.AsyncClient(timeout=5.0)

        # Simple per-company rate-limiting: at most 1 webhook/sec per company
        # to avoid flooding when many events arrive simultaneously.
        self._last_webhook: dict[int, float] = defaultdict(float)
        self._min_interval_s = 1.0

    def subscribe(self, queue: asyncio.Queue):
        self._subscribers.append(queue)

    def unsubscribe(self, queue: asyncio.Queue):
        try:
            self._subscribers.remove(queue)
        except ValueError:
            pass

    async def broadcast(self, decision: dict):
        """Push decision to all SSE subscribers (drop if queue full)."""
        if decision.get("risk_level") == "PASS":
            return  # SSE only for actionable events
        for q in list(self._subscribers):
            try:
                q.put_nowait(decision)
            except asyncio.QueueFull:
                pass  # slow subscriber — drop rather than block

    async def send_webhook(self, company_id: int, decision: dict):
        """
        POST decision to the company's registered webhook URL.
        Rate-limited to one call per second per company.
        Failures are logged, not raised.
        """
        url = self._webhooks.get(company_id)
        if not url:
            return

        now = time.monotonic()
        last = self._last_webhook[company_id]
        if now - last < self._min_interval_s:
            log.debug("Webhook rate-limited for company %d", company_id)
            return

        self._last_webhook[company_id] = now

        payload = {
            "company_id":  decision["company_id"],
            "user_id":     decision["user_id"],
            "timestamp_ms": decision["timestamp_ms"],
            "risk_level":  decision["risk_level"],
            "is_fraud":    decision["is_fraud"],
            "fraud_score": decision["fraud_score"],
            "z_score":     decision["z_score"],
            "reason":      decision["reason"],
        }

        try:
            resp = await self._http.post(url, json=payload)
            if resp.status_code >= 400:
                log.warning(
                    "Webhook for company %d returned %d",
                    company_id, resp.status_code,
                )
        except Exception as exc:
            log.warning("Webhook delivery failed for company %d: %s", company_id, exc)
