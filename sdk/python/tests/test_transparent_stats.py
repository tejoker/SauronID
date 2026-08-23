import json
from unittest.mock import Mock, patch

import pytest

from sauronid_client.client import SauronIDClient


def test_submit_transparent_stats_uses_strict_production_shape():
    response = Mock(ok=True)
    response.json.return_value = {
        "stored": True,
        "latency_ms_verify": 4,
        "statement_hash": "ab",
    }
    client = SauronIDClient(
        "https://core.example", admin_key="admin-secret", tenant_id="tenant-a"
    )
    with patch("sauronid_client.client.requests.request", return_value=response) as request:
        result = client.submit_transparent_stats(
            checkpoint_id="zkc_1",
            metric_id="success_rate",
            claimed_value=1000,
            period_start=10,
            period_end=20,
            receipt_b64="e30=",
        )

    method, url = request.call_args.args[:2]
    body = json.loads(request.call_args.kwargs["data"])
    headers = request.call_args.kwargs["headers"]
    assert method == "POST"
    assert url == "https://core.example/v1/stats/submit-transparent"
    assert body["program_id"] == "sauron-stats-v1"
    assert body["tenant_id"] == "tenant-a"
    assert body["receipt_b64"] == "e30="
    assert "proof" not in body
    assert headers["x-admin-key"] == "admin-secret"
    assert result["statement_hash"] == "ab"


def test_submit_transparent_stats_rejects_unsupported_metric_before_network():
    client = SauronIDClient("https://core.example", admin_key="admin-secret")
    with pytest.raises(ValueError, match="not implemented"):
        client.submit_transparent_stats(
            checkpoint_id="zkc_1",
            metric_id="latency_p99",
            claimed_value=1,
            period_start=10,
            period_end=20,
            receipt_b64="e30=",
        )
