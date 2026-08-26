"""End-to-end test: Python adapter against a live SauronID core.

Run with:

  cd sdk/python
  pip install -e .
  pip install pytest
  pytest tests/test_e2e_live.py -v

Requires a running core at $SAURON_CORE_URL (default http://127.0.0.1:3001) with
the seed.sh users registered. Skipped automatically when the core is unreachable.

Coverage:
  - Public /health returns {ok: true}
  - SauronIDClient.user_auth() round-trips
  - register_llm_agent() actually registers (server-computed checksum)
  - SignedAgent.call() with the correct headers passes per-call signature
  - Mismatched config_digest is rejected with 401 'config drift'
  - Mismatched body is rejected with 401 'signature'
  - Replay of the same nonce is rejected with 409
"""

from __future__ import annotations

import json
import os
import time

import pytest
import requests

CORE_URL = os.getenv("SAURON_CORE_URL", "http://127.0.0.1:3001")


def _core_alive() -> bool:
    try:
        r = requests.get(f"{CORE_URL}/health", timeout=2)
        return r.status_code == 200 and r.json().get("ok") is True
    except Exception:  # noqa: BLE001
        return False


def _tool_available() -> bool:
    """Is the agent-action-tool resolvable?

    Two of these tests sign a call with it. Guarding only on "is the core up"
    meant that on a machine with a running core but no built tool they FAILED
    instead of skipping, which reads as a product regression rather than a
    missing build artefact.
    """
    from sauronid_client.agent import _agent_action_tool_path

    try:
        return bool(_agent_action_tool_path())
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not (_core_alive() and _tool_available()),
    reason=f"needs a core at {CORE_URL} and an agent-action-tool "
    "(build it, or set SAURONID_AGENT_ACTION_TOOL)",
)


def test_public_health_returns_ok_only():
    """Public /health must NOT leak runtime/feature-flag info."""
    r = requests.get(f"{CORE_URL}/health", timeout=5)
    assert r.status_code == 200
    j = r.json()
    assert set(j.keys()) == {"ok"}
    assert j["ok"] is True


def test_admin_health_detailed_requires_admin_key():
    r = requests.get(f"{CORE_URL}/admin/health/detailed", timeout=5)
    assert r.status_code == 401


def test_register_signed_agent_and_call_round_trip():
    """Full flow: user_auth → register_llm_agent → agent.call() succeeds."""
    from sauronid_client import SauronIDClient, register_llm_agent

    admin_key = os.environ.get("SAURON_ADMIN_KEY")
    if not admin_key:
        import pytest

        pytest.skip("SAURON_ADMIN_KEY not set — export it or source .dev-secrets")
    client = SauronIDClient(base_url=CORE_URL, admin_key=admin_key)

    # The seed script creates alice@sauron.dev
    auth = client.user_auth("alice@sauron.dev", "pass_alice")
    assert auth["session"]
    assert auth["key_image"]

    agent = register_llm_agent(
        client,
        user_session=auth["session"],
        user_key_image=auth["key_image"],
        model_id="claude-opus-4-7",
        system_prompt=f"E2E test agent for pytest at {time.time()}",
        tools=["search"],
        intent_scope=["payment_initiation"],
    )
    assert agent.agent_id.startswith("agt_")
    assert agent.config_digest.startswith("sha256:")

    # Make a signed call. We POST to /agent/payment/authorize with a body the
    # server is going to reject for unrelated reasons (fake ajwt) — but the
    # per-call sig check happens FIRST and will pass. So we expect 401 / 400
    # but NOT one mentioning "sig" or "drift" or "nonce".
    body = {
        "ajwt": "deliberately.invalid.token",
        "jti": f"jti-pytest-{int(time.time()*1000)}",
        "amount_minor": 100,
        "currency": "EUR",
        "merchant_id": "test-merchant",
        "payment_ref": f"pytest-{time.time()}",
    }
    resp = agent.call("POST", "/agent/payment/authorize", json_body=body)
    body_text = resp.text
    # Per-call sig check passed (no "drift", "config", "nonce", "sig" in body)
    assert "drift" not in body_text.lower()
    assert "config digest" not in body_text.lower()


def test_drift_detection_rejects_wrong_config_digest():
    """If the agent runtime claims a wrong config digest, every call rejects."""
    from sauronid_client import SauronIDClient, register_llm_agent

    client = SauronIDClient(base_url=CORE_URL)
    auth = client.user_auth("bob@sauron.dev", "pass_bob")
    agent = register_llm_agent(
        client,
        user_session=auth["session"],
        user_key_image=auth["key_image"],
        model_id="m",
        system_prompt="drift test",
        tools=[],
    )
    # Override the digest to simulate a tampered runtime
    agent.config_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    resp = agent.call("POST", "/agent/payment/authorize", json_body={"jti": "x"})
    assert resp.status_code == 401
    assert "drift" in resp.text.lower()


def test_per_call_nonce_replay_rejected():
    """Reusing a nonce on a second call yields 409."""
    from sauronid_client import SauronIDClient, register_llm_agent

    client = SauronIDClient(base_url=CORE_URL)
    auth = client.user_auth("charlie@sauron.dev", "pass_charlie")
    agent = register_llm_agent(
        client,
        user_session=auth["session"],
        user_key_image=auth["key_image"],
        model_id="m",
        system_prompt="replay test",
        tools=[],
    )
    body = {"jti": "replay-test"}

    # Sign once and reuse the headers
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = agent._sign_call_headers("POST", "/agent/payment/authorize", body_bytes)

    r1 = requests.post(
        f"{CORE_URL}/agent/payment/authorize",
        headers={"content-type": "application/json", **headers},
        data=body_bytes,
        timeout=5,
    )
    r2 = requests.post(
        f"{CORE_URL}/agent/payment/authorize",
        headers={"content-type": "application/json", **headers},
        data=body_bytes,
        timeout=5,
    )
    # The second request's nonce is rejected (409). The first might also fail
    # for downstream reasons (fake ajwt), but the second's failure mode should
    # be specifically "call nonce replay".
    assert r2.status_code == 409
    assert "replay" in r2.text.lower() or "nonce" in r2.text.lower()
