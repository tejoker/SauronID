"""Regression tests for the Python agent's security-critical request paths."""

from __future__ import annotations

import base64
import json
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sauronid_client.agent import (
    SignedAgent,
    _intent_json,
    _resolve_ring_material,
    register_llm_agent,
)
from sauronid_client.client import SauronIDClient


def _jwt_with_jti(jti: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"jti": jti}, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"eyJhbGciOiJub25lIn0.{payload}.signature"


def test_ring_material_rejects_partial_keypairs() -> None:
    with pytest.raises(ValueError, match="must be supplied together"):
        _resolve_ring_material("public", None, "key-image")


def test_ring_material_keeps_one_explicit_keypair() -> None:
    material = _resolve_ring_material("public", "secret", "key-image")
    assert material == ("public", "secret", "key-image")


def test_ring_material_generates_one_consistent_keypair() -> None:
    with patch(
        "sauronid_client.agent._gen_ring_keypair",
        return_value=("generated-public", "generated-secret", "generated-image"),
    ) as keygen:
        material = _resolve_ring_material(None, None, None)
    assert material == ("generated-public", "generated-secret", "generated-image")
    keygen.assert_called_once_with()


def test_intent_json_exposes_egress_allowlist_deterministically() -> None:
    assert _intent_json(
        ["payment_initiation"],
        [{"host": "api.example.com", "methods": ["POST"], "path_prefix": "/v1"}],
    ) == (
        '{"scope":["payment_initiation"],"egress_allowlist":'
        '[{"host":"api.example.com","methods":["POST"],"path_prefix":"/v1"}]}'
    )


def test_register_llm_agent_serialises_payment_cap_into_intent() -> None:
    client = SauronIDClient(base_url="http://core", timeout=3)
    register_resp = Mock(
        ok=True, status_code=200, text="", json=lambda: {"agent_id": "agt_cap"}
    )
    with patch(
        "sauronid_client.agent.requests.post", return_value=register_resp
    ) as post:
        with patch.object(
            client, "get_json", return_value={"agent_checksum": "sha256:cap"}
        ):
            agent = register_llm_agent(
                client,
                user_session="session",
                user_key_image="human-image",
                model_id="claude-sonnet-4-5",
                system_prompt="prompt",
                tools=["search"],
                public_key_hex="11" * 32,
                ring_secret_hex="22" * 32,
                ring_key_image_hex="33" * 32,
                max_amount=5.0,
                currency="USD",
                merchant_allowlist=["mch_demo_payments"],
            )
    body = json.loads(post.call_args.kwargs["data"])
    intent = json.loads(body["intent_json"])
    assert intent["maxAmount"] == 5.0
    assert intent["currency"] == "USD"
    assert intent["constraints"] == {"merchant_allowlist": ["mch_demo_payments"]}
    assert "payment_initiation" in intent["scope"]
    assert "payment_initiation" in agent.intent_scope


def test_register_llm_agent_rejects_half_specified_payment_cap() -> None:
    client = SauronIDClient(base_url="http://core", timeout=3)
    with pytest.raises(ValueError, match="max_amount and currency"):
        register_llm_agent(
            client,
            user_session="session",
            user_key_image="human-image",
            model_id="claude-sonnet-4-5",
            system_prompt="prompt",
            tools=["search"],
            public_key_hex="11" * 32,
            ring_secret_hex="22" * 32,
            ring_key_image_hex="33" * 32,
            max_amount=5.0,  # currency missing
        )


def test_authorize_payment_signs_the_final_post() -> None:
    client = SauronIDClient(base_url="http://core", timeout=3)
    agent = SignedAgent(
        client=client,
        agent_id="agt_test",
        config_digest="sha256:test",
        private_key=Ed25519PrivateKey.generate(),
        human_key_image="human-image",
        ring_secret_hex="ring-secret",
    )
    responses = [
        Mock(ok=True, status_code=200, text="", json=lambda: {"ajwt": _jwt_with_jti("jti-1")}),
        Mock(ok=True, status_code=200, text="", json=lambda: {"pop_challenge_id": "pop-1", "challenge": "challenge"}),
        Mock(ok=True, status_code=200, text="", json=lambda: {"challenge": "action"}),
        Mock(ok=True, status_code=200, text="", json=lambda: {"authorization_id": "auth-1"}),
    ]
    with patch("sauronid_client.agent.requests.post", side_effect=responses) as post:
        with patch.object(agent, "sign_action_challenge", return_value={"envelope": {}, "ring_signature": "sig"}):
            result = agent.authorize_payment(
                user_session="session",
                amount_minor=100,
                currency="EUR",
                payment_ref="payment-1",
            )

    assert result is responses[-1]
    assert post.call_count == 4
    final_kwargs = post.call_args_list[-1].kwargs
    headers = final_kwargs["headers"]
    assert {
        "x-sauron-agent-id",
        "x-sauron-call-ts",
        "x-sauron-call-nonce",
        "x-sauron-call-sig",
        "x-sauron-call-audience",
        "x-sauron-protocol-version",
        "x-sauron-agent-config-digest",
        "x-sauron-tenant-id",
    } <= set(headers)
    body = final_kwargs["data"]
    assert isinstance(body, bytes)
    assert json.loads(body)["payment_ref"] == "payment-1"
