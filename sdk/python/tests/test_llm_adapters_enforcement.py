"""Tests for the LLM-runtime adapters' policy-enforcement wiring.

Three tests per adapter (= 9 total):

1. Happy path: tool allowed, original fn invoked, return value flows
   through the adapter's LLM-facing surface.
2. Deny path: tool denied, original fn NOT invoked, error surfaced to
   the LLM in the adapter-specific shape.
3. ``on_deny`` callback fires BEFORE the error surfaces.

All LLM SDKs (langchain / openai / anthropic) are mocked: we never hit
the network or import their real packages, keeping this test file fast
and isolated from upstream churn.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from sauronid_client.anthropic_adapter import (
    SauronAnthropicAgent,
    dispatch_tool_use_blocks,
)
from sauronid_client.enforcement import (
    BudgetTracker,
    Deny,
    Enforcer,
    PolicyCache,
)
from sauronid_client.langchain import (
    SauronLangChainAgent,
    bind_tools,
)
from sauronid_client.openai_adapter import (
    SauronOpenAIAssistant,
    dispatch_tool_calls,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResp:
    """Minimal ``requests`` response stand-in for PolicyCache injection."""

    def __init__(self, payload: Dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 300

    def json(self) -> Dict[str, Any]:
        return self._payload


def _make_enforcer(allowed: List[str], policy_id: str = "pol_t") -> Enforcer:
    """Build a live :class:`Enforcer` backed by an in-memory cache.

    No HTTP roundtrip: the cache's :class:`requests.Session` is a
    :class:`MagicMock` returning a fixed AST.
    """

    session = MagicMock()
    session.get.return_value = _FakeResp(
        {
            "version": "0.1",
            "agent": "agent-1",
            "binding": {"allowed_tools": allowed},
        }
    )
    cache = PolicyCache(
        core_url="http://srv", refresh_interval_s=0, http_session=session
    )
    cache.load(policy_id)
    budget = BudgetTracker(policy_id=policy_id, flush_interval_s=0)
    return Enforcer(
        cache=cache, budget=budget, policy_id=policy_id, agent_id="agent-1"
    )


class _FakeLCBaseTool:
    """Duck-typed LangChain ``BaseTool`` for adapter tests."""

    def __init__(self, name: str, fn: Any, description: str = "") -> None:
        self.name = name
        self.description = description
        self._fn = fn
        self.calls: List[tuple] = []

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self._fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# LangChain — 3 tests
# ---------------------------------------------------------------------------


def test_langchain_allow_invokes_original_tool() -> None:
    enf = _make_enforcer(["search"])
    tool = _FakeLCBaseTool("search", lambda q: f"hits for {q}")
    [guarded] = bind_tools([tool], enf)
    out = guarded._run("opus 4.7")
    assert out == "hits for opus 4.7"
    assert tool.calls == [(("opus 4.7",), {})]


def test_langchain_deny_returns_error_string_and_skips_original() -> None:
    enf = _make_enforcer(["search"])  # 'transfer' NOT allowed
    transfer = _FakeLCBaseTool("transfer", lambda **_kw: "moved")
    agent = SauronLangChainAgent(tools=[transfer], enforcer=enf)
    [wrapped] = agent.tools
    out = wrapped._run(amount=100)
    assert isinstance(out, str)
    assert out.startswith("Policy denied:")
    assert "transfer" in out or "allowlist" in out
    assert transfer.calls == []  # original NEVER invoked


def test_langchain_on_deny_callback_fires_before_error_surfaces() -> None:
    enf = _make_enforcer(["search"])
    transfer = _FakeLCBaseTool("transfer", lambda **_kw: "moved")
    seen: List[Deny] = []

    [wrapped] = bind_tools(
        [transfer], enf, on_deny=lambda d: seen.append(d)
    )
    out = wrapped._run(amount=10)
    assert len(seen) == 1
    assert isinstance(seen[0], Deny)
    assert seen[0].check == "allowlist"
    assert out.startswith("Policy denied:")


# ---------------------------------------------------------------------------
# OpenAI Assistants — 3 tests
# ---------------------------------------------------------------------------


def _openai_tool_call(call_id: str, name: str, args: Dict[str, Any]) -> Any:
    """Build an OpenAI-shaped tool-call object the dispatcher accepts."""

    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


def test_openai_allow_invokes_tool_and_passes_output_through() -> None:
    enf = _make_enforcer(["search"])
    invoked: List[Dict[str, Any]] = []

    def search(query: str) -> str:
        invoked.append({"query": query})
        return f"hits for {query}"

    outputs = dispatch_tool_calls(
        [_openai_tool_call("call_1", "search", {"query": "opus"})],
        {"search": search},
        enforcer=enf,
    )
    assert outputs == [{"tool_call_id": "call_1", "output": "hits for opus"}]
    assert invoked == [{"query": "opus"}]


def test_openai_deny_returns_tool_output_with_policy_denied_and_skips_tool() -> None:
    enf = _make_enforcer(["search"])
    called: List[Any] = []

    def transfer(**kwargs: Any) -> str:
        called.append(kwargs)
        return "ok"

    assistant = SauronOpenAIAssistant(
        tools={"transfer": transfer}, enforcer=enf
    )
    outputs = assistant.dispatch(
        [_openai_tool_call("call_x", "transfer", {"amount": 99})]
    )
    assert len(outputs) == 1
    assert outputs[0]["tool_call_id"] == "call_x"
    assert outputs[0]["output"].startswith("Policy denied:")
    assert "allowlist" in outputs[0]["output"]
    assert called == []


def test_openai_on_deny_callback_fires_before_error_surfaces() -> None:
    enf = _make_enforcer(["search"])
    seen: List[Deny] = []

    def transfer(**_kw: Any) -> str:
        return "ok"

    outputs = dispatch_tool_calls(
        [_openai_tool_call("call_d", "transfer", {"amount": 1})],
        {"transfer": transfer},
        enforcer=enf,
        on_deny=lambda d: seen.append(d),
    )
    assert len(seen) == 1
    assert seen[0].check == "allowlist"
    assert outputs[0]["output"].startswith("Policy denied:")


# ---------------------------------------------------------------------------
# Anthropic Computer Use — 3 tests
# ---------------------------------------------------------------------------


def _anthropic_block(block_id: str, name: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Build an Anthropic-shaped ``tool_use`` block dict."""

    return {"type": "tool_use", "id": block_id, "name": name, "input": kwargs}


def test_anthropic_allow_invokes_tool_and_returns_tool_result_block() -> None:
    enf = _make_enforcer(["bash"])

    def bash(command: str) -> str:
        return f"ran: {command}"

    results = dispatch_tool_use_blocks(
        [_anthropic_block("tu_1", "bash", {"command": "ls"})],
        {"bash": bash},
        enforcer=enf,
    )
    assert results == [
        {"type": "tool_result", "tool_use_id": "tu_1", "content": "ran: ls"}
    ]


def test_anthropic_deny_returns_is_error_result_and_skips_tool() -> None:
    enf = _make_enforcer(["bash"])
    invoked: List[Any] = []

    def transfer(**kwargs: Any) -> str:
        invoked.append(kwargs)
        return "moved"

    agent = SauronAnthropicAgent(tools={"transfer": transfer}, enforcer=enf)
    results = agent.dispatch(
        [_anthropic_block("tu_x", "transfer", {"amount": 50})]
    )
    assert len(results) == 1
    assert results[0]["type"] == "tool_result"
    assert results[0]["tool_use_id"] == "tu_x"
    assert results[0]["is_error"] is True
    assert results[0]["content"].startswith("Policy denied:")
    assert invoked == []


def test_anthropic_on_deny_callback_fires_before_error_surfaces() -> None:
    enf = _make_enforcer(["bash"])
    seen: List[Deny] = []

    def transfer(**_kw: Any) -> str:
        return "ok"

    results = dispatch_tool_use_blocks(
        [_anthropic_block("tu_d", "transfer", {"amount": 1})],
        {"transfer": transfer},
        enforcer=enf,
        on_deny=lambda d: seen.append(d),
    )
    assert len(seen) == 1
    assert seen[0].check == "allowlist"
    assert results[0]["is_error"] is True
    assert results[0]["content"].startswith("Policy denied:")
