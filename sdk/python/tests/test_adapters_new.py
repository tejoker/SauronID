"""Tests for wrap() routing and the LlamaIndex / CrewAI / AutoGen adapters.

Frameworks are never imported: every adapter is duck-typed, so all
fixtures are plain Python fakes (same approach as
test_llm_adapters_enforcement.py). The require_* import-guard tests skip
themselves in the unlikely case the real framework IS installed.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from sauronid_client import wrap
from sauronid_client.autogen_adapter import guard_function, guard_functions
from sauronid_client.crewai_adapter import SauronCrewAIAgent, bind_crewai_tools
from sauronid_client.enforcement import (
    BudgetTracker,
    Enforcer,
    PolicyCache,
    PolicyDeniedError,
)
from sauronid_client.llamaindex_adapter import (
    SauronLlamaIndexAgent,
    bind_llamaindex_tools,
)


# ---------------------------------------------------------------------------
# Helpers (mirrors test_llm_adapters_enforcement.py)
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
    """Build a live :class:`Enforcer` backed by a stubbed policy fetch."""

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


class _FakeLCTool:
    """Duck-typed LangChain ``BaseTool``."""

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self.description = ""
        self._fn = fn
        self.calls: List[tuple] = []

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self._fn(*args, **kwargs)


class _FakeLlamaTool:
    """Duck-typed LlamaIndex ``FunctionTool`` (metadata + call + fn)."""

    def __init__(self, name: str, fn: Any) -> None:
        self.metadata = SimpleNamespace(name=name, description="")
        self.fn = fn

    def call(self, *args: Any, **kwargs: Any) -> Any:
        return self.fn(*args, **kwargs)


class _FakeCrewTool:
    """Duck-typed CrewAI ``BaseTool`` (name + description + _run)."""

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self.description = ""
        self._fn = fn
        self.calls: List[tuple] = []

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self._fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# wrap() routing
# ---------------------------------------------------------------------------


def test_wrap_plain_callable_allow() -> None:
    enf = _make_enforcer(["search"])

    def search(q: str) -> str:
        return f"hits for {q}"

    guarded = wrap(search, enforcer=enf)
    assert guarded("opus") == "hits for opus"


def test_wrap_plain_callable_deny_raises_and_skips_original() -> None:
    enf = _make_enforcer(["search"])
    called: List[Any] = []

    def transfer(**kwargs: Any) -> str:
        called.append(kwargs)
        return "moved"

    guarded = wrap(transfer, enforcer=enf)
    with pytest.raises(PolicyDeniedError) as exc:
        guarded(amount=100)
    assert exc.value.check == "allowlist"
    assert called == []


def test_wrap_callable_list_binds_each() -> None:
    enf = _make_enforcer(["a", "b"])

    def a() -> str:
        return "A"

    def b() -> str:
        return "B"

    ga, gb = wrap([a, b], enforcer=enf)
    assert (ga(), gb()) == ("A", "B")


def test_wrap_routes_langchain_tool_list() -> None:
    enf = _make_enforcer(["search"])
    ok = _FakeLCTool("search", lambda q: q.upper())
    bad = _FakeLCTool("transfer", lambda **_kw: "moved")

    g_ok, g_bad = wrap([ok, bad], enforcer=enf)
    assert g_ok._run("hi") == "HI"
    out = g_bad._run(amount=1)
    assert isinstance(out, str) and out.startswith("Policy denied:")
    assert bad.calls == []


def test_wrap_routes_llamaindex_tool_list() -> None:
    enf = _make_enforcer(["search"])
    tool = _FakeLlamaTool("search", lambda q: f"hits for {q}")
    [guarded] = wrap([tool], enforcer=enf)
    assert guarded.call("opus") == "hits for opus"


def test_wrap_routes_mapping_openai_default_and_anthropic_flavor() -> None:
    from sauronid_client.anthropic_adapter import SauronAnthropicAgent
    from sauronid_client.openai_adapter import SauronOpenAIAssistant

    enf = _make_enforcer(["search"])
    tools = {"search": lambda query: f"hits for {query}"}
    assert isinstance(wrap(tools, enforcer=enf), SauronOpenAIAssistant)
    assert isinstance(
        wrap(tools, enforcer=enf, flavor="anthropic"), SauronAnthropicAgent
    )


def test_wrap_without_wiring_raises_value_error() -> None:
    with pytest.raises(ValueError, match="enforcer=|policy_id"):
        wrap(lambda: None)


def test_wrap_rejects_raw_llm_client_objects() -> None:
    enf = _make_enforcer(["search"])
    fake_openai_client = SimpleNamespace(beta=object())
    with pytest.raises(TypeError, match="dispatch_tool_calls"):
        wrap(fake_openai_client, enforcer=enf)


# ---------------------------------------------------------------------------
# Import guards — modules import fine without frameworks; require_* raises
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module_name", "require_attr", "framework_top_module"),
    [
        ("sauronid_client.llamaindex_adapter", "require_llama_index", "llama_index"),
        ("sauronid_client.crewai_adapter", "require_crewai", "crewai"),
        ("sauronid_client.autogen_adapter", "require_autogen", "autogen"),
    ],
)
def test_adapter_importable_without_framework(
    module_name: str, require_attr: str, framework_top_module: str
) -> None:
    module = importlib.import_module(module_name)  # never raises
    if importlib.util.find_spec(framework_top_module) is not None:
        pytest.skip(f"{framework_top_module} installed; ImportError path untestable")
    with pytest.raises(ImportError, match=r"pip install 'sauronid-client\["):
        getattr(module, require_attr)()


# ---------------------------------------------------------------------------
# LlamaIndex adapter
# ---------------------------------------------------------------------------


def test_llamaindex_deny_returns_string_and_skips_original() -> None:
    enf = _make_enforcer(["search"])
    invoked: List[Any] = []

    def transfer(**kwargs: Any) -> str:
        invoked.append(kwargs)
        return "moved"

    agent = SauronLlamaIndexAgent(
        tools=[_FakeLlamaTool("transfer", transfer)], enforcer=enf
    )
    [guarded] = agent.tools
    out = guarded.call(amount=50)
    assert isinstance(out, str) and out.startswith("Policy denied:")
    assert invoked == []


def test_llamaindex_signed_agent_egress_logged_on_allow() -> None:
    enf = _make_enforcer(["search"])
    signed_agent = MagicMock()
    [guarded] = bind_llamaindex_tools(
        [_FakeLlamaTool("search", lambda q: q)],
        enf,
        signed_agent=signed_agent,
        target_host="api.example.com",
    )
    assert guarded.call("opus") == "opus"
    signed_agent.report_egress.assert_called_once()
    kwargs = signed_agent.report_egress.call_args.kwargs
    assert kwargs["target_host"] == "api.example.com"
    assert kwargs["target_path"].endswith("#tool:search")
    assert kwargs["body_hash_hex"]


def test_llamaindex_signed_agent_egress_skipped_on_deny() -> None:
    enf = _make_enforcer(["search"])
    signed_agent = MagicMock()
    [guarded] = bind_llamaindex_tools(
        [_FakeLlamaTool("transfer", lambda **_kw: "moved")],
        enf,
        signed_agent=signed_agent,
        target_host="api.example.com",
    )
    assert guarded.call(amount=1).startswith("Policy denied:")
    signed_agent.report_egress.assert_not_called()


# ---------------------------------------------------------------------------
# CrewAI adapter
# ---------------------------------------------------------------------------


def test_crewai_run_surface_allow_and_deny() -> None:
    enf = _make_enforcer(["search"])
    ok = _FakeCrewTool("search", lambda q: f"hits for {q}")
    bad = _FakeCrewTool("transfer", lambda **_kw: "moved")

    g_ok, g_bad = bind_crewai_tools([ok, bad], enf)
    assert g_ok.run("opus") == "hits for opus"
    out = g_bad.run(amount=9)
    assert isinstance(out, str) and out.startswith("Policy denied:")
    assert bad.calls == []


def test_crewai_agent_passthrough_without_enforcer() -> None:
    tool = _FakeCrewTool("search", lambda q: q)
    agent = SauronCrewAIAgent(tools=[tool])
    assert agent.tools == [tool]


def test_crewai_raise_on_deny() -> None:
    enf = _make_enforcer(["search"])
    [guarded] = bind_crewai_tools(
        [_FakeCrewTool("transfer", lambda **_kw: "moved")], enf, raise_on_deny=True
    )
    with pytest.raises(PolicyDeniedError):
        guarded.run(amount=1)


# ---------------------------------------------------------------------------
# AutoGen adapter
# ---------------------------------------------------------------------------


def test_autogen_guard_function_allow_preserves_metadata() -> None:
    enf = _make_enforcer(["search"])

    def search(query: str) -> str:
        """Search the web."""
        return f"hits for {query}"

    guarded = guard_function(search, enf)
    assert guarded("opus") == "hits for opus"
    assert guarded.__name__ == "search"
    assert guarded.__doc__ == "Search the web."


def test_autogen_guard_function_deny_returns_string_and_skips_original() -> None:
    enf = _make_enforcer(["search"])
    invoked: List[Any] = []

    def transfer(amount: int) -> str:
        invoked.append(amount)
        return "moved"

    guarded = guard_function(transfer, enf)
    out = guarded(amount=100)
    assert isinstance(out, str) and out.startswith("Policy denied:")
    assert invoked == []


def test_autogen_guard_functions_uses_mapping_key_as_tool_name() -> None:
    enf = _make_enforcer(["web_search"])

    def search(query: str) -> str:
        return f"hits for {query}"

    guarded = guard_functions({"web_search": search, "transfer": search}, enf)
    assert guarded["web_search"]("opus") == "hits for opus"
    assert guarded["transfer"]("opus").startswith("Policy denied:")


def test_wrap_routes_crewai_subclass_defined_outside_crewai_module() -> None:
    """User tools subclass the framework base in their own module; wrap()
    must sniff the MRO, not the leaf class, to route to the CrewAI adapter
    (whose guarded tools expose the public run() entry point)."""
    base = type("BaseTool", (), {})
    base.__module__ = "crewai.tools.base_tool"

    def _run(self, query: str) -> str:
        return f"hits for {query}"

    user_tool_cls = type(
        "SearchTool", (base,), {"_run": _run, "name": "search", "description": "d"}
    )
    # Leaf class lives in the test module, exactly like real user code.
    assert user_tool_cls.__module__ != "crewai.tools.base_tool"

    enf = _make_enforcer(["search"])
    [guarded] = wrap([user_tool_cls()], enforcer=enf)
    assert guarded.run(query="opus") == "hits for opus"
