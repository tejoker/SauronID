"""Unit tests for the Sprint 3 runtime enforcement layer.

Run with:

    pip install pytest
    cd sdk/python
    python -m pytest tests/test_enforcement.py -q

Mirrors the TypeScript test surface in ``sdk/typescript/tests/`` so the three
implementations (Rust server, TS client, Python client) stay aligned.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from sauronid_client.enforcement import (
    Action,
    Allow,
    BudgetState,
    BudgetTracker,
    CompiledPolicy,
    Deny,
    EvaluationContext,
    PendingSpendRecord,
    PolicyCache,
    PolicyDeniedError,
    PolicyNotLoadedError,
    bind,
    compute_now_tz_hhmm,
    evaluate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_policy(binding: Dict[str, Any]) -> CompiledPolicy:
    """Build a synthetic :class:`CompiledPolicy` for evaluator tests."""

    return CompiledPolicy(
        policy_id="pol_test",
        agent="agent-test",
        version="0.1",
        binding=binding,
        checks=[],
    )


def _mk_action(**overrides: Any) -> Action:
    """Build a default :class:`Action`. Override individual fields via kwargs."""

    defaults: Dict[str, Any] = {
        "action_id": "act_test",
        "tool": "http_get",
        "amount_usd": None,
        "data_classification": None,
        "signatures": [],
        "delegation_depth": 0,
        "timestamp": int(time.time()),
    }
    defaults.update(overrides)
    return Action(**defaults)


def _mk_ctx(**overrides: Any) -> EvaluationContext:
    """Build a default :class:`EvaluationContext`."""

    defaults: Dict[str, Any] = {
        "spend_total_usd": 0.0,
        "recent_call_timestamps": [],
        "now_epoch": int(time.time()),
        "now_tz_hhmm": "12:00",
    }
    defaults.update(overrides)
    return EvaluationContext(**defaults)


class _FakeResp:
    """Minimal ``requests`` response stand-in."""

    def __init__(self, payload: Dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 300

    def json(self) -> Dict[str, Any]:
        return self._payload


# ---------------------------------------------------------------------------
# PolicyCache
# ---------------------------------------------------------------------------


def _fake_ast(allowed_tools: List[str] | None = None) -> Dict[str, Any]:
    return {
        "version": "0.1",
        "agent": "agent-1",
        "binding": {"allowed_tools": allowed_tools or ["http_get"]},
    }


def test_policy_cache_fresh_load_hits_server() -> None:
    session = MagicMock()
    session.get.return_value = _FakeResp(_fake_ast(["http_get"]))
    cache = PolicyCache(
        core_url="http://srv",
        admin_key="dev",
        refresh_interval_s=0,
        http_session=session,
    )

    policy = cache.load("pol_xyz")

    assert policy.policy_id == "pol_xyz"
    assert policy.agent == "agent-1"
    assert policy.binding["allowed_tools"] == ["http_get"]
    assert "allowlist" in policy.checks
    session.get.assert_called_once()
    # Authorization header carried.
    _args, kwargs = session.get.call_args
    assert kwargs["headers"]["authorization"] == "Bearer dev"


def test_policy_cache_second_load_serves_from_memory() -> None:
    session = MagicMock()
    session.get.return_value = _FakeResp(_fake_ast())
    cache = PolicyCache(core_url="http://srv", refresh_interval_s=0, http_session=session)

    a = cache.load("pol_abc")
    b = cache.load("pol_abc")

    assert a is b
    assert session.get.call_count == 1


def test_policy_cache_refresh_keeps_last_good_on_error() -> None:
    session = MagicMock()
    session.get.side_effect = [
        _FakeResp(_fake_ast(["http_get"])),
        _FakeResp({}, status_code=500),
    ]
    cache = PolicyCache(core_url="http://srv", refresh_interval_s=0, http_session=session)
    cache.load("pol_abc")
    # Force-refresh fails -> we keep the original cached entry.
    cache.refresh("pol_abc")
    policy = cache.get("pol_abc")
    assert policy is not None
    assert policy.binding["allowed_tools"] == ["http_get"]


# ---------------------------------------------------------------------------
# BudgetTracker
# ---------------------------------------------------------------------------


def test_budget_tracker_records_and_totals() -> None:
    bt = BudgetTracker(policy_id="pol_x")
    bt.record(10.0, "a1")
    bt.record(2.5, "a2")
    assert bt.total() == pytest.approx(12.5)


def test_budget_tracker_recent_calls_within_window() -> None:
    bt = BudgetTracker(policy_id="pol_x")
    bt.record(1.0)
    bt.record(2.0)
    recents = bt.recent_calls(60)
    assert len(recents) == 2
    now = int(time.time())
    for t in recents:
        assert now - t <= 1  # both freshly recorded


def test_budget_tracker_recent_calls_prunes_old_entries() -> None:
    bt = BudgetTracker(policy_id="pol_x")
    # Inject an entry with a timestamp 1h in the past via internal state.
    bt._calls.append((int(time.time()) - 3600, "ancient"))  # noqa: SLF001
    bt.record(1.0)
    fresh = bt.recent_calls(60)
    assert len(fresh) == 1  # ancient one pruned


# ---------------------------------------------------------------------------
# Evaluator — one allow + one deny per invariant (14 cases)
# ---------------------------------------------------------------------------


def test_eval_allowlist_allow() -> None:
    p = _mk_policy({"allowed_tools": ["http_get", "search"]})
    v = evaluate(p, _mk_action(tool="http_get"), _mk_ctx())
    assert isinstance(v, Allow)


def test_eval_allowlist_deny() -> None:
    p = _mk_policy({"allowed_tools": ["search"]})
    v = evaluate(p, _mk_action(tool="exec"), _mk_ctx())
    assert isinstance(v, Deny)
    assert v.check == "allowlist"


def test_eval_budget_allow() -> None:
    p = _mk_policy({"max_budget_usd": 100.0})
    v = evaluate(p, _mk_action(amount_usd=20.0), _mk_ctx(spend_total_usd=50.0))
    assert isinstance(v, Allow)


def test_eval_budget_deny() -> None:
    p = _mk_policy({"max_budget_usd": 100.0})
    v = evaluate(p, _mk_action(amount_usd=80.0), _mk_ctx(spend_total_usd=50.0))
    assert isinstance(v, Deny)
    assert v.check == "budget"
    assert "exceeds cap" in v.reason


def test_eval_scope_allow() -> None:
    p = _mk_policy({"data_scope": {"allow": ["public"], "deny": ["pii"]}})
    v = evaluate(p, _mk_action(data_classification="PUBLIC"), _mk_ctx())
    assert isinstance(v, Allow)


def test_eval_scope_deny_on_deny_list() -> None:
    p = _mk_policy({"data_scope": {"allow": [], "deny": ["pii"]}})
    v = evaluate(p, _mk_action(data_classification="PII"), _mk_ctx())
    assert isinstance(v, Deny)
    assert v.check == "scope"


def test_eval_rate_limit_allow() -> None:
    now = int(time.time())
    p = _mk_policy({"rate_limit": {"requests_per_minute": 5}})
    v = evaluate(
        p,
        _mk_action(),
        _mk_ctx(now_epoch=now, recent_call_timestamps=[now - 30, now - 20]),
    )
    assert isinstance(v, Allow)


def test_eval_rate_limit_deny() -> None:
    now = int(time.time())
    p = _mk_policy({"rate_limit": {"requests_per_minute": 3}})
    v = evaluate(
        p,
        _mk_action(),
        _mk_ctx(
            now_epoch=now,
            recent_call_timestamps=[now - 5, now - 4, now - 3, now - 2],
        ),
    )
    assert isinstance(v, Deny)
    assert v.check == "rate_limit"


def test_eval_time_window_allow_wrap_around() -> None:
    p = _mk_policy({"time_window": {"start": "22:00", "end": "06:00", "timezone": "UTC"}})
    v = evaluate(p, _mk_action(), _mk_ctx(now_tz_hhmm="23:30"))
    assert isinstance(v, Allow)


def test_eval_time_window_deny() -> None:
    p = _mk_policy({"time_window": {"start": "09:00", "end": "17:00", "timezone": "UTC"}})
    v = evaluate(p, _mk_action(), _mk_ctx(now_tz_hhmm="20:00"))
    assert isinstance(v, Deny)
    assert v.check == "time_window"


def test_eval_signatures_allow_m_of_n() -> None:
    p = _mk_policy(
        {
            "required_signatures": [
                {"role": "human_approver", "threshold": 2},
            ]
        }
    )
    v = evaluate(
        p,
        _mk_action(signatures=["human_approver", "human_approver", "bot"]),
        _mk_ctx(),
    )
    assert isinstance(v, Allow)


def test_eval_signatures_deny_below_threshold() -> None:
    p = _mk_policy(
        {
            "required_signatures": [
                {"role": "human_approver", "threshold": 2},
            ]
        }
    )
    v = evaluate(p, _mk_action(signatures=["human_approver"]), _mk_ctx())
    assert isinstance(v, Deny)
    assert v.check == "signatures"


def test_eval_delegation_allow() -> None:
    p = _mk_policy({"delegation": {"max_depth": 2}})
    v = evaluate(p, _mk_action(delegation_depth=2), _mk_ctx())
    assert isinstance(v, Allow)


def test_eval_delegation_deny() -> None:
    p = _mk_policy({"delegation": {"max_depth": 1}})
    v = evaluate(p, _mk_action(delegation_depth=3), _mk_ctx())
    assert isinstance(v, Deny)
    assert v.check == "delegation_depth"


def test_compute_now_tz_hhmm_fallback_to_utc() -> None:
    # Hand-crafted epoch: 2024-01-01 12:00 UTC.
    hhmm = compute_now_tz_hhmm(1704110400, "Not/A_Real_Zone")
    assert hhmm == "12:00"


# ---------------------------------------------------------------------------
# bind() — wrapper behaviour
# ---------------------------------------------------------------------------


def _loaded_cache(binding: Dict[str, Any], policy_id: str = "pol_b") -> PolicyCache:
    """Build a PolicyCache pre-seeded with one synthetic CompiledPolicy."""

    session = MagicMock()
    session.get.return_value = _FakeResp(
        {"version": "0.1", "agent": "agent-1", "binding": binding}
    )
    cache = PolicyCache(core_url="http://srv", refresh_interval_s=0, http_session=session)
    cache.load(policy_id)
    return cache


def test_bind_allow_invokes_tool() -> None:
    cache = _loaded_cache({"allowed_tools": ["my_tool"]})

    def my_tool(x: int) -> int:
        return x * 2

    wrapped = bind(my_tool, agent_id="a1", policy_id="pol_b", cache=cache)
    assert wrapped(21) == 42


def test_bind_deny_raises_policy_denied_error() -> None:
    cache = _loaded_cache({"allowed_tools": ["other"]})

    def my_tool() -> str:  # not in allowlist
        return "ran"

    wrapped = bind(my_tool, agent_id="a1", policy_id="pol_b", cache=cache)
    with pytest.raises(PolicyDeniedError) as ei:
        wrapped()
    err = ei.value
    assert err.check == "allowlist"
    assert err.policy_id == "pol_b"
    assert err.action_id  # populated


def test_bind_deny_does_not_call_original() -> None:
    cache = _loaded_cache({"allowed_tools": ["other"]})
    called = {"n": 0}

    def my_tool() -> None:
        called["n"] += 1

    wrapped = bind(my_tool, agent_id="a1", policy_id="pol_b", cache=cache)
    with pytest.raises(PolicyDeniedError):
        wrapped()
    assert called["n"] == 0


def test_bind_policy_not_loaded_raises() -> None:
    session = MagicMock()
    cache = PolicyCache(core_url="http://srv", refresh_interval_s=0, http_session=session)

    def my_tool() -> None:
        return None

    wrapped = bind(my_tool, agent_id="a1", policy_id="pol_missing", cache=cache)
    with pytest.raises(PolicyNotLoadedError) as ei:
        wrapped()
    assert ei.value.policy_id == "pol_missing"


def test_bind_on_deny_callback_fires_before_raise() -> None:
    cache = _loaded_cache({"allowed_tools": ["other"]})
    captured: List[Deny] = []

    def my_tool() -> None:
        return None

    wrapped = bind(
        my_tool,
        agent_id="a1",
        policy_id="pol_b",
        cache=cache,
        on_deny=lambda d: captured.append(d),
    )
    with pytest.raises(PolicyDeniedError):
        wrapped()
    assert len(captured) == 1
    assert isinstance(captured[0], Deny)
    assert captured[0].check == "allowlist"


def test_bind_budget_tracker_records_after_allow() -> None:
    cache = _loaded_cache(
        {"allowed_tools": ["my_tool"], "max_budget_usd": 100.0}
    )
    bt = BudgetTracker(policy_id="pol_b")

    def my_tool() -> str:
        return "ok"

    def classify(_name: str, _args: Any, _kwargs: Any) -> Dict[str, Any]:
        return {"amount_usd": 5.0}

    wrapped = bind(
        my_tool,
        agent_id="a1",
        policy_id="pol_b",
        cache=cache,
        budget_tracker=bt,
        classify_action=classify,
    )
    assert wrapped() == "ok"
    assert bt.total() == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# BudgetTracker — server-side ledger wiring (Sprint 3 follow-up)
# ---------------------------------------------------------------------------


def test_budget_tracker_manual_flush_drains_pending() -> None:
    seen: List[BudgetState] = []

    def flush_fn(state: BudgetState) -> None:
        seen.append(state)

    bt = BudgetTracker(policy_id="pol_man", flush_interval_s=0, flush_fn=flush_fn)
    bt.record(10.0, "a1")
    bt.record(2.5, "a2")
    assert bt.pending_count() == 2
    bt.flush()
    assert len(seen) == 1
    assert len(seen[0].pending) == 2
    assert seen[0].pending[0].amount_usd == pytest.approx(10.0)
    assert bt.pending_count() == 0
    bt.stop()


def test_budget_tracker_timer_triggers_flush_when_pending() -> None:
    calls: List[int] = []

    def flush_fn(_state: BudgetState) -> None:
        calls.append(1)

    bt = BudgetTracker(policy_id="pol_timer", flush_interval_s=0.05, flush_fn=flush_fn)
    try:
        bt.record(1.0)
        # Wait long enough for one timer tick.
        time.sleep(0.2)
        assert len(calls) >= 1, "timer flushed at least once"
        bt.record(2.0)
        time.sleep(0.2)
        assert len(calls) >= 2, "timer flushed again after new record"
    finally:
        bt.stop()


def test_budget_tracker_server_push_posts_each_record() -> None:
    posts: List[Dict[str, Any]] = []

    fake_session = MagicMock()
    fake_resp = MagicMock()
    fake_resp.ok = True
    fake_resp.status_code = 200

    def _post(url: str, json: Dict[str, Any], headers: Dict[str, str], timeout: int):  # type: ignore[override]
        posts.append({"url": url, "json": json, "headers": headers})
        return fake_resp

    fake_session.post.side_effect = _post

    flush_fn = BudgetTracker.server_push(
        core_url="http://core",
        admin_key="dev",
        agent_id="agent-A",
        policy_id="pol_srv",
        http_session=fake_session,
    )
    bt = BudgetTracker(policy_id="pol_srv", flush_interval_s=0, flush_fn=flush_fn)
    bt.record(10.0, "act-1")
    bt.record(5.0)
    bt.flush()

    assert len(posts) == 2
    assert posts[0]["url"] == "http://core/v1/agents/agent-A/spend"
    assert posts[0]["json"]["policy_id"] == "pol_srv"
    assert posts[0]["json"]["amount_usd"] == 10.0
    assert posts[0]["json"]["action_id"] == "act-1"
    # Second record had no action_id; key omitted.
    assert "action_id" not in posts[1]["json"]
    assert posts[0]["headers"]["authorization"] == "Bearer dev"
    bt.stop()


def test_budget_tracker_stop_triggers_final_flush() -> None:
    flushed: List[BudgetState] = []

    def flush_fn(state: BudgetState) -> None:
        flushed.append(state)

    bt = BudgetTracker(policy_id="pol_stop", flush_interval_s=0, flush_fn=flush_fn)
    bt.record(7.0, "stop-rec")
    assert bt.pending_count() == 1
    bt.stop()
    assert len(flushed) == 1
    assert len(flushed[0].pending) == 1
    assert isinstance(flushed[0].pending[0], PendingSpendRecord)
    assert bt.pending_count() == 0
