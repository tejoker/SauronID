"""LlamaIndex adapter — wrap FunctionTool-style tools with SauronID enforcement.

This module is purely additive. Importing it has no side effects on
existing :mod:`sauronid_client` behaviour. The llama-index package is
**not** a runtime dependency: this adapter only needs duck-typed
``FunctionTool`` objects (anything with ``.metadata.name`` — or a plain
``.name`` — and a ``call`` / ``fn`` / ``__call__``), mirroring how
:mod:`sauronid_client.langchain` treats LangChain tools. Call
:func:`require_llama_index` when you need the real framework classes;
it raises a helpful :class:`ImportError` when the extra is missing.

Public surface:

- :func:`bind_llamaindex_tools` — wrap a list of LlamaIndex tools.
- :class:`SauronLlamaIndexAgent` — thin holder bundling an enforcer
  with a tool list.
- :func:`require_llama_index` — lazy import guard for the optional dep.

Both wrapping surfaces support ``classify_action`` / ``on_deny`` /
``raise_on_deny`` exactly like :func:`sauronid_client.langchain.bind_tools`,
plus optional :class:`~sauronid_client.agent.SignedAgent` egress logging:
pass ``signed_agent`` + ``target_host`` and every allowed tool call is
reported via ``SignedAgent.report_egress`` before the tool runs
(fail-closed, same semantics as :class:`sauronid_client.adapters.LangChainTool`).

Denial surface: on a deny the wrapper returns a string of the form
``"Policy denied: <reason>"`` as the tool result so the agent loop can
recover; ``raise_on_deny=True`` re-raises :class:`PolicyDeniedError`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, List, Optional, Sequence

from .enforcement import (
    ClassifyFn,
    Enforcer,
    OnDenyFn,
    PolicyDeniedError,
)
from .langchain import _deny_message

__all__ = [
    "bind_llamaindex_tools",
    "SauronLlamaIndexAgent",
    "require_llama_index",
]


def require_llama_index() -> Any:
    """Import and return :mod:`llama_index.core`, or raise a helpful error.

    The adapter itself never needs the framework (duck typing); use this
    only when you must construct real LlamaIndex classes.
    """

    try:
        import llama_index.core as _llama_core
    except ImportError as err:
        raise ImportError(
            "llama-index-core is not installed. The sauronid-client LlamaIndex "
            "adapter is duck-typed and does not require it, but this helper "
            "does. Install with: pip install 'sauronid-client[llamaindex]'"
        ) from err
    return _llama_core


class _GuardedLlamaTool:
    """Drop-in wrapper preserving the LlamaIndex ``FunctionTool`` surface.

    Wraps the underlying tool's ``fn`` / ``call`` with
    :meth:`Enforcer.bind`. On :class:`PolicyDeniedError` the wrapper
    either re-raises (``raise_on_deny=True``) or returns a string error
    the agent loop will pass to the LLM as the tool result.
    """

    def __init__(
        self,
        tool: Any,
        enforcer: Enforcer,
        *,
        classify_action: Optional[ClassifyFn] = None,
        on_deny: Optional[OnDenyFn] = None,
        raise_on_deny: bool = False,
        signed_agent: Optional[Any] = None,
        target_host: Optional[str] = None,
        target_path: str = "/",
    ) -> None:
        self._tool = tool
        self._enforcer = enforcer
        self._on_deny = on_deny
        self._raise_on_deny = raise_on_deny
        self._signed_agent = signed_agent
        self._target_host = target_host
        self._target_path = target_path
        # Mirror the FunctionTool attributes hosts read for dispatch.
        meta = getattr(tool, "metadata", None)
        self.metadata = meta
        self.name = (
            getattr(meta, "name", None)
            or getattr(tool, "name", None)
            or tool.__class__.__name__
        )
        self.description = (
            getattr(meta, "description", None)
            or getattr(tool, "description", "")
        )

        inner: Callable[..., Any] = (
            getattr(tool, "fn", None)
            or getattr(tool, "call", None)
            or tool.__call__
        )

        def _proxy(*args: Any, **kwargs: Any) -> Any:
            # Policy verdict already passed (bind evaluates first); report
            # egress fail-closed, then run.
            self._report_egress(args, kwargs)
            return inner(*args, **kwargs)

        _proxy.__name__ = self.name  # ensure Action.tool == name
        self._guarded = enforcer.bind(
            _proxy,
            classify_action=classify_action,
            on_deny=on_deny,
        )

    def _report_egress(self, args: Any, kwargs: Any) -> None:
        """Log the tool call via ``SignedAgent.report_egress`` when wired.

        Fail closed: a raising ``report_egress`` blocks the tool call,
        matching :class:`sauronid_client.adapters.LangChainTool`.
        """

        if self._signed_agent is None or self._target_host is None:
            return
        body_repr = json.dumps(
            {"args": list(args), "kwargs": dict(kwargs)},
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        self._signed_agent.report_egress(
            target_host=self._target_host,
            target_path=f"{self._target_path}#tool:{self.name}",
            method="POST",
            body_hash_hex=hashlib.sha256(body_repr).hexdigest(),
        )

    def call(self, *args: Any, **kwargs: Any) -> Any:
        """Sync execution entry point. Returns deny string on policy deny."""

        try:
            return self._guarded(*args, **kwargs)
        except PolicyDeniedError as err:
            if self._raise_on_deny:
                raise
            return _deny_message(err)

    async def acall(self, *args: Any, **kwargs: Any) -> Any:
        """Async execution entry point. Falls back to sync ``call``."""

        inner_acall = getattr(self._tool, "acall", None)
        if inner_acall is None:
            return self.call(*args, **kwargs)
        try:
            async def _aproxy(*a: Any, **kw: Any) -> Any:
                self._report_egress(a, kw)
                return await inner_acall(*a, **kw)

            _aproxy.__name__ = self.name
            guarded_async = self._enforcer.bind(_aproxy, on_deny=self._on_deny)
            return await guarded_async(*args, **kwargs)
        except PolicyDeniedError as err:
            if self._raise_on_deny:
                raise
            return _deny_message(err)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Allow callable-style invocation, mirroring ``FunctionTool.__call__``."""

        return self.call(*args, **kwargs)


def bind_llamaindex_tools(
    tools: Sequence[Any],
    enforcer: Enforcer,
    *,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
    raise_on_deny: bool = False,
    signed_agent: Optional[Any] = None,
    target_host: Optional[str] = None,
    target_path: str = "/",
) -> List[_GuardedLlamaTool]:
    """Wrap each LlamaIndex tool in ``tools`` with policy enforcement.

    Args:
        tools: FunctionTool-style tools (``.metadata.name`` or ``.name``
            plus ``call`` / ``fn`` / ``__call__``).
        enforcer: Pre-configured :class:`Enforcer`.
        classify_action: Optional per-tool action annotator, same shape as
            :func:`sauronid_client.enforcement.bind`'s ``classify_action``.
        on_deny: Optional hook fired before a denial surfaces to the LLM.
        raise_on_deny: ``True`` re-raises :class:`PolicyDeniedError`;
            ``False`` (default) returns a ``"Policy denied: ..."`` string.
        signed_agent: Optional :class:`~sauronid_client.agent.SignedAgent`.
            When set (with ``target_host``), every allowed call is logged
            via ``report_egress`` before the tool runs.
        target_host: Egress host reported for the tool calls.
        target_path: Egress path prefix (suffixed with ``#tool:<name>``).

    Returns:
        List of wrapped tools, same length and order as ``tools``.
    """

    return [
        _GuardedLlamaTool(
            t,
            enforcer,
            classify_action=classify_action,
            on_deny=on_deny,
            raise_on_deny=raise_on_deny,
            signed_agent=signed_agent,
            target_host=target_host,
            target_path=target_path,
        )
        for t in tools
    ]


class SauronLlamaIndexAgent:
    """Bundle an :class:`Enforcer` with a wrapped LlamaIndex tool list.

    Mirrors :class:`sauronid_client.langchain.SauronLangChainAgent`:
    when ``enforcer`` is ``None`` the tools pass through untouched.

    Example::

        from sauronid_client import create_enforcer
        from sauronid_client.llamaindex_adapter import SauronLlamaIndexAgent

        enf = create_enforcer(core_url=..., admin_key=..., policy_id=..., agent_id=...)
        agent = SauronLlamaIndexAgent(tools=[search_tool], enforcer=enf)
        # agent.tools is the guarded list, ready for an AgentRunner.
    """

    def __init__(
        self,
        *,
        tools: Sequence[Any],
        enforcer: Optional[Enforcer] = None,
        classify_action: Optional[ClassifyFn] = None,
        on_deny: Optional[OnDenyFn] = None,
        raise_on_deny: bool = False,
        signed_agent: Optional[Any] = None,
        target_host: Optional[str] = None,
        target_path: str = "/",
    ) -> None:
        self.enforcer = enforcer
        if enforcer is None:
            self.tools: List[Any] = list(tools)
        else:
            self.tools = bind_llamaindex_tools(
                tools,
                enforcer,
                classify_action=classify_action,
                on_deny=on_deny,
                raise_on_deny=raise_on_deny,
                signed_agent=signed_agent,
                target_host=target_host,
                target_path=target_path,
            )
