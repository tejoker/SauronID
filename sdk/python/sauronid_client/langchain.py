"""LangChain adapter — wrap tools with SauronID policy enforcement.

This module is purely additive. Importing it has no side effects on
existing :mod:`sauronid_client` behaviour. The langchain package itself
is **not** a runtime dependency: this adapter only needs duck-typed
``Tool`` objects (anything with ``.name``, ``.description`` and an
``_run`` / ``__call__``) so it works whether the host project pulls in
``langchain``, ``langchain_core`` or ships their own custom tool class.

Public surface:

- :func:`bind_tools` — wrap a list of LangChain tools.
- :class:`SauronLangChainAgent` — thin holder that bundles an enforcer
  with a tool list (handy when constructing an AgentExecutor).

Both surfaces support:

- ``classify_action`` — per-tool action annotator forwarded to
  :func:`sauronid_client.enforcement.bind`. Receives
  ``(tool_name, args, kwargs)`` and returns a dict of overrides.
- ``on_deny`` — fired before :class:`PolicyDeniedError` propagates.

Denial surface: on a deny the wrapper produces a string of the form
``"Policy denied: <reason>"`` returned to the LLM as the tool result so
the agent loop can recover gracefully. When ``raise_on_deny=True`` the
wrapper instead re-raises :class:`PolicyDeniedError` so the host can
crash the loop deliberately.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional, Protocol, Sequence

from .enforcement import (
    ClassifyFn,
    Enforcer,
    OnDenyFn,
    PolicyDeniedError,
)

__all__ = [
    "bind_tools",
    "SauronLangChainAgent",
    "ToolLike",
]


class ToolLike(Protocol):
    """Duck-typed LangChain ``BaseTool`` surface.

    Anything with ``name``, ``description`` and an ``_run`` callable
    satisfies this contract. We deliberately avoid importing langchain
    so the SDK stays dep-free.
    """

    name: str
    description: str

    def _run(self, *args: Any, **kwargs: Any) -> Any: ...  # noqa: D401


def _deny_message(err: PolicyDeniedError) -> str:
    """Render a deny error as a string suitable for handing back to the LLM."""

    return f"Policy denied: {err.reason} (check={err.check}, action={err.action_id})"


class _GuardedTool:
    """Drop-in wrapper preserving the LangChain ``BaseTool`` surface.

    Wraps the underlying tool's ``_run`` / ``_arun`` with
    :meth:`Enforcer.bind`. On :class:`PolicyDeniedError` the wrapper
    either re-raises (``raise_on_deny=True``) or returns a string error
    that the LangChain executor will pass to the LLM as the tool result.
    """

    def __init__(
        self,
        tool: Any,
        enforcer: Enforcer,
        *,
        classify_action: Optional[ClassifyFn] = None,
        on_deny: Optional[OnDenyFn] = None,
        raise_on_deny: bool = False,
    ) -> None:
        self._tool = tool
        self._enforcer = enforcer
        self._on_deny = on_deny
        self._raise_on_deny = raise_on_deny
        # Mirror BaseTool attributes used by LangChain dispatch.
        self.name = getattr(tool, "name", tool.__class__.__name__)
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)
        self.return_direct = getattr(tool, "return_direct", False)

        # Build the bound callable once. We wrap the underlying ``_run``
        # in a plain function so the evaluator sees the LLM-facing tool
        # name (``Action.tool``) rather than the Python method name. We
        # can't mutate ``__name__`` on a bound method, so a thin closure
        # is the safest cross-runtime path.
        inner_run: Callable[..., Any] = getattr(tool, "_run", None) or tool.__call__

        def _run_proxy(*args: Any, **kwargs: Any) -> Any:
            return inner_run(*args, **kwargs)

        _run_proxy.__name__ = self.name  # ensure Action.tool == name
        self._guarded = enforcer.bind(
            _run_proxy,
            classify_action=classify_action,
            on_deny=on_deny,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Sync execution entry point. Returns deny string on policy deny."""

        try:
            return self._guarded(*args, **kwargs)
        except PolicyDeniedError as err:
            if self._raise_on_deny:
                raise
            return _deny_message(err)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async execution entry point. Falls back to sync ``_run``."""

        arun = getattr(self._tool, "_arun", None)
        if arun is None:
            return self._run(*args, **kwargs)
        # Async-safe: re-evaluate via the guarded sync fn first, then if
        # allowed delegate to the underlying ``_arun``. Mirrors LangChain
        # semantics where ``_arun`` may bypass ``_run``.
        try:
            async def _arun_proxy(*a: Any, **kw: Any) -> Any:
                return await arun(*a, **kw)

            _arun_proxy.__name__ = self.name
            guarded_async = self._enforcer.bind(
                _arun_proxy,
                on_deny=self._on_deny,
            )
            return await guarded_async(*args, **kwargs)
        except PolicyDeniedError as err:
            if self._raise_on_deny:
                raise
            return _deny_message(err)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Allow callable-style invocation. Mirrors LangChain ``Tool.__call__``."""

        return self._run(*args, **kwargs)


def bind_tools(
    tools: Sequence[Any],
    enforcer: Enforcer,
    *,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
    raise_on_deny: bool = False,
) -> List[_GuardedTool]:
    """Wrap each tool in ``tools`` with policy enforcement.

    The returned wrappers are drop-in replacements for the original
    tools and can be passed to a LangChain ``AgentExecutor`` as-is.

    Args:
        tools: LangChain-style tools (anything with ``name`` + ``_run``).
        enforcer: Pre-configured :class:`Enforcer`.
        classify_action: Optional per-tool action annotator. Same shape
            as :func:`sauronid_client.enforcement.bind`'s ``classify_action``.
            Applied to every tool in the list.
        on_deny: Optional hook fired before a denial surfaces to the LLM.
        raise_on_deny: When ``True`` the wrapper re-raises
            :class:`PolicyDeniedError`; when ``False`` (default) it
            returns a ``"Policy denied: …"`` string so the agent loop
            can recover.

    Returns:
        List of wrapped tools, same length and order as ``tools``.
    """

    return [
        _GuardedTool(
            t,
            enforcer,
            classify_action=classify_action,
            on_deny=on_deny,
            raise_on_deny=raise_on_deny,
        )
        for t in tools
    ]


class SauronLangChainAgent:
    """Bundle an :class:`Enforcer` with a wrapped tool list.

    Convenience holder for code that wants a single object to hand to
    ``AgentExecutor.from_agent_and_tools(tools=agent.tools, ...)``.

    Example::

        from sauronid_client import create_enforcer
        from sauronid_client.langchain import SauronLangChainAgent

        enf = create_enforcer(core_url=..., admin_key=..., policy_id=..., agent_id=...)
        agent = SauronLangChainAgent(
            tools=[search_tool, transfer_tool],
            enforcer=enf,
            classify_action=lambda name, args, _kw: (
                {"amount_usd": args[0]} if name == "transfer" else {}
            ),
        )
        # agent.tools is the guarded list, ready for AgentExecutor.
    """

    def __init__(
        self,
        *,
        tools: Sequence[Any],
        enforcer: Optional[Enforcer] = None,
        classify_action: Optional[ClassifyFn] = None,
        on_deny: Optional[OnDenyFn] = None,
        raise_on_deny: bool = False,
    ) -> None:
        """Construct a wrapped agent.

        When ``enforcer`` is ``None`` the tools are passed through
        untouched, preserving byte-identical behaviour for callers that
        don't opt into enforcement.
        """

        self.enforcer = enforcer
        if enforcer is None:
            self.tools: List[Any] = list(tools)
        else:
            self.tools = bind_tools(
                tools,
                enforcer,
                classify_action=classify_action,
                on_deny=on_deny,
                raise_on_deny=raise_on_deny,
            )
