"""CrewAI adapter — wrap BaseTool-style tools with SauronID enforcement.

This module is purely additive. Importing it has no side effects on
existing :mod:`sauronid_client` behaviour. The crewai package is **not**
a runtime dependency: CrewAI's ``BaseTool`` duck-types exactly like a
LangChain tool (``.name``, ``.description``, ``._run``), so this adapter
reuses the guarded wrapper from :mod:`sauronid_client.langchain` and
adds the public ``run()`` entry point CrewAI dispatch calls. Use
:func:`require_crewai` when you need the real framework classes; it
raises a helpful :class:`ImportError` when the extra is missing.

Public surface:

- :func:`bind_crewai_tools` — wrap a list of CrewAI tools.
- :class:`SauronCrewAIAgent` — thin holder bundling an enforcer with a
  tool list.
- :func:`require_crewai` — lazy import guard for the optional dep.

Denial surface: on a deny the wrapper returns a string of the form
``"Policy denied: <reason>"`` as the tool result so the crew loop can
recover; ``raise_on_deny=True`` re-raises :class:`PolicyDeniedError`.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from .enforcement import ClassifyFn, Enforcer, OnDenyFn
from .langchain import _GuardedTool

__all__ = [
    "bind_crewai_tools",
    "SauronCrewAIAgent",
    "require_crewai",
]


def require_crewai() -> Any:
    """Import and return :mod:`crewai`, or raise a helpful error.

    The adapter itself never needs the framework (duck typing); use this
    only when you must construct real CrewAI classes.
    """

    try:
        import crewai as _crewai
    except ImportError as err:
        raise ImportError(
            "crewai is not installed. The sauronid-client CrewAI adapter is "
            "duck-typed and does not require it, but this helper does. "
            "Install with: pip install 'sauronid-client[crewai]'"
        ) from err
    return _crewai


class _GuardedCrewAITool(_GuardedTool):
    """Guarded wrapper exposing CrewAI's public ``run()`` entry point.

    CrewAI executes tools via ``tool.run(...)`` (which normally proxies
    ``_run``); everything else — name/description mirroring, deny-string
    behaviour, ``classify_action`` / ``on_deny`` — is inherited from the
    LangChain wrapper since the tool surfaces are identical.
    """

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Public execution entry point. Returns deny string on policy deny."""

        return self._run(*args, **kwargs)


def bind_crewai_tools(
    tools: Sequence[Any],
    enforcer: Enforcer,
    *,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
    raise_on_deny: bool = False,
) -> List[_GuardedCrewAITool]:
    """Wrap each CrewAI tool in ``tools`` with policy enforcement.

    Args:
        tools: CrewAI-style tools (anything with ``name`` + ``_run``).
        enforcer: Pre-configured :class:`Enforcer`.
        classify_action: Optional per-tool action annotator, same shape as
            :func:`sauronid_client.enforcement.bind`'s ``classify_action``.
        on_deny: Optional hook fired before a denial surfaces to the LLM.
        raise_on_deny: ``True`` re-raises :class:`PolicyDeniedError`;
            ``False`` (default) returns a ``"Policy denied: ..."`` string.

    Returns:
        List of wrapped tools, same length and order as ``tools``.
    """

    return [
        _GuardedCrewAITool(
            t,
            enforcer,
            classify_action=classify_action,
            on_deny=on_deny,
            raise_on_deny=raise_on_deny,
        )
        for t in tools
    ]


class SauronCrewAIAgent:
    """Bundle an :class:`Enforcer` with a wrapped CrewAI tool list.

    Mirrors :class:`sauronid_client.langchain.SauronLangChainAgent`:
    when ``enforcer`` is ``None`` the tools pass through untouched.

    Example::

        from sauronid_client import create_enforcer
        from sauronid_client.crewai_adapter import SauronCrewAIAgent

        enf = create_enforcer(core_url=..., admin_key=..., policy_id=..., agent_id=...)
        crew_agent = SauronCrewAIAgent(tools=[search_tool], enforcer=enf)
        # crew_agent.tools is the guarded list, ready for crewai.Agent(tools=...).
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
        self.enforcer = enforcer
        if enforcer is None:
            self.tools: List[Any] = list(tools)
        else:
            self.tools = bind_crewai_tools(
                tools,
                enforcer,
                classify_action=classify_action,
                on_deny=on_deny,
                raise_on_deny=raise_on_deny,
            )
