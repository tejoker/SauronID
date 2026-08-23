"""One-import policy wrapper — ``sauronid_client.wrap(...)``.

Routes duck-typed input to the right adapter. It is a router, not a
framework: all real behaviour lives in the per-framework adapter modules.

Dispatch table:

- plain callable            -> :func:`sauronid_client.enforcement.bind`
- list/tuple of callables   -> list of bound callables
- list of LlamaIndex tools  -> :func:`llamaindex_adapter.bind_llamaindex_tools`
- list of CrewAI tools      -> :func:`crewai_adapter.bind_crewai_tools`
- list of LangChain tools   -> :func:`sauronid_client.langchain.bind_tools`
- ``{name: callable}`` map  -> :class:`SauronOpenAIAssistant` (default) or
                               :class:`SauronAnthropicAgent` (``flavor="anthropic"``)

Raw OpenAI / Anthropic SDK clients cannot be wrapped directly (the tool
loop lives in host code); a helpful :class:`TypeError` points at the
dispatch helpers instead.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from .anthropic_adapter import SauronAnthropicAgent
from .crewai_adapter import bind_crewai_tools
from .enforcement import ClassifyFn, Enforcer, OnDenyFn, create_enforcer
from .langchain import bind_tools
from .llamaindex_adapter import bind_llamaindex_tools
from .openai_adapter import SauronOpenAIAssistant

__all__ = ["wrap"]


def _resolve_enforcer(
    enforcer: Optional[Enforcer],
    client: Optional[Any],
    policy_id: Optional[str],
    agent_id: Optional[str],
) -> Enforcer:
    """Return ``enforcer`` as-is, or build one from a SauronIDClient."""

    if enforcer is not None:
        return enforcer
    core_url = getattr(client, "base_url", None)
    if not (core_url and policy_id and agent_id):
        raise ValueError(
            "wrap() needs either enforcer=, or client= (SauronIDClient) "
            "plus policy_id= and agent_id="
        )
    return create_enforcer(
        core_url=core_url,
        admin_key=getattr(client, "admin_key", None),
        policy_id=policy_id,
        agent_id=agent_id,
        tenant_id=getattr(client, "tenant_id", None),
    )


def wrap(
    agent_or_tools: Any,
    *,
    client: Optional[Any] = None,
    policy_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    enforcer: Optional[Enforcer] = None,
    flavor: str = "openai",
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
    raise_on_deny: bool = False,
) -> Any:
    """Wrap tools / callables with SauronID policy enforcement.

    Args:
        agent_or_tools: What to guard — see the module dispatch table.
        client: :class:`~sauronid_client.client.SauronIDClient` used with
            ``policy_id`` + ``agent_id`` to build an enforcer. Ignored
            when ``enforcer`` is passed.
        policy_id: Policy to enforce (required unless ``enforcer=``).
        agent_id: Agent id (required unless ``enforcer=``).
        enforcer: Pre-built :class:`Enforcer`; skips client wiring.
        flavor: ``"openai"`` (default) or ``"anthropic"`` — only used
            when ``agent_or_tools`` is a ``{name: callable}`` mapping.
        classify_action / on_deny / raise_on_deny: Forwarded to the
            underlying adapter (``raise_on_deny`` where supported).

    Returns:
        The adapter-specific guarded object (see dispatch table).
    """

    enf = _resolve_enforcer(enforcer, client, policy_id, agent_id)
    common = dict(classify_action=classify_action, on_deny=on_deny)
    x = agent_or_tools

    if isinstance(x, Mapping):
        cls = SauronAnthropicAgent if flavor == "anthropic" else SauronOpenAIAssistant
        return cls(tools=x, enforcer=enf, **common)

    if callable(x) and not isinstance(x, (list, tuple)):
        return enf.bind(x, **common)

    if isinstance(x, (list, tuple)):
        if not x:
            return []
        first = x[0]
        # User tools subclass a framework base class in their own module, so
        # sniff the whole MRO, not just the leaf class.
        mro_mods = [c.__module__ or "" for c in type(first).__mro__]
        if any(m.startswith("crewai") for m in mro_mods):
            return bind_crewai_tools(x, enf, raise_on_deny=raise_on_deny, **common)
        if any(m.startswith("llama_index") for m in mro_mods) or (
            hasattr(first, "metadata") and hasattr(first, "call")
        ):
            return bind_llamaindex_tools(x, enf, raise_on_deny=raise_on_deny, **common)
        if hasattr(first, "_run") or hasattr(first, "name"):
            return bind_tools(x, enf, raise_on_deny=raise_on_deny, **common)
        if all(callable(t) for t in x):
            return [enf.bind(t, **common) for t in x]

    if hasattr(x, "beta") or hasattr(x, "messages"):
        raise TypeError(
            "wrap() cannot guard a raw LLM SDK client — the tool loop lives "
            "in your code. Pass your tools instead, or use "
            "sauronid_client.dispatch_tool_calls (OpenAI) / "
            "sauronid_client.dispatch_tool_use_blocks (Anthropic)."
        )
    raise TypeError(
        f"wrap() does not know how to guard {type(x).__name__!r}; pass a "
        "callable, a list of tools/callables, or a {name: callable} mapping"
    )
