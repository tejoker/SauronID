"""Anthropic Computer Use / Tool Use adapter — policy-enforce the loop.

Anthropic's tool-use protocol returns ``tool_use`` blocks in the model
response; the host process executes each block and feeds the result
back as a ``tool_result`` content block on the next user turn. This
adapter wraps the host's tool dispatch so every tool call is enforced
by SauronID before it runs.

On deny the adapter emits a tool result of the form::

    {
        "type": "tool_result",
        "tool_use_id": "<id>",
        "content": "Policy denied: <reason>",
        "is_error": True,
    }

so the model sees a structured error and can recover instead of crashing
the agent loop.

The Anthropic SDK is **not** a runtime dependency: blocks are treated
as duck-typed objects with ``id``, ``name`` and ``input`` attributes,
with a Mapping fallback for raw API JSON / test fakes.

Public surface:

- :class:`SauronAnthropicAgent` — wrap a dict of ``{name: callable}``
  tools, mirroring :class:`SauronOpenAIAssistant`.
- :func:`dispatch_tool_use_blocks` — process a list of ``tool_use``
  blocks and return the ``tool_result`` list for the next message.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping, Optional

from .enforcement import (
    ClassifyFn,
    Enforcer,
    OnDenyFn,
    PolicyDeniedError,
)

__all__ = [
    "SauronAnthropicAgent",
    "dispatch_tool_use_blocks",
]


ToolFn = Callable[..., Any]


def _block_attrs(block: Any) -> tuple[str, str, Dict[str, Any]]:
    """Extract ``(id, name, input_dict)`` from a duck-typed tool_use block."""

    if isinstance(block, Mapping):
        bid = str(block.get("id", ""))
        name = str(block.get("name", ""))
        raw_input = block.get("input", {})
    else:
        bid = str(getattr(block, "id", ""))
        name = str(getattr(block, "name", ""))
        raw_input = getattr(block, "input", {})
    if isinstance(raw_input, Mapping):
        return bid, name, dict(raw_input)
    if isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            parsed = {}
        return bid, name, parsed if isinstance(parsed, dict) else {}
    return bid, name, {}


def _deny_result(tool_use_id: str, err: PolicyDeniedError) -> Dict[str, Any]:
    """Render an Anthropic ``tool_result`` block for a policy denial."""

    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": f"Policy denied: {err.reason} (check={err.check})",
        "is_error": True,
    }


def _success_result(tool_use_id: str, result: Any) -> Dict[str, Any]:
    """Render an Anthropic ``tool_result`` block for a successful call."""

    if isinstance(result, str):
        content: Any = result
    else:
        try:
            content = json.dumps(result, default=str)
        except (TypeError, ValueError):
            content = str(result)
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": content,
    }


class SauronAnthropicAgent:
    """Policy-enforced tool-call dispatcher for Anthropic tool use.

    Mirrors :class:`SauronOpenAIAssistant` but emits Anthropic-shaped
    ``tool_result`` blocks.

    Example::

        agent = SauronAnthropicAgent(
            tools={"bash": run_bash, "transfer": transfer},
            enforcer=enf,
            classify_action=lambda name, _a, kw: (
                {"amount_usd": kw["amount"]} if name == "transfer" else {}
            ),
        )
        results = agent.dispatch(
            [b for b in msg.content if b.type == "tool_use"]
        )
        # results -> feed back as a user message with content=[*results]
    """

    def __init__(
        self,
        *,
        tools: Mapping[str, ToolFn],
        enforcer: Optional[Enforcer] = None,
        classify_action: Optional[ClassifyFn] = None,
        on_deny: Optional[OnDenyFn] = None,
    ) -> None:
        """Construct a dispatcher.

        Args:
            tools: Mapping ``{name: callable}``. ``name`` must match the
                ``tool_use.name`` emitted by the model.
            enforcer: Optional :class:`Enforcer`. ``None`` keeps legacy
                pass-through behaviour.
            classify_action: Optional per-tool annotator forwarded to
                :meth:`Enforcer.bind`.
            on_deny: Optional callback fired before denial surfaces.
        """

        self._raw_tools: Dict[str, ToolFn] = dict(tools)
        self.enforcer = enforcer
        self._on_deny = on_deny
        if enforcer is None:
            self._tools: Dict[str, ToolFn] = dict(tools)
        else:
            self._tools = {
                name: self._wrap(name, fn, enforcer, classify_action, on_deny)
                for name, fn in tools.items()
            }

    @staticmethod
    def _wrap(
        name: str,
        fn: ToolFn,
        enforcer: Enforcer,
        classify_action: Optional[ClassifyFn],
        on_deny: Optional[OnDenyFn],
    ) -> ToolFn:
        """Bind ``fn`` to ``enforcer`` and rename so the evaluator sees ``name``.

        Wraps in a thin closure to support bound methods (whose
        ``__name__`` is read-only).
        """

        def _proxy(*args: Any, **kwargs: Any) -> Any:
            return fn(*args, **kwargs)

        _proxy.__name__ = name
        return enforcer.bind(
            _proxy, classify_action=classify_action, on_deny=on_deny
        )

    def dispatch(self, tool_use_blocks: List[Any]) -> List[Dict[str, Any]]:
        """Execute a list of ``tool_use`` blocks and return ``tool_result`` blocks.

        Args:
            tool_use_blocks: Sequence of Anthropic tool-use blocks (or
                test fakes / raw dicts).

        Returns:
            List of ``tool_result`` dicts ready to be assembled into the
            next user message's ``content``.
        """

        results: List[Dict[str, Any]] = []
        for block in tool_use_blocks:
            bid, name, kwargs = _block_attrs(block)
            tool = self._tools.get(name)
            if tool is None:
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": bid,
                        "content": f"Policy denied: unknown tool '{name}'",
                        "is_error": True,
                    }
                )
                continue
            try:
                result = tool(**kwargs)
            except PolicyDeniedError as err:
                results.append(_deny_result(bid, err))
                continue
            results.append(_success_result(bid, result))
        return results


def dispatch_tool_use_blocks(
    tool_use_blocks: List[Any],
    tools: Mapping[str, ToolFn],
    *,
    enforcer: Optional[Enforcer] = None,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
) -> List[Dict[str, Any]]:
    """Functional shortcut around :class:`SauronAnthropicAgent`."""

    agent = SauronAnthropicAgent(
        tools=tools,
        enforcer=enforcer,
        classify_action=classify_action,
        on_deny=on_deny,
    )
    return agent.dispatch(tool_use_blocks)
