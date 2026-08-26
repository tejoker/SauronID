"""OpenAI Assistants adapter — policy-enforce the tool-call dispatch loop.

OpenAI Assistants surface tool calls as ``requires_action`` events. The
host process is responsible for executing each tool and submitting the
output back to the API. This adapter sits between the LLM tool-call
request and the host executor: every call passes through
:meth:`Enforcer.bind` first.

On deny the adapter returns a structured tool output of the form::

    {
        "tool_call_id": "<id>",
        "output": "Policy denied: <reason>",
    }

which is exactly what ``submit_tool_outputs`` expects, so the next LLM
turn sees the denial as a normal tool result and can recover.

The OpenAI SDK is **not** a runtime dependency: the adapter uses
duck-typed access (``tool_call.id``, ``tool_call.function.name``,
``tool_call.function.arguments``) and falls back to dict-style lookups.

Public surface:

- :class:`SauronOpenAIAssistant` — wraps a dict of ``{name: callable}``
  tools with optional policy enforcement.
- :func:`dispatch_tool_calls` — process a list of tool calls and return
  the ``[{"tool_call_id", "output"}]`` array OpenAI expects.
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
    "SauronOpenAIAssistant",
    "dispatch_tool_calls",
]


ToolFn = Callable[..., Any]


def _tool_call_attrs(tool_call: Any) -> tuple[str, str, str]:
    """Extract ``(id, name, arguments_json)`` from a duck-typed tool call.

    Supports both attribute access (real OpenAI SDK objects) and dict
    access (test fakes / raw API JSON).
    """

    if isinstance(tool_call, Mapping):
        tc_id = str(tool_call.get("id", ""))
        fn = tool_call.get("function", {}) or {}
        if isinstance(fn, Mapping):
            name = str(fn.get("name", ""))
            args = fn.get("arguments", "{}")
        else:
            name = str(getattr(fn, "name", ""))
            args = getattr(fn, "arguments", "{}")
    else:
        tc_id = str(getattr(tool_call, "id", ""))
        fn = getattr(tool_call, "function", None)
        name = str(getattr(fn, "name", "")) if fn is not None else ""
        args = getattr(fn, "arguments", "{}") if fn is not None else "{}"
    return tc_id, name, args if isinstance(args, str) else json.dumps(args)


def _deny_output(tool_call_id: str, err: PolicyDeniedError) -> Dict[str, str]:
    """Render an OpenAI ``submit_tool_outputs`` row for a policy denial."""

    return {
        "tool_call_id": tool_call_id,
        "output": f"Policy denied: {err.reason} (check={err.check})",
    }


class SauronOpenAIAssistant:
    """Policy-enforced tool-call dispatcher for the OpenAI Assistants API.

    Construct with a ``tools`` map of ``{name: callable}``. When
    ``enforcer`` is supplied each callable is wrapped via
    :meth:`Enforcer.bind` and any denial is surfaced to the LLM as a
    structured tool output. When ``enforcer`` is ``None`` the dispatcher
    behaves byte-identically to a plain ``tools[name](**args)`` call.

    Example::

        assistant = SauronOpenAIAssistant(
            tools={"search": search, "transfer": transfer},
            enforcer=enf,
            classify_action=lambda name, args, kw: (
                {"amount_usd": kw["amount"]} if name == "transfer" else {}
            ),
        )
        outputs = assistant.dispatch(run.required_action.submit_tool_outputs.tool_calls)
        client.beta.threads.runs.submit_tool_outputs(
            thread_id=t.id, run_id=run.id, tool_outputs=outputs,
        )
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
            tools: Mapping ``{name: callable}`` of the host tools. The
                ``name`` must match what the LLM emits in tool calls.
            enforcer: Optional :class:`Enforcer`. When ``None`` tools
                run unwrapped (legacy behaviour).
            classify_action: Optional action annotator forwarded to
                :meth:`Enforcer.bind`. Applied to every tool.
            on_deny: Optional hook fired before a denial surfaces. Useful
                for audit / metrics.
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
        """Bind ``fn`` to the enforcer, preserving the LLM-facing name.

        Wraps ``fn`` in a thin closure so we can stamp ``__name__`` even
        when ``fn`` is a bound method (whose ``__name__`` is read-only).
        """

        def _proxy(*args: Any, **kwargs: Any) -> Any:
            return fn(*args, **kwargs)

        _proxy.__name__ = name
        return enforcer.bind(
            _proxy, classify_action=classify_action, on_deny=on_deny
        )

    def dispatch(self, tool_calls: List[Any]) -> List[Dict[str, str]]:
        """Execute a list of OpenAI tool calls and return the outputs.

        For each call: parse name + args, invoke the (possibly enforced)
        tool, and produce one ``{"tool_call_id", "output"}`` row. On
        :class:`PolicyDeniedError` the row contains
        ``"Policy denied: <reason>"`` so the next turn can recover.

        Args:
            tool_calls: Sequence of tool-call objects from the API
                (or test fakes). Both attribute- and dict-shaped calls
                are accepted.

        Returns:
            List ready to hand to
            ``client.beta.threads.runs.submit_tool_outputs``.
        """

        outputs: List[Dict[str, str]] = []
        for tc in tool_calls:
            tc_id, name, args_json = _tool_call_attrs(tc)
            tool = self._tools.get(name)
            if tool is None:
                outputs.append(
                    {
                        "tool_call_id": tc_id,
                        "output": f"Policy denied: unknown tool '{name}'",
                    }
                )
                continue
            try:
                parsed: Dict[str, Any] = json.loads(args_json or "{}")
            except json.JSONDecodeError:
                parsed = {}
            try:
                result = tool(**parsed) if isinstance(parsed, dict) else tool(parsed)
            except PolicyDeniedError as err:
                outputs.append(_deny_output(tc_id, err))
                continue
            outputs.append(
                {
                    "tool_call_id": tc_id,
                    "output": result if isinstance(result, str) else json.dumps(
                        result, default=str
                    ),
                }
            )
        return outputs


def dispatch_tool_calls(
    tool_calls: List[Any],
    tools: Mapping[str, ToolFn],
    *,
    enforcer: Optional[Enforcer] = None,
    classify_action: Optional[ClassifyFn] = None,
    on_deny: Optional[OnDenyFn] = None,
) -> List[Dict[str, str]]:
    """Functional shortcut around :class:`SauronOpenAIAssistant`.

    Useful for one-shot dispatch where building a long-lived assistant
    object would be overkill.
    """

    assistant = SauronOpenAIAssistant(
        tools=tools,
        enforcer=enforcer,
        classify_action=classify_action,
        on_deny=on_deny,
    )
    return assistant.dispatch(tool_calls)
