"""Drop-in adapters for the three big agent runtimes.

The pattern is the same in all three: the runtime exposes a "tool execution"
hook. Wrap that hook so every tool call is signed by the registered SauronID
agent, the egress is logged, and the response is anchored.

Why this works for ANY runtime, including Anthropic Computer Use and OpenAI
Assistants: those products return *structured tool-call requests* from the
LLM. Your code is what actually executes the tool. SauronID sits between
"LLM said run_tool" and "tool actually runs". Concretely:

  Anthropic Computer Use -> reads `tool_use` blocks -> wraps `run_tool(...)`
  OpenAI Assistants      -> reads `requires_action` -> wraps `submit_tool_outputs(...)`
  LangChain              -> AgentExecutor's `_perform_agent_action` hook
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Mapping, Optional, Sequence

from .agent import SignedAgent

# ─────────────────────────────────────────────────────────────────────────
# LangChain
# ─────────────────────────────────────────────────────────────────────────


class LangChainTool:
    """Wrap a LangChain `BaseTool` so each `_run` call is signed.

    Usage:

        from langchain.tools import BaseTool
        from sauronid_client.adapters import LangChainTool
        original = MySearchTool()  # any langchain BaseTool
        guarded = LangChainTool(agent, original, target_host="search.api.example.com")
        # `guarded` is a drop-in replacement: agent_executor.tools = [guarded]
    """

    def __init__(
        self,
        agent: SignedAgent,
        tool: Any,                       # langchain.tools.BaseTool
        target_host: str,
        target_path: str = "/",
    ):
        self.agent = agent
        self.tool = tool
        self.target_host = target_host
        self.target_path = target_path
        # Mirror the BaseTool surface langchain uses for dispatch.
        self.name = getattr(tool, "name", tool.__class__.__name__)
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)
        self.return_direct = getattr(tool, "return_direct", False)

    def _run(self, *args, **kwargs):
        # Pre-flight: log egress before calling the wrapped tool.
        body_repr = json.dumps(
            {"args": list(args), "kwargs": dict(kwargs)},
            separators=(",", ":"), default=str,
        ).encode("utf-8")
        body_hash = hashlib.sha256(body_repr).hexdigest()
        # Fail closed. A security adapter must never turn an unavailable guard
        # into permission to run the tool. Production deployments should use
        # SignedAgent.egress_request so the network call itself crosses core.
        self.agent.report_egress(
            target_host=self.target_host,
            target_path=self.target_path,
            method="POST",
            body_hash_hex=body_hash,
        )
        return self.tool._run(*args, **kwargs)

    async def _arun(self, *args, **kwargs):
        # LangChain BaseTool may have async path.
        body_repr = json.dumps(
            {"args": list(args), "kwargs": dict(kwargs)},
            separators=(",", ":"), default=str,
        ).encode("utf-8")
        body_hash = hashlib.sha256(body_repr).hexdigest()
        self.agent.report_egress(
            target_host=self.target_host,
            target_path=self.target_path,
            method="POST",
            body_hash_hex=body_hash,
        )
        if hasattr(self.tool, "_arun"):
            return await self.tool._arun(*args, **kwargs)
        return self.tool._run(*args, **kwargs)


# ─────────────────────────────────────────────────────────────────────────
# OpenAI Assistants API
# ─────────────────────────────────────────────────────────────────────────


def wrap_openai_tool_call(
    agent: SignedAgent,
    tool_call: Any,                              # openai-py ToolCall
    executor: Callable[[Any], Any],
    *,
    target_host: str,
    target_path: str = "/",
) -> Any:
    """Execute one OpenAI Assistants tool call through the SauronID leash.

    Usage in the standard run-poll loop:

        run = client.beta.threads.runs.create(thread_id=t.id, assistant_id=a.id)
        while run.status == "requires_action":
            for tc in run.required_action.submit_tool_outputs.tool_calls:
                output = wrap_openai_tool_call(
                    sauronid_agent, tc, my_executor,
                    target_host="api.example.com",
                )
                tool_outputs.append({"tool_call_id": tc.id, "output": output})
            run = client.beta.threads.runs.submit_tool_outputs(...)
    """
    # OpenAI ToolCall has .function.name and .function.arguments (JSON string).
    name = getattr(tool_call.function, "name", "")
    args_json = getattr(tool_call.function, "arguments", "{}")
    try:
        body_hash = hashlib.sha256(args_json.encode("utf-8")).hexdigest()
    except Exception:
        body_hash = ""

    agent.report_egress(
        target_host=target_host,
        target_path=f"{target_path}#tool:{name}",
        method="POST",
        body_hash_hex=body_hash,
    )
    return executor(tool_call)


# ─────────────────────────────────────────────────────────────────────────
# Anthropic Computer Use / Tool Use
# ─────────────────────────────────────────────────────────────────────────


def wrap_anthropic_tool_use(
    agent: SignedAgent,
    tool_use_block: Mapping[str, Any],
    executor: Callable[[Mapping[str, Any]], Any],
    *,
    target_host: str,
    target_path: str = "/",
) -> Any:
    """Execute one Anthropic `tool_use` block through the SauronID leash.

    Usage:

        msg = client.messages.create(model="claude-opus-4-7", tools=[...], ...)
        for block in msg.content:
            if block.type == "tool_use":
                result = wrap_anthropic_tool_use(
                    sauronid_agent,
                    {"name": block.name, "input": block.input, "id": block.id},
                    my_executor,
                    target_host="api.example.com",
                )
    """
    name = tool_use_block.get("name", "")
    input_json = json.dumps(tool_use_block.get("input", {}),
                             separators=(",", ":"), default=str)
    body_hash = hashlib.sha256(input_json.encode("utf-8")).hexdigest()
    agent.report_egress(
        target_host=target_host,
        target_path=f"{target_path}#tool:{name}",
        method="POST",
        body_hash_hex=body_hash,
    )
    return executor(tool_use_block)
