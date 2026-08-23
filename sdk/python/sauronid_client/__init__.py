"""SauronID Python client.

Sign and route every AI-agent call through SauronID. Works with any agent
runtime — LangChain, OpenAI Assistants, Anthropic Computer Use, MCP servers,
plain `requests` — by wrapping the tool-call execution layer.

Quick example:

    from sauronid_client import SauronIDClient, register_llm_agent

    client = SauronIDClient(base_url="https://sauronid.your-co.internal",
                            admin_key="…")
    agent = register_llm_agent(
        client,
        user_session=...,                        # opaque from /user/auth
        user_key_image=...,                      # user's ring key image (hex)
        model_id="claude-opus-4-7",
        system_prompt=open("prompt.md").read(),
        tools=["search", "fetch"],
    )
    # agent.private_key never leaves the process; agent.config_digest is
    # what the server stored as agents.agent_checksum.

    # Use anywhere you'd normally do `requests.post(...)`:
    resp = agent.call("POST", "/internal/api/search",
                       json={"query": "Anthropic claude opus 4.7 docs"})
    # SauronID has signed, replay-protected, body-bound, intent-leashed,
    # config-digest-checked the call. Audit row is anchored to BTC + Solana.
"""

from .client import SauronIDClient, SauronIDError
from .agent import (
    SignedAgent,
    register_llm_agent,
    register_mcp_agent,
    register_custom_agent,
)
from .adapters import (
    LangChainTool,
    wrap_openai_tool_call,
    wrap_anthropic_tool_use,
)
from .enforcement import (
    PolicyCache,
    BudgetTracker,
    PolicyDeniedError,
    PolicyNotLoadedError,
    Verdict,
    Allow,
    Deny,
    Action,
    EvaluationContext,
    CompiledPolicy,
    Enforcer,
    evaluate,
    bind,
    create_enforcer,
)
# LLM-runtime adapters (Sprint 11 follow-up). Additive — existing
# ``adapters`` re-exports above are unchanged.
from .langchain import (
    bind_tools,
    SauronLangChainAgent,
)
from .openai_adapter import (
    SauronOpenAIAssistant,
    dispatch_tool_calls,
)
from .anthropic_adapter import (
    SauronAnthropicAgent,
    dispatch_tool_use_blocks,
)
# 3rd-wave framework adapters + one-import wrapper. None of these import
# their framework at module import time (duck typing / lazy require_*
# guards), so eager re-export keeps package import framework-free.
from .llamaindex_adapter import (
    bind_llamaindex_tools,
    SauronLlamaIndexAgent,
    require_llama_index,
)
from .crewai_adapter import (
    bind_crewai_tools,
    SauronCrewAIAgent,
    require_crewai,
)
from .autogen_adapter import (
    guard_function,
    guard_functions,
    require_autogen,
)
from .wrap import wrap

__version__ = "0.2.0"
__all__ = [
    "SauronIDClient",
    "SauronIDError",
    "SignedAgent",
    "register_llm_agent",
    "register_mcp_agent",
    "register_custom_agent",
    "LangChainTool",
    "wrap_openai_tool_call",
    "wrap_anthropic_tool_use",
    # Sprint 3 enforcement layer
    "PolicyCache",
    "BudgetTracker",
    "PolicyDeniedError",
    "PolicyNotLoadedError",
    "Verdict",
    "Allow",
    "Deny",
    "Action",
    "EvaluationContext",
    "CompiledPolicy",
    "Enforcer",
    "evaluate",
    "bind",
    "create_enforcer",
    # LLM-runtime adapters
    "bind_tools",
    "SauronLangChainAgent",
    "SauronOpenAIAssistant",
    "dispatch_tool_calls",
    "SauronAnthropicAgent",
    "dispatch_tool_use_blocks",
    # 3rd-wave framework adapters + one-import wrapper
    "bind_llamaindex_tools",
    "SauronLlamaIndexAgent",
    "require_llama_index",
    "bind_crewai_tools",
    "SauronCrewAIAgent",
    "require_crewai",
    "guard_function",
    "guard_functions",
    "require_autogen",
    "wrap",
]
