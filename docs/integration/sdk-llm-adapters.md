# SauronID SDK — LLM Runtime Adapters

Policy enforcement for the three big agent runtimes — LangChain, OpenAI
Assistants, Anthropic Computer Use — wired through the same
`Enforcer.bind()` primitive documented in
[`sdk-integration.md`](sdk-integration.md). Adapters are additive:
existing code that does not pass `enforcer=...` keeps working
byte-identically.

Common bootstrap:

```python
from sauronid_client import create_enforcer

enf = create_enforcer(
    core_url="http://core:3001",
    admin_key=os.environ["SAURON_ADMIN_KEY"],
    policy_id="pol_abc...",
    agent_id="agent-pay-1",
)
```

The `enf` object exposes `enf.bind(tool, classify_action=..., on_deny=...)`
and the same `classify_action` / `on_deny` hooks are forwarded by every
adapter in this document.

---

## Wrap your LangChain tools

Pass a list of LangChain `BaseTool` instances (or anything with `.name`
+ `._run`) through `bind_tools` and feed the result straight into
`AgentExecutor`:

```python
from langchain.agents import AgentExecutor
from sauronid_client.langchain import bind_tools

guarded = bind_tools(
    [search_tool, transfer_tool],
    enforcer=enf,
    classify_action=lambda name, args, kwargs: (
        {"amount_usd": kwargs["amount"]} if name == "transfer" else {}
    ),
    on_deny=lambda d: log.warning("sauron deny: %s -> %s", d.check, d.reason),
)

executor = AgentExecutor.from_agent_and_tools(agent=my_agent, tools=guarded)
```

On a deny the wrapper returns `"Policy denied: <reason> (check=...,
action=...)"` as the tool result so the LLM sees a normal-looking error
and can recover (e.g. re-plan, call a different tool, ask the human).
The original `_run` is **never** invoked. Pass `raise_on_deny=True`
to short-circuit the executor instead.

You can also wrap once with `SauronLangChainAgent`:

```python
from sauronid_client.langchain import SauronLangChainAgent

agent = SauronLangChainAgent(
    tools=[search_tool, transfer_tool],
    enforcer=enf,
    classify_action=lambda name, args, kw: (
        {"amount_usd": kw["amount"]} if name == "transfer" else {}
    ),
)
executor = AgentExecutor.from_agent_and_tools(agent=my_agent, tools=agent.tools)
```

---

## Wrap your OpenAI Assistants

OpenAI Assistants surface tool calls as `requires_action`. The
`SauronOpenAIAssistant` dispatcher handles the inner loop:

```python
from openai import OpenAI
from sauronid_client.openai_adapter import SauronOpenAIAssistant

client = OpenAI()
assistant = SauronOpenAIAssistant(
    tools={"search": run_search, "transfer": run_transfer},
    enforcer=enf,
    classify_action=lambda name, _a, kw: (
        {"amount_usd": kw["amount"]} if name == "transfer" else {}
    ),
    on_deny=lambda d: log.warning("sauron deny: %s", d.reason),
)

run = client.beta.threads.runs.create(thread_id=t.id, assistant_id=a.id)
while run.status == "requires_action":
    outputs = assistant.dispatch(
        run.required_action.submit_tool_outputs.tool_calls
    )
    run = client.beta.threads.runs.submit_tool_outputs(
        thread_id=t.id, run_id=run.id, tool_outputs=outputs,
    )
```

Each denial yields a normal-looking tool output row:

```python
{"tool_call_id": "call_abc", "output": "Policy denied: <reason> (check=allowlist)"}
```

so `submit_tool_outputs` accepts it and the next turn sees the error
the same way it would see any other tool result.

For one-shot use without a long-lived object:

```python
from sauronid_client.openai_adapter import dispatch_tool_calls

outputs = dispatch_tool_calls(
    tool_calls, {"search": run_search}, enforcer=enf,
)
```

---

## Wrap your Anthropic Computer Use

Anthropic's tool-use loop returns `tool_use` blocks; the host executes
them and feeds back `tool_result` blocks on the next user turn:

```python
import anthropic
from sauronid_client.anthropic_adapter import SauronAnthropicAgent

client = anthropic.Anthropic()
agent = SauronAnthropicAgent(
    tools={"bash": run_bash, "transfer": run_transfer},
    enforcer=enf,
    classify_action=lambda name, _a, kw: (
        {"amount_usd": kw["amount"]} if name == "transfer" else {}
    ),
    on_deny=lambda d: log.warning("sauron deny: %s", d.reason),
)

msg = client.messages.create(model="claude-opus-4-7", tools=[...], messages=[...])
while any(b.type == "tool_use" for b in msg.content):
    results = agent.dispatch([b for b in msg.content if b.type == "tool_use"])
    msg = client.messages.create(
        model="claude-opus-4-7",
        tools=[...],
        messages=[..., {"role": "user", "content": results}],
    )
```

Each denial becomes a structured `tool_result` block with
`is_error=True`:

```python
{
    "type": "tool_result",
    "tool_use_id": "tu_abc",
    "content": "Policy denied: <reason> (check=allowlist)",
    "is_error": True,
}
```

so Claude sees the error in the same shape as any other tool failure
and can recover.

---

## `classify_action` and `on_deny`

Both hooks ride on top of the underlying `Enforcer.bind()`. See the
[`sdk-integration.md`](sdk-integration.md) reference for the full
semantics; the short version:

- **`classify_action(tool_name, args, kwargs) -> dict`** — synthesise
  the `Action` fields the evaluator needs. Recognised keys:
  `amount_usd`, `data_classification`, `signatures`,
  `delegation_depth`, `timestamp`. Returning `{}` means "no overrides"
  (zero-amount tool call, no classification).

- **`on_deny(Deny) -> None`** — fires **before** the denial surfaces.
  Use for audit logging, metrics, paging, etc. Anything the callback
  raises propagates instead of the original `PolicyDeniedError`, so
  keep it side-effect-only.

Both hooks apply to every tool wrapped by the adapter. If you need
per-tool divergent behaviour, call `enforcer.bind(...)` directly for
the special-case tools and pass them through the rest of the adapter
plumbing.

---

## Constraints

- **No new pip deps.** LangChain / OpenAI / Anthropic SDKs are *not*
  required at runtime. Adapters use duck-typed access plus `Protocol`
  typing; the test suite mocks each SDK end-to-end.
- **Additive.** Importing an adapter without passing `enforcer=...`
  keeps all calls byte-identical to the pre-enforcement behaviour. No
  silent policy is ever applied to a tool the caller did not opt in.
- **Allowlist names.** The evaluator checks the tool's `__name__`
  attribute against the policy's `allowed_tools`. Adapters stamp
  `__name__` on a thin proxy so the LLM-facing name (not the Python
  function name) is what the policy sees. If you bypass the adapter
  and call `enforcer.bind(fn)` yourself on a method, do the same.
