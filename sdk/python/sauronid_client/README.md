# sauronid_client (Python)

Sign every AI-agent call through SauronID. Works with LangChain, OpenAI
Assistants, Anthropic Computer Use, MCP servers, plain `requests`.

## Install

```bash
pip install sauronid-client                     # when published
# or, from source:
pip install -e sdk/python
```

Dependencies: `requests`, `cryptography`. Both pure-Python wheels on every
major platform.

## Five-line example

```python
from sauronid_client import SauronIDClient, register_llm_agent

client = SauronIDClient(base_url="http://localhost:3001")
auth = client.user_auth("alice@sauron.dev", "pass_alice")
agent = register_llm_agent(
    client,
    user_session=auth["session"],
    user_key_image=auth["key_image"],
    model_id="claude-opus-4-7",
    system_prompt="You are a research assistant.",
    tools=["search", "fetch"],
)

# Every call is signed + replay-protected + body-bound + audit-anchored.
resp = agent.call("POST", "/internal/api/search",
                   json_body={"query": "Anthropic claude opus 4.7 docs"})
print(resp.status_code, resp.text)
```

## LangChain integration

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import BaseTool
from sauronid_client.adapters import LangChainTool

original_tools = [my_search_tool, my_db_tool]    # any BaseTool subclasses
guarded_tools = [
    LangChainTool(agent, t, target_host=target_for(t))
    for t in original_tools
]
executor = AgentExecutor(agent=create_tool_calling_agent(...), tools=guarded_tools)
```

Each `_run` call records an egress entry on SauronID. The entries are
included in the next merkle anchor batch (Bitcoin OTS + Solana Memo).

## OpenAI Assistants API

```python
from openai import OpenAI
from sauronid_client.adapters import wrap_openai_tool_call

oai = OpenAI()
run = oai.beta.threads.runs.create(thread_id=t.id, assistant_id=a.id)

while run.status == "requires_action":
    outputs = []
    for tc in run.required_action.submit_tool_outputs.tool_calls:
        out = wrap_openai_tool_call(
            agent, tc, my_executor,
            target_host="api.example.com",
        )
        outputs.append({"tool_call_id": tc.id, "output": out})
    run = oai.beta.threads.runs.submit_tool_outputs(
        thread_id=t.id, run_id=run.id, tool_outputs=outputs
    )
```

## Anthropic Computer Use / Tool Use

```python
from anthropic import Anthropic
from sauronid_client.adapters import wrap_anthropic_tool_use

ac = Anthropic()
msg = ac.messages.create(model="claude-opus-4-7", tools=[...], ...)
for block in msg.content:
    if block.type == "tool_use":
        result = wrap_anthropic_tool_use(
            agent,
            {"name": block.name, "input": block.input, "id": block.id},
            my_tool_executor,
            target_host="api.example.com",
        )
```

## What this gives you operationally

1. Every tool call from your agent is **signed** with the agent's PoP key.
2. Body bytes are **bound** into the signature. Tampered request → 401.
3. Replay against any other endpoint → 401.
4. Replay with the same nonce → 409.
5. If the agent's model_id, system_prompt, or tool list changes without first
   calling `POST /agent/<id>/checksum/update`, the SauronID server's stored
   checksum mismatches the runtime's — every call rejects with `config drift`.
6. Every tool execution is recorded in `agent_egress_log`. The merkle root of
   that log is anchored to Bitcoin (OpenTimestamps) and Solana (Memo) every
   N minutes — the audit trail cannot be silently rewritten.

## Reading back the agent record

```python
record = client.get_json(f"/agent/{agent.agent_id}")
# {
#   "agent_id": "agt_…",
#   "agent_checksum": "sha256:...",     ← server-computed binding digest
#   "intent_json": "...",
#   "expires_at": ...,
#   "revoked": false,
# }
```

## Rotating the checksum (system prompt update / new tool added)

```python
# When you legitimately need to update the system prompt or tool list:
import requests, json

new_inputs = {
    "model_id": "claude-opus-4-7",
    "system_prompt": open("prompts/research_v2.md").read(),
    "tools": ["search", "fetch", "calc"],
}
r = requests.post(
    f"{client.base_url}/agent/{agent.agent_id}/checksum/update",
    headers={"x-sauron-session": auth["session"], "content-type": "application/json"},
    data=json.dumps({
        "agent_type": "llm",
        "checksum_inputs": new_inputs,
        "reason": "Added calc tool",
    }),
)
print(r.json())
# {
#   "agent_id": "agt_…",
#   "from_checksum": "sha256:abc…",
#   "to_checksum":   "sha256:def…",
#   "version": 2
# }
agent.config_digest = r.json()["to_checksum"]   # use new digest from now on
```

The rotation is appended to `agent_checksum_audit` (server-side) AND
included in the next on-chain anchor batch.
