# Python quickstart

Register an agent and make a signed call from a source checkout. Cold Rust
builds can take 15–45 minutes; no sub-minute setup claim is made.

## Prerequisites

- A running core. From the repo root: `docker compose up`
  (core on `http://localhost:3001`, dashboard on `http://localhost:3000`,
  dev login `dev`/`dev`, seeded demo users like `alice@sauron.dev`).
- Ring-key generation uses the bundled `agent-action-tool` binary. Release
  wheels will ship it after the first approved release. From a source checkout:
  `cd core && cargo build --release`, or point
  `SAURONID_AGENT_ACTION_TOOL` at an existing binary.

## Install

```bash
python -m pip install -e ./sdk/python
```

Optional framework extras: `sauronid-client[langchain]`, `[llamaindex]`,
`[crewai]`, `[autogen]`, `[openai]`, `[anthropic]`.

## Register and call

```python
from sauronid_client import SauronIDClient, register_llm_agent

client = SauronIDClient(base_url="http://localhost:3001",
                        admin_key="dev-only-admin-key-not-for-production")
auth = client.user_auth("alice@sauron.dev", "pass_alice")  # dev-only login

agent = register_llm_agent(
    client,
    user_session=auth["session"],
    user_key_image=auth["key_image"],
    model_id="claude-sonnet-4-5",
    system_prompt="You are a careful assistant.",
    tools=["search"],
)

resp = agent.call("GET", f"/agent/{agent.agent_id}")
print(resp.status_code, resp.json())

agent.revoke(auth["session"])
```

`register_llm_agent` generates the Ed25519 PoP keypair in-process; the
server computes the binding checksum over `model_id` + `system_prompt` +
`tools` and returns it as `agent.config_digest`. Every `agent.call(...)`
carries the signed `x-sauron-*` header set (call-sig v2): timestamp,
single-use nonce, body SHA-256, and the config digest.

## What you get back

The agent record echoes the binding:

```json
{
  "agent_id": "agt_...",
  "agent_checksum": "9f2c...",
  "human_key_image": "a1b4...",
  "intent_json": "{\"scope\":[\"search\"]}",
  "status": "active"
}
```

A validated action (payment, egress) additionally returns an
`action_receipt`:

```json
{
  "receipt_id": "rcp_...",
  "action_hash": "6d1e...",
  "agent_id": "agt_...",
  "policy_version": "v1",
  "timestamp": 1752912000,
  "status": "authorized",
  "signature": "..."
}
```

## What a denial looks like

Denials come back as 4xx with a JSON envelope (legacy routes may still
return plain text):

```json
{"error": {"code": "...", "message": "...", "fix": "..."}}
```

At the tool boundary the SDK raises `PolicyDeniedError` with `.check`,
`.reason`, `.policy_id`, `.action_id`.

## Next steps

- Runnable version of this page: `examples/python-quickstart/` in the repo.
- [Payments guide](/guides/payments) — `agent.authorize_payment(...)` and
  intent caps: pass `max_amount=` + `currency=` (plus optional
  `merchant_allowlist=`) to `register_llm_agent` to register a
  server-enforced payment cap.
- [Egress guide](/guides/egress) — `agent.egress_request(...)` through the
  enforcing gateway.
- [Policies guide](/guides/policies) — upload a Policy DSL document and
  enforce it at the tool boundary with `sauronid_client.wrap(...)`.
