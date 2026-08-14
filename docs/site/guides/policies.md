# Policies

The Policy DSL is a declarative YAML/JSON document describing what an agent
may do: tool allowlist, budget cap, rate limit, time window, data scope,
required signatures. This page is the operational bridge — upload, bind,
evaluate, enforce. The full language reference lives in
[`docs/policy-dsl.md`](https://github.com/tejoker/SauronID/blob/main/docs/policy-dsl.md).

## Write

```yaml
version: "1"
agent: support_agent
binding:
  allowed_tools: [search]
  max_budget_usd: 50
  rate_limit: { requests_per_minute: 30 }
```

## Upload

Admin-gated. Accepts JSON `{"raw_yaml": "..."}` or a raw YAML body:

```bash
curl -s http://localhost:3001/v1/policy/upload \
  -H "x-admin-key: $SAURON_ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d "{\"raw_yaml\": $(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' policy.yaml)}"
# -> {"policy_id": "pol_<32-hex>", "agent": "support_agent", "checks": [...]}
```

## Bind to an agent

```bash
curl -s -X POST "http://localhost:3001/v1/agents/$AGENT_ID/policy_binding" \
  -H "x-admin-key: $SAURON_ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d "{\"policy_id\": \"$POLICY_ID\"}"
```

Once bound, server-side action paths (payments, `POST /policy/authorize`)
consult this policy in addition to the agent's intent.

## Evaluate

Dry-run any action against a policy — with `agent_id` the server-side spend
ledger is consulted; without it you get simulator mode:

```bash
curl -s http://localhost:3001/v1/policy/evaluate \
  -H "x-admin-key: $SAURON_ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"policy_id": "'$POLICY_ID'", "action": {"tool": "search"}}'
# -> {"verdict": "allow", "trace": [{"check": "allowlist", "verdict": "allow"}, ...]}
```

## Enforce at the tool boundary

The SDKs fetch the compiled policy (`GET /v1/policy/{id}`), cache it with
background refresh, and evaluate every tool call locally before it runs —
denials never leave your process. One-shot wiring:

```python
from sauronid_client import wrap

guarded_tools = wrap(
    my_tools,                      # callable, list of tools, or {name: fn}
    client=client,
    policy_id=policy_id,
    agent_id=agent.agent_id,
)
```

TypeScript: `createEnforcer({coreUrl, adminKey, policyId, agentId})` then
`enf.bind(tool)` or the framework adapters. Go:
`sauronid.CreateEnforcer(ctx, opts)` then `sauronid.Bind(...)`. Spend is
pushed to the server-authoritative ledger
(`POST /v1/agents/{id}/spend`) so the budget cannot be reset by restarting
the process.

## Full reference

- Language: `docs/policy-dsl.md` (repo)
- JSON schema for IDE autocomplete: `schemas/policy.schema.json`
- Framework adapters: `docs/sdk-llm-adapters.md` (repo) and the
  `examples/` tree.
