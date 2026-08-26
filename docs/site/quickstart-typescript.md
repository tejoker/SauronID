# TypeScript quickstart

Register an agent and make a signed call from Node 18+.

## Prerequisites

- A running core. From the repo root: `docker compose up`
  (core on `http://localhost:3001`, dashboard on `http://localhost:3000`,
  dev login `dev`/`dev`, seeded demo users like `alice@sauron.dev`).
- Ring-key generation uses the `agent-action-tool` binary. Until the first
  approved package release, build it with `cd core && cargo build --release`, or point
  `SAURONID_AGENT_ACTION_TOOL` at an existing binary.

## Install

```bash
npm ci --prefix sdk/typescript
npm run build --prefix sdk/typescript
```

## Register and call

```ts
import { SauronIDClient, registerLlmAgent } from "@sauronid/agentic";

const client = new SauronIDClient({
    baseUrl: "http://localhost:3001",
    adminKey: "dev-only-admin-key-not-for-production",
});
const auth = await client.userAuth("alice@sauron.dev", "pass_alice"); // dev-only

const agent = await registerLlmAgent(client, {
    userSession: auth.session,
    userKeyImage: auth.key_image,
    modelId: "claude-sonnet-4-5",
    systemPrompt: "You are a careful assistant.",
    tools: ["search"],
});

const resp = await agent.call("GET", `/agent/${agent.agentId}`);
console.log(resp.status, await resp.json());

await agent.revoke(auth.session);
```

`registerLlmAgent` generates the Ed25519 PoP keypair in-process; the server
computes the binding checksum over `modelId` + `systemPrompt` + `tools` and
returns it as `agent.configDigest`. Every `agent.call(...)` carries the
signed `x-sauron-*` header set (call-sig v2): timestamp, single-use nonce,
body SHA-256, and the config digest.

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
`action_receipt` with `receipt_id`, `action_hash`, `policy_version`, and a
server `signature` — verify it with `POST /agent/action/receipt/verify`.

## What a denial looks like

Denials come back as 4xx with a JSON envelope (legacy routes may still
return plain text):

```json
{"error": {"code": "...", "message": "...", "fix": "..."}}
```

At the tool boundary, `enforcer.bind(...)` throws `PolicyDeniedError`; the
framework adapters (`sauronTools`, `dispatchToolCalls`,
`dispatchToolUseBlocks`) instead resolve the tool result to
`"Policy denied: <reason>"` so the model loop recovers.

## Next steps

- Runnable version of this page: `examples/typescript-quickstart/` in the
  repo; Vercel AI SDK wiring in `examples/vercel-ai/`.
- [Payments guide](/guides/payments) — `agent.authorizePayment(...)`; pass
  `maxAmount` + `currency` (plus optional `merchantAllowlist`) to
  `registerLlmAgent` to register a server-enforced payment cap.
- [Egress guide](/guides/egress) — `agent.egressRequest(...)`.
- [Policies guide](/guides/policies) — `createEnforcer(...)` + `sauronTools(...)`.
