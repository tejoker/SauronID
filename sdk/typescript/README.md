# @sauronid/agentic

TypeScript SDK for SauronID agent identity: register an AI agent, sign every
outbound call with Ed25519 (call-sig v2, replay-protected, body-bound), and
enforce policy at the tool boundary.

## Install

```bash
npm install @sauronid/agentic
```

## Quickstart

```ts
import { SauronIDClient, registerLlmAgent } from "@sauronid/agentic";

const client = new SauronIDClient({ baseUrl: "http://localhost:3001" });
const auth = await client.userAuth("alice@sauron.dev", "pass_alice"); // {session, key_image}

const agent = await registerLlmAgent(client, {
    userSession: auth.session,
    userKeyImage: auth.key_image,
    modelId: "claude-sonnet-4-5",
    systemPrompt: "You are a careful assistant.",
    tools: ["search"],
});

// Every call carries the seven x-sauron-* headers, signed with the agent's
// Ed25519 PoP key over the exact body bytes. Nonces are single-use.
const resp = await agent.call("POST", "/internal/api/search", {
    jsonBody: { q: "sauron" },
});

await agent.revoke(auth.session);
```

`registerLlmAgent` generates the Ed25519 PoP keypair in-process and a
Ristretto ring keypair via the `agent-action-tool` binary (install the
prebuilt `@sauronid/agent-action-tool` package, build with
`cd core && cargo build --release`, or set `$SAURONID_AGENT_ACTION_TOOL`).
Operators holding their own ring keys pass `publicKeyHex`, `ringSecretHex`,
and `ringKeyImageHex` explicitly. Also available: `registerMcpAgent`,
`registerCustomAgent`, `agent.authorizePayment(...)`,
`agent.egressRequest(...)`, `agent.reportEgress(...)`.

## Framework adapters

Policy-enforce the tool dispatch loop of your framework. No framework SDK is
required — tools and tool calls are typed structurally.

```ts
import { createEnforcer, sauronTools } from "@sauronid/agentic";

const enf = await createEnforcer({
    coreUrl: "http://localhost:3001",
    policyId: "pol_abc",
    agentId: agent.agentId,
});

// Vercel AI SDK: wrap the tool set passed to generateText/streamText.
const tools = sauronTools(myTools, { enforcer: enf, agent });
// A denied tool resolves to "Policy denied: <reason>" so the model recovers.
```

OpenAI and Anthropic loops use the same options:

```ts
import { dispatchToolCalls, dispatchToolUseBlocks } from "@sauronid/agentic";

const outputs = await dispatchToolCalls(run.tool_calls, hostTools, { enforcer: enf });
const results = await dispatchToolUseBlocks(toolUseBlocks, hostTools, { enforcer: enf });
```

## Docs

- Repository: https://github.com/tejoker/SauronID (`sdk/typescript/`)
- Threat model, multi-tenancy, and stats submission: `docs/` in the repo
- Python client with identical wire semantics: `sdk/python/`

## License

Apache-2.0
