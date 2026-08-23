# SauronID examples

Every example assumes the dev stack is up — from the repo root:

```bash
docker compose up
```

Core: `http://localhost:3001`. Dashboard: `http://localhost:3000`
(login `dev`/`dev`). Seeded demo user: `alice@sauron.dev` / `pass_alice`.
The dev admin key used throughout is
`dev-only-admin-key-not-for-production`.

The three quickstarts register a real agent, which needs the
`agent-action-tool` binary for ring-key generation. Installed packages bundle
it (Python platform wheels; `@sauronid/agent-action-tool` on npm). From a
source checkout: `cd core && cargo build --release`, or set
`SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool`. The adapter
examples only upload a policy and need no Rust toolchain.

| Folder | Shows | Prereqs |
|---|---|---|
| `python-quickstart/` | user_auth, register_llm_agent, signed call, over-limit payment denial | `pip install sauronid-client`, agent-action-tool |
| `typescript-quickstart/` | userAuth, registerLlmAgent, signed call, over-limit payment denial | Node 18+, `npm install`, built `sdk/typescript/`, agent-action-tool |
| `go-quickstart/` | UserAuth, RegisterLLMAgent, signed Call, over-limit payment denial | Go 1.22+, agent-action-tool |
| `langchain/` | LangChain tools wrapped with `wrap()`; allowed vs denied tool call | `pip install "sauronid-client[langchain]"` |
| `llamaindex/` | LlamaIndex FunctionTools wrapped with `wrap()`; allowed vs denied | `pip install "sauronid-client[llamaindex]"` |
| `crewai/` | CrewAI BaseTools wrapped with `wrap()`; allowed vs denied `run()` | `pip install "sauronid-client[crewai]"` |
| `autogen/` | `guard_functions` + AutoGen registration; allowed vs denied | `pip install "sauronid-client[autogen]"` |
| `openai-tools/` | `dispatch_tool_calls` over API-shaped tool calls; no OpenAI key needed | `pip install sauronid-client` |
| `anthropic-tools/` | `dispatch_tool_use_blocks` over API-shaped blocks; no Anthropic key needed | `pip install sauronid-client` |
| `vercel-ai/` | `sauronTools()` wrapping an `ai` tool set (illustrative) | Node 18+, `npm install`, built `sdk/typescript/` |
| `curl/` | Pure-curl tour: health, dev registration, denial with the error envelope | curl |

Docs: `docs/site/` (concepts, quickstarts, guides) and `schemas/openapi.yaml`
for the full API surface.
