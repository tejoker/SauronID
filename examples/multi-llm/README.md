# Multiple LLMs, one gateway, at the same time

SauronID never talks to a model. It binds the **agent process**: `model_id`, the
system prompt and the tool list are hashed into a checksum that every subsequent
call must carry. "Which LLM" is therefore not an integration question — Claude,
GPT, Gemini, a local Llama, or something that ships next year are all a different
`model_id` string in the same binding.

This example registers three agents under one human owner, gives each a different
model, tool set and spend cap, and runs them concurrently against a single
gateway.

```bash
docker compose up                      # from the repo root
pip install sauronid-client
python examples/multi-llm/main.py
```

Real output from a live gateway:

```
agent        model                     cap  binding checksum
research     claude-opus-4-5        10.00  sha256:000f2a73566801cc0...
procurement  gpt-5                  50.00  sha256:b7988358eb404a20c...
support      gemini-2.5-pro          1.00  sha256:acedd64ab4cc57ad3...

signed call  research     (claude-opus-4-5     ) -> 200
signed call  procurement  (gpt-5               ) -> 200
signed call  support      (gemini-2.5-pro      ) -> 200

25.00 EUR    research     (claude-opus-4-5     ) -> DENIED
25.00 EUR    procurement  (gpt-5               ) -> ALLOWED
25.00 EUR    support      (gemini-2.5-pro      ) -> DENIED

recent receipts (attributed per agent):
  procurement  gpt-5                accepted
```

Three things worth pointing at in a demo:

1. **Different models produce different checksums.** An agent cannot swap the
   model behind its own registration without re-registering — the config digest
   travels on every call and the gateway checks it.
2. **The same request gets different answers at the same instant.** 25.00 EUR is
   allowed for procurement (50.00 cap) and refused for research (10.00) and
   support (1.00). One gateway, one moment, three mandates.
3. **The audit trail stays separable.** Only the accepted action produces a
   receipt, attributed to the agent that made it — so a mixed-vendor fleet can be
   reconstructed after the fact, per model.

For MCP clients (Claude Desktop, Claude Code, Codex, Gemini CLI, Cursor), the
same gateway is reached with one config block per client and no SDK at all — see
`sdk/mcp-server/README.md`.
