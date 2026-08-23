# SauronID Go SDK

Go client + policy enforcement layer for the SauronID core server.
Feature-parity with the TypeScript SDK in `sdk/typescript/` and the Python SDK
in `sdk/python/sauronid_client/`.

## Install

```bash
go get github.com/tejoker/SauronID/sdk/go/sauronid
```

Requires Go 1.22+.

## Quickstart

```go
ctx := context.Background()
client := sauronid.NewClient(sauronid.ClientOptions{BaseURL: "http://localhost:8080"})

auth, err := client.UserAuth(ctx, "ops@example.com", "password") // dev-only legacy auth
if err != nil { log.Fatal(err) }

agent, err := sauronid.RegisterLLMAgent(ctx, client, sauronid.RegisterLLMAgentOptions{
	UserSession:  auth.Session,
	UserKeyImage: auth.KeyImage,
	ModelID:      "gpt-4o",
	SystemPrompt: "You are a payments copilot.",
	Tools:        []string{"send_email"},
})
if err != nil { log.Fatal(err) }

resp, err := agent.Call(ctx, "POST", "/agent/action/challenge", body) // signed x-sauron-* headers
if err != nil { log.Fatal(err) }
defer resp.Body.Close()

_ = agent.Revoke(ctx, auth.Session)
```

`RegisterLLMAgent` generates the Ed25519 PoP keypair in-process, lets the
server compute the binding config digest, and returns a `SignedAgent` whose
`Call` signs every request with the protocol-v2 call signature. See also
`RegisterMCPAgent`, `RegisterCustomAgent`, `AuthorizePayment`,
`EgressRequest`, `ReportEgress`, `SignActionChallenge`.

## Local policy enforcement

```go
package main

import (
	"context"
	"errors"
	"log"

	"github.com/tejoker/SauronID/sdk/go/sauronid"
)

func main() {
	ctx := context.Background()

	cache := sauronid.NewPolicyCache(sauronid.PolicyCacheOptions{
		CoreURL:  "http://localhost:8080",
		AdminKey: "...",
	})
	defer cache.Stop()
	if _, err := cache.Load(ctx, "pol_abc"); err != nil {
		log.Fatal(err)
	}

	budget := sauronid.NewBudgetTracker(sauronid.BudgetTrackerOptions{
		PolicyID: "pol_abc",
		FlushFn: sauronid.ServerPush(sauronid.ServerPushOptions{
			CoreURL: "http://localhost:8080",
			AgentID: "agent-1", PolicyID: "pol_abc",
		}),
	})
	defer budget.Stop()

	sendEmail := sauronid.ToolFunc(func(args ...interface{}) (interface{}, error) {
		// real tool body
		return "queued", nil
	})
	guarded := sauronid.Bind("send_email", sendEmail, sauronid.BindOptions{
		AgentID: "agent-1", PolicyID: "pol_abc",
		Cache: cache, BudgetTracker: budget,
		ClassifyAction: func(_ string, args []interface{}) map[string]interface{} {
			return map[string]interface{}{"amount_usd": 0.10}
		},
	})

	if _, err := guarded("hello@example.com"); err != nil {
		var denied *sauronid.PolicyDeniedError
		if errors.As(err, &denied) {
			log.Printf("denied: %s — %s", denied.Check, denied.Reason)
		}
	}
}
```

For the one-shot wiring use `sauronid.CreateEnforcer(ctx, opts)`.

## API surface

- `Client` — HTTP client for user auth, agent register/revoke, policy upload/list/evaluate, spend ledger, stats submit.
- `RegisterLLMAgent` / `RegisterMCPAgent` / `RegisterCustomAgent` — registration + PoP keypair generation, returns a `SignedAgent`.
- `SignedAgent` — signed `Call`, `AuthorizePayment`, `EgressRequest`, `ReportEgress`, `SignActionChallenge`, `Revoke`.
- `PolicyCache` — fetches compiled policies via `GET /v1/policy/:id`, background refresh.
- `BudgetTracker` — in-memory spend + rate ledger, optional server-side flush.
- `Bind` — wraps an arbitrary tool with policy enforcement.
- `Enforcer` / `CreateEnforcer` — one-shot wiring.
- `Evaluate` — pure invariant evaluator (7 checks).
- `SignCall`, `GeneratePopKeyPair`, `SignPopChallenge` — call-signing + PoP key helpers.
- `SubmitTransparentStats` — POSTs a native RISC Zero STARK receipt to `/v1/stats/submit-transparent`. Generate
  and verify the receipt with the pinned `transparent-zk` prover first; the server's 200 is storage, not your
  own verification. (The Groth16 `SubmitStats` that used to sit here is deleted — the route it called has been
  archived and returned 404.)

Full reference: `go doc github.com/tejoker/SauronID/sdk/go/sauronid`.

## Cross-impl parity

Verdict semantics (allow/deny strings) match the TypeScript and Python
evaluators byte-for-byte. The `cross_impl_test.go` file hard-codes
identical fixtures so a regression in any of the three SDKs surfaces
immediately.

## Known limitations

- **No proof generation.** Receipts come from the version-pinned Rust prover in `transparent-zk/`, not from
  any SDK. Go transports one that already exists (`SubmitTransparentStats`).
- **No local policy YAML parser.** Upload policies via the server's
  `POST /v1/policy` endpoint (`Client.UploadPolicy`) — the server returns
  the canonical compiled AST that the cache then fetches.
- **No LangChain / OpenAI / Anthropic adapters.** Go does not yet have a
  canonical LLM-tool framework. The `Bind` primitive is framework-agnostic
  — wrap any `ToolFunc`.
- **HTTP only.** No gRPC interface in this version.

## Layout

| File | Purpose |
|---|---|
| `types.go` | Verdict, Action, Binding, CompiledPolicy types |
| `evaluator.go` | The 7-invariant pure evaluator + ComputeNowTzHhmm |
| `policy_cache.go` | HTTP-backed compiled-policy cache |
| `budget_tracker.go` | Spend + rate ledger, ServerPush flush |
| `bind.go` | Tool wrapper, PolicyDeniedError, PolicyNotLoadedError |
| `enforcer.go` | CreateEnforcer one-shot wiring |
| `stats.go` | MetricValue interchange + Client.SubmitTransparentStats |
| `pop_keys.go` | Ed25519 PoP keypair helpers |
| `call_sig.go` | Signed-call header bundle |
| `signed_agent.go` | SignedAgent runtime + Register*Agent helpers |
| `client.go` | Bare HTTP client (agent / policy / spend) |
| `examples/main.go` | End-to-end demo |
