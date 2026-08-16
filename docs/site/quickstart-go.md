# Go quickstart

Register an agent and make a signed call. Requires Go 1.22+.

## Prerequisites

- A running core. From the repo root: `docker compose up`
  (core on `http://localhost:3001`, dashboard on `http://localhost:3000`,
  dev login `dev`/`dev`, seeded demo users like `alice@sauron.dev`).
- Ring-key generation uses the `agent-action-tool` binary:
  `cd core && cargo build --release` (no prebuilt channel for Go yet), or
  point `SAURONID_AGENT_ACTION_TOOL` at an existing binary.

## Install

```bash
go get github.com/tejoker/SauronID/clients/go/sauronid
```

## Register and call

```go
package main

import (
	"context"
	"fmt"
	"log"

	sauronid "github.com/tejoker/SauronID/clients/go/sauronid"
)

func main() {
	ctx := context.Background()
	client := sauronid.NewClient(sauronid.ClientOptions{BaseURL: "http://localhost:3001"})

	auth, err := client.UserAuth(ctx, "alice@sauron.dev", "pass_alice") // dev-only
	if err != nil { log.Fatal(err) }

	agent, err := sauronid.RegisterLLMAgent(ctx, client, sauronid.RegisterLLMAgentOptions{
		UserSession:  auth.Session,
		UserKeyImage: auth.KeyImage,
		ModelID:      "claude-sonnet-4-5",
		SystemPrompt: "You are a careful assistant.",
		Tools:        []string{"search"},
	})
	if err != nil { log.Fatal(err) }

	resp, err := agent.Call(ctx, "GET", "/agent/"+agent.AgentID, nil)
	if err != nil { log.Fatal(err) }
	defer resp.Body.Close()
	fmt.Println("status:", resp.StatusCode)

	_ = agent.Revoke(ctx, auth.Session)
}
```

`RegisterLLMAgent` generates the Ed25519 PoP keypair in-process; the server
computes the binding checksum and returns it as `agent.ConfigDigest`. Every
`agent.Call(...)` carries the signed `x-sauron-*` header set (call-sig v2):
timestamp, single-use nonce, body SHA-256, and the config digest.

## What you get back

The agent record echoes the binding
(`agent_id`, `agent_checksum`, `human_key_image`, `intent_json`, `status`).
Validated actions (payments, egress) return an `action_receipt` with
`receipt_id`, `action_hash`, `policy_version`, and a server `signature` —
verify with `POST /agent/action/receipt/verify`.

## What a denial looks like

Denials come back as 4xx with a JSON envelope (legacy routes may still
return plain text):

```json
{"error": {"code": "...", "message": "...", "fix": "..."}}
```

Locally, a tool wrapped with `sauronid.Bind(...)` returns a
`*sauronid.PolicyDeniedError` (match with `errors.As`) carrying `Check` and
`Reason`.

## Next steps

- Runnable version of this page: `examples/go-quickstart/` in the repo.
- [Payments guide](/guides/payments) — `agent.AuthorizePayment(...)`; set
  `MaxAmount` + `Currency` (plus optional `MerchantAllowlist`) on
  `RegisterLLMAgentOptions` to register a server-enforced payment cap.
- [Egress guide](/guides/egress) — `agent.EgressRequest(...)`.
- [Policies guide](/guides/policies) — `sauronid.CreateEnforcer(...)` and
  `sauronid.Bind(...)`; note the Go SDK has no local YAML parser — upload
  policies via `Client.UploadPolicy`.
