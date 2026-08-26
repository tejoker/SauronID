// SauronID Go quickstart: register, make a signed call, get denied.
//
// Prereqs: `docker compose up` at the repo root and the agent-action-tool
// binary (`cd core && cargo build --release`, or set
// SAURONID_AGENT_ACTION_TOOL). See README.md.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	sauronid "github.com/tejoker/SauronID/sdk/go/sauronid"
)

const coreURL = "http://localhost:3001"

func main() {
	adminKey := os.Getenv("SAURON_ADMIN_KEY") // dev stack default below
	if adminKey == "" {
		adminKey = "dev-only-admin-key-not-for-production"
	}
	ctx := context.Background()
	client := sauronid.NewClient(sauronid.ClientOptions{BaseURL: coreURL, AdminKey: adminKey})

	// 1. Authenticate the human owner (dev-only password login, seeded user).
	auth, err := client.UserAuth(ctx, "alice@sauron.dev", "pass_alice")
	if err != nil {
		log.Fatalf("user auth: %v", err)
	}
	fmt.Printf("user session ok, key_image=%.16s...\n", auth.KeyImage)

	// 2. Register the agent. model + prompt + tools become the binding
	//    checksum; the Ed25519 PoP keypair never leaves this process.
	//    MaxAmount + Currency register a server-enforced payment cap.
	agent, err := sauronid.RegisterLLMAgent(ctx, client, sauronid.RegisterLLMAgentOptions{
		UserSession:  auth.Session,
		UserKeyImage: auth.KeyImage,
		ModelID:      "claude-sonnet-4-5",
		SystemPrompt: "You are a careful assistant.",
		Tools:        []string{"search"},
		IntentScope:  []string{"payment_initiation"},
		MaxAmount:    5.00,
		Currency:     "EUR",
	})
	if err != nil {
		log.Fatalf("register: %v", err)
	}
	fmt.Printf("registered agent_id=%s\nbinding checksum  =%s\n", agent.AgentID, agent.ConfigDigest)

	// 3. A signed call (call-sig v2 headers: ts, nonce, body hash, digest).
	resp, err := agent.Call(ctx, "GET", "/agent/"+agent.AgentID, nil)
	if err != nil {
		log.Fatalf("signed call: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("signed call -> %d (%d bytes)\n", resp.StatusCode, len(body))

	// 4. A deliberately over-limit payment. The intent caps this agent at
	//    5.00 EUR, so the leash denies 2500.00 EUR server-side with the real
	//    "Requested amount ... exceeds intent maxAmount" message (see
	//    docs/site/guides/payments.md).
	denial, err := agent.AuthorizePayment(ctx, sauronid.AuthorizePaymentParams{
		UserSession: auth.Session,
		AmountMinor: 250_000, // 2500.00 EUR
		Currency:    "EUR",
		PaymentRef:  "quickstart-overlimit-001",
	})
	if err != nil {
		log.Fatalf("authorize payment: %v", err)
	}
	denialBody, _ := io.ReadAll(denial.Body)
	denial.Body.Close()
	fmt.Printf("payment attempt -> %d (expected 403)\ndenial body: %s\n",
		denial.StatusCode, denialBody)
	if denial.StatusCode != 403 {
		log.Fatal("leash should have denied this payment")
	}

	if err := agent.Revoke(ctx, auth.Session); err != nil {
		log.Fatalf("revoke: %v", err)
	}
	fmt.Println("agent revoked")
}
