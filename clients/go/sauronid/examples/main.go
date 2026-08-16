// Example end-to-end use of the SauronID Go SDK.
//
// The example stands up an in-process httptest server that pretends to be
// the SauronID core, loads a policy through the cache, binds a fake tool,
// and demonstrates both the allow and deny paths.
//
// Run with:
//
//	go run ./examples
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/tejoker/SauronID/clients/go/sauronid"
)

func main() {
	// Spin up a fake core. In production this is the real URL.
	srv := fakeCore()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cache := sauronid.NewPolicyCache(sauronid.PolicyCacheOptions{
		CoreURL:         srv.URL,
		RefreshInterval: 10 * time.Second,
	})
	defer cache.Stop()

	if _, err := cache.Load(ctx, "pol_example"); err != nil {
		log.Fatalf("load policy: %v", err)
	}

	budget := sauronid.NewBudgetTracker(sauronid.BudgetTrackerOptions{
		PolicyID:      "pol_example",
		FlushInterval: -1, // offline mode for the demo
	})
	defer budget.Stop()

	sendEmail := sauronid.ToolFunc(func(args ...interface{}) (interface{}, error) {
		fmt.Printf("[tool] send_email called with %d args\n", len(args))
		return "queued", nil
	})
	guarded := sauronid.Bind("send_email", sendEmail, sauronid.BindOptions{
		AgentID: "agent-example", PolicyID: "pol_example",
		Cache: cache, BudgetTracker: budget,
		ClassifyAction: func(_ string, args []interface{}) map[string]interface{} {
			return map[string]interface{}{"amount_usd": 0.10}
		},
	})

	// Allow path
	if out, err := guarded("hello@example.com", "body"); err != nil {
		log.Fatalf("unexpected error: %v", err)
	} else {
		fmt.Printf("allow path: tool returned %q. total spent: %.2f\n", out, budget.Total())
	}

	// Deny path — call a tool not in the allowlist.
	deny := sauronid.Bind("rm_rf", sendEmail, sauronid.BindOptions{
		AgentID: "agent-example", PolicyID: "pol_example", Cache: cache,
	})
	if _, err := deny(); err != nil {
		var denied *sauronid.PolicyDeniedError
		if errors.As(err, &denied) {
			fmt.Printf("deny path: check=%s reason=%q action=%s\n", denied.Check, denied.Reason, denied.ActionID)
		} else {
			log.Fatalf("unexpected non-deny error: %v", err)
		}
	}
}

func fakeCore() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policy/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"version": "0.1",
			"agent":   "agent-example",
			"binding": map[string]interface{}{
				"allowed_tools":  []string{"send_email"},
				"max_budget_usd": 100,
			},
		})
	})
	return httptest.NewServer(mux)
}
