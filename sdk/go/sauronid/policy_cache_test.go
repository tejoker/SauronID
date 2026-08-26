package sauronid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newPolicyServer(t *testing.T, calls *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policy/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{
			"version": "0.1",
			"agent":   "agent-1",
			"binding": map[string]interface{}{
				"allowed_tools":  []string{"http_get"},
				"max_budget_usd": 100,
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	return httptest.NewServer(mux)
}

func TestPolicyCache_Load(t *testing.T) {
	var calls int32
	srv := newPolicyServer(t, &calls)
	defer srv.Close()
	cache := NewPolicyCache(PolicyCacheOptions{CoreURL: srv.URL, RefreshInterval: -1})
	defer cache.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := cache.Load(ctx, "pol_abc")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if p.PolicyID != "pol_abc" {
		t.Fatalf("policy_id mismatch: %s", p.PolicyID)
	}
	if p.Binding.MaxBudgetUsd == nil || *p.Binding.MaxBudgetUsd != 100 {
		t.Fatalf("max_budget_usd mismatch: %+v", p.Binding.MaxBudgetUsd)
	}
}

func TestPolicyCache_CachedHit(t *testing.T) {
	var calls int32
	srv := newPolicyServer(t, &calls)
	defer srv.Close()
	cache := NewPolicyCache(PolicyCacheOptions{CoreURL: srv.URL, RefreshInterval: -1})
	defer cache.Stop()

	ctx := context.Background()
	if _, err := cache.Load(ctx, "pol_abc"); err != nil {
		t.Fatalf("first Load failed: %v", err)
	}
	if _, err := cache.Load(ctx, "pol_abc"); err != nil {
		t.Fatalf("second Load failed: %v", err)
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", c)
	}
}

func TestPolicyCache_Refresh(t *testing.T) {
	var calls int32
	srv := newPolicyServer(t, &calls)
	defer srv.Close()
	cache := NewPolicyCache(PolicyCacheOptions{CoreURL: srv.URL, RefreshInterval: -1})
	defer cache.Stop()

	ctx := context.Background()
	if _, err := cache.Load(ctx, "pol_abc"); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := cache.Refresh(ctx, "pol_abc"); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if c := atomic.LoadInt32(&calls); c != 2 {
		t.Fatalf("expected 2 HTTP calls, got %d", c)
	}
}
