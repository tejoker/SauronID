package sauronid

import (
	"errors"
	"testing"
)

// Inject a policy directly so tests don't need HTTP.
func injectPolicy(cache *PolicyCache, p *CompiledPolicy) {
	cache.mu.Lock()
	cache.entries[p.PolicyID] = p
	cache.mu.Unlock()
}

func TestBind_Allow(t *testing.T) {
	cache := NewPolicyCache(PolicyCacheOptions{RefreshInterval: -1})
	defer cache.Stop()
	injectPolicy(cache, mkPolicy(Binding{AllowedTools: []string{"do_thing"}}))

	called := false
	tool := ToolFunc(func(args ...interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	})
	wrapped := Bind("do_thing", tool, BindOptions{
		AgentID: "agent-1", PolicyID: "pol_test", Cache: cache,
	})
	out, err := wrapped("x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Fatalf("expected 'ok', got %v", out)
	}
	if !called {
		t.Fatalf("tool was not called")
	}
}

func TestBind_Deny(t *testing.T) {
	cache := NewPolicyCache(PolicyCacheOptions{RefreshInterval: -1})
	defer cache.Stop()
	injectPolicy(cache, mkPolicy(Binding{AllowedTools: []string{"other"}}))

	called := false
	tool := ToolFunc(func(args ...interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	})
	wrapped := Bind("do_thing", tool, BindOptions{
		AgentID: "agent-1", PolicyID: "pol_test", Cache: cache,
	})
	_, err := wrapped()
	if err == nil {
		t.Fatalf("expected PolicyDeniedError, got nil")
	}
	var denied *PolicyDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *PolicyDeniedError, got %T: %v", err, err)
	}
	if denied.Check != "allowlist" {
		t.Fatalf("expected check=allowlist, got %s", denied.Check)
	}
	if called {
		t.Fatalf("tool MUST NOT be called on deny")
	}
}

func TestBind_ClassifierOverride(t *testing.T) {
	cache := NewPolicyCache(PolicyCacheOptions{RefreshInterval: -1})
	defer cache.Stop()
	injectPolicy(cache, mkPolicy(Binding{MaxBudgetUsd: ptrF(50)}))

	classify := func(toolName string, args []interface{}) map[string]interface{} {
		return map[string]interface{}{"amount_usd": 75.0}
	}
	tool := ToolFunc(func(args ...interface{}) (interface{}, error) { return nil, nil })
	wrapped := Bind("spend", tool, BindOptions{
		AgentID: "agent-1", PolicyID: "pol_test", Cache: cache,
		ClassifyAction: classify,
	})
	_, err := wrapped()
	var denied *PolicyDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *PolicyDeniedError, got %T: %v", err, err)
	}
	if denied.Check != "budget" {
		t.Fatalf("expected check=budget, got %s", denied.Check)
	}
}

func TestBind_OnDenyCallback(t *testing.T) {
	cache := NewPolicyCache(PolicyCacheOptions{RefreshInterval: -1})
	defer cache.Stop()
	injectPolicy(cache, mkPolicy(Binding{AllowedTools: []string{"other"}}))

	var captured Verdict
	wrapped := Bind("do_thing", ToolFunc(func(_ ...interface{}) (interface{}, error) { return nil, nil }), BindOptions{
		AgentID: "agent-1", PolicyID: "pol_test", Cache: cache,
		OnDeny: func(v Verdict) { captured = v },
	})
	_, _ = wrapped()
	if captured.Kind != "deny" || captured.Check != "allowlist" {
		t.Fatalf("OnDeny did not receive the deny verdict: %+v", captured)
	}
}

func TestBind_PolicyNotLoaded(t *testing.T) {
	cache := NewPolicyCache(PolicyCacheOptions{RefreshInterval: -1})
	defer cache.Stop()
	// Don't inject any policy.
	wrapped := Bind("do_thing", ToolFunc(func(_ ...interface{}) (interface{}, error) { return nil, nil }), BindOptions{
		AgentID: "agent-1", PolicyID: "pol_missing", Cache: cache,
	})
	_, err := wrapped()
	var notLoaded *PolicyNotLoadedError
	if !errors.As(err, &notLoaded) {
		t.Fatalf("expected *PolicyNotLoadedError, got %T: %v", err, err)
	}
	if notLoaded.PolicyID != "pol_missing" {
		t.Fatalf("expected pol_missing, got %s", notLoaded.PolicyID)
	}
}
