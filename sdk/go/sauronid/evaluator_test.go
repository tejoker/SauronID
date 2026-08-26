package sauronid

import (
	"testing"
	"time"
)

func mkPolicy(b Binding) *CompiledPolicy {
	return &CompiledPolicy{
		PolicyID: "pol_test",
		Agent:    "agent-test",
		Version:  "0.1",
		Binding:  b,
	}
}

func mkAction(overrides func(a *Action)) *Action {
	a := &Action{
		ActionID:        "act_test",
		Tool:            "http_get",
		Signatures:      []string{},
		DelegationDepth: 0,
		Timestamp:       time.Now().Unix(),
	}
	if overrides != nil {
		overrides(a)
	}
	return a
}

func mkCtx(overrides func(c *EvaluationContext)) *EvaluationContext {
	c := &EvaluationContext{
		SpendTotalUsd:        0,
		RecentCallTimestamps: nil,
		NowEpoch:             time.Now().Unix(),
		NowTzHhmm:            "12:00",
	}
	if overrides != nil {
		overrides(c)
	}
	return c
}

func ptrF(v float64) *float64 { return &v }
func ptrS(v string) *string   { return &v }

// 1. allowlist allow
func TestEvaluate_AllowlistAllow(t *testing.T) {
	p := mkPolicy(Binding{AllowedTools: []string{"http_get", "http_post"}})
	v := Evaluate(p, mkAction(nil), mkCtx(nil))
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// 2. allowlist deny
func TestEvaluate_AllowlistDeny(t *testing.T) {
	p := mkPolicy(Binding{AllowedTools: []string{"http_post"}})
	v := Evaluate(p, mkAction(nil), mkCtx(nil))
	if v.Kind != "deny" || v.Check != "allowlist" {
		t.Fatalf("expected deny/allowlist, got %+v", v)
	}
	want := "tool 'http_get' not in allowlist"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 3. budget allow
func TestEvaluate_BudgetAllow(t *testing.T) {
	p := mkPolicy(Binding{MaxBudgetUsd: ptrF(100)})
	a := mkAction(func(a *Action) { a.AmountUsd = ptrF(50) })
	c := mkCtx(func(c *EvaluationContext) { c.SpendTotalUsd = 25 })
	v := Evaluate(p, a, c)
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// 4. budget deny
func TestEvaluate_BudgetDeny(t *testing.T) {
	p := mkPolicy(Binding{MaxBudgetUsd: ptrF(100)})
	a := mkAction(func(a *Action) { a.AmountUsd = ptrF(80) })
	c := mkCtx(func(c *EvaluationContext) { c.SpendTotalUsd = 25 })
	v := Evaluate(p, a, c)
	if v.Kind != "deny" || v.Check != "budget" {
		t.Fatalf("expected deny/budget, got %+v", v)
	}
	want := "projected spend 105.00 USD exceeds cap 100.00 USD"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 5. scope allow (in allow list)
func TestEvaluate_ScopeAllow(t *testing.T) {
	p := mkPolicy(Binding{
		DataScope: &DataScope{Allow: []string{"public", "internal"}, Deny: []string{}},
	})
	a := mkAction(func(a *Action) { a.DataClassification = ptrS("public") })
	v := Evaluate(p, a, mkCtx(nil))
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// 6. scope deny (deny list)
func TestEvaluate_ScopeDeny(t *testing.T) {
	p := mkPolicy(Binding{
		DataScope: &DataScope{Allow: []string{}, Deny: []string{"pii"}},
	})
	a := mkAction(func(a *Action) { a.DataClassification = ptrS("PII") })
	v := Evaluate(p, a, mkCtx(nil))
	if v.Kind != "deny" || v.Check != "scope" {
		t.Fatalf("expected deny/scope, got %+v", v)
	}
	want := "classification 'pii' is on deny list"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 7. scope deny (not in allow list)
func TestEvaluate_ScopeNotInAllow(t *testing.T) {
	p := mkPolicy(Binding{
		DataScope: &DataScope{Allow: []string{"public"}, Deny: []string{}},
	})
	a := mkAction(func(a *Action) { a.DataClassification = ptrS("internal") })
	v := Evaluate(p, a, mkCtx(nil))
	if v.Kind != "deny" || v.Check != "scope" {
		t.Fatalf("expected deny/scope, got %+v", v)
	}
	want := `classification 'internal' not in allow list ["public"]`
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 8. rate_limit allow
func TestEvaluate_RateLimitAllow(t *testing.T) {
	now := int64(1_700_000_000)
	p := mkPolicy(Binding{RateLimit: &RateLimit{RequestsPerMinute: 5}})
	c := mkCtx(func(c *EvaluationContext) {
		c.NowEpoch = now
		c.RecentCallTimestamps = []int64{now - 10, now - 30, now - 50}
	})
	v := Evaluate(p, mkAction(nil), c)
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// 9. rate_limit deny
func TestEvaluate_RateLimitDeny(t *testing.T) {
	now := int64(1_700_000_000)
	p := mkPolicy(Binding{RateLimit: &RateLimit{RequestsPerMinute: 3}})
	c := mkCtx(func(c *EvaluationContext) {
		c.NowEpoch = now
		c.RecentCallTimestamps = []int64{now - 5, now - 10, now - 15, now - 20}
	})
	v := Evaluate(p, mkAction(nil), c)
	if v.Kind != "deny" || v.Check != "rate_limit" {
		t.Fatalf("expected deny/rate_limit, got %+v", v)
	}
	want := "4 calls in last 60s reached limit 3"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 10. time_window allow
func TestEvaluate_TimeWindowAllow(t *testing.T) {
	p := mkPolicy(Binding{TimeWindow: &TimeWindow{Start: "08:00", End: "18:00", Timezone: "UTC"}})
	c := mkCtx(func(c *EvaluationContext) { c.NowTzHhmm = "10:30" })
	v := Evaluate(p, mkAction(nil), c)
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// 11. time_window deny
func TestEvaluate_TimeWindowDeny(t *testing.T) {
	p := mkPolicy(Binding{TimeWindow: &TimeWindow{Start: "08:00", End: "18:00", Timezone: "Europe/Paris"}})
	c := mkCtx(func(c *EvaluationContext) { c.NowTzHhmm = "22:00" })
	v := Evaluate(p, mkAction(nil), c)
	if v.Kind != "deny" || v.Check != "time_window" {
		t.Fatalf("expected deny/time_window, got %+v", v)
	}
	want := "current time 22:00 (Europe/Paris) outside window [08:00, 18:00]"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 12. signatures allow
func TestEvaluate_SignaturesAllow(t *testing.T) {
	p := mkPolicy(Binding{
		RequiredSignatures: []SignatureRequirement{
			{Role: "human_approver", Threshold: 1},
		},
	})
	a := mkAction(func(a *Action) { a.Signatures = []string{"human_approver"} })
	v := Evaluate(p, a, mkCtx(nil))
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// 13. signatures deny
func TestEvaluate_SignaturesDeny(t *testing.T) {
	p := mkPolicy(Binding{
		RequiredSignatures: []SignatureRequirement{
			{Role: "human_approver", Threshold: 2},
		},
	})
	a := mkAction(func(a *Action) { a.Signatures = []string{"human_approver"} })
	v := Evaluate(p, a, mkCtx(nil))
	if v.Kind != "deny" || v.Check != "signatures" {
		t.Fatalf("expected deny/signatures, got %+v", v)
	}
	want := "role 'human_approver' has 1 of 2 required signatures"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// 14. delegation_depth deny
func TestEvaluate_DelegationDepthDeny(t *testing.T) {
	p := mkPolicy(Binding{Delegation: &DelegationLimits{MaxDepth: 1}})
	a := mkAction(func(a *Action) { a.DelegationDepth = 2 })
	v := Evaluate(p, a, mkCtx(nil))
	if v.Kind != "deny" || v.Check != "delegation_depth" {
		t.Fatalf("expected deny/delegation_depth, got %+v", v)
	}
	want := "delegation_depth = 2 exceeds max 1"
	if v.Reason != want {
		t.Fatalf("reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// extra: time window wrap-around
func TestEvaluate_TimeWindowWrapAround(t *testing.T) {
	// 22:00..06:00 window, hhmm=23:30 → allow
	p := mkPolicy(Binding{TimeWindow: &TimeWindow{Start: "22:00", End: "06:00", Timezone: "UTC"}})
	c := mkCtx(func(c *EvaluationContext) { c.NowTzHhmm = "23:30" })
	v := Evaluate(p, mkAction(nil), c)
	if v.Kind != "allow" {
		t.Fatalf("expected allow, got %+v", v)
	}
}

// extra: ComputeNowTzHhmm returns "HH:MM"
func TestComputeNowTzHhmm(t *testing.T) {
	// 1700000000 unix = 2023-11-14T22:13:20Z; UTC -> "22:13".
	got := ComputeNowTzHhmm(1_700_000_000, "UTC")
	if got != "22:13" {
		t.Fatalf("expected 22:13, got %q", got)
	}
	// Invalid tz falls back to UTC.
	got = ComputeNowTzHhmm(1_700_000_000, "Not/A_Zone")
	if got != "22:13" {
		t.Fatalf("expected UTC fallback 22:13, got %q", got)
	}
}
