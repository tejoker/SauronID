package sauronid

// Cross-implementation parity tests. Hard-coded TS/Python verdict
// strings; Go MUST produce identical reasons given identical inputs.

import (
	"testing"
)

// TS fixture: budget invariant deny reason format
//
//   `projected spend ${projected.toFixed(2)} USD exceeds cap ${cap.toFixed(2)} USD`
func TestCrossImpl_BudgetReason(t *testing.T) {
	p := mkPolicy(Binding{MaxBudgetUsd: ptrF(50.5)})
	a := mkAction(func(a *Action) { a.AmountUsd = ptrF(1.25) })
	c := mkCtx(func(c *EvaluationContext) { c.SpendTotalUsd = 49.5 })
	v := Evaluate(p, a, c)
	want := "projected spend 50.75 USD exceeds cap 50.50 USD"
	if v.Kind != "deny" || v.Reason != want {
		t.Fatalf("budget reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// Python fixture: scope allow-list JSON representation
//
//   '[' + ','.join(f'"{x}"' for x in allow_list) + ']'
//
// → ["finance","public"]
func TestCrossImpl_ScopeAllowListLiteral(t *testing.T) {
	p := mkPolicy(Binding{
		DataScope: &DataScope{Allow: []string{"finance", "public"}, Deny: []string{}},
	})
	a := mkAction(func(a *Action) { a.DataClassification = ptrS("Internal") })
	v := Evaluate(p, a, mkCtx(nil))
	want := `classification 'internal' not in allow list ["finance","public"]`
	if v.Reason != want {
		t.Fatalf("scope literal mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}

// TS fixture: rate_limit deny reason
//
//   `${count} calls in last 60s reached limit ${limit}`
func TestCrossImpl_RateLimitReason(t *testing.T) {
	now := int64(2_000_000_000)
	p := mkPolicy(Binding{RateLimit: &RateLimit{RequestsPerMinute: 2}})
	c := mkCtx(func(c *EvaluationContext) {
		c.NowEpoch = now
		c.RecentCallTimestamps = []int64{now - 10, now - 20, now - 30}
	})
	v := Evaluate(p, mkAction(nil), c)
	want := "3 calls in last 60s reached limit 2"
	if v.Reason != want {
		t.Fatalf("rate_limit reason mismatch:\n got %q\nwant %q", v.Reason, want)
	}
}
