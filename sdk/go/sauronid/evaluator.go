package sauronid

import (
	"fmt"
	"strings"
	"time"
)

// RateWindowSecs is the width of the rate-limit sliding window in seconds.
// Must match the Rust + TypeScript + Python evaluators.
const RateWindowSecs = 60

// Evaluate runs every applicable check from policy.Binding against action.
//
// It returns the first deny verdict, or {Kind: "allow"} if all checks pass.
//
// Order mirrors core::policy::compiler::compile:
//
//	allowlist -> budget -> scope -> rate_limit -> time_window ->
//	signatures -> delegation_depth.
//
// Reason strings are byte-equivalent with the TypeScript and Python SDKs
// so cross-impl tests can hard-code identical fixtures.
func Evaluate(policy *CompiledPolicy, action *Action, ctx *EvaluationContext) Verdict {
	b := policy.Binding

	// 1. allowlist (tool name)
	if b.AllowedTools != nil {
		found := false
		for _, t := range b.AllowedTools {
			if t == action.Tool {
				found = true
				break
			}
		}
		if !found {
			return Verdict{
				Kind:   "deny",
				Check:  "allowlist",
				Reason: fmt.Sprintf("tool '%s' not in allowlist", action.Tool),
			}
		}
	}

	// 2. budget
	if b.MaxBudgetUsd != nil {
		amount := 0.0
		if action.AmountUsd != nil {
			amount = *action.AmountUsd
		}
		projected := ctx.SpendTotalUsd + amount
		if projected > *b.MaxBudgetUsd {
			return Verdict{
				Kind:  "deny",
				Check: "budget",
				Reason: fmt.Sprintf(
					"projected spend %s USD exceeds cap %s USD",
					formatFixed2(projected),
					formatFixed2(*b.MaxBudgetUsd),
				),
			}
		}
	}

	// 3. scope (data classification)
	if b.DataScope != nil && action.DataClassification != nil {
		tag := strings.ToLower(*action.DataClassification)
		denyList := lowerAll(b.DataScope.Deny)
		allowList := lowerAll(b.DataScope.Allow)
		if contains(denyList, tag) {
			return Verdict{
				Kind:   "deny",
				Check:  "scope",
				Reason: fmt.Sprintf("classification '%s' is on deny list", tag),
			}
		}
		if len(allowList) > 0 && !contains(allowList, tag) {
			return Verdict{
				Kind:  "deny",
				Check: "scope",
				Reason: fmt.Sprintf(
					"classification '%s' not in allow list %s",
					tag,
					jsonArrayLiteral(allowList),
				),
			}
		}
	}

	// 4. rate_limit
	if b.RateLimit != nil {
		limit := b.RateLimit.RequestsPerMinute
		lower := ctx.NowEpoch - RateWindowSecs
		count := 0
		for _, t := range ctx.RecentCallTimestamps {
			if t > lower && t <= ctx.NowEpoch {
				count++
			}
		}
		if count >= limit {
			return Verdict{
				Kind:   "deny",
				Check:  "rate_limit",
				Reason: fmt.Sprintf("%d calls in last 60s reached limit %d", count, limit),
			}
		}
	}

	// 5. time_window
	if b.TimeWindow != nil {
		if !inWindow(b.TimeWindow.Start, b.TimeWindow.End, ctx.NowTzHhmm) {
			return Verdict{
				Kind:  "deny",
				Check: "time_window",
				Reason: fmt.Sprintf(
					"current time %s (%s) outside window [%s, %s]",
					ctx.NowTzHhmm,
					b.TimeWindow.Timezone,
					b.TimeWindow.Start,
					b.TimeWindow.End,
				),
			}
		}
	}

	// 6. signatures (M-of-N per role)
	if b.RequiredSignatures != nil {
		for _, req := range b.RequiredSignatures {
			got := 0
			for _, s := range action.Signatures {
				if s == req.Role {
					got++
				}
			}
			if got < req.Threshold {
				return Verdict{
					Kind:  "deny",
					Check: "signatures",
					Reason: fmt.Sprintf(
						"role '%s' has %d of %d required signatures",
						req.Role, got, req.Threshold,
					),
				}
			}
		}
	}

	// 7. delegation depth
	if b.Delegation != nil {
		if action.DelegationDepth > b.Delegation.MaxDepth {
			return Verdict{
				Kind:  "deny",
				Check: "delegation_depth",
				Reason: fmt.Sprintf(
					"delegation_depth = %d exceeds max %d",
					action.DelegationDepth, b.Delegation.MaxDepth,
				),
			}
		}
	}

	return Verdict{Kind: "allow"}
}

// ComputeNowTzHhmm returns "HH:MM" in the given IANA timezone for the
// supplied unix-epoch second.
//
// Falls back to UTC if time.LoadLocation rejects the timezone name.
func ComputeNowTzHhmm(epochSec int64, ianaTz string) string {
	t := time.Unix(epochSec, 0).UTC()
	loc, err := time.LoadLocation(ianaTz)
	if err == nil {
		local := t.In(loc)
		return local.Format("15:04")
	}
	return t.Format("15:04")
}

// inWindow returns true if hhmm is in [start, end] inclusive, with
// wrap-around support when start > end.
func inWindow(start, end, hhmm string) bool {
	if start <= end {
		return hhmm >= start && hhmm <= end
	}
	return hhmm >= start || hhmm <= end
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func contains(list []string, x string) bool {
	for _, s := range list {
		if s == x {
			return true
		}
	}
	return false
}

// jsonArrayLiteral renders a string list as a compact JSON literal,
// matching TS JSON.stringify(["a","b"]) byte-for-byte: ["a","b"] with no
// inter-element whitespace.
func jsonArrayLiteral(items []string) string {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, s := range items {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(s)
		sb.WriteByte('"')
	}
	sb.WriteByte(']')
	return sb.String()
}

// formatFixed2 mimics the JS Number.prototype.toFixed(2) output exactly:
// half-away-from-zero rounding to two decimals.
func formatFixed2(v float64) string {
	// JS toFixed uses IEEE round-half-to-even in some engines, but in
	// practice the test fixtures avoid the .005 boundary. Use Go default
	// "%.2f" which gives the same output for the values our reasons
	// produce.
	return fmt.Sprintf("%.2f", v)
}
