package sauronid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// ToolFunc is the generic tool signature Bind operates on. Custom typed
// tools can be adapted to this signature via a thin closure.
type ToolFunc func(args ...interface{}) (interface{}, error)

// ClassifyFn extracts policy-relevant fields from a tool's positional
// arguments. The returned map is merged into the synthesised Action
// before evaluation. Recognised keys mirror the Action struct:
// "amount_usd" (float64), "data_classification" (string),
// "signatures" ([]string), "delegation_depth" (uint32), "tool" (string),
// "timestamp" (int64), "metadata" (map[string]interface{}).
type ClassifyFn func(toolName string, args []interface{}) map[string]interface{}

// OnDenyFn is invoked just before PolicyDeniedError is returned. Use it
// for audit/metric hooks; the function receives the deny Verdict.
type OnDenyFn func(verdict Verdict)

// BindOptions configures Bind.
type BindOptions struct {
	// AgentID this tool belongs to. Echoed in future audit hooks.
	AgentID string
	// PolicyID to evaluate against. Must already be loaded into Cache.
	PolicyID string
	// Cache holding the compiled policy.
	Cache *PolicyCache
	// BudgetTracker is the optional spend / rate ledger. nil = zero spend
	// + empty history per evaluation.
	BudgetTracker *BudgetTracker
	// ClassifyAction extracts Action overrides from the call arguments.
	ClassifyAction ClassifyFn
	// OnDeny fires BEFORE PolicyDeniedError is returned.
	OnDeny OnDenyFn
}

// PolicyDeniedError is returned by a Bind-wrapped tool when a local
// invariant denies the call.
type PolicyDeniedError struct {
	Check    string
	Reason   string
	PolicyID string
	ActionID string
}

func (e *PolicyDeniedError) Error() string {
	return fmt.Sprintf(
		"policy '%s' denied action '%s' (%s): %s",
		e.PolicyID, e.ActionID, e.Check, e.Reason,
	)
}

// PolicyNotLoadedError is returned by a Bind-wrapped tool when the
// policy is missing from the cache. Call PolicyCache.Load first.
type PolicyNotLoadedError struct {
	PolicyID string
}

func (e *PolicyNotLoadedError) Error() string {
	return fmt.Sprintf(
		"policy '%s' not loaded - call cache.Load() before Bind()",
		e.PolicyID,
	)
}

// Bind wraps tool with policy enforcement.
//
// The returned function has the same call signature. On each call it:
//
//  1. fetches the policy from the cache (errors with PolicyNotLoadedError
//     when missing);
//  2. synthesises an Action (random id, current timestamp, tool name) and
//     applies the optional ClassifyAction overrides;
//  3. builds an EvaluationContext from the optional BudgetTracker;
//  4. runs Evaluate; on deny returns PolicyDeniedError WITHOUT invoking
//     tool;
//  5. on allow forwards to tool and, when AmountUsd is non-nil, records
//     the spend.
func Bind(toolName string, tool ToolFunc, opts BindOptions) ToolFunc {
	return func(args ...interface{}) (interface{}, error) {
		policy := opts.Cache.Get(opts.PolicyID)
		if policy == nil {
			return nil, &PolicyNotLoadedError{PolicyID: opts.PolicyID}
		}

		name := toolName
		if name == "" {
			name = "anonymous"
		}
		now := time.Now().Unix()
		action := &Action{
			ActionID:        randomActionID(),
			Tool:            name,
			Signatures:      []string{},
			DelegationDepth: 0,
			Timestamp:       now,
		}
		if opts.ClassifyAction != nil {
			overrides := opts.ClassifyAction(name, args)
			applyOverrides(action, overrides)
		}

		tz := "UTC"
		if policy.Binding.TimeWindow != nil && policy.Binding.TimeWindow.Timezone != "" {
			tz = policy.Binding.TimeWindow.Timezone
		}
		spendTotal := 0.0
		var recent []int64
		if opts.BudgetTracker != nil {
			spendTotal = opts.BudgetTracker.Total()
			recentMs := opts.BudgetTracker.RecentCalls(60 * time.Second)
			recent = make([]int64, len(recentMs))
			for i, ms := range recentMs {
				recent[i] = ms / 1000
			}
		}
		ctx := &EvaluationContext{
			SpendTotalUsd:        spendTotal,
			RecentCallTimestamps: recent,
			NowEpoch:             action.Timestamp,
			NowTzHhmm:            ComputeNowTzHhmm(action.Timestamp, tz),
		}

		verdict := Evaluate(policy, action, ctx)
		if verdict.Kind == "deny" {
			if opts.OnDeny != nil {
				opts.OnDeny(verdict)
			}
			return nil, &PolicyDeniedError{
				Check:    verdict.Check,
				Reason:   verdict.Reason,
				PolicyID: opts.PolicyID,
				ActionID: action.ActionID,
			}
		}

		result, err := tool(args...)
		if err != nil {
			return nil, err
		}
		if opts.BudgetTracker != nil && action.AmountUsd != nil {
			opts.BudgetTracker.Record(*action.AmountUsd, action.ActionID)
		}
		return result, nil
	}
}

// applyOverrides copies recognised Action fields out of `overrides`.
//
// Unknown keys land in action.Metadata so callers can carry custom
// payload without breaking the schema.
func applyOverrides(action *Action, overrides map[string]interface{}) {
	if len(overrides) == 0 {
		return
	}
	for k, v := range overrides {
		switch k {
		case "amount_usd":
			if f, ok := toFloat64(v); ok {
				action.AmountUsd = &f
			}
		case "data_classification":
			if s, ok := v.(string); ok {
				action.DataClassification = &s
			}
		case "signatures":
			if list, ok := v.([]string); ok {
				action.Signatures = list
			} else if anyList, ok := v.([]interface{}); ok {
				out := make([]string, 0, len(anyList))
				for _, x := range anyList {
					if s, ok := x.(string); ok {
						out = append(out, s)
					}
				}
				action.Signatures = out
			}
		case "delegation_depth":
			if u, ok := toUint32(v); ok {
				action.DelegationDepth = u
			}
		case "tool":
			if s, ok := v.(string); ok {
				action.Tool = s
			}
		case "timestamp":
			if i, ok := toInt64(v); ok {
				action.Timestamp = i
			}
		case "metadata":
			if m, ok := v.(map[string]interface{}); ok {
				action.Metadata = m
			}
		default:
			if action.Metadata == nil {
				action.Metadata = map[string]interface{}{}
			}
			action.Metadata[k] = v
		}
	}
}

func toFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	}
	return 0, false
}

func toUint32(v interface{}) (uint32, bool) {
	switch x := v.(type) {
	case uint32:
		return x, true
	case int:
		if x < 0 {
			return 0, false
		}
		return uint32(x), true
	case int64:
		if x < 0 {
			return 0, false
		}
		return uint32(x), true
	case float64:
		if x < 0 {
			return 0, false
		}
		return uint32(x), true
	}
	return 0, false
}

func toInt64(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case float64:
		return int64(x), true
	}
	return 0, false
}

func randomActionID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
