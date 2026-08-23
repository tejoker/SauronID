// Package sauronid is the Go SDK for the SauronID core server.
//
// The package mirrors the TypeScript SDK in sdk/typescript/ and the Python SDK in
// sdk/python/sauronid_client/. Verdict semantics are byte-equivalent
// across all three implementations so cross-impl tests pass.
//
// Two enforcement primitives ship in this package:
//
//   - Bind: wrap an arbitrary tool function with policy enforcement that
//     evaluates a CompiledPolicy locally before each invocation.
//   - CreateEnforcer: one-shot helper that wires a PolicyCache plus a
//     BudgetTracker plus Bind for the 80% use case.
//
// The runtime contract for which Action is allowed against which
// CompiledPolicy is the same across the Rust server, the TypeScript
// client, and this Go client. The 7 invariants evaluated in order are:
// allowlist, budget, scope, rate_limit, time_window, signatures,
// delegation_depth.
package sauronid

// Verdict is the allow/deny outcome of a local invariant evaluation.
//
// Kind is either "allow" or "deny". When Kind == "deny", Check holds the
// invariant name (e.g. "budget") and Reason holds a human-readable
// explanation that is safe to log or surface to operators. The strings
// match the TypeScript and Python evaluators byte-for-byte.
type Verdict struct {
	Kind   string `json:"kind"`
	Check  string `json:"check,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Action is one tool invocation evaluated against a CompiledPolicy.
//
// It mirrors the server Action struct. Pointer fields (AmountUsd,
// DataClassification) are nil when absent, matching the optional
// semantics of the TS undefined / Python None.
type Action struct {
	// ActionID is the caller-supplied unique id (also used in receipts).
	ActionID string `json:"action_id"`
	// Tool is the tool/method invoked (e.g. "http_get").
	Tool string `json:"tool"`
	// AmountUsd is the USD amount if the action moves money. nil = 0.
	AmountUsd *float64 `json:"amount_usd,omitempty"`
	// DataClassification is the data classification tag of the touched resource.
	DataClassification *string `json:"data_classification,omitempty"`
	// Signatures is the list of role names that have signed this action.
	Signatures []string `json:"signatures"`
	// DelegationDepth is the number of delegation hops from the root agent.
	DelegationDepth uint32 `json:"delegation_depth"`
	// Timestamp is the unix-epoch seconds when the action was created.
	Timestamp int64 `json:"timestamp"`
	// Metadata is opaque caller-supplied metadata (forwarded by Bind classifiers).
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// EvaluationContext is the read-only surrounding context for one evaluation.
type EvaluationContext struct {
	// SpendTotalUsd is the cumulative USD spend observed so far.
	SpendTotalUsd float64
	// RecentCallTimestamps holds unix-epoch seconds of recent calls
	// (rate-limit input).
	RecentCallTimestamps []int64
	// NowEpoch is the current unix-epoch seconds.
	NowEpoch int64
	// NowTzHhmm is "HH:MM" 24-hour in the policy's timezone.
	NowTzHhmm string
}

// DataScope is the classification-tag based data scope.
type DataScope struct {
	// Allow is the tag list the agent may operate on. Empty = no allow constraint.
	Allow []string `json:"allow"`
	// Deny is the tag list the agent must never touch. Takes precedence over Allow.
	Deny []string `json:"deny"`
}

// RateLimit is the per-minute request cap.
type RateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute"`
}

// TimeWindow is the wall-clock window the agent may act within.
type TimeWindow struct {
	// Start is the window start, "HH:MM" 24-hour.
	Start string `json:"start"`
	// End is the window end, "HH:MM" 24-hour.
	End string `json:"end"`
	// Timezone is the IANA timezone (e.g. "Europe/Paris").
	Timezone string `json:"timezone"`
}

// SignatureRequirement is one M-of-N clause in the signatures invariant.
type SignatureRequirement struct {
	Role      string `json:"role"`
	Threshold int    `json:"threshold"`
}

// DelegationLimits caps sub-agent delegation depth.
type DelegationLimits struct {
	MaxDepth         uint32   `json:"max_depth"`
	AllowedSubagents []string `json:"allowed_subagents,omitempty"`
}

// Binding is the structured binding section returned by GET /v1/policy/:id.
//
// Every field is optional; nil = no constraint for that invariant.
type Binding struct {
	AllowedTools       []string               `json:"allowed_tools,omitempty"`
	MaxBudgetUsd       *float64               `json:"max_budget_usd,omitempty"`
	DataScope          *DataScope             `json:"data_scope,omitempty"`
	RateLimit          *RateLimit             `json:"rate_limit,omitempty"`
	TimeWindow         *TimeWindow            `json:"time_window,omitempty"`
	RequiredSignatures []SignatureRequirement `json:"required_signatures,omitempty"`
	Delegation         *DelegationLimits      `json:"delegation,omitempty"`
}

// CompiledPolicy is the policy AST as observed by the SDK.
type CompiledPolicy struct {
	// PolicyID is the server-assigned id (pol_<32-hex>).
	PolicyID string `json:"policy_id"`
	// Agent is the agent identifier the policy is bound to.
	Agent string `json:"agent"`
	// Version is the DSL version string.
	Version string `json:"version"`
	// Binding holds the structured invariant configuration.
	Binding Binding `json:"binding"`
	// Checks names the invariants the policy compiled into (diagnostic).
	Checks []string `json:"checks"`
}
