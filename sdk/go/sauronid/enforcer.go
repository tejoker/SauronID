package sauronid

import (
	"context"
	"net/http"
	"time"
)

// CreateEnforcerOptions configures CreateEnforcer.
type CreateEnforcerOptions struct {
	CoreURL          string
	AdminKey         string
	PolicyID         string
	AgentID          string
	TenantID         string
	RefreshInterval  time.Duration
	BudgetFlushEvery time.Duration
	// ServerSideSpend default true. When true, the budget tracker is
	// wired to POST /v1/agents/:agent_id/spend via ServerPush. When
	// false, the in-memory counter is the only ledger (offline / test).
	ServerSideSpend *bool
	HTTPClient      *http.Client
}

// Enforcer bundles the cache + budget tracker + helpers for one policy.
type Enforcer struct {
	Cache   *PolicyCache
	Budget  *BudgetTracker
	opts    CreateEnforcerOptions
	loaded  bool
}

// CreateEnforcer loads the policy synchronously, instantiates the cache
// and budget tracker, and returns an Enforcer pre-wired to the supplied
// agent/policy.
//
// The function blocks on the policy fetch; callers wanting a non-blocking
// startup should construct PolicyCache + BudgetTracker manually.
func CreateEnforcer(ctx context.Context, opts CreateEnforcerOptions) (*Enforcer, error) {
	if opts.RefreshInterval == 0 {
		opts.RefreshInterval = 60 * time.Second
	}
	if opts.BudgetFlushEvery == 0 {
		opts.BudgetFlushEvery = 30 * time.Second
	}
	serverSideSpend := true
	if opts.ServerSideSpend != nil {
		serverSideSpend = *opts.ServerSideSpend
	}
	cache := NewPolicyCache(PolicyCacheOptions{
		CoreURL:         opts.CoreURL,
		AdminKey:        opts.AdminKey,
		RefreshInterval: opts.RefreshInterval,
		HTTPClient:      opts.HTTPClient,
		TenantID:        opts.TenantID,
	})
	if _, err := cache.Load(ctx, opts.PolicyID); err != nil {
		cache.Stop()
		return nil, err
	}
	var flushFn FlushFn
	if serverSideSpend {
		flushFn = ServerPush(ServerPushOptions{
			CoreURL:    opts.CoreURL,
			AdminKey:   opts.AdminKey,
			AgentID:    opts.AgentID,
			PolicyID:   opts.PolicyID,
			TenantID:   opts.TenantID,
			HTTPClient: opts.HTTPClient,
		})
	}
	budget := NewBudgetTracker(BudgetTrackerOptions{
		PolicyID:      opts.PolicyID,
		FlushInterval: opts.BudgetFlushEvery,
		FlushFn:       flushFn,
	})
	return &Enforcer{
		Cache:  cache,
		Budget: budget,
		opts:   opts,
		loaded: true,
	}, nil
}

// Bind returns a Bind-wrapped version of tool, pre-configured for the
// enforcer's policy and agent.
func (e *Enforcer) Bind(toolName string, tool ToolFunc, extra ...BindOptions) ToolFunc {
	base := BindOptions{
		AgentID:       e.opts.AgentID,
		PolicyID:      e.opts.PolicyID,
		Cache:         e.Cache,
		BudgetTracker: e.Budget,
	}
	if len(extra) > 0 {
		// Allow callers to override ClassifyAction / OnDeny only.
		x := extra[0]
		if x.ClassifyAction != nil {
			base.ClassifyAction = x.ClassifyAction
		}
		if x.OnDeny != nil {
			base.OnDeny = x.OnDeny
		}
	}
	return Bind(toolName, tool, base)
}

// Stop halts background timers and runs one final budget flush.
func (e *Enforcer) Stop() {
	if e.Cache != nil {
		e.Cache.Stop()
	}
	if e.Budget != nil {
		e.Budget.Stop()
	}
}
