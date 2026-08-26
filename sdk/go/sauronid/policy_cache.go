package sauronid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// PolicyCacheOptions configures a PolicyCache.
type PolicyCacheOptions struct {
	// CoreURL is the base URL of the core server (no trailing slash).
	CoreURL string
	// AdminKey is the admin bearer token. Empty disables the header.
	AdminKey string
	// RefreshInterval is the background refresh period. Zero disables refresh.
	// Default 60s.
	RefreshInterval time.Duration
	// HTTPClient overrides the default http.Client (tests / custom transport).
	HTTPClient *http.Client
	// TenantID, when non-empty, attaches an X-Sauron-Tenant-Id header to every
	// outbound request. Single-tenant deployments leave this empty.
	TenantID string
}

// PolicyCache fetches compiled policies from the core server and keeps
// them hot in memory for sub-millisecond local evaluation.
//
// The cache is safe for concurrent use. Background refresh is armed on
// the first successful Load(); subsequent reads via Get() are read-only
// against the in-memory map.
type PolicyCache struct {
	coreURL         string
	adminKey        string
	refreshInterval time.Duration
	client          *http.Client
	tenantID        string

	mu      sync.RWMutex
	entries map[string]*CompiledPolicy
	timers  map[string]*time.Ticker
	stopChs map[string]chan struct{}
	stopped bool
}

// NewPolicyCache constructs a cache. Pass an empty struct for defaults.
func NewPolicyCache(opts PolicyCacheOptions) *PolicyCache {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.RefreshInterval == 0 {
		opts.RefreshInterval = 60 * time.Second
	}
	return &PolicyCache{
		coreURL:         trimTrailingSlash(opts.CoreURL),
		adminKey:        opts.AdminKey,
		refreshInterval: opts.RefreshInterval,
		client:          opts.HTTPClient,
		tenantID:        opts.TenantID,
		entries:         map[string]*CompiledPolicy{},
		timers:          map[string]*time.Ticker{},
		stopChs:         map[string]chan struct{}{},
	}
}

// Load fetches the policy with the given id, caches it, and arms a
// background refresh timer. Subsequent calls for the same id return the
// cached entry without a network roundtrip.
func (c *PolicyCache) Load(ctx context.Context, policyID string) (*CompiledPolicy, error) {
	c.mu.RLock()
	existing, ok := c.entries[policyID]
	c.mu.RUnlock()
	if ok {
		return existing, nil
	}
	fresh, err := c.fetchOne(ctx, policyID)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries[policyID] = fresh
	c.mu.Unlock()
	c.armRefresh(policyID)
	return fresh, nil
}

// Get returns the cached policy or nil on miss. It performs no I/O.
func (c *PolicyCache) Get(policyID string) *CompiledPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[policyID]
}

// Refresh forces a fresh fetch. On failure the cached entry is preserved
// and a warning is logged via the standard logger.
func (c *PolicyCache) Refresh(ctx context.Context, policyID string) error {
	fresh, err := c.fetchOne(ctx, policyID)
	if err != nil {
		log.Printf("[PolicyCache] refresh %s failed: %v", policyID, err)
		return err
	}
	c.mu.Lock()
	c.entries[policyID] = fresh
	c.mu.Unlock()
	return nil
}

// Stop cancels every background refresh timer. Idempotent. Call before
// process exit.
func (c *PolicyCache) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	stopChs := c.stopChs
	timers := c.timers
	c.stopChs = map[string]chan struct{}{}
	c.timers = map[string]*time.Ticker{}
	c.mu.Unlock()
	for _, ch := range stopChs {
		close(ch)
	}
	for _, t := range timers {
		t.Stop()
	}
}

func (c *PolicyCache) fetchOne(ctx context.Context, policyID string) (*CompiledPolicy, error) {
	u := fmt.Sprintf("%s/v1/policy/%s", c.coreURL, url.PathEscape(policyID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminKey)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Sauron-Tenant-Id", c.tenantID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET %s -> %d: %s", u, resp.StatusCode, string(body))
	}
	var ast struct {
		Version     string  `json:"version"`
		Agent       string  `json:"agent"`
		Description string  `json:"description"`
		Binding     Binding `json:"binding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ast); err != nil {
		return nil, fmt.Errorf("decode policy %s: %w", policyID, err)
	}
	checks := deriveChecks(&ast.Binding)
	return &CompiledPolicy{
		PolicyID: policyID,
		Agent:    ast.Agent,
		Version:  ast.Version,
		Binding:  ast.Binding,
		Checks:   checks,
	}, nil
}

func (c *PolicyCache) armRefresh(policyID string) {
	if c.refreshInterval <= 0 {
		return
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	if old, ok := c.timers[policyID]; ok {
		old.Stop()
	}
	if oldCh, ok := c.stopChs[policyID]; ok {
		close(oldCh)
	}
	ticker := time.NewTicker(c.refreshInterval)
	stopCh := make(chan struct{})
	c.timers[policyID] = ticker
	c.stopChs[policyID] = stopCh
	c.mu.Unlock()
	go func() {
		for {
			select {
			case <-ticker.C:
				// Use a fresh context so cancelled parents do not kill refresh.
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_ = c.Refresh(ctx, policyID)
				cancel()
			case <-stopCh:
				return
			}
		}
	}()
}

// deriveChecks mirrors the TS / Python derivation so the diagnostic
// `Checks` slice is identical across SDKs.
func deriveChecks(b *Binding) []string {
	var checks []string
	if b.AllowedTools != nil {
		checks = append(checks, "allowlist")
	}
	if b.MaxBudgetUsd != nil {
		checks = append(checks, "budget")
	}
	if b.DataScope != nil {
		checks = append(checks, "scope")
	}
	if b.RateLimit != nil {
		checks = append(checks, "rate_limit")
	}
	if b.TimeWindow != nil {
		checks = append(checks, "time_window")
	}
	if len(b.RequiredSignatures) > 0 {
		checks = append(checks, "signatures")
	}
	if b.Delegation != nil {
		checks = append(checks, "delegation_depth")
	}
	return checks
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// ErrPolicyNotFound is returned by Load when the server returns 404.
var ErrPolicyNotFound = errors.New("policy not found")
