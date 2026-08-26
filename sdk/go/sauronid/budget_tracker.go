package sauronid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// PendingSpendRecord is one queued spend waiting for the next Flush.
type PendingSpendRecord struct {
	AmountUsd float64 `json:"amount_usd"`
	ActionID  string  `json:"action_id,omitempty"`
	// Timestamp is the unix-epoch milliseconds when Record was called.
	Timestamp int64 `json:"timestamp"`
}

// BudgetState is the snapshot handed to a flush function.
type BudgetState struct {
	PolicyID         string
	TotalUsd         float64
	CallTimestampsMs []int64
	Pending          []PendingSpendRecord
}

// FlushFn is invoked from the background timer with the current state.
// Returning a non-nil error preserves the pending list so the next tick
// retries.
type FlushFn func(ctx context.Context, state BudgetState) error

// BudgetTrackerOptions configures a BudgetTracker.
type BudgetTrackerOptions struct {
	// PolicyID this tracker covers.
	PolicyID string
	// FlushInterval is the auto-flush period. Zero disables the timer.
	// Default 30s.
	FlushInterval time.Duration
	// FlushFn is the hook drained by the timer. Nil = silently drop pending.
	FlushFn FlushFn
}

// BudgetTracker is a thread-safe in-memory spend + rate ledger.
//
// Sprint 3 wires an optional server-side flush so the in-memory total is
// no longer the source of truth (closes redteam A3: local counter
// tampering). See ServerPush for the canonical flush builder.
type BudgetTracker struct {
	policyID      string
	flushInterval time.Duration
	flushFn       FlushFn

	mu               sync.Mutex
	totalUsd         float64
	callTimestampsMs []int64
	pending          []PendingSpendRecord
	stopCh           chan struct{}
	stopped          bool
	wg               sync.WaitGroup
}

// NewBudgetTracker constructs a tracker. If FlushInterval > 0 a
// background goroutine is started immediately.
func NewBudgetTracker(opts BudgetTrackerOptions) *BudgetTracker {
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 30 * time.Second
	}
	b := &BudgetTracker{
		policyID:      opts.PolicyID,
		flushInterval: opts.FlushInterval,
		flushFn:       opts.FlushFn,
		stopCh:        make(chan struct{}),
	}
	if opts.FlushInterval > 0 {
		b.wg.Add(1)
		go b.loop()
	}
	return b
}

// Record adds one tool invocation to the ledger. amountUsd is added to
// the running total (use 0 for no-spend calls) and a unix-millisecond
// timestamp is appended for the rate-window.
func (b *BudgetTracker) Record(amountUsd float64, actionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.totalUsd += amountUsd
	now := time.Now().UnixMilli()
	b.callTimestampsMs = append(b.callTimestampsMs, now)
	// Cap history at last 1024 entries — matches TS bound.
	if len(b.callTimestampsMs) > 1024 {
		b.callTimestampsMs = b.callTimestampsMs[len(b.callTimestampsMs)-1024:]
	}
	b.pending = append(b.pending, PendingSpendRecord{
		AmountUsd: amountUsd,
		ActionID:  actionID,
		Timestamp: now,
	})
}

// Total returns the current spend total in USD.
func (b *BudgetTracker) Total() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.totalUsd
}

// PendingCount returns the number of records waiting for the next flush.
func (b *BudgetTracker) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// RecentCalls returns the call timestamps (unix-epoch milliseconds)
// inside the last `window` duration. Older entries are pruned as a
// side effect.
func (b *BudgetTracker) RecentCalls(window time.Duration) []int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := time.Now().Add(-window).UnixMilli()
	firstFresh := 0
	for i, t := range b.callTimestampsMs {
		if t > cutoff {
			firstFresh = i
			break
		}
		firstFresh = i + 1
	}
	if firstFresh > 0 {
		b.callTimestampsMs = b.callTimestampsMs[firstFresh:]
	}
	out := make([]int64, len(b.callTimestampsMs))
	copy(out, b.callTimestampsMs)
	return out
}

// Flush sends the current pending list through the configured FlushFn.
// On error the pending list is preserved so the next tick retries.
//
// If no FlushFn was configured, pending records are silently dropped to
// mirror the TS no-op default.
func (b *BudgetTracker) Flush(ctx context.Context) error {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return nil
	}
	snapshot := make([]PendingSpendRecord, len(b.pending))
	copy(snapshot, b.pending)
	state := BudgetState{
		PolicyID:         b.policyID,
		TotalUsd:         b.totalUsd,
		CallTimestampsMs: append([]int64(nil), b.callTimestampsMs...),
		Pending:          snapshot,
	}
	flushFn := b.flushFn
	b.mu.Unlock()

	if flushFn == nil {
		b.mu.Lock()
		// Drop only what we snapshotted; new records may have landed.
		n := minInt(len(snapshot), len(b.pending))
		b.pending = b.pending[n:]
		b.mu.Unlock()
		return nil
	}
	if err := flushFn(ctx, state); err != nil {
		log.Printf("[BudgetTracker] flush failed for %s: %v", b.policyID, err)
		return err
	}
	b.mu.Lock()
	n := minInt(len(snapshot), len(b.pending))
	b.pending = b.pending[n:]
	b.mu.Unlock()
	return nil
}

// Stop halts the background timer and runs one final flush. Idempotent.
func (b *BudgetTracker) Stop() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	close(b.stopCh)
	b.mu.Unlock()
	b.wg.Wait()
	// Final flush so nothing is lost on shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = b.Flush(ctx)
}

func (b *BudgetTracker) loop() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.mu.Lock()
			has := len(b.pending) > 0
			b.mu.Unlock()
			if !has {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = b.Flush(ctx)
			cancel()
		case <-b.stopCh:
			return
		}
	}
}

// ServerPushOptions configures the canonical FlushFn that POSTs each
// pending record to POST /v1/agents/:agent_id/spend.
type ServerPushOptions struct {
	CoreURL    string
	AdminKey   string
	AgentID    string
	PolicyID   string
	TenantID   string
	HTTPClient *http.Client
}

// ServerPush builds a FlushFn that POSTs each pending record to the
// server-side spend ledger. See BudgetTrackerOptions.FlushFn.
func ServerPush(opts ServerPushOptions) FlushFn {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	coreURL := trimTrailingSlash(opts.CoreURL)
	target := fmt.Sprintf("%s/v1/agents/%s/spend", coreURL, url.PathEscape(opts.AgentID))
	return func(ctx context.Context, state BudgetState) error {
		for _, rec := range state.Pending {
			body := map[string]interface{}{
				"policy_id":  opts.PolicyID,
				"amount_usd": rec.AmountUsd,
			}
			if rec.ActionID != "" {
				body["action_id"] = rec.ActionID
			}
			buf, err := json.Marshal(body)
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			if opts.AdminKey != "" {
				req.Header.Set("Authorization", "Bearer "+opts.AdminKey)
			}
			if opts.TenantID != "" {
				req.Header.Set("X-Sauron-Tenant-Id", opts.TenantID)
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			body2, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("POST %s -> %d: %s", target, resp.StatusCode, string(body2))
			}
		}
		return nil
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
