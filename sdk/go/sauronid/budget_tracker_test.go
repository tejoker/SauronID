package sauronid

import (
	"context"
	"testing"
	"time"
)

func TestBudgetTracker_RecordAndTotal(t *testing.T) {
	b := NewBudgetTracker(BudgetTrackerOptions{PolicyID: "pol", FlushInterval: -1})
	defer b.Stop()
	b.Record(10.5, "a1")
	b.Record(20.25, "a2")
	if got := b.Total(); got != 30.75 {
		t.Fatalf("total mismatch: got %v want 30.75", got)
	}
	if got := b.PendingCount(); got != 2 {
		t.Fatalf("pending mismatch: got %d", got)
	}
}

func TestBudgetTracker_RecentCalls(t *testing.T) {
	b := NewBudgetTracker(BudgetTrackerOptions{PolicyID: "pol", FlushInterval: -1})
	defer b.Stop()
	// Inject manual timestamps to bypass time.Now.
	b.mu.Lock()
	now := time.Now().UnixMilli()
	b.callTimestampsMs = []int64{
		now - 120_000, // older than 60s window
		now - 30_000,  // inside
		now - 5_000,   // inside
	}
	b.mu.Unlock()
	recent := b.RecentCalls(60 * time.Second)
	if len(recent) != 2 {
		t.Fatalf("expected 2 in-window calls, got %d (%v)", len(recent), recent)
	}
}

func TestBudgetTracker_Flush(t *testing.T) {
	var seen []PendingSpendRecord
	flushFn := func(_ context.Context, state BudgetState) error {
		seen = append(seen, state.Pending...)
		return nil
	}
	b := NewBudgetTracker(BudgetTrackerOptions{
		PolicyID:      "pol",
		FlushInterval: -1, // disable timer
		FlushFn:       flushFn,
	})
	defer b.Stop()
	b.Record(1.5, "a")
	b.Record(2.5, "b")
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("expected 2 pending sent, got %d", len(seen))
	}
	if b.PendingCount() != 0 {
		t.Fatalf("expected pending drained, got %d", b.PendingCount())
	}
}
