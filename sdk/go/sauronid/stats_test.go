package sauronid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitTransparentStats_Happy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stats/submit-transparent", func(w http.ResponseWriter, r *http.Request) {
		var got TransparentStatsSubmission
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.ProgramID != StatsProgramID || got.TenantID != "tenant-1" {
			t.Fatalf("wrong transparent binding: %+v", got)
		}
		if r.Header.Get("X-Admin-Key") != "admin-secret" {
			t.Fatal("admin key header missing")
		}
		_ = json.NewEncoder(w).Encode(SubmitResponse{Stored: true, StatementHash: "proof-statement"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(ClientOptions{BaseURL: srv.URL, AdminKey: "admin-secret"})
	resp, err := c.SubmitTransparentStats(context.Background(), TransparentStatsSubmission{
		TenantID:     "tenant-1",
		MetricID:     "success_rate",
		ClaimedValue: 1000,
		PeriodStart:  10,
		PeriodEnd:    20,
		CheckpointID: "zkc_1",
		ReceiptB64:   "e30=",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Stored || resp.StatementHash != "proof-statement" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
