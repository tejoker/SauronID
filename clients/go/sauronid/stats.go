package sauronid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Period delimits the time range a MetricValue covers.
type Period struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// MetricValue is one row of the locally aggregated stats output. Mirrors
// the TS MetricValue type for direct cross-impl interchange.
type MetricValue struct {
	ID           string  `json:"id"`
	Value        float64 `json:"value"`
	ValueFixed   int64   `json:"value_fixed"`
	NRecordsUsed int     `json:"n_records_used"`
	Period       Period  `json:"period"`
}

// SubmitResponse is the JSON returned by /v1/stats/submit-transparent on success.
type SubmitResponse struct {
	Stored          bool   `json:"stored"`
	LatencyMsVerify int    `json:"latency_ms_verify"`
	StatementHash   string `json:"statement_hash"`
}

const StatsProgramID = "sauron-stats-v1"

// TransparentStatsSubmission is the production
// POST /v1/stats/submit-transparent body. Generate and independently verify
// ReceiptB64 with the version-pinned transparent-zk tools before submitting it.
type TransparentStatsSubmission struct {
	TenantID      string  `json:"tenant_id"`
	AgentID       *string `json:"agent_id_or_none"`
	MetricID      string  `json:"metric_id"`
	ClaimedValue  int64   `json:"claimed_value"`
	PeriodStart   int64   `json:"period_start"`
	PeriodEnd     int64   `json:"period_end"`
	CheckpointID  string  `json:"checkpoint_id"`
	ProgramID     string  `json:"program_id"`
	ReceiptB64    string  `json:"receipt_b64"`
}

// ErrInvalidStatsSubmission is returned for client-side validation failures of
// a TransparentStatsSubmission.
var ErrInvalidStatsSubmission = errors.New("invalid stats submission")

// SubmitTransparentStats transports a native RISC Zero STARK receipt to the
// production stats endpoint. It deliberately does not treat the server's
// response as independent proof verification; callers should run the published
// local verifier before submission.
func (c *Client) SubmitTransparentStats(ctx context.Context, sub TransparentStatsSubmission) (*SubmitResponse, error) {
	if sub.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidStatsSubmission)
	}
	if sub.ProgramID == "" {
		sub.ProgramID = StatsProgramID
	}
	if sub.ProgramID != StatsProgramID {
		return nil, fmt.Errorf("%w: program_id must be %s", ErrInvalidStatsSubmission, StatsProgramID)
	}
	if sub.CheckpointID == "" || sub.ReceiptB64 == "" {
		return nil, fmt.Errorf("%w: checkpoint_id and receipt_b64 required", ErrInvalidStatsSubmission)
	}
	if sub.PeriodStart > sub.PeriodEnd {
		return nil, fmt.Errorf("%w: period_start must be <= period_end", ErrInvalidStatsSubmission)
	}
	switch sub.MetricID {
	case "success_rate", "error_rate", "tool_call_count", "cost_total":
	default:
		return nil, fmt.Errorf("%w: metric_id is not implemented by %s", ErrInvalidStatsSubmission, StatsProgramID)
	}
	body, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	u := c.baseURL + "/v1/stats/submit-transparent"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminKey)
		req.Header.Set("X-Admin-Key", c.adminKey)
	}
	req.Header.Set("X-Sauron-Tenant-Id", sub.TenantID)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s -> %d: %s", u, resp.StatusCode, string(respBody))
	}
	var out SubmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode submit response: %w", err)
	}
	return &out, nil
}

