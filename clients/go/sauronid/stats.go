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

// StatsSubmission is the body of POST /v1/stats/submit.
//
// The Go SDK does NOT ship a ZK-proof generator (snarkjs is JS-only).
// Customers compute proofs via the TS or Python SDK and submit them via
// this struct.
type StatsSubmission struct {
	TenantID     string   `json:"tenant_id"`
	AgentID      *string  `json:"agent_id_or_none"`
	MetricID     string   `json:"metric_id"`
	ClaimedValue int64    `json:"claimed_value"`
	NRecords     int      `json:"n_records"`
	PeriodStart  int64    `json:"period_start"`
	PeriodEnd    int64    `json:"period_end"`
	MerkleRoot   string   `json:"merkle_root"`
	ProofB64     string   `json:"proof_b64"`
	VkID         string   `json:"vk_id"`
	CheckpointID string   `json:"checkpoint_id"`
	PublicInputs []string `json:"public_inputs"`
}

// SubmitResponse is the JSON returned by /v1/stats/submit on success.
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

// SubmitStats POSTs `sub` to {coreURL}/v1/stats/submit.
//
// Deprecated: the server no longer serves this route. It was the Circom/Groth16
// path, which production already refused ("Groth16 verification is
// development-only; production accepts pinned native STARK receipts"), and its
// verifier is archived under archive/removed-2026-08/groth16-zkp/. Against a
// current core this returns 404.
//
// Use SubmitTransparentStats, which posts a native STARK receipt to
// /v1/stats/submit-transparent and is the path the server still serves.
//
// The method validates that mandatory fields are set before sending so
// most operator typos are caught client-side. Returns the server's
// SubmitResponse on success.
func (c *Client) SubmitStats(ctx context.Context, sub StatsSubmission) (*SubmitResponse, error) {
	if err := validateStatsSubmission(&sub); err != nil {
		return nil, err
	}
	body, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	u := c.baseURL + "/v1/stats/submit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminKey)
	}
	if sub.TenantID != "" {
		req.Header.Set("X-Sauron-Tenant-Id", sub.TenantID)
	}
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

// ErrInvalidStatsSubmission is returned for client-side validation
// failures of a StatsSubmission.
var ErrInvalidStatsSubmission = errors.New("invalid stats submission")

func validateStatsSubmission(s *StatsSubmission) error {
	if s.TenantID == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidStatsSubmission)
	}
	if s.MetricID == "" {
		return fmt.Errorf("%w: metric_id required", ErrInvalidStatsSubmission)
	}
	if s.PeriodStart >= s.PeriodEnd {
		return fmt.Errorf("%w: period_start must be < period_end", ErrInvalidStatsSubmission)
	}
	if s.MerkleRoot == "" {
		return fmt.Errorf("%w: merkle_root required", ErrInvalidStatsSubmission)
	}
	if s.ProofB64 == "" {
		return fmt.Errorf("%w: proof_b64 required", ErrInvalidStatsSubmission)
	}
	if s.VkID == "" {
		return fmt.Errorf("%w: vk_id required", ErrInvalidStatsSubmission)
	}
	if s.CheckpointID == "" {
		return fmt.Errorf("%w: checkpoint_id required", ErrInvalidStatsSubmission)
	}
	if s.NRecords <= 0 {
		return fmt.Errorf("%w: n_records must be > 0", ErrInvalidStatsSubmission)
	}
	return nil
}
