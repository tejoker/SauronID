package sauronid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ClientOptions configures a SauronID HTTP client.
type ClientOptions struct {
	// BaseURL is the core server (no trailing slash).
	BaseURL string
	// AdminKey is the admin bearer token. Empty disables the header for
	// admin routes (admin-only methods will then fail with 401 server-side).
	AdminKey string
	// TenantID, when non-empty, attaches X-Sauron-Tenant-Id to every request.
	TenantID string
	// Timeout is the per-request timeout. Default 10s.
	Timeout time.Duration
	// HTTPClient overrides the default http.Client.
	HTTPClient *http.Client
}

// Client is a thin HTTP client for the SauronID core server.
//
// It does not cache agent secrets; per-call signing belongs in a
// downstream signed-agent wrapper (out of scope here).
type Client struct {
	baseURL    string
	adminKey   string
	tenantID   string
	httpClient *http.Client
}

// NewClient constructs a Client. Pass an empty struct for defaults.
func NewClient(opts ClientOptions) *Client {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Client{
		baseURL:    trimTrailingSlash(opts.BaseURL),
		adminKey:   opts.AdminKey,
		tenantID:   opts.TenantID,
		httpClient: client,
	}
}

// Error is a typed error carrying the HTTP status and raw response body.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("SauronID HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(buf)
	}
	u := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminKey)
		// Some legacy admin routes expect X-Admin-Key.
		req.Header.Set("X-Admin-Key", c.adminKey)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Sauron-Tenant-Id", c.tenantID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{Status: resp.StatusCode, Body: string(respBody)}
	}
	return respBody, nil
}

// ─────────────────────────────────────────────────────────────────────
// User auth
// ─────────────────────────────────────────────────────────────────────

// UserAuthResponse is the JSON returned by POST /user/auth.
type UserAuthResponse struct {
	Session   string `json:"session"`
	KeyImage  string `json:"key_image"`
	ExpiresAt int64  `json:"expires_at"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// UserAuth performs development-only legacy password authentication
// (POST /user/auth). Production deployments disable this route; use the
// Ed25519 challenge flow (/user/auth/challenge + /user/auth/finish) there.
func (c *Client) UserAuth(ctx context.Context, email, password string) (*UserAuthResponse, error) {
	body, err := c.do(ctx, http.MethodPost, "/user/auth", map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return nil, err
	}
	var out UserAuthResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode user auth response: %w", err)
	}
	return &out, nil
}

// ─────────────────────────────────────────────────────────────────────
// Agent lifecycle
// ─────────────────────────────────────────────────────────────────────

// RegisterAgentRequest is the body of POST /agent/register.
type RegisterAgentRequest struct {
	HumanKeyImage              string                 `json:"human_key_image"`
	AgentType                  string                 `json:"agent_type"`
	ChecksumInputs             map[string]interface{} `json:"checksum_inputs"`
	AgentChecksum              string                 `json:"agent_checksum"`
	IntentJSON                 string                 `json:"intent_json"`
	PublicKeyHex               string                 `json:"public_key_hex"`
	RingKeyImageHex            string                 `json:"ring_key_image_hex"`
	PopJkt                     string                 `json:"pop_jkt"`
	PopPublicKeyB64u           string                 `json:"pop_public_key_b64u"`
	TTLSecs                    int                    `json:"ttl_secs"`
	AttestationChallengeID    string                 `json:"attestation_challenge_id,omitempty"`
	AttestationKind           string                 `json:"attestation_kind,omitempty"`
	AttestationBlob           string                 `json:"attestation_blob,omitempty"`
	ExpectedMeasurementHex    string                 `json:"expected_measurement_hex,omitempty"`
	AttestationPubKeyB64u     string                 `json:"attestation_pubkey_b64u,omitempty"`
	TPM2QuoteB64              string                 `json:"tpm2_quote_b64,omitempty"`
	TPM2AttestB64             string                 `json:"tpm2_attest_b64,omitempty"`
	TPM2SignatureB64          string                 `json:"tpm2_signature_b64,omitempty"`
	TPM2AIKCertPEM            string                 `json:"tpm2_aik_cert_pem,omitempty"`
	TPM2EKCertChainPEM        string                 `json:"tpm2_ek_cert_chain_pem,omitempty"`
	TPM2PCRSet                string                 `json:"tpm2_pcr_set,omitempty"`
	TPM2AttestationPubKeyB64u string                 `json:"tpm2_attestation_pubkey_b64u,omitempty"`
}

// AttestationChallenge is a one-use nonce bound to the authenticated human,
// tenant, and future Ed25519 PoP key. A TPM/Nitro provider must embed its nonce
// and the same PoP key in the signed registration document.
type AttestationChallenge struct {
	AttestationChallengeID string `json:"attestation_challenge_id"`
	Nonce                  string `json:"nonce"`
	PopJkt                 string `json:"pop_jkt"`
	ExpiresAt              int64  `json:"expires_at"`
}

// RequestAttestationChallenge obtains the nonce that must be attested before
// RegisterAgent. Hardware-backed production registrations cannot skip it.
func (c *Client) RequestAttestationChallenge(ctx context.Context, userSession, popPublicKeyB64u string) (*AttestationChallenge, error) {
	buf, err := json.Marshal(map[string]string{"pop_public_key_b64u": popPublicKeyB64u})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/attestation/challenge", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sauron-Session", userSession)
	if c.tenantID != "" {
		req.Header.Set("X-Sauron-Tenant-Id", c.tenantID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{Status: resp.StatusCode, Body: string(body)}
	}
	var out AttestationChallenge
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode attestation challenge: %w", err)
	}
	return &out, nil
}

// RegisterAgentResponse is the JSON returned by POST /agent/register.
type RegisterAgentResponse struct {
	AgentID string `json:"agent_id"`
}

// RegisterAgent calls POST /agent/register.
//
// The caller provides the session and request body. The server computes
// the canonical agent_checksum from ChecksumInputs and returns the
// assigned agent id.
func (c *Client) RegisterAgent(ctx context.Context, userSession string, req RegisterAgentRequest) (*RegisterAgentResponse, error) {
	buf, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	u := c.baseURL + "/agent/register"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if userSession != "" {
		httpReq.Header.Set("X-Sauron-Session", userSession)
	}
	if c.tenantID != "" {
		httpReq.Header.Set("X-Sauron-Tenant-Id", c.tenantID)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{Status: resp.StatusCode, Body: string(respBody)}
	}
	var out RegisterAgentResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}
	return &out, nil
}

// RevokeAgent calls DELETE /agent/{agent_id}.
func (c *Client) RevokeAgent(ctx context.Context, agentID, userSession string) error {
	u := c.baseURL + "/agent/" + url.PathEscape(agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	if userSession != "" {
		req.Header.Set("X-Sauron-Session", userSession)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Sauron-Tenant-Id", c.tenantID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Body: string(body)}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Policy ops
// ─────────────────────────────────────────────────────────────────────

// PolicyUploadResponse is the JSON returned by POST /v1/policy.
type PolicyUploadResponse struct {
	PolicyID string `json:"policy_id"`
}

// PolicySummary is one row of GET /v1/policy.
type PolicySummary struct {
	PolicyID string `json:"policy_id"`
	Agent    string `json:"agent"`
	Version  string `json:"version"`
}

// EvaluateResponse is the JSON returned by POST /v1/policy/:id/evaluate.
type EvaluateResponse struct {
	Verdict Verdict `json:"verdict"`
}

// UploadPolicy uploads either a YAML or JSON-encoded policy body.
func (c *Client) UploadPolicy(ctx context.Context, body string) (*PolicyUploadResponse, error) {
	u := c.baseURL + "/v1/policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	// Server distinguishes YAML vs JSON by content-type; default to JSON.
	if len(body) > 0 && body[0] == '{' {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/yaml")
	}
	if c.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminKey)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Sauron-Tenant-Id", c.tenantID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{Status: resp.StatusCode, Body: string(respBody)}
	}
	var out PolicyUploadResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode upload response: %w", err)
	}
	return &out, nil
}

// ListPolicies fetches GET /v1/policy.
func (c *Client) ListPolicies(ctx context.Context) ([]PolicySummary, error) {
	body, err := c.do(ctx, http.MethodGet, "/v1/policy", nil)
	if err != nil {
		return nil, err
	}
	var out []PolicySummary
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode list response: %w", err)
	}
	return out, nil
}

// EvaluatePolicy calls POST /v1/policy/:id/evaluate to ask the server
// for an authoritative verdict (as opposed to the local Evaluate).
func (c *Client) EvaluatePolicy(ctx context.Context, policyID string, action Action, agentID *string) (*EvaluateResponse, error) {
	body := map[string]interface{}{
		"action": action,
	}
	if agentID != nil {
		body["agent_id"] = *agentID
	}
	respBody, err := c.do(ctx, http.MethodPost, "/v1/policy/"+url.PathEscape(policyID)+"/evaluate", body)
	if err != nil {
		return nil, err
	}
	var out EvaluateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode evaluate response: %w", err)
	}
	return &out, nil
}

// ─────────────────────────────────────────────────────────────────────
// Spend ledger
// ─────────────────────────────────────────────────────────────────────

// RecordSpendResponse is the JSON returned by POST /v1/agents/:id/spend.
type RecordSpendResponse struct {
	TotalUsd float64 `json:"total_usd"`
}

// SpendSummary is the JSON returned by GET /v1/agents/:id/spend.
type SpendSummary struct {
	AgentID  string  `json:"agent_id"`
	PolicyID string  `json:"policy_id"`
	TotalUsd float64 `json:"total_usd"`
}

// RecordSpend calls POST /v1/agents/:id/spend.
func (c *Client) RecordSpend(ctx context.Context, agentID, policyID string, amountUsd float64) (*RecordSpendResponse, error) {
	body := map[string]interface{}{
		"policy_id":  policyID,
		"amount_usd": amountUsd,
	}
	respBody, err := c.do(ctx, http.MethodPost, "/v1/agents/"+url.PathEscape(agentID)+"/spend", body)
	if err != nil {
		return nil, err
	}
	var out RecordSpendResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode spend response: %w", err)
	}
	return &out, nil
}

// GetSpend calls GET /v1/agents/:id/spend?policy_id=...
func (c *Client) GetSpend(ctx context.Context, agentID, policyID string) (*SpendSummary, error) {
	q := url.Values{}
	if policyID != "" {
		q.Set("policy_id", policyID)
	}
	path := "/v1/agents/" + url.PathEscape(agentID) + "/spend"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var out SpendSummary
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode spend summary: %w", err)
	}
	return &out, nil
}
