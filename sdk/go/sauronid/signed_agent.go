package sauronid

// Signed agent runtime. Mirrors sdk/python/sauronid_client/agent.py:
// registration generates the Ed25519 PoP keypair, the server computes the
// binding checksum, and every outbound call carries the full x-sauron-*
// header bundle produced by SignCall.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// PopThumbprint computes the RFC 7638 thumbprint of an Ed25519 OKP JWK
// (base64url-no-padding of sha256 over the canonical JWK JSON).
func PopThumbprint(publicKeyB64u string) string {
	x, _ := json.Marshal(publicKeyB64u)
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%s}`, x)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jwtClaim reads a string claim from a JWT payload without verifying the
// signature (the server verifies; we only need `jti` to bind challenges).
func jwtClaim(token, claim string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var obj map[string]interface{}
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	s, _ := obj[claim].(string)
	return s
}

// ─────────────────────────────────────────────────────────────────────
// Ring key material (Ristretto keypair via the Rust agent-action-tool)
// ─────────────────────────────────────────────────────────────────────

// agentActionToolPath locates the Rust `agent-action-tool` binary via
// $SAURONID_AGENT_ACTION_TOOL, then $PATH.
//
// ponytail: no repo-relative fallback like Python's __file__ trick — a Go
// binary has no package directory at runtime. Env var or PATH.
func agentActionToolPath() (string, error) {
	if p := os.Getenv("SAURONID_AGENT_ACTION_TOOL"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath("agent-action-tool"); err == nil {
		return p, nil
	}
	return "", errors.New("could not locate agent-action-tool: build the SauronID core (`cd core && cargo build --release`) and add it to $PATH, set $SAURONID_AGENT_ACTION_TOOL, or pass PublicKeyHex + RingSecretHex + RingKeyImageHex explicitly")
}

func genRingKeypair() (publicKeyHex, secretHex, ringKeyImageHex string, err error) {
	binary, err := agentActionToolPath()
	if err != nil {
		return "", "", "", err
	}
	out, err := exec.Command(binary, "keygen").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", "", "", fmt.Errorf("agent-action-tool keygen failed: %s", exitErr.Stderr)
		}
		return "", "", "", fmt.Errorf("agent-action-tool keygen failed: %w", err)
	}
	var data struct {
		PublicKeyHex    string `json:"public_key_hex"`
		SecretHex       string `json:"secret_hex"`
		RingKeyImageHex string `json:"ring_key_image_hex"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return "", "", "", fmt.Errorf("decode keygen output: %w", err)
	}
	return data.PublicKeyHex, data.SecretHex, data.RingKeyImageHex, nil
}

// resolveRingMaterial returns (publicKeyHex, ringSecretHex, ringKeyImageHex).
// Partial material is rejected: combining parts from different keypairs would
// make action proofs unverifiable. When nothing is supplied, one fresh keypair
// is generated via agent-action-tool.
func resolveRingMaterial(publicKeyHex, ringSecretHex, ringKeyImageHex string) (string, string, string, error) {
	supplied := 0
	for _, v := range []string{publicKeyHex, ringSecretHex, ringKeyImageHex} {
		if v != "" {
			supplied++
		}
	}
	switch supplied {
	case 3:
		return publicKeyHex, ringSecretHex, ringKeyImageHex, nil
	case 0:
		return genRingKeypair()
	default:
		return "", "", "", errors.New("ring public key, ring secret, and ring key image must be supplied together; partial key material is unsafe")
	}
}

// intentJSON serializes the agent intent for the registration API. Payment
// keys match core's enforce_strict_payment_intent: top-level
// "maxAmount"/"currency", "constraints.merchant_allowlist".
func intentJSON(scope []string, egressAllowlist []interface{}, maxAmount float64, currency string, merchantAllowlist []string) (string, error) {
	if scope == nil {
		scope = []string{}
	}
	payload := map[string]interface{}{"scope": scope}
	if egressAllowlist != nil {
		payload["egress_allowlist"] = egressAllowlist
	}
	if maxAmount != 0 {
		payload["maxAmount"] = maxAmount
		payload["currency"] = currency
	}
	if merchantAllowlist != nil {
		payload["constraints"] = map[string]interface{}{"merchant_allowlist": merchantAllowlist}
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// ─────────────────────────────────────────────────────────────────────
// SignedAgent
// ─────────────────────────────────────────────────────────────────────

// SignedAgent is a registered agent holding the keys to sign every
// outbound call. Construct via RegisterLLMAgent / RegisterMCPAgent /
// RegisterCustomAgent. Keep RingSecretHex out of logs.
type SignedAgent struct {
	Client       *Client
	AgentID      string
	ConfigDigest string
	Keypair      *PopKeyPair
	IntentScope  []string
	// HumanKeyImage is the human owner's key image (delegator), set at
	// registration; required for the action-leash flows.
	HumanKeyImage string
	// RingSecretHex is the Ristretto ring-signing secret. Present when the
	// keypair was generated at registration; empty when the operator
	// supplied only the public key + key image (sign envelopes externally).
	RingSecretHex string
	TenantID      string
	Audience      string
}

// Call makes a SauronID-protected HTTP call against the client base URL and
// returns the raw *http.Response (caller closes Body). Pass nil jsonBody for
// GET-style requests; non-nil bodies are JSON-encoded and sent with
// content-type application/json.
func (a *SignedAgent) Call(ctx context.Context, method, path string, jsonBody interface{}) (*http.Response, error) {
	var body []byte
	contentType := ""
	if jsonBody != nil {
		buf, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, err
		}
		body = buf
		contentType = "application/json"
	}
	return a.callRaw(ctx, method, path, body, contentType)
}

func (a *SignedAgent) callRaw(ctx context.Context, method, path string, body []byte, contentType string) (*http.Response, error) {
	hdrs, err := SignCall(SignCallParams{
		AgentID:           a.AgentID,
		AgentConfigDigest: a.ConfigDigest,
		PrivateKey:        a.Keypair.PrivateKey,
		Method:            method,
		Path:              path,
		Body:              body,
		TenantID:          a.TenantID,
		Audience:          a.Audience,
		ContentType:       contentType,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), a.Client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	hdrs.SetOn(req.Header)
	return a.Client.httpClient.Do(req)
}

// callJSON executes a signed call and decodes a 2xx JSON response into out.
func (a *SignedAgent) callJSON(ctx context.Context, method, path string, jsonBody, out interface{}) error {
	resp, err := a.Call(ctx, method, path, jsonBody)
	if err != nil {
		return err
	}
	return readJSONResponse(resp, out)
}

// sessionPost sends an unsigned session-authenticated POST (token minting,
// PoP challenges) and decodes the JSON response into out.
func (a *SignedAgent) sessionPost(ctx context.Context, path, userSession string, body, out interface{}) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Client.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sauron-Session", userSession)
	req.Header.Set("X-Sauron-Tenant-Id", a.TenantID)
	resp, err := a.Client.httpClient.Do(req)
	if err != nil {
		return err
	}
	return readJSONResponse(resp, out)
}

func readJSONResponse(resp *http.Response, out interface{}) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Body: string(body)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (a *SignedAgent) mintAJWT(ctx context.Context, userSession string, ttlSecs int) (ajwt, jti string, err error) {
	var out struct {
		Ajwt string `json:"ajwt"`
	}
	body := map[string]interface{}{"agent_id": a.AgentID, "ttl_secs": ttlSecs}
	if err := a.sessionPost(ctx, "/agent/token", userSession, body, &out); err != nil {
		return "", "", err
	}
	return out.Ajwt, jwtClaim(out.Ajwt, "jti"), nil
}

// signPopJWS EdDSA-signs a PoP challenge as a compact JWS
// (header.payload.sig) with the agent's per-call Ed25519 key. Matches the
// server's verify_ed25519_pop_jws.
func (a *SignedAgent) signPopJWS(challenge string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(challenge))
	signingInput := header + "." + payload
	sig := ed25519.Sign(a.Keypair.PrivateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// actionChallengeBody is the body of POST /agent/action/challenge.
type actionChallengeBody struct {
	AgentID       string `json:"agent_id"`
	HumanKeyImage string `json:"human_key_image"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	MerchantID    string `json:"merchant_id"`
	AmountMinor   int64  `json:"amount_minor"`
	Currency      string `json:"currency"`
	AjwtJti       string `json:"ajwt_jti"`
	TTLSecs       int    `json:"ttl_secs"`
}

// SignActionChallenge ring-signs an action-envelope challenge (the JSON
// returned by POST /agent/action/challenge) with this agent's ring secret,
// via the Rust agent-action-tool. Returns the proof
// {"envelope", "ring_signature"} to submit to an action endpoint.
func (a *SignedAgent) SignActionChallenge(challenge json.RawMessage) (json.RawMessage, error) {
	if a.RingSecretHex == "" {
		return nil, errors.New("ring secret unavailable: this agent was registered with an externally-held key; sign the challenge with your own agent-action-tool, or register via the default keypair path")
	}
	binary, err := agentActionToolPath()
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, challenge); err != nil {
		return nil, fmt.Errorf("invalid challenge JSON: %w", err)
	}
	out, err := exec.Command(
		binary, "sign-challenge",
		"--secret-hex", a.RingSecretHex,
		"--challenge-json", compact.String(),
	).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("agent-action-tool sign-challenge failed: %s", exitErr.Stderr)
		}
		return nil, fmt.Errorf("agent-action-tool sign-challenge failed: %w", err)
	}
	return json.RawMessage(out), nil
}

// AuthorizePaymentParams configures SignedAgent.AuthorizePayment.
type AuthorizePaymentParams struct {
	UserSession string
	AmountMinor int64
	Currency    string
	PaymentRef  string
	MerchantID  string
	// TTLSecs bounds the minted A-JWT. Default 300.
	TTLSecs int
}

// AuthorizePayment runs the end-to-end payment authorization through the
// SauronID leash: mint an A-JWT, EdDSA-sign a PoP challenge, ring-sign an
// action challenge over the exact payment args, then POST
// /agent/payment/authorize. Returns the raw Response so the caller can read
// authorization_id (200) or a policy denial (403). Requires the ring secret
// and the human owner's key image (both set by register-* with generated keys).
func (a *SignedAgent) AuthorizePayment(ctx context.Context, p AuthorizePaymentParams) (*http.Response, error) {
	if a.RingSecretHex == "" {
		return nil, errors.New("ring secret unavailable: register via the default keypair path so the agent can ring-sign the payment envelope")
	}
	if a.HumanKeyImage == "" {
		return nil, errors.New("HumanKeyImage unknown; register via Register*Agent")
	}
	ttl := p.TTLSecs
	if ttl == 0 {
		ttl = 300
	}
	ajwt, jti, err := a.mintAJWT(ctx, p.UserSession, ttl)
	if err != nil {
		return nil, err
	}

	var pop struct {
		PopChallengeID string `json:"pop_challenge_id"`
		Challenge      string `json:"challenge"`
	}
	if err := a.sessionPost(ctx, "/agent/pop/challenge", p.UserSession,
		map[string]string{"agent_id": a.AgentID}, &pop); err != nil {
		return nil, err
	}
	popJWS := a.signPopJWS(pop.Challenge)

	var challenge json.RawMessage
	if err := a.callJSON(ctx, http.MethodPost, "/agent/action/challenge", actionChallengeBody{
		AgentID:       a.AgentID,
		HumanKeyImage: a.HumanKeyImage,
		Action:        "payment_initiation",
		Resource:      p.PaymentRef,
		MerchantID:    p.MerchantID,
		AmountMinor:   p.AmountMinor,
		Currency:      p.Currency,
		AjwtJti:       jti,
		TTLSecs:       120,
	}, &challenge); err != nil {
		return nil, err
	}
	proof, err := a.SignActionChallenge(challenge)
	if err != nil {
		return nil, err
	}

	return a.Call(ctx, http.MethodPost, "/agent/payment/authorize", map[string]interface{}{
		"ajwt":             ajwt,
		"amount_minor":     p.AmountMinor,
		"currency":         p.Currency,
		"payment_ref":      p.PaymentRef,
		"merchant_id":      p.MerchantID,
		"pop_challenge_id": pop.PopChallengeID,
		"pop_jws":          popJWS,
		"agent_action":     proof,
	})
}

// ReportEgress records an outbound call to a third-party API in the SauronID
// egress log (POST /agent/egress/log). Wire HTTP client wrappers to call this
// BEFORE every outbound request.
func (a *SignedAgent) ReportEgress(ctx context.Context, targetHost, targetPath, method, bodyHashHex string, statusCode int) error {
	return a.callJSON(ctx, http.MethodPost, "/agent/egress/log", map[string]interface{}{
		"agent_id":      a.AgentID,
		"target_host":   targetHost,
		"target_path":   targetPath,
		"method":        strings.ToUpper(method),
		"body_hash_hex": bodyHashHex,
		"status_code":   statusCode,
	}, nil)
}

// EgressRequestParams configures SignedAgent.EgressRequest.
type EgressRequestParams struct {
	UserSession string
	Method      string
	// URL must be absolute http(s) without userinfo, query, or fragment
	// (query strings are intentionally refused by core).
	URL     string
	Body    string
	Headers map[string]string
	// TTLSecs bounds the minted A-JWT. Default 300.
	TTLSecs int
}

// EgressRequest executes one outbound HTTP request through the enforcing
// gateway: mint an A-JWT, ring-sign an action challenge over the exact URL,
// obtain a body-bound capability, and consume it once. A failed network
// attempt spends the capability, preventing ambiguous retries.
func (a *SignedAgent) EgressRequest(ctx context.Context, p EgressRequestParams) (map[string]interface{}, error) {
	if a.RingSecretHex == "" {
		return nil, errors.New("ring secret unavailable; sign egress authorization externally")
	}
	parsed, err := url.Parse(p.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, errors.New("url must be absolute http(s)")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, errors.New("url userinfo, query, and fragment are not supported")
	}
	ttl := p.TTLSecs
	if ttl == 0 {
		ttl = 300
	}
	ajwt, jti, err := a.mintAJWT(ctx, p.UserSession, ttl)
	if err != nil {
		return nil, err
	}

	var challenge json.RawMessage
	if err := a.callJSON(ctx, http.MethodPost, "/agent/action/challenge", actionChallengeBody{
		AgentID:       a.AgentID,
		HumanKeyImage: a.HumanKeyImage,
		Action:        "egress",
		Resource:      p.URL,
		MerchantID:    parsed.Hostname(),
		AmountMinor:   0,
		Currency:      "",
		AjwtJti:       jti,
		TTLSecs:       120,
	}, &challenge); err != nil {
		return nil, err
	}
	proof, err := a.SignActionChallenge(challenge)
	if err != nil {
		return nil, err
	}

	bodyHash := sha256.Sum256([]byte(p.Body))
	var capability struct {
		Capability string `json:"capability"`
	}
	if err := a.callJSON(ctx, http.MethodPost, "/agent/egress/capability", map[string]interface{}{
		"agent_id":      a.AgentID,
		"ajwt":          ajwt,
		"method":        strings.ToUpper(p.Method),
		"url":           p.URL,
		"body_hash_hex": hex.EncodeToString(bodyHash[:]),
		"agent_action":  proof,
	}, &capability); err != nil {
		return nil, err
	}

	headers := p.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	var out map[string]interface{}
	if err := a.callJSON(ctx, http.MethodPost, "/agent/egress/proxy", map[string]interface{}{
		"capability": capability.Capability,
		"method":     strings.ToUpper(p.Method),
		"url":        p.URL,
		"headers":    headers,
		"body":       p.Body,
	}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke deletes the agent (DELETE /agent/{agent_id}).
func (a *SignedAgent) Revoke(ctx context.Context, userSession string) error {
	return a.Client.RevokeAgent(ctx, a.AgentID, userSession)
}

// ─────────────────────────────────────────────────────────────────────
// Registration — typed inputs per agent kind; the server canonicalises
// and computes the binding checksum.
//
// ponytail: no attestation-provider hook here — hardware-attested
// registrations use Client.RequestAttestationChallenge + Client.RegisterAgent
// directly with the attestation fields filled in.
// ─────────────────────────────────────────────────────────────────────

// RegisterLLMAgentOptions configures RegisterLLMAgent. The model +
// system prompt + tool list become the binding checksum; flipping any of
// them at runtime without rotating via /agent/{id}/checksum/update will
// reject every subsequent call.
type RegisterLLMAgentOptions struct {
	UserSession  string
	UserKeyImage string
	ModelID      string
	SystemPrompt string
	Tools        []string
	// PublicKeyHex, RingSecretHex, RingKeyImageHex supply an existing
	// Ristretto ring keypair. All three together or none: when omitted one
	// fresh keypair is generated via agent-action-tool.
	PublicKeyHex    string
	RingSecretHex   string
	RingKeyImageHex string
	IntentScope     []string
	EgressAllowlist []interface{}
	// MaxAmount is a payment cap in major units (5.0 = 500 minor). Requires
	// Currency; core enforces the pair on every AuthorizePayment call.
	// Setting it also ensures payment_initiation is in the intent scope.
	MaxAmount float64
	// Currency is the ISO currency for the payment cap. Requires MaxAmount.
	Currency string
	// MerchantAllowlist becomes constraints.merchant_allowlist in the intent.
	MerchantAllowlist []string
	// PopJkt overrides the RFC 7638 thumbprint of the generated PoP key.
	PopJkt string
	// TTLSecs is the agent registration TTL. Default 3600.
	TTLSecs     int
	ExtraInputs map[string]interface{}
}

// RegisterLLMAgent registers an LLM agent and returns a SignedAgent ready to
// make signed calls. The Ed25519 PoP keypair is generated in-process and
// never leaves it.
func RegisterLLMAgent(ctx context.Context, client *Client, opts RegisterLLMAgentOptions) (*SignedAgent, error) {
	inputs := map[string]interface{}{
		"model_id":      opts.ModelID,
		"system_prompt": opts.SystemPrompt,
		"tools":         stringList(opts.Tools),
	}
	for k, v := range opts.ExtraInputs {
		inputs[k] = v
	}
	return registerSignedAgent(ctx, client, registerParams{
		userSession:     opts.UserSession,
		userKeyImage:    opts.UserKeyImage,
		agentType:       "llm",
		inputs:          inputs,
		publicKeyHex:    opts.PublicKeyHex,
		ringSecretHex:   opts.RingSecretHex,
		ringKeyImageHex: opts.RingKeyImageHex,
		intentScope:     opts.IntentScope,
		egressAllowlist: opts.EgressAllowlist,
		maxAmount:       opts.MaxAmount,
		currency:        opts.Currency,
		merchantAllow:   opts.MerchantAllowlist,
		popJkt:          opts.PopJkt,
		ttlSecs:         opts.TTLSecs,
	})
}

// RegisterMCPAgentOptions configures RegisterMCPAgent.
type RegisterMCPAgentOptions struct {
	UserSession     string
	UserKeyImage    string
	ManifestJSON    map[string]interface{}
	ToolSignatures  []string
	PublicKeyHex    string
	RingSecretHex   string
	RingKeyImageHex string
	IntentScope     []string
	EgressAllowlist []interface{}
	// MaxAmount / Currency / MerchantAllowlist: see RegisterLLMAgentOptions.
	MaxAmount         float64
	Currency          string
	MerchantAllowlist []string
	PopJkt            string
	TTLSecs           int
	ExtraInputs       map[string]interface{}
}

// RegisterMCPAgent registers an MCP server-style agent.
func RegisterMCPAgent(ctx context.Context, client *Client, opts RegisterMCPAgentOptions) (*SignedAgent, error) {
	inputs := map[string]interface{}{
		"manifest_json":   opts.ManifestJSON,
		"tool_signatures": stringList(opts.ToolSignatures),
	}
	for k, v := range opts.ExtraInputs {
		inputs[k] = v
	}
	return registerSignedAgent(ctx, client, registerParams{
		userSession:     opts.UserSession,
		userKeyImage:    opts.UserKeyImage,
		agentType:       "mcp_server",
		inputs:          inputs,
		publicKeyHex:    opts.PublicKeyHex,
		ringSecretHex:   opts.RingSecretHex,
		ringKeyImageHex: opts.RingKeyImageHex,
		intentScope:     opts.IntentScope,
		egressAllowlist: opts.EgressAllowlist,
		maxAmount:       opts.MaxAmount,
		currency:        opts.Currency,
		merchantAllow:   opts.MerchantAllowlist,
		popJkt:          opts.PopJkt,
		ttlSecs:         opts.TTLSecs,
	})
}

// RegisterCustomAgentOptions configures RegisterCustomAgent.
type RegisterCustomAgentOptions struct {
	UserSession  string
	UserKeyImage string
	// Inputs is hashed verbatim — the operator decides what goes in.
	// Recommended fields per docs/security/threat-model.md.
	Inputs          map[string]interface{}
	PublicKeyHex    string
	RingSecretHex   string
	RingKeyImageHex string
	IntentScope     []string
	EgressAllowlist []interface{}
	// MaxAmount / Currency / MerchantAllowlist: see RegisterLLMAgentOptions.
	MaxAmount         float64
	Currency          string
	MerchantAllowlist []string
	PopJkt            string
	TTLSecs           int
}

// RegisterCustomAgent registers a custom-type agent.
func RegisterCustomAgent(ctx context.Context, client *Client, opts RegisterCustomAgentOptions) (*SignedAgent, error) {
	inputs := make(map[string]interface{}, len(opts.Inputs))
	for k, v := range opts.Inputs {
		inputs[k] = v
	}
	return registerSignedAgent(ctx, client, registerParams{
		userSession:     opts.UserSession,
		userKeyImage:    opts.UserKeyImage,
		agentType:       "custom",
		inputs:          inputs,
		publicKeyHex:    opts.PublicKeyHex,
		ringSecretHex:   opts.RingSecretHex,
		ringKeyImageHex: opts.RingKeyImageHex,
		intentScope:     opts.IntentScope,
		egressAllowlist: opts.EgressAllowlist,
		maxAmount:       opts.MaxAmount,
		currency:        opts.Currency,
		merchantAllow:   opts.MerchantAllowlist,
		popJkt:          opts.PopJkt,
		ttlSecs:         opts.TTLSecs,
	})
}

type registerParams struct {
	userSession     string
	userKeyImage    string
	agentType       string
	inputs          map[string]interface{}
	publicKeyHex    string
	ringSecretHex   string
	ringKeyImageHex string
	intentScope     []string
	egressAllowlist []interface{}
	maxAmount       float64
	currency        string
	merchantAllow   []string
	popJkt          string
	ttlSecs         int
}

func stringList(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func registerSignedAgent(ctx context.Context, client *Client, p registerParams) (*SignedAgent, error) {
	if p.userSession == "" {
		return nil, errors.New("UserSession is required")
	}
	if p.userKeyImage == "" {
		return nil, errors.New("UserKeyImage is required")
	}
	kp, err := GeneratePopKeyPair()
	if err != nil {
		return nil, err
	}
	pkHex, ringSecret, ringKI, err := resolveRingMaterial(p.publicKeyHex, p.ringSecretHex, p.ringKeyImageHex)
	if err != nil {
		return nil, err
	}
	if p.egressAllowlist != nil {
		p.inputs["egress_allowlist"] = p.egressAllowlist
	}
	if (p.maxAmount != 0) != (p.currency != "") {
		return nil, errors.New("MaxAmount and Currency must be provided together")
	}
	intentScope := p.intentScope
	if p.maxAmount != 0 && !slices.Contains(intentScope, "payment_initiation") {
		intentScope = append(append([]string(nil), intentScope...), "payment_initiation")
	}
	intent, err := intentJSON(intentScope, p.egressAllowlist, p.maxAmount, p.currency, p.merchantAllow)
	if err != nil {
		return nil, err
	}
	popJkt := p.popJkt
	if popJkt == "" {
		popJkt = PopThumbprint(kp.PublicKeyB64u)
	}
	ttl := p.ttlSecs
	if ttl == 0 {
		ttl = 3600
	}
	resp, err := client.RegisterAgent(ctx, p.userSession, RegisterAgentRequest{
		HumanKeyImage:    p.userKeyImage,
		AgentType:        p.agentType,
		ChecksumInputs:   p.inputs,
		AgentChecksum:    "", // server computes
		IntentJSON:       intent,
		PublicKeyHex:     pkHex,
		RingKeyImageHex:  ringKI,
		PopJkt:           popJkt,
		PopPublicKeyB64u: kp.PublicKeyB64u,
		TTLSecs:          ttl,
	})
	if err != nil {
		return nil, err
	}

	// Read back the server-computed digest from the agent record.
	body, err := client.do(ctx, http.MethodGet, "/agent/"+url.PathEscape(resp.AgentID), nil)
	if err != nil {
		return nil, err
	}
	var rec struct {
		AgentChecksum string `json:"agent_checksum"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("decode agent record: %w", err)
	}

	tenant := client.tenantID
	if tenant == "" {
		tenant = "default"
	}
	return &SignedAgent{
		Client:        client,
		AgentID:       resp.AgentID,
		ConfigDigest:  rec.AgentChecksum,
		Keypair:       kp,
		IntentScope:   append([]string(nil), intentScope...),
		HumanKeyImage: p.userKeyImage,
		RingSecretHex: ringSecret,
		TenantID:      tenant,
		Audience:      "sauron-core",
	}, nil
}
