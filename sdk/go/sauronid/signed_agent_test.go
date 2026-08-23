package sauronid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCore records what a registration + signed call hits.
type fakeCore struct {
	registerBody map[string]interface{}
	registerHdrs http.Header
	callHdrs     []http.Header
	callBodies   [][]byte
	revokedPath  string
	revokeHdrs   http.Header
}

const (
	testAgentID = "agt_test"
	testDigest  = "cfg_digest_1"
)

func newFakeCore(t *testing.T) (*httptest.Server, *fakeCore) {
	t.Helper()
	fc := &fakeCore{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &fc.registerBody); err != nil {
			t.Errorf("register body not JSON: %v", err)
		}
		fc.registerHdrs = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_id":"` + testAgentID + `"}`))
	})
	mux.HandleFunc("GET /agent/"+testAgentID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_checksum":"` + testDigest + `"}`))
	})
	mux.HandleFunc("DELETE /agent/"+testAgentID, func(w http.ResponseWriter, r *http.Request) {
		fc.revokedPath = r.URL.Path
		fc.revokeHdrs = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/v1/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fc.callHdrs = append(fc.callHdrs, r.Header.Clone())
		fc.callBodies = append(fc.callBodies, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, fc
}

// testRingMaterial supplies explicit ring material so tests do not depend on
// the Rust agent-action-tool binary.
var testRingMaterial = struct{ pk, secret, ki string }{
	pk:     "aa11223344556677aa11223344556677aa11223344556677aa11223344556677",
	secret: "bb11223344556677bb11223344556677bb11223344556677bb11223344556677",
	ki:     "cc11223344556677cc11223344556677cc11223344556677cc11223344556677",
}

func registerTestLLMAgent(t *testing.T, baseURL string) (*SignedAgent, *Client) {
	t.Helper()
	client := NewClient(ClientOptions{BaseURL: baseURL})
	agent, err := RegisterLLMAgent(context.Background(), client, RegisterLLMAgentOptions{
		UserSession:     "sess_1",
		UserKeyImage:    "ki_human",
		ModelID:         "gpt-4o",
		SystemPrompt:    "You are a payments copilot.",
		Tools:           []string{"send_email", "search"},
		PublicKeyHex:    testRingMaterial.pk,
		RingSecretHex:   testRingMaterial.secret,
		RingKeyImageHex: testRingMaterial.ki,
		IntentScope:     []string{"payments"},
	})
	if err != nil {
		t.Fatalf("RegisterLLMAgent: %v", err)
	}
	return agent, client
}

func TestRegisterLLMAgent_RequestBody(t *testing.T) {
	srv, fc := newFakeCore(t)
	agent, _ := registerTestLLMAgent(t, srv.URL)

	if agent.AgentID != testAgentID {
		t.Fatalf("agent id: got %q want %q", agent.AgentID, testAgentID)
	}
	if agent.ConfigDigest != testDigest {
		t.Fatalf("config digest: got %q want %q", agent.ConfigDigest, testDigest)
	}
	if got := fc.registerHdrs.Get("X-Sauron-Session"); got != "sess_1" {
		t.Fatalf("session header: got %q", got)
	}

	body := fc.registerBody
	for name, want := range map[string]string{
		"agent_type":         "llm",
		"human_key_image":    "ki_human",
		"public_key_hex":     testRingMaterial.pk,
		"ring_key_image_hex": testRingMaterial.ki,
		"agent_checksum":     "",
	} {
		if got, _ := body[name].(string); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}

	inputs, ok := body["checksum_inputs"].(map[string]interface{})
	if !ok {
		t.Fatalf("checksum_inputs missing or not object: %v", body["checksum_inputs"])
	}
	if inputs["model_id"] != "gpt-4o" || inputs["system_prompt"] != "You are a payments copilot." {
		t.Errorf("checksum inputs mismatch: %v", inputs)
	}
	tools, _ := inputs["tools"].([]interface{})
	if len(tools) != 2 || tools[0] != "send_email" || tools[1] != "search" {
		t.Errorf("tools mismatch: %v", inputs["tools"])
	}

	popB64u, _ := body["pop_public_key_b64u"].(string)
	pub, err := base64.RawURLEncoding.DecodeString(popB64u)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pop_public_key_b64u invalid: %q (%v)", popB64u, err)
	}
	if got, _ := body["pop_jkt"].(string); got != PopThumbprint(popB64u) {
		t.Errorf("pop_jkt: got %q want RFC 7638 thumbprint %q", got, PopThumbprint(popB64u))
	}

	var intent struct {
		Scope []string `json:"scope"`
	}
	intentRaw, _ := body["intent_json"].(string)
	if err := json.Unmarshal([]byte(intentRaw), &intent); err != nil || len(intent.Scope) != 1 || intent.Scope[0] != "payments" {
		t.Errorf("intent_json mismatch: %q (%v)", intentRaw, err)
	}
	if ttl, _ := body["ttl_secs"].(float64); ttl != 3600 {
		t.Errorf("ttl_secs default: got %v want 3600", ttl)
	}
}

func TestRegisterLLMAgent_PaymentCapIntent(t *testing.T) {
	srv, fc := newFakeCore(t)
	client := NewClient(ClientOptions{BaseURL: srv.URL})
	agent, err := RegisterLLMAgent(context.Background(), client, RegisterLLMAgentOptions{
		UserSession:       "sess_1",
		UserKeyImage:      "ki_human",
		ModelID:           "gpt-4o",
		Tools:             []string{"search"},
		PublicKeyHex:      testRingMaterial.pk,
		RingSecretHex:     testRingMaterial.secret,
		RingKeyImageHex:   testRingMaterial.ki,
		IntentScope:       []string{"search"},
		MaxAmount:         5.0,
		Currency:          "USD",
		MerchantAllowlist: []string{"mch_demo_payments"},
	})
	if err != nil {
		t.Fatalf("RegisterLLMAgent: %v", err)
	}

	var intent struct {
		Scope       []string `json:"scope"`
		MaxAmount   float64  `json:"maxAmount"`
		Currency    string   `json:"currency"`
		Constraints struct {
			MerchantAllowlist []string `json:"merchant_allowlist"`
		} `json:"constraints"`
	}
	intentRaw, _ := fc.registerBody["intent_json"].(string)
	if err := json.Unmarshal([]byte(intentRaw), &intent); err != nil {
		t.Fatalf("intent_json not JSON: %q (%v)", intentRaw, err)
	}
	if intent.MaxAmount != 5.0 || intent.Currency != "USD" {
		t.Errorf("payment cap mismatch: %q", intentRaw)
	}
	if len(intent.Constraints.MerchantAllowlist) != 1 || intent.Constraints.MerchantAllowlist[0] != "mch_demo_payments" {
		t.Errorf("merchant allowlist mismatch: %q", intentRaw)
	}
	found := false
	for _, s := range intent.Scope {
		if s == "payment_initiation" {
			found = true
		}
	}
	if !found {
		t.Errorf("payment_initiation missing from intent scope: %q", intentRaw)
	}
	found = false
	for _, s := range agent.IntentScope {
		if s == "payment_initiation" {
			found = true
		}
	}
	if !found {
		t.Errorf("payment_initiation missing from agent.IntentScope: %v", agent.IntentScope)
	}
}

func TestRegisterLLMAgent_HalfSpecifiedPaymentCapRejected(t *testing.T) {
	srv, _ := newFakeCore(t)
	client := NewClient(ClientOptions{BaseURL: srv.URL})
	_, err := RegisterLLMAgent(context.Background(), client, RegisterLLMAgentOptions{
		UserSession:     "sess_1",
		UserKeyImage:    "ki_human",
		ModelID:         "m",
		PublicKeyHex:    testRingMaterial.pk,
		RingSecretHex:   testRingMaterial.secret,
		RingKeyImageHex: testRingMaterial.ki,
		MaxAmount:       5.0, // Currency missing
	})
	if err == nil || !strings.Contains(err.Error(), "MaxAmount and Currency") {
		t.Fatalf("expected MaxAmount/Currency pair error, got %v", err)
	}
}

func TestRegisterAgent_PartialRingMaterialRejected(t *testing.T) {
	srv, _ := newFakeCore(t)
	client := NewClient(ClientOptions{BaseURL: srv.URL})
	_, err := RegisterLLMAgent(context.Background(), client, RegisterLLMAgentOptions{
		UserSession:  "sess_1",
		UserKeyImage: "ki_human",
		ModelID:      "m",
		PublicKeyHex: testRingMaterial.pk, // secret + key image missing
	})
	if err == nil {
		t.Fatal("expected partial ring material to be rejected")
	}
}

func TestSignedAgentCall_HeadersAndSignature(t *testing.T) {
	srv, fc := newFakeCore(t)
	agent, _ := registerTestLLMAgent(t, srv.URL)
	ctx := context.Background()

	resp, err := agent.Call(ctx, "POST", "/v1/echo", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if len(fc.callHdrs) != 1 {
		t.Fatalf("expected 1 recorded call, got %d", len(fc.callHdrs))
	}
	hdrs := fc.callHdrs[0]

	for _, tc := range []struct {
		header string
		want   string // empty means present-and-non-empty only
	}{
		{"x-sauron-agent-id", testAgentID},
		{"x-sauron-call-ts", ""},
		{"x-sauron-call-nonce", ""},
		{"x-sauron-call-sig", ""},
		{"x-sauron-agent-config-digest", testDigest},
		{"x-sauron-call-audience", "sauron-core"},
		{"x-sauron-protocol-version", "2"},
		{"x-sauron-tenant-id", "default"},
	} {
		got := hdrs.Get(tc.header)
		if got == "" {
			t.Errorf("header %s missing", tc.header)
			continue
		}
		if tc.want != "" && got != tc.want {
			t.Errorf("header %s: got %q want %q", tc.header, got, tc.want)
		}
	}

	// The signature must verify under the generated PoP public key over the
	// canonical v2 payload reconstructed from what the server received.
	bodyHash := sha256.Sum256(fc.callBodies[0])
	payload := canonicalFields("sauron.call.v2", [][2]string{
		{"version", "2"},
		{"agent_id", hdrs.Get("x-sauron-agent-id")},
		{"tenant_id", hdrs.Get("x-sauron-tenant-id")},
		{"audience", hdrs.Get("x-sauron-call-audience")},
		{"method", "POST"},
		{"target_uri", "/v1/echo"},
		{"content_type", "application/json"},
		{"body_sha256", hex.EncodeToString(bodyHash[:])},
		{"config_digest", hdrs.Get("x-sauron-agent-config-digest")},
		{"timestamp_ms", hdrs.Get("x-sauron-call-ts")},
		{"nonce", hdrs.Get("x-sauron-call-nonce")},
	})
	sig, err := base64.RawURLEncoding.DecodeString(hdrs.Get("x-sauron-call-sig"))
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(agent.Keypair.PublicKey, payload, sig) {
		t.Fatal("call signature does not verify over the canonical v2 payload")
	}
}

func TestSignedAgentCall_NonceDiffers(t *testing.T) {
	srv, fc := newFakeCore(t)
	agent, _ := registerTestLLMAgent(t, srv.URL)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		resp, err := agent.Call(ctx, "POST", "/v1/echo", map[string]int{"i": i})
		if err != nil {
			t.Fatalf("Call %d: %v", i, err)
		}
		resp.Body.Close()
	}
	n1 := fc.callHdrs[0].Get("x-sauron-call-nonce")
	n2 := fc.callHdrs[1].Get("x-sauron-call-nonce")
	if n1 == "" || n1 == n2 {
		t.Fatalf("nonces must be fresh per call: %q vs %q", n1, n2)
	}
}

func TestSignedAgentRevoke(t *testing.T) {
	srv, fc := newFakeCore(t)
	agent, _ := registerTestLLMAgent(t, srv.URL)

	if err := agent.Revoke(context.Background(), "sess_1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if fc.revokedPath != "/agent/"+testAgentID {
		t.Fatalf("revoke path: got %q want %q", fc.revokedPath, "/agent/"+testAgentID)
	}
	if got := fc.revokeHdrs.Get("X-Sauron-Session"); got != "sess_1" {
		t.Fatalf("revoke session header: got %q", got)
	}
}
