package sauronid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CallSigHeaders is the five-header bundle that authenticates a single
// outbound SauronID-protected request.
type CallSigHeaders struct {
	AgentID           string
	CallTS            string
	CallNonce         string
	CallSig           string
	AgentConfigDigest string
	CallAudience      string
	ProtocolVersion   string
	TenantID          string
}

// SetOn copies every header onto h. Keys use the canonical x-sauron-* form.
func (s CallSigHeaders) SetOn(h interface{ Set(string, string) }) {
	h.Set("x-sauron-agent-id", s.AgentID)
	h.Set("x-sauron-call-ts", s.CallTS)
	h.Set("x-sauron-call-nonce", s.CallNonce)
	h.Set("x-sauron-call-sig", s.CallSig)
	h.Set("x-sauron-agent-config-digest", s.AgentConfigDigest)
	h.Set("x-sauron-call-audience", s.CallAudience)
	h.Set("x-sauron-protocol-version", s.ProtocolVersion)
	h.Set("x-sauron-tenant-id", s.TenantID)
}

// SignCallParams configures SignCall.
type SignCallParams struct {
	AgentID           string
	AgentConfigDigest string
	PrivateKey        ed25519.PrivateKey
	Method            string
	Path              string
	Body              []byte
	TenantID          string
	Audience          string
	ContentType       string
}

func canonicalFields(domain string, fields [][2]string) []byte {
	var out bytes.Buffer
	push := func(value string) {
		_ = binary.Write(&out, binary.BigEndian, uint32(len([]byte(value))))
		out.WriteString(value)
	}
	push(domain)
	for _, field := range fields {
		push(field[0])
		push(field[1])
	}
	return out.Bytes()
}

// SignCall computes the canonical SauronID call signature.
//
// Payload format mirrors the Python and TypeScript SDKs byte-for-byte using
// protocol-v2's length-prefixed fields. The returned bundle includes the
// tenant selector that is itself bound into the signature.
func SignCall(p SignCallParams) (CallSigHeaders, error) {
	if len(p.PrivateKey) != ed25519.PrivateKeySize {
		return CallSigHeaders{}, fmt.Errorf("private key wrong size: got %d want %d", len(p.PrivateKey), ed25519.PrivateKeySize)
	}
	ts := time.Now().UnixMilli()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return CallSigHeaders{}, fmt.Errorf("sign call: read nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce[:])
	bodyHash := sha256.Sum256(p.Body)
	tenantID := p.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	audience := p.Audience
	if audience == "" {
		audience = "sauron-core"
	}
	payload := canonicalFields("sauron.call.v2", [][2]string{
		{"version", "2"},
		{"agent_id", p.AgentID},
		{"tenant_id", tenantID},
		{"audience", audience},
		{"method", strings.ToUpper(p.Method)},
		{"target_uri", p.Path},
		{"content_type", strings.ToLower(strings.TrimSpace(p.ContentType))},
		{"body_sha256", hex.EncodeToString(bodyHash[:])},
		{"config_digest", p.AgentConfigDigest},
		{"timestamp_ms", fmt.Sprintf("%d", ts)},
		{"nonce", nonceHex},
	})
	sig := ed25519.Sign(p.PrivateKey, payload)
	return CallSigHeaders{
		AgentID:           p.AgentID,
		CallTS:            fmt.Sprintf("%d", ts),
		CallNonce:         nonceHex,
		CallSig:           base64.RawURLEncoding.EncodeToString(sig),
		AgentConfigDigest: p.AgentConfigDigest,
		CallAudience:      audience,
		ProtocolVersion:   "2",
		TenantID:          tenantID,
	}, nil
}
