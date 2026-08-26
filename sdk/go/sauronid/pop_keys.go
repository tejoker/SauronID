package sauronid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// PopKeyPair holds an Ed25519 Proof-of-Possession keypair.
//
// PrivateKey is the full 64-byte ed25519 private key (seed + public).
// PublicKeyB64u is the base64url-no-padding encoding of the 32-byte
// public key (the value the server stores as the agent's PoP key).
type PopKeyPair struct {
	PrivateKey    ed25519.PrivateKey
	PublicKey     ed25519.PublicKey
	PublicKeyB64u string
}

// GeneratePopKeyPair returns a fresh Ed25519 keypair.
func GeneratePopKeyPair() (*PopKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate pop keypair: %w", err)
	}
	return &PopKeyPair{
		PrivateKey:    priv,
		PublicKey:     pub,
		PublicKeyB64u: base64.RawURLEncoding.EncodeToString(pub),
	}, nil
}

// SignPopChallenge returns base64url-no-padding(ed25519(msg)).
func SignPopChallenge(kp *PopKeyPair, msg []byte) string {
	sig := ed25519.Sign(kp.PrivateKey, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyPopChallenge returns true if `sigB64u` is a valid Ed25519
// signature of `msg` under `publicKey` (provided in either raw bytes or
// base64url-no-padding).
func VerifyPopChallenge(publicKey []byte, msg []byte, sigB64u string) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64u)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, msg, sig)
}
