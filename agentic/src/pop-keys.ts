/**
 * SauronID Proof-of-Possession Keys — Ephemeral Ed25519 key pairs for A-JWT binding.
 *
 * Each agent session generates a fresh Ed25519 key pair. The public key is embedded
 * in the A-JWT via the `cnf` (confirmation) claim as a JWK thumbprint.
 * This binds the token to the specific agent process, preventing:
 *   - Token theft (stolen token can't be used without the private key)
 *   - Replay attacks (each session has unique keys)
 *   - Cross-process usage (keys are non-exportable in production)
 */

import * as crypto from "crypto";
import * as jose from "jose";

export interface PopKeyPair {
    /** Ed25519 private key (CryptoKey or KeyObject) */
    privateKey: crypto.KeyObject;
    /** Ed25519 public key */
    publicKey: crypto.KeyObject;
    /** Key ID (random UUID) */
    kid: string;
    /** JWK representation of the public key */
    publicJwk: jose.JWK;
    /** JWK thumbprint (for the `cnf` JWT claim) */
    thumbprint: string;
    /** Creation timestamp */
    createdAt: Date;
}

/**
 * Generate a new ephemeral Ed25519 key pair for Proof-of-Possession.
 *
 * These keys are session-scoped:
 *   - Generated when the agent starts
 *   - Used to sign PoP challenges
 *   - Destroyed when the agent session ends
 *
 * @returns PopKeyPair with private key, public JWK, and thumbprint
 */
export async function generatePopKeyPair(): Promise<PopKeyPair> {
    // Generate Ed25519 key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

    const kid = crypto.randomUUID();

    // Export public key as JWK
    const publicJwk = publicKey.export({ format: "jwk" }) as jose.JWK;
    publicJwk.kid = kid;
    publicJwk.use = "sig";
    publicJwk.alg = "EdDSA";

    // Compute JWK thumbprint (RFC 7638)
    // For Ed25519: SHA-256 of canonical {"crv":"Ed25519","kty":"OKP","x":"..."}
    const thumbprintInput = JSON.stringify({
        crv: publicJwk.crv,
        kty: publicJwk.kty,
        x: publicJwk.x,
    });
    const thumbprint = crypto
        .createHash("sha256")
        .update(thumbprintInput)
        .digest("base64url");

    return {
        privateKey,
        publicKey,
        kid,
        publicJwk,
        thumbprint,
        createdAt: new Date(),
    };
}

/**
 * Sign a PoP challenge with the ephemeral private key.
 *
 * Used during token acquisition to prove possession of the key
 * that matches the `cnf` claim in the A-JWT.
 *
 * @param challenge   The challenge string from the IdP
 * @param keyPair     The agent's PoP key pair
 * @returns           Compact JWS (signed challenge)
 */
export async function signPopChallenge(
    challenge: string,
    keyPair: PopKeyPair
): Promise<string> {
    const jws = await new jose.CompactSign(
        new TextEncoder().encode(challenge)
    )
        .setProtectedHeader({
            alg: "EdDSA",
            kid: keyPair.kid,
            typ: "pop+jwt",
        })
        .sign(keyPair.privateKey);

    return jws;
}

/**
 * Verify a PoP challenge signature.
 *
 * @param jws         The signed challenge JWS
 * @param publicKey   The agent's public key
 * @returns           The decoded challenge payload
 */
export async function verifyPopChallenge(
    jws: string,
    publicKey: crypto.KeyObject
): Promise<{ payload: string; valid: boolean }> {
    try {
        const { payload } = await jose.compactVerify(jws, publicKey);
        return {
            payload: new TextDecoder().decode(payload),
            valid: true,
        };
    } catch {
        return { payload: "", valid: false };
    }
}
