import { randomBytes } from "crypto";
import { ristretto255 } from "@noble/curves/ed25519.js";

/** Two distinct random compressed-Ristretto hex strings (64 hex chars) for parent/child agents. */
// Ristretto255 group order.
const RISTRETTO_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

/**
 * Random unique Ristretto255 point as 64-char hex.
 * Safe for concurrent runs: uses 32 random bytes as scalar seed.
 */
export function randomRistrettoHex(): string {
    const seed = randomBytes(32);
    const scalar = BigInt("0x" + seed.toString("hex")) % RISTRETTO_ORDER || 1n;
    return Buffer.from(ristretto255.Point.BASE.multiply(scalar).toBytes()).toString("hex");
}
