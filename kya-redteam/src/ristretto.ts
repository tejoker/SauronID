import { ristretto255 } from "@noble/curves/ed25519.js";

/** Two distinct valid compressed-Ristretto hex strings (64 hex chars) for parent/child agents. */
export function twoRistrettoHexes(): { pk1: string; pk2: string } {
    const p1 = ristretto255.Point.BASE;
    const p2 = p1.multiply(3n);
    const hex = (p: typeof p1) => Buffer.from(p.toBytes()).toString("hex");
    return { pk1: hex(p1), pk2: hex(p2) };
}
