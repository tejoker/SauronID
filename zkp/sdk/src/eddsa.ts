/**
 * SauronID EdDSA Module — BabyJubJub EdDSA signing compatible with circom's EdDSAPoseidonVerifier.
 *
 * Uses circomlibjs to generate keys, sign, and verify using the same curve and hash
 * that the Circom circuits expect.
 */

// @ts-ignore — circomlibjs has no types
const circomlibjs = require("circomlibjs");

export interface EdDSAKeyPair {
    privKey: Buffer;
    pubKey: [bigint, bigint]; // [Ax, Ay] on BabyJubJub
}

export interface EdDSASignature {
    R8: [bigint, bigint]; // [R8x, R8y]
    S: bigint;
}

let eddsaInstance: any = null;
let babyJubInstance: any = null;

/**
 * Initialize the EdDSA and BabyJub instances (lazy singleton).
 */
async function getEdDSA(): Promise<any> {
    if (!eddsaInstance) {
        eddsaInstance = await circomlibjs.buildEddsa();
        babyJubInstance = await circomlibjs.buildBabyjub();
    }
    return { eddsa: eddsaInstance, babyJub: babyJubInstance };
}

/**
 * Generate a new EdDSA key pair on BabyJubJub.
 */
export async function generateKeyPair(): Promise<EdDSAKeyPair> {
    const { eddsa } = await getEdDSA();

    // Generate a random 32-byte private key
    const privKey = Buffer.from(
        Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))
    );

    const pubKey = eddsa.prv2pub(privKey);

    return {
        privKey,
        pubKey: [
            eddsa.F.toObject(pubKey[0]),
            eddsa.F.toObject(pubKey[1]),
        ],
    };
}

/**
 * Generate a deterministic key pair from a seed (for testing).
 */
export async function keyPairFromSeed(seed: string): Promise<EdDSAKeyPair> {
    const { eddsa } = await getEdDSA();
    const crypto = require("crypto");
    const privKey = crypto.createHash("sha256").update(seed).digest();
    const pubKey = eddsa.prv2pub(privKey);

    return {
        privKey,
        pubKey: [
            eddsa.F.toObject(pubKey[0]),
            eddsa.F.toObject(pubKey[1]),
        ],
    };
}

/**
 * Sign a message (field element) with EdDSA-Poseidon.
 * The message should be a BigInt representing the Poseidon hash of the data.
 */
export async function sign(
    message: bigint,
    privKey: Buffer
): Promise<EdDSASignature> {
    const { eddsa } = await getEdDSA();
    const msgF = eddsa.F.e(message);
    const sig = eddsa.signPoseidon(privKey, msgF);

    return {
        R8: [eddsa.F.toObject(sig.R8[0]), eddsa.F.toObject(sig.R8[1])],
        S: sig.S,
    };
}

/**
 * Verify an EdDSA-Poseidon signature.
 */
export async function verify(
    message: bigint,
    signature: EdDSASignature,
    pubKey: [bigint, bigint]
): Promise<boolean> {
    const { eddsa } = await getEdDSA();
    const msgF = eddsa.F.e(message);
    const pubKeyF = [eddsa.F.e(pubKey[0]), eddsa.F.e(pubKey[1])];

    const sig = {
        R8: [eddsa.F.e(signature.R8[0]), eddsa.F.e(signature.R8[1])],
        S: signature.S,
    };

    return eddsa.verifyPoseidon(msgF, sig, pubKeyF);
}
