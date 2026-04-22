pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * PoseidonHasher — reused from MerkleInclusion.
 */
template PoseidonHasher2() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

/**
 * MerklePathVerifier — verifies a Merkle proof from leaf to root.
 * @param levels  Number of levels in the tree (holds 2^levels leaves).
 */
template MerklePathVerifier2(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    component mux[levels];
    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = PoseidonHasher2();
        hashers[i].left  <== mux[i].out[0];
        hashers[i].right <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].hash;
    }
    root <== levelHashes[levels];
}

/**
 * PaymentNonMembershipSMT
 *
 * Proves that an agent has NO consumed payment recorded in a 30-day window.
 *
 * Private inputs:
 *   - leafValue        : must be 0 (no payment consumed)
 *   - pathElements[20] : Merkle siblings along the path from the leaf to the root
 *   - pathIndices[20]  : direction bits (0=left, 1=right)
 *
 * Public inputs:
 *   - keyHigh, keyLow  : 128-bit halves of SHA256(agent_id|window_start)
 *                        split to fit within the BN254 scalar field
 *   - windowStart      : Unix timestamp of the 30-day window start
 *   - smtRoot          : current Poseidon SMT root
 *
 * The leaf hash is: Poseidon(keyHigh, keyLow, leafValue)
 * The circuit constrains leafValue === 0, proving non-payment.
 */
template PaymentNonMembershipSMT(levels) {
    // Private
    signal input leafValue;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Public
    signal input keyHigh;
    signal input keyLow;
    signal input windowStart;
    signal input smtRoot;

    // 1. Enforce non-membership: leafValue must be 0.
    leafValue === 0;

    // 2. Compute leaf hash: Poseidon(keyHigh, keyLow, 0)
    component leafHasher = Poseidon(3);
    leafHasher.inputs[0] <== keyHigh;
    leafHasher.inputs[1] <== keyLow;
    leafHasher.inputs[2] <== leafValue;

    // 3. Verify Merkle path from leaf to root.
    component pathVerifier = MerklePathVerifier2(levels);
    pathVerifier.leaf <== leafHasher.out;
    for (var i = 0; i < levels; i++) {
        pathVerifier.pathElements[i] <== pathElements[i];
        pathVerifier.pathIndices[i]  <== pathIndices[i];
    }

    // 4. Constrain computed root to equal the public smtRoot.
    pathVerifier.root === smtRoot;

    // windowStart is a public input — the verifier pins it externally.
    // No additional constraint needed; snarkjs will include it in publicSignals.
}

component main {public [keyHigh, keyLow, windowStart, smtRoot]} =
    PaymentNonMembershipSMT(20);
