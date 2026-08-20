pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

/**
 * SignedLogEntry — generalization of CredentialVerification for the
 * `agent_action_receipts` action-log domain.
 *
 * Proves the prover knows a tuple (h, sig, path) such that:
 *   1. MerkleVerify(root, h, path) — h is the leaf of a Merkle path that
 *      reproduces the public `root`.
 *   2. EdDSAPoseidon(pubkey, h, sig) — the leaf hash h was signed by `pubkey`.
 *
 * Public inputs:
 *   - root              : Merkle root of the action-log tree
 *   - pubkeyAx, pubkeyAy: BabyJubJub pubkey of the agent / signer
 *
 * Private inputs:
 *   - leafHash          : Poseidon hash of the log entry (h)
 *   - sigR8x, sigR8y, sigS : EdDSA-Poseidon signature components (sig)
 *   - pathElements[levels] : sibling hashes along the Merkle path
 *   - pathIndices[levels]  : 0/1 left/right indicators along the Merkle path
 *
 * Depth bound: parameterized; depth ≤ 20 in the default `main`. Action-log trees
 * in production may exceed this — operators must compile a larger template if
 * the tree depth grows. See zkp/ceremony/circuits-list.json for the depth used
 * by the dev verification keys.
 */
template SignedLogEntry(levels) {
    // Private inputs
    signal input leafHash;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Public inputs
    signal input root;
    signal input pubkeyAx;
    signal input pubkeyAy;

    // Public output
    signal output valid;

    // Step 1: Merkle path verification
    component hashers[levels];
    component mux[levels];
    signal levelHashes[levels + 1];
    levelHashes[0] <== leafHash;

    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].out;
    }

    component rootCheck = IsEqual();
    rootCheck.in[0] <== levelHashes[levels];
    rootCheck.in[1] <== root;
    rootCheck.out === 1;

    // Step 2: EdDSA-Poseidon signature on leafHash
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pubkeyAx;
    sigVerifier.Ay <== pubkeyAy;
    sigVerifier.S <== sigS;
    sigVerifier.R8x <== sigR8x;
    sigVerifier.R8y <== sigR8y;
    sigVerifier.M <== leafHash;

    valid <== 1;
}

component main {public [root, pubkeyAx, pubkeyAy]} = SignedLogEntry(20);
