pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * PoseidonHasher — Hashes two children to produce the parent in a Merkle tree.
 * Uses Poseidon(left, right) which is ~300 constraints (vs ~28000 for SHA-256).
 */
template PoseidonHasher() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

/**
 * MerklePathVerifier — Verifies a Merkle proof from leaf to root.
 * @param levels  Number of levels in the tree (tree can hold 2^levels leaves)
 */
template MerklePathVerifier(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];     // 0 = leaf is left child, 1 = leaf is right child
    signal output root;

    component hashers[levels];
    component mux[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // pathIndices must be binary
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = PoseidonHasher();
        hashers[i].left <== mux[i].out[0];
        hashers[i].right <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].hash;
    }

    root <== levelHashes[levels];
}

/**
 * MerkleInclusion — Proves:
 *   1. A credential hash IS in the inclusion Sparse Merkle Tree
 *   2. The credential hash is NOT in the revocation SMT
 *   3. The issuer signed the inclusion root with EdDSA-Poseidon
 *
 * @param inclusionLevels  Depth of the inclusion SMT
 * @param revocationLevels Depth of the revocation SMT
 */
template MerkleInclusion(inclusionLevels, revocationLevels) {
    // ─── Private inputs ──────────────────────────────────────
    signal input credentialHash;

    // Inclusion proof
    signal input inclusionPathElements[inclusionLevels];
    signal input inclusionPathIndices[inclusionLevels];

    // Revocation non-membership proof (sibling path for zero-leaf)
    signal input revocationPathElements[revocationLevels];
    signal input revocationPathIndices[revocationLevels];
    signal input revocationLeafValue;  // Must be 0 to prove non-membership

    // Issuer signature on inclusion root
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // ─── Public inputs ───────────────────────────────────────
    signal input inclusionRoot;
    signal input revocationRoot;
    signal input issuerPubKeyAx;
    signal input issuerPubKeyAy;

    // ─── Public output ───────────────────────────────────────
    signal output valid;

    // ─── Step 1: Verify inclusion proof ──────────────────────
    component inclusionVerifier = MerklePathVerifier(inclusionLevels);
    inclusionVerifier.leaf <== credentialHash;
    for (var i = 0; i < inclusionLevels; i++) {
        inclusionVerifier.pathElements[i] <== inclusionPathElements[i];
        inclusionVerifier.pathIndices[i] <== inclusionPathIndices[i];
    }

    // The computed root must match the public inclusion root
    component rootCheck = IsEqual();
    rootCheck.in[0] <== inclusionVerifier.root;
    rootCheck.in[1] <== inclusionRoot;
    rootCheck.out === 1;

    // ─── Step 2: Verify non-revocation ───────────────────────
    // Prove that at the position of credentialHash in the revocation tree,
    // the leaf value is 0 (empty slot = not revoked)
    revocationLeafValue === 0;

    // The position in the revocation tree MUST match the bits of the credentialHash
    component hashBits = Num2Bits(revocationLevels);
    hashBits.in <== credentialHash;

    component revocationVerifier = MerklePathVerifier(revocationLevels);
    revocationVerifier.leaf <== revocationLeafValue;
    for (var i = 0; i < revocationLevels; i++) {
        revocationVerifier.pathElements[i] <== revocationPathElements[i];
        
        // CONSTRAIN path indices to the actual credentialHash bits
        revocationPathIndices[i] === hashBits.out[i];
        revocationVerifier.pathIndices[i] <== revocationPathIndices[i];
    }

    // The computed revocation root must match
    component revRootCheck = IsEqual();
    revRootCheck.in[0] <== revocationVerifier.root;
    revRootCheck.in[1] <== revocationRoot;
    revRootCheck.out === 1;

    // ─── Step 3: Verify issuer signature on inclusion root ───
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== issuerPubKeyAx;
    sigVerifier.Ay <== issuerPubKeyAy;
    sigVerifier.S <== issuerSigS;
    sigVerifier.R8x <== issuerSigR8x;
    sigVerifier.R8y <== issuerSigR8y;
    sigVerifier.M <== inclusionRoot;

    valid <== 1;
}

component main {public [inclusionRoot, revocationRoot, issuerPubKeyAx, issuerPubKeyAy]} = MerkleInclusion(10, 10);
