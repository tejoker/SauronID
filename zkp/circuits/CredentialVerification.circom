pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

/**
 * PoseidonHasher2 — Hash two values with Poseidon.
 */
template PoseidonHasher2() {
    signal input left;
    signal input right;
    signal output hash;
    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    hash <== h.out;
}

/**
 * MerklePath — Verifies a Merkle proof.
 */
template MerklePath(levels) {
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
        hashers[i].left <== mux[i].out[0];
        hashers[i].right <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].hash;
    }
    root <== levelHashes[levels];
}

/**
 * CredentialVerification — Master proof circuit for SauronID.
 *
 * Combines:
 *   1. EdDSA signature verification on the full credential hash
 *   2. Age threshold verification (selective disclosure)
 *   3. Nationality match (selective disclosure)
 *   4. Merkle inclusion proof (credential is in the issuer's tree)
 *
 * The credential is a Poseidon hash of 5 claims:
 *   H(dateOfBirth, nationality, documentNumber, expiryDate, issuerId)
 *
 * The prover selectively reveals:
 *   - Whether they meet an age threshold (without revealing DOB)
 *   - Whether they match a required nationality (without revealing it unless desired)
 *
 * @param treeLevels  Depth of the inclusion Merkle tree
 */
template CredentialVerification(treeLevels) {
    // ─── Private credential data ─────────────────────────────
    signal input dateOfBirth;        // YYYYMMDD integer
    signal input nationality;        // Field element (packed string hash)
    signal input documentNumber;     // Field element (packed string hash)
    signal input expiryDate;         // YYYYMMDD integer
    signal input issuerId;           // Field element identifying the issuer

    // ─── Private issuer signature ────────────────────────────
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // ─── Private Merkle inclusion proof ──────────────────────
    signal input merklePathElements[treeLevels];
    signal input merklePathIndices[treeLevels];

    // ─── Public inputs ───────────────────────────────────────
    signal input currentDate;        // YYYYMMDD integer
    signal input ageThreshold;       // e.g. 18
    signal input requiredNationality;// Field element (0 if no nationality check)
    signal input merkleRoot;         // Expected inclusion tree root
    signal input issuerPubKeyAx;     // Issuer public key
    signal input issuerPubKeyAy;

    // ─── Public outputs ──────────────────────────────────────
    signal output ageVerified;       // 1 if age >= threshold
    signal output nationalityMatched;// 1 if nationality matches (or 0 if no check)
    signal output credentialValid;   // 1 if all checks pass

    // ═══ Step 1: Compute credential hash ═════════════════════
    component credHasher = Poseidon(5);
    credHasher.inputs[0] <== dateOfBirth;
    credHasher.inputs[1] <== nationality;
    credHasher.inputs[2] <== documentNumber;
    credHasher.inputs[3] <== expiryDate;
    credHasher.inputs[4] <== issuerId;
    signal credentialHash;
    credentialHash <== credHasher.out;

    // ═══ Step 2: Verify issuer EdDSA signature on credential hash ═══
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== issuerPubKeyAx;
    sigVerifier.Ay <== issuerPubKeyAy;
    sigVerifier.S <== issuerSigS;
    sigVerifier.R8x <== issuerSigR8x;
    sigVerifier.R8y <== issuerSigR8y;
    sigVerifier.M <== credentialHash;

    // ═══ Step 3: Age verification ════════════════════════════
    signal ageDiff;
    ageDiff <== currentDate - dateOfBirth;
    signal ageThresholdScaled;
    ageThresholdScaled <== ageThreshold * 10000;

    component ageCheck = GreaterEqThan(32);
    ageCheck.in[0] <== ageDiff;
    ageCheck.in[1] <== ageThresholdScaled;
    ageVerified <== ageCheck.out;

    // ═══ Step 4: Nationality match ═══════════════════════════
    // If requiredNationality == 0, skip nationality check (output 1)
    // Otherwise check nationality == requiredNationality
    component natCheck = IsEqual();
    natCheck.in[0] <== nationality;
    natCheck.in[1] <== requiredNationality;

    component reqIsZero = IsZero();
    reqIsZero.in <== requiredNationality;

    // nationalityMatched = reqIsZero OR natCheck
    // = reqIsZero + natCheck - reqIsZero * natCheck
    signal natProduct;
    natProduct <== reqIsZero.out * natCheck.out;
    nationalityMatched <== reqIsZero.out + natCheck.out - natProduct;

    // ═══ Step 5: Merkle inclusion proof ══════════════════════
    component merkleVerifier = MerklePath(treeLevels);
    merkleVerifier.leaf <== credentialHash;
    for (var i = 0; i < treeLevels; i++) {
        merkleVerifier.pathElements[i] <== merklePathElements[i];
        merkleVerifier.pathIndices[i] <== merklePathIndices[i];
    }

    component merkleRootCheck = IsEqual();
    merkleRootCheck.in[0] <== merkleVerifier.root;
    merkleRootCheck.in[1] <== merkleRoot;
    merkleRootCheck.out === 1;

    // ═══ Step 6: Document not expired ════════════════════════
    component expiryCheck = GreaterEqThan(32);
    expiryCheck.in[0] <== expiryDate;
    expiryCheck.in[1] <== currentDate;

    // ═══ Step 7: Combined validity ═══════════════════════════
    // credentialValid = ageVerified AND nationalityMatched AND expiryCheck
    signal temp;
    temp <== ageVerified * nationalityMatched;
    credentialValid <== temp * expiryCheck.out;

    // Constrain that the credential must be valid
    credentialValid === 1;
}

component main {public [currentDate, ageThreshold, requiredNationality, merkleRoot, issuerPubKeyAx, issuerPubKeyAy]} = CredentialVerification(10);
