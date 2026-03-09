pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * AgeVerification — Proves that a user meets an age threshold without revealing
 * their actual date of birth.
 *
 * The issuer signs the Poseidon hash of the date of birth (as YYYYMMDD integer).
 * The circuit verifies:
 *   1. The issuer's EdDSA-Poseidon signature on H(dateOfBirth) is valid
 *   2. (currentDate - dateOfBirth) >= ageThreshold * 10000
 *      (using YYYYMMDD integer encoding: 20260304 - 19900101 = 360203 >= 18*10000 = 180000)
 *
 * Private inputs: dateOfBirth, issuer signature components (R8x, R8y, S)
 * Public inputs:  ageThreshold, currentDate, issuer public key (Ax, Ay)
 */
template AgeVerification() {
    // ─── Private inputs ──────────────────────────────────────
    signal input dateOfBirth;        // YYYYMMDD as integer, e.g. 19900315
    signal input issuerSigR8x;       // EdDSA signature R8.x
    signal input issuerSigR8y;       // EdDSA signature R8.y
    signal input issuerSigS;         // EdDSA signature S

    // ─── Public inputs ───────────────────────────────────────
    signal input ageThreshold;       // e.g. 18
    signal input currentDate;        // YYYYMMDD as integer, e.g. 20260304
    signal input issuerPubKeyAx;     // Issuer public key Ax (BabyJubJub)
    signal input issuerPubKeyAy;     // Issuer public key Ay (BabyJubJub)

    // ─── Public output ───────────────────────────────────────
    signal output valid;

    // ─── Step 1: Hash the date of birth with Poseidon ────────
    component hasher = Poseidon(1);
    hasher.inputs[0] <== dateOfBirth;
    // hasher.out = Poseidon(dateOfBirth)

    // ─── Step 2: Verify issuer signature on the hash ─────────
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== issuerPubKeyAx;
    sigVerifier.Ay <== issuerPubKeyAy;
    sigVerifier.S <== issuerSigS;
    sigVerifier.R8x <== issuerSigR8x;
    sigVerifier.R8y <== issuerSigR8y;
    sigVerifier.M <== hasher.out;
    // If signature is invalid, the circuit constraints will fail

    // ─── Step 3: Compute age difference ──────────────────────
    // ageDiff = currentDate - dateOfBirth (in YYYYMMDD encoding)
    // ageThresholdScaled = ageThreshold * 10000
    // We need ageDiff >= ageThresholdScaled
    signal ageDiff;
    ageDiff <== currentDate - dateOfBirth;

    signal ageThresholdScaled;
    ageThresholdScaled <== ageThreshold * 10000;

    // ─── Step 4: Check ageDiff >= ageThresholdScaled ─────────
    // Using 32-bit comparator GreaterEqualThan (sufficient for YYYYMMDD range)
    // Note: The template is actually GreaterEqThan in circomlib.
    component geq = GreaterEqThan(32);
    geq.in[0] <== ageDiff;
    geq.in[1] <== ageThresholdScaled;

    valid <== geq.out;

    // Constrain valid to be 1 (proof is only valid if age check passes)
    valid === 1;
}

component main {public [ageThreshold, currentDate, issuerPubKeyAx, issuerPubKeyAy]} = AgeVerification();
