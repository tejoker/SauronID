pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionSetNonMembership — proves that the `tool` field of a committed
 * action-log entry is NOT a member of the denylist set committed at
 * `denylistRoot`, using a sorted-Merkle-SMT-style non-membership proof.
 *
 * Strategy: the denylist set is committed as a sorted Merkle tree of pairs
 * (low, high) such that low < high are adjacent set members; we prove that
 * `toolValue` falls strictly between two adjacent committed elements
 * (low < toolValue < high) by Merkle-verifying the pair leaf.
 *
 * Public inputs:
 *   - root        : action-log Merkle root
 *   - denylistRoot: sorted-pair denylist Merkle root
 *   - entryIndex  : index of entry in the action-log
 *
 * Private inputs:
 *   - entry[entryFields]            : the action-log entry
 *   - entryPathElements[levels]     : action-log path siblings
 *   - entryPathIndices[levels]      : action-log path indicators
 *   - toolValue                     : value being proven non-member
 *   - low, high                     : adjacent denylist members straddling toolValue
 *   - pairPathElements[setLevels]   : siblings for pair leaf Merkle path
 *   - pairPathIndices[setLevels]    : indicators for pair leaf Merkle path
 *
 * The denylist leaf format is Poseidon(low, high, 2). Operators MUST build
 * the denylist tree with leaves sorted ascending by `low`. Sentinel leaves
 * (low=0, high=2^64-1 endpoints) cover values outside the represented range.
 * Depth ≤ 20 for both trees.
 */
template ActionSetNonMembership(levels, setLevels, entryFields) {
    // Public inputs
    signal input root;
    signal input denylistRoot;
    signal input entryIndex;

    // Private inputs
    signal input entry[entryFields];
    signal input entryPathElements[levels];
    signal input entryPathIndices[levels];
    signal input toolValue;
    signal input low;
    signal input high;
    signal input pairPathElements[setLevels];
    signal input pairPathIndices[setLevels];

    // Public output
    signal output valid;

    // Protocol tuple offset 3 is tool id.
    entry[3] === toolValue;

    // circomlib's 64-bit comparators are sound only when all operands are
    // explicitly range constrained. Without these gadgets, a prover can use
    // a large BN254 field element and exploit modular wraparound.
    component toolBits = Num2Bits(64);
    component lowBits = Num2Bits(64);
    component highBits = Num2Bits(64);
    toolBits.in <== toolValue;
    lowBits.in <== low;
    highBits.in <== high;

    // ─── 2. low < toolValue < high (strict gap) ───
    component cmpLow = LessThan(64);
    cmpLow.in[0] <== low;
    cmpLow.in[1] <== toolValue;
    cmpLow.out === 1;

    component cmpHigh = LessThan(64);
    cmpHigh.in[0] <== toolValue;
    cmpHigh.in[1] <== high;
    cmpHigh.out === 1;

    // ─── 3. Action-log Merkle path verification ───
    component leafHasher = Poseidon(entryFields);
    for (var f = 0; f < entryFields; f++) {
        leafHasher.inputs[f] <== entry[f];
    }
    component idxBits = Num2Bits(levels);
    idxBits.in <== entryIndex;

    component logHashers[levels];
    component logMux[levels];
    signal logLevels[levels + 1];
    logLevels[0] <== leafHasher.out;

    for (var i = 0; i < levels; i++) {
        entryPathIndices[i] === idxBits.out[i];

        logMux[i] = MultiMux1(2);
        logMux[i].c[0][0] <== logLevels[i];
        logMux[i].c[0][1] <== entryPathElements[i];
        logMux[i].c[1][0] <== entryPathElements[i];
        logMux[i].c[1][1] <== logLevels[i];
        logMux[i].s <== entryPathIndices[i];

        logHashers[i] = Poseidon(2);
        logHashers[i].inputs[0] <== logMux[i].out[0];
        logHashers[i].inputs[1] <== logMux[i].out[1];
        logLevels[i + 1] <== logHashers[i].out;
    }
    component logRootCheck = IsEqual();
    logRootCheck.in[0] <== logLevels[levels];
    logRootCheck.in[1] <== root;
    logRootCheck.out === 1;

    // ─── 4. Sorted-pair leaf Poseidon(low, high, 2) Merkle path ───
    component pairLeafHasher = Poseidon(3);
    pairLeafHasher.inputs[0] <== low;
    pairLeafHasher.inputs[1] <== high;
    pairLeafHasher.inputs[2] <== 2;

    component setHashers[setLevels];
    component setMux[setLevels];
    signal setLevelHashes[setLevels + 1];
    setLevelHashes[0] <== pairLeafHasher.out;

    for (var i = 0; i < setLevels; i++) {
        pairPathIndices[i] * (1 - pairPathIndices[i]) === 0;

        setMux[i] = MultiMux1(2);
        setMux[i].c[0][0] <== setLevelHashes[i];
        setMux[i].c[0][1] <== pairPathElements[i];
        setMux[i].c[1][0] <== pairPathElements[i];
        setMux[i].c[1][1] <== setLevelHashes[i];
        setMux[i].s <== pairPathIndices[i];

        setHashers[i] = Poseidon(2);
        setHashers[i].inputs[0] <== setMux[i].out[0];
        setHashers[i].inputs[1] <== setMux[i].out[1];
        setLevelHashes[i + 1] <== setHashers[i].out;
    }
    component setRootCheck = IsEqual();
    setRootCheck.in[0] <== setLevelHashes[setLevels];
    setRootCheck.in[1] <== denylistRoot;
    setRootCheck.out === 1;

    valid <== 1;
}

component main {public [root, denylistRoot, entryIndex]} = ActionSetNonMembership(20, 10, 6);
