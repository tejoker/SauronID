pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionSetMembership — proves that the `tool` field of a committed action-log
 * entry belongs to the allowlist set committed at `allowlistRoot`.
 *
 * Two Merkle paths are checked:
 *   (a) the entry's Merkle path into the action-log (`root`, at `entryIndex`)
 *   (b) the tool value's Merkle path into the allowlist set (`allowlistRoot`)
 *
 * Public inputs:
 *   - root            : action-log Merkle root
 *   - allowlistRoot   : allowlist set Merkle root (set of tool hashes)
 *   - entryIndex      : index of the entry in the action-log
 *
 * Private inputs:
 *   - entry[entryFields]         : the action-log entry
 *   - entryPathElements[levels]  : sibling hashes for entry path
 *   - entryPathIndices[levels]   : left/right indicators for entry path
 *   - toolValue                  : Poseidon-hashable tool identifier (must equal entry[toolOffset])
 *   - toolSelector[entryFields]  : one-hot selector for the tool field
 *   - setPathElements[setLevels] : sibling hashes for set membership path
 *   - setPathIndices[setLevels]  : left/right indicators for set membership path
 *
 * Depth ≤ 20 for both trees (recompile for larger). The set tree leaves are
 * Poseidon(toolValue, 1) so that the prover cannot fake membership by
 * supplying a path whose leaf is just `toolValue`.
 */
template ActionSetMembership(levels, setLevels, entryFields) {
    // Public inputs
    signal input root;
    signal input allowlistRoot;
    signal input entryIndex;

    // Private inputs
    signal input entry[entryFields];
    signal input entryPathElements[levels];
    signal input entryPathIndices[levels];
    signal input toolValue;
    signal input setPathElements[setLevels];
    signal input setPathIndices[setLevels];

    // Public output
    signal output valid;

    // Protocol tuple offset 3 is tool id.
    entry[3] === toolValue;

    // ─── 2. Action-log Merkle path verification (leaf = Poseidon(entry)) ───
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

    // ─── 3. Set membership Merkle path (leaf = Poseidon(toolValue, 1)) ───
    component setLeafHasher = Poseidon(2);
    setLeafHasher.inputs[0] <== toolValue;
    setLeafHasher.inputs[1] <== 1;

    component setHashers[setLevels];
    component setMux[setLevels];
    signal setLevelHashes[setLevels + 1];
    setLevelHashes[0] <== setLeafHasher.out;

    for (var i = 0; i < setLevels; i++) {
        setPathIndices[i] * (1 - setPathIndices[i]) === 0;

        setMux[i] = MultiMux1(2);
        setMux[i].c[0][0] <== setLevelHashes[i];
        setMux[i].c[0][1] <== setPathElements[i];
        setMux[i].c[1][0] <== setPathElements[i];
        setMux[i].c[1][1] <== setLevelHashes[i];
        setMux[i].s <== setPathIndices[i];

        setHashers[i] = Poseidon(2);
        setHashers[i].inputs[0] <== setMux[i].out[0];
        setHashers[i].inputs[1] <== setMux[i].out[1];
        setLevelHashes[i + 1] <== setHashers[i].out;
    }

    component setRootCheck = IsEqual();
    setRootCheck.in[0] <== setLevelHashes[setLevels];
    setRootCheck.in[1] <== allowlistRoot;
    setRootCheck.out === 1;

    valid <== 1;
}

component main {public [root, allowlistRoot, entryIndex]} = ActionSetMembership(20, 10, 6);
