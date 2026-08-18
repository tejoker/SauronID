pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionTimeWindow — proves the `timestamp` field of a committed action-log
 * entry falls within [start, end].
 *
 * Public inputs:
 *   - root        : action-log Merkle root
 *   - start, end  : inclusive time window (e.g. unix epoch seconds)
 *   - entryIndex  : index of the entry
 *
 * Private inputs:
 *   - entry[entryFields]         : action-log entry
 *   - pathElements[levels]       : Merkle siblings
 *   - pathIndices[levels]        : left/right indicators
 *   - timestamp is fixed to protocol tuple offset 5
 *
 * Bound: 64-bit comparators (epoch seconds easily fit).
 *
 * Depth ≤ 20 in the default `main` instantiation; recompile for deeper trees.
 */
template ActionTimeWindow(levels, entryFields) {
    // Public inputs
    signal input root;
    signal input start;
    signal input end;
    signal input entryIndex;

    // Private inputs
    signal input entry[entryFields];
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Public output
    signal output valid;

    signal ts;
    // Protocol tuple offset 5 is timestamp.
    ts <== entry[5];

    component tsBits = Num2Bits(64);
    component startBits = Num2Bits(64);
    component endBits = Num2Bits(64);
    tsBits.in <== ts;
    startBits.in <== start;
    endBits.in <== end;

    // ─── 2. start ≤ ts ≤ end (64-bit range) ───
    component geStart = GreaterEqThan(64);
    geStart.in[0] <== ts;
    geStart.in[1] <== start;
    geStart.out === 1;

    component leEnd = LessEqThan(64);
    leEnd.in[0] <== ts;
    leEnd.in[1] <== end;
    leEnd.out === 1;

    // ─── 3. Merkle path verify with leaf = Poseidon(entry) ───
    component leafHasher = Poseidon(entryFields);
    for (var f = 0; f < entryFields; f++) {
        leafHasher.inputs[f] <== entry[f];
    }
    component idxBits = Num2Bits(levels);
    idxBits.in <== entryIndex;

    component hashers[levels];
    component mux[levels];
    signal levelHashes[levels + 1];
    levelHashes[0] <== leafHasher.out;

    for (var i = 0; i < levels; i++) {
        pathIndices[i] === idxBits.out[i];

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

    valid <== 1;
}

component main {public [root, start, end, entryIndex]} = ActionTimeWindow(20, 6);
