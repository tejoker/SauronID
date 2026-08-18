pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionSumBound — proves that Σ amount(entry_i) ≤ budget over a public
 * contiguous range of N entry indices.
 *
 * Each entry is committed as Poseidon(entry[0..entryFields]). The amount lies
 * at protocol tuple offset 2, fixed in the circuit.
 *
 * Public inputs:
 *   - root        : Merkle root of the action-log tree
 *   - budget      : upper bound on the sum (64-bit)
 *   - iLo, iHi    : inclusive range of entry indices (iHi = iLo + N - 1)
 *
 * Private inputs:
 *   - entries[N][entryFields]      : the entries
 *   - pathElements[N][levels]      : Merkle sibling hashes per entry
 *   - pathIndices[N][levels]       : left/right indicators per entry
 *
 * Bound: 64-bit sum comparator (allows summing many 32-bit amounts safely).
 *
 * Depth ≤ 20 levels; entries fixed at N = 4 in `main` (operators recompile
 * for larger windows). See zkp/ceremony/circuits-list.json.
 */
template ActionSumBound(levels, entryFields, N) {
    // Public inputs
    signal input root;
    signal input budget;
    signal input iLo;
    signal input iHi;

    // Private inputs
    signal input entries[N][entryFields];
    signal input pathElements[N][levels];
    signal input pathIndices[N][levels];

    // Public output
    signal output valid;

    // iHi == iLo + N - 1
    iHi === iLo + (N - 1);

    // Per-entry: extract amount, hash leaf, verify Merkle path at index iLo+k
    component leafHasher[N];
    component idxBits[N];
    component hashers[N][levels];
    component mux[N][levels];
    component rootCheck[N];
    component amountBits[N];

    signal extracted[N];
    signal pathLevels[N][levels + 1];

    for (var k = 0; k < N; k++) {
        // Protocol tuple offset 2 is amount; the prover cannot redirect the
        // budget comparison to a different private column.
        extracted[k] <== entries[k][2];
        amountBits[k] = Num2Bits(32);
        amountBits[k].in <== extracted[k];

        // Hash the leaf.
        leafHasher[k] = Poseidon(entryFields);
        for (var f = 0; f < entryFields; f++) {
            leafHasher[k].inputs[f] <== entries[k][f];
        }

        // Decompose (iLo + k) into bits, constrain pathIndices to match.
        idxBits[k] = Num2Bits(levels);
        idxBits[k].in <== iLo + k;

        pathLevels[k][0] <== leafHasher[k].out;
        for (var i = 0; i < levels; i++) {
            pathIndices[k][i] === idxBits[k].out[i];

            mux[k][i] = MultiMux1(2);
            mux[k][i].c[0][0] <== pathLevels[k][i];
            mux[k][i].c[0][1] <== pathElements[k][i];
            mux[k][i].c[1][0] <== pathElements[k][i];
            mux[k][i].c[1][1] <== pathLevels[k][i];
            mux[k][i].s <== pathIndices[k][i];

            hashers[k][i] = Poseidon(2);
            hashers[k][i].inputs[0] <== mux[k][i].out[0];
            hashers[k][i].inputs[1] <== mux[k][i].out[1];
            pathLevels[k][i + 1] <== hashers[k][i].out;
        }

        rootCheck[k] = IsEqual();
        rootCheck[k].in[0] <== pathLevels[k][levels];
        rootCheck[k].in[1] <== root;
        rootCheck[k].out === 1;
    }

    // Sum: accumulator + comparator
    signal sums[N + 1];
    sums[0] <== 0;
    for (var k = 0; k < N; k++) {
        sums[k + 1] <== sums[k] + extracted[k];
    }
    signal total;
    total <== sums[N];

    component totalBits = Num2Bits(64);
    component budgetBits = Num2Bits(64);
    totalBits.in <== total;
    budgetBits.in <== budget;

    component le = LessEqThan(64);
    le.in[0] <== total;
    le.in[1] <== budget;
    le.out === 1;

    valid <== 1;
}

component main {public [root, budget, iLo, iHi]} = ActionSumBound(20, 6, 4);
