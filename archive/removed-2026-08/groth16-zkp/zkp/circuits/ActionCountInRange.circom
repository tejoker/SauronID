pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionCountInRange — proves that, among the entries at indices [iLo, iHi],
 * the count of entries whose field F equals V is ≤ limit.
 *
 * The prover supplies N candidate entries (the ones being counted). Each entry
 * Merkle-verifies into the action-log at its corresponding index. The prover
 * also supplies an indicator b_k ∈ {0,1} per entry, claiming "entry k matches
 * (F == V) → b_k = 1, else 0". The circuit enforces b_k consistency with the
 * (entry, F, V) data so the prover cannot under-count: an entry with field
 * F == V MUST be flagged b_k = 1. (Over-counting is impossible because Σ b_k
 * is the published count value and is bounded by ≤ limit.)
 *
 * The shipped fixed-arity circuit covers every index in [iLo, iHi] because it
 * enforces iHi=iLo+N-1 and verifies entry k at iLo+k. A larger range requires
 * a new versioned circuit or a reviewed recursive construction.
 *
 * Public inputs:
 *   - root        : action-log Merkle root
 *   - F           : public numeric tuple offset selected inside the circuit
 *   - V           : value being counted
 *   - limit       : upper bound on the count
 *   - iLo, iHi    : range of entry indices considered (iHi = iLo + N - 1)
 *
 * Private inputs:
 *   - entries[N][entryFields]      : candidate matching entries
 *   - pathElements[N][levels]      : Merkle siblings per entry
 *   - pathIndices[N][levels]       : left/right indicators per entry
 *   - matchFlag[N]                 : 0/1, 1 iff entry matches F==V
 *
 * Depth ≤ 20; N = 4 in `main`.
 */
template ActionCountInRange(levels, entryFields, N) {
    // Public inputs
    signal input root;
    signal input F;
    signal input V;
    signal input limit;
    signal input iLo;
    signal input iHi;

    // Private inputs
    signal input entries[N][entryFields];
    signal input pathElements[N][levels];
    signal input pathIndices[N][levels];
    signal input matchFlag[N];

    // Public output
    signal output valid;

    // ─── 0. Public numeric field index → circuit-derived selector ───
    component fieldIndexEq[entryFields];
    signal selectorSum[entryFields + 1];
    selectorSum[0] <== 0;
    for (var f = 0; f < entryFields; f++) {
        fieldIndexEq[f] = IsEqual();
        fieldIndexEq[f].in[0] <== F;
        fieldIndexEq[f].in[1] <== f;
        selectorSum[f + 1] <== selectorSum[f] + fieldIndexEq[f].out;
    }
    selectorSum[entryFields] === 1;

    // iHi = iLo + N - 1
    iHi === iLo + (N - 1);

    // ─── 1. Per-entry: Merkle verify + matchFlag consistency ───
    component leafHasher[N];
    component idxBits[N];
    component hashers[N][levels];
    component mux[N][levels];
    component rootCheck[N];
    component fieldEq[N];

    signal extracted[N];
    signal partials[N][entryFields + 1];
    signal pathLevels[N][levels + 1];

    for (var k = 0; k < N; k++) {
        // Extract entry[F]
        partials[k][0] <== 0;
        for (var f = 0; f < entryFields; f++) {
            partials[k][f + 1] <== partials[k][f] + fieldIndexEq[f].out * entries[k][f];
        }
        extracted[k] <== partials[k][entryFields];

        // matchFlag[k] ∈ {0,1}
        matchFlag[k] * (1 - matchFlag[k]) === 0;

        // If entry[F] == V then matchFlag[k] MUST be 1.
        // We enforce: matchFlag[k] == IsEqual(extracted[k], V).
        fieldEq[k] = IsEqual();
        fieldEq[k].in[0] <== extracted[k];
        fieldEq[k].in[1] <== V;
        matchFlag[k] === fieldEq[k].out;

        // Hash the leaf
        leafHasher[k] = Poseidon(entryFields);
        for (var f = 0; f < entryFields; f++) {
            leafHasher[k].inputs[f] <== entries[k][f];
        }

        // Merkle verify at index iLo + k
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

    // ─── 2. Σ matchFlag ≤ limit ───
    signal counts[N + 1];
    counts[0] <== 0;
    for (var k = 0; k < N; k++) {
        counts[k + 1] <== counts[k] + matchFlag[k];
    }
    signal total;
    total <== counts[N];

    component limitBits = Num2Bits(32);
    limitBits.in <== limit;

    component le = LessEqThan(32);
    le.in[0] <== total;
    le.in[1] <== limit;
    le.out === 1;

    valid <== 1;
}

component main {public [root, F, V, limit, iLo, iHi]} = ActionCountInRange(20, 6, 4);
