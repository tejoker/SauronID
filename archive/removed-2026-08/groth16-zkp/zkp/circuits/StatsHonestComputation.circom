pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * StatsHonestComputation — Sprint 7 anti-cheat proof.
 *
 * Proves that a claimed cohort statistic was honestly computed from a
 * Merkle-committed set of action receipts. Each receipt is a 6-field tuple
 * Poseidon-hashed into a Merkle leaf; the prover supplies the leaf + path
 * and the circuit recomputes the root, the aggregation, and checks the
 * claimed value matches. The typed receipt tuple has seven fields.
 *
 * Public inputs:
 *   - root          : action-log Merkle root (bound by the verifier).
 *   - metric_id     : 0..9 index into the metric catalog.
 *   - claimed_value : fixed-point integer (1000x) the prover claims.
 *   - n_records     : number of receipts that contributed (matches active N).
 *   - period_start  : inclusive unix-epoch second of the reporting window.
 *   - period_end    : inclusive unix-epoch second of the reporting window.
 *
 * Private inputs:
 *   - entries[N][6]            : per-receipt field tuple
 *                                [status_bit, latency_ms, amount_milli_usd,
 *                                 tool_id, agent_id_hash, created_at].
 *   - pathElements[N][levels]  : Merkle sibling hashes per receipt.
 *   - pathIndices[N][levels]   : left/right indicators per receipt.
 *
 * Metric semantics (only ZK-provable subset shipped in Sprint 7):
 *   - 0 success_rate              : sum(status_bit) / n_records   (rate × 1000)
 *   - 3 error_rate                : sum(1 - status_bit) / n_records
 *   - 4 tool_call_count           : sum(tool_id != 0)
 *   - 6 cost_total                : sum(amount_milli_usd)
 *   - 7 policy_violations_blocked : sum(status_bit_denied)         (status_bit == 0 proxy)
 *   - 9 avg_session_duration      : sum(latency_ms) / n_records / 1000
 *
 * Percentile metrics (latency_p50, latency_p99) and distinct-cardinality
 * (unique_tools_used, sessions_count) are intentionally NOT covered. They
 * require a permutation argument over a sorted private witness, which is a
 * separate circuit (see docs/stats-submission.md "What we don't cover yet").
 *
 * The shipped main has N=4 receipts per proof and requires authoritative
 * tree_size=4. Larger arities require a new circuit version and proving key.
 */
template StatsHonestComputation(levels, entryFields, N) {
    // Public inputs
    signal input root;
    signal input metric_id;
    signal input claimed_value;
    signal input n_records;
    signal input period_start;
    signal input period_end;
    signal input tree_size;
    signal input tenant_hash;
    signal input agent_hash;

    // Private inputs
    signal input entries[N][entryFields];
    signal input pathElements[N][levels];
    signal input pathIndices[N][levels];

    // Public output
    signal output valid;

    // ─────────────────────────────────────────────────────────────────────
    // 1. Per-receipt: hash leaf + verify Merkle path against `root`.
    //
    // Every entry must be in the committed tree; the prover cannot fabricate
    // a receipt without breaking root binding.
    // ─────────────────────────────────────────────────────────────────────
    component leafHasher[N];
    component mux[N][levels];
    component hashers[N][levels];
    component rootCheck[N];
    component indexBits[N];
    component latencyBits[N];
    component amountBits[N];
    component createdBits[N];
    component createdAfterStart[N];
    component createdBeforeEnd[N];
    component agentScopeIsZero = IsZero();
    agentScopeIsZero.in <== agent_hash;
    component periodStartBits = Num2Bits(64);
    component periodEndBits = Num2Bits(64);
    periodStartBits.in <== period_start;
    periodEndBits.in <== period_end;

    signal pathLevels[N][levels + 1];

    for (var k = 0; k < N; k++) {
        // Typed receipt schema:
        // [status, latency_ms, amount_milli, tool_id,
        //  tenant_hash, agent_hash, created_at].
        entries[k][0] * (1 - entries[k][0]) === 0;
        latencyBits[k] = Num2Bits(64);
        latencyBits[k].in <== entries[k][1];
        amountBits[k] = Num2Bits(64);
        amountBits[k].in <== entries[k][2];
        createdBits[k] = Num2Bits(64);
        createdBits[k].in <== entries[k][6];
        entries[k][4] === tenant_hash;
        (1 - agentScopeIsZero.out) * (entries[k][5] - agent_hash) === 0;

        createdAfterStart[k] = GreaterEqThan(64);
        createdAfterStart[k].in[0] <== entries[k][6];
        createdAfterStart[k].in[1] <== period_start;
        createdAfterStart[k].out === 1;
        createdBeforeEnd[k] = LessEqThan(64);
        createdBeforeEnd[k].in[0] <== entries[k][6];
        createdBeforeEnd[k].in[1] <== period_end;
        createdBeforeEnd[k].out === 1;

        leafHasher[k] = Poseidon(entryFields);
        for (var f = 0; f < entryFields; f++) {
            leafHasher[k].inputs[f] <== entries[k][f];
        }
        pathLevels[k][0] <== leafHasher[k].out;

        // Complete-tree coverage for this fixed-arity circuit: every index
        // 0..N-1 is proved exactly once. The verifier separately binds
        // tree_size to its authoritative checkpoint.
        indexBits[k] = Num2Bits(levels);
        indexBits[k].in <== k;

        for (var i = 0; i < levels; i++) {
            pathIndices[k][i] === indexBits[k].out[i];

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

    // ─────────────────────────────────────────────────────────────────────
    // 2. Compute the candidate aggregation for every provable metric. Then
    //    select the one matching `metric_id` via a 10-way one-hot mux.
    //
    // Cost: 6 candidate sums + 10 equality checks vs metric_id. Cheap
    // relative to the Merkle path verifications above (which dominate).
    // ─────────────────────────────────────────────────────────────────────

    // Extract typed columns from `entries`.
    signal status_bit[N];      // field 0
    signal latency_ms[N];      // field 1
    signal amount_milli[N];    // field 2
    signal tool_id[N];         // field 3
    for (var k = 0; k < N; k++) {
        status_bit[k]   <== entries[k][0];
        latency_ms[k]   <== entries[k][1];
        amount_milli[k] <== entries[k][2];
        tool_id[k]      <== entries[k][3];
    }

    // sum_status — count of status==ok rows
    signal sum_status[N + 1];
    sum_status[0] <== 0;
    for (var k = 0; k < N; k++) {
        sum_status[k + 1] <== sum_status[k] + status_bit[k];
    }

    // sum_latency — running total of latency_ms
    signal sum_lat[N + 1];
    sum_lat[0] <== 0;
    for (var k = 0; k < N; k++) {
        sum_lat[k + 1] <== sum_lat[k] + latency_ms[k];
    }

    // sum_amount — running total of amount_milli_usd
    signal sum_amt[N + 1];
    sum_amt[0] <== 0;
    for (var k = 0; k < N; k++) {
        sum_amt[k + 1] <== sum_amt[k] + amount_milli[k];
    }

    // tool_present[k] = 1 if tool_id[k] != 0 else 0. We use IsZero gadget;
    // the circuit's column is a witness-side string hash so a non-empty tool
    // never collides with the zero field element.
    component tool_zero[N];
    signal tool_present[N];
    signal sum_tool[N + 1];
    sum_tool[0] <== 0;
    for (var k = 0; k < N; k++) {
        tool_zero[k] = IsZero();
        tool_zero[k].in <== tool_id[k];
        tool_present[k] <== 1 - tool_zero[k].out;
        sum_tool[k + 1] <== sum_tool[k] + tool_present[k];
    }

    // denied[k] = 1 if status_bit == 0 (mirrors the SDK's "status != ok" rule
    // condensed to a single bit for the ZK circuit).
    signal denied[N];
    signal sum_denied[N + 1];
    sum_denied[0] <== 0;
    for (var k = 0; k < N; k++) {
        denied[k] <== 1 - status_bit[k];
        sum_denied[k + 1] <== sum_denied[k] + denied[k];
    }

    // Candidate values per metric_id. Encoded as fixed-point (×1000) to match
    // the SDK's `toFixedPoint`. For rate metrics we multiply by 1000 BEFORE
    // dividing by n_records to preserve precision.
    //
    // Division: we expose `claimed_value * n_records == numerator * 1000`
    // as the integrity constraint instead of literal field division (circom
    // has no native division; the SDK supplies the n_records public input).

    // metric 0 — success_rate     : numerator = sum_status,  denom = n_records, scaled ×1000
    // metric 3 — error_rate       : numerator = N - sum_status (n_records - sum_status), scaled ×1000
    // metric 4 — tool_call_count  : numerator = sum_tool,    no denom (count × 1000)
    // metric 6 — cost_total       : numerator = sum_amount,  no denom (already milli-USD; ×1 = ×1000 conceptually)
    // metric 7 — policy_viol      : numerator = sum_denied,  no denom
    // metric 9 — avg_duration_s   : numerator = sum_latency, denom = n_records * 1000 (ms→s scaled), scaled ×1000

    // For uniform handling, every metric expresses a (numerator, denominator)
    // pair such that the constraint is:
    //   claimed_value * denominator == numerator * 1000
    //
    // | metric_id | numerator        | denominator   |
    // |     0     | sum_status       | n_records     |
    // |     3     | n_records - sum_status | n_records |
    // |     4     | sum_tool         | 1             |
    // |     6     | sum_amount       | 1000          | (milli-USD → USD output scaled ×1000 → integer USD)
    // |     7     | sum_denied       | 1             |
    // |     9     | sum_latency      | n_records * 1000 |
    //
    // metric 1,2 (percentiles) and 5,8 (distinct counts) are not provable
    // here — the SDK rejects them client-side via NotProvableError, and we
    // belt-and-braces here by requiring metric_id ∈ {0,3,4,6,7,9}.

    component is0 = IsEqual();   is0.in[0] <== metric_id; is0.in[1] <== 0;
    component is3 = IsEqual();   is3.in[0] <== metric_id; is3.in[1] <== 3;
    component is4 = IsEqual();   is4.in[0] <== metric_id; is4.in[1] <== 4;
    component is6 = IsEqual();   is6.in[0] <== metric_id; is6.in[1] <== 6;
    component is7 = IsEqual();   is7.in[0] <== metric_id; is7.in[1] <== 7;
    component is9 = IsEqual();   is9.in[0] <== metric_id; is9.in[1] <== 9;

    // Provable metric guard — at least one matches.
    signal one_of_provable;
    one_of_provable <== is0.out + is3.out + is4.out + is6.out + is7.out + is9.out;
    one_of_provable === 1;

    // Numerator selection (mux). Each metric contributes (idx_eq * numerator).
    signal num0; num0 <== is0.out * sum_status[N];
    signal num3; num3 <== is3.out * (n_records - sum_status[N]);
    signal num4; num4 <== is4.out * sum_tool[N];
    signal num6; num6 <== is6.out * sum_amt[N];
    signal num7; num7 <== is7.out * sum_denied[N];
    signal num9; num9 <== is9.out * sum_lat[N];
    signal numerator;
    numerator <== num0 + num3 + num4 + num6 + num7 + num9;

    // Denominator selection.
    signal n_x1000; n_x1000 <== n_records * 1000;
    signal den0; den0 <== is0.out * n_records;
    signal den3; den3 <== is3.out * n_records;
    signal den4; den4 <== is4.out * 1;
    signal den6; den6 <== is6.out * 1000;
    signal den7; den7 <== is7.out * 1;
    signal den9; den9 <== is9.out * n_x1000;
    signal denominator;
    denominator <== den0 + den3 + den4 + den6 + den7 + den9;

    // Honesty constraint: claimed_value * denominator == numerator * 1000.
    signal lhs; lhs <== claimed_value * denominator;
    signal rhs; rhs <== numerator * 1000;
    lhs === rhs;

    // Period sanity — period_end must not be before period_start.
    component period_check = LessEqThan(64);
    period_check.in[0] <== period_start;
    period_check.in[1] <== period_end;
    period_check.out === 1;

    component claimedBits = Num2Bits(64);
    claimedBits.in <== claimed_value;
    tree_size === N;

    // n_records must equal N (the active arity). Keeps the public input
    // bound to the prover's actual contribution count.
    n_records === N;

    valid <== 1;
}

// Depth ≤ 20 levels (matches the action-log circuits family).
// entryFields = 7, N = 4 — larger windows require a versioned circuit/key.
component main {public [root, metric_id, claimed_value, n_records, period_start, period_end, tree_size, tenant_hash, agent_hash]} = StatsHonestComputation(20, 7, 4);
