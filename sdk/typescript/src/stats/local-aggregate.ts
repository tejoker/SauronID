/**
 * Sprint 7 — local metric aggregator.
 *
 * Runs entirely client-side over a customer's committed receipt set. Output
 * feeds both the cohort submission (see `integrity-proof.ts`) and the
 * customer's own dashboard.
 *
 * **Determinism contract.** Every aggregation is fully deterministic on the
 * (receipts, periodStart, periodEnd) tuple — same inputs always produce the
 * same fixed-point output. That guarantee is the bridge between this module
 * and the ZK circuit: the witness generator MUST reproduce the same integer.
 *
 * Percentiles use the nearest-rank algorithm (no interpolation) so the
 * output is one of the input values, never an averaged synthetic number.
 * Sorting is stable (Array.prototype.sort with a numeric comparator); ties
 * resolve to the lower-index element which is what nearest-rank wants.
 */

import {
    METRICS,
    type MetricId,
    type MetricDefinition,
    toFixedPoint,
} from "./metric-catalog";

/** Receipt shape consumed by the aggregator. Mirrors the server's
 *  `agent_action_receipts` row plus the few SDK-side fields we need. */
export interface ReceiptLike {
    receipt_id: string;
    action_hash: string;
    /** Per-action cost in USD. Required for `cost_total`. */
    amount_usd?: number;
    /** Latency in milliseconds. Required for latency_* + avg_session_duration. */
    latency_ms?: number;
    /** Free-form status; `"ok"` is the success sentinel. */
    status: string;
    /** Tool name. Empty string counts as "no tool". */
    tool: string;
    agent_id: string;
    /** Unix-epoch seconds. */
    created_at: number;
}

/** Output shape for a single metric. */
export interface MetricValue {
    id: MetricId;
    /** Native (un-scaled) numeric value. */
    value: number;
    /** Fixed-point representation used by the ZK circuit / DB. */
    value_fixed: number;
    /** Number of receipts that contributed to this aggregation (post-filter). */
    n_records_used: number;
    /** Reporting period — inclusive bounds. */
    period: { start: number; end: number };
}

/**
 * Stateless local aggregator. The constructor takes the receipt set + period;
 * `compute` / `computeAll` perform the math.
 */
export class LocalAggregator {
    private readonly receipts: ReceiptLike[];
    private readonly periodStart: number;
    private readonly periodEnd: number;

    constructor(opts: {
        receipts: ReceiptLike[];
        periodStart: number;
        periodEnd: number;
    }) {
        if (opts.periodEnd < opts.periodStart) {
            throw new Error(
                `LocalAggregator: periodEnd (${opts.periodEnd}) < periodStart (${opts.periodStart})`,
            );
        }
        this.periodStart = opts.periodStart;
        this.periodEnd = opts.periodEnd;
        // Filter to in-period receipts ONCE so each compute() is O(N).
        this.receipts = opts.receipts.filter(
            (r) => r.created_at >= opts.periodStart && r.created_at <= opts.periodEnd,
        );
    }

    /** Number of in-period receipts (matches `n_records_used` for non-filtering metrics). */
    public size(): number {
        return this.receipts.length;
    }

    /** Compute a single metric. */
    public compute(metricId: MetricId): MetricValue {
        const def: MetricDefinition | undefined = METRICS[metricId];
        if (!def) throw new Error(`unknown metricId: ${metricId}`);

        const value = this.computeRaw(def);
        return {
            id: def.id,
            value,
            value_fixed: toFixedPoint(value),
            n_records_used: this.receipts.length,
            period: { start: this.periodStart, end: this.periodEnd },
        };
    }

    /** Compute every metric in the catalog. */
    public computeAll(): Record<MetricId, MetricValue> {
        const out: Partial<Record<MetricId, MetricValue>> = {};
        for (const id of Object.keys(METRICS) as MetricId[]) {
            out[id] = this.compute(id);
        }
        return out as Record<MetricId, MetricValue>;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Internal: per-metric math. Kept in one switch so the aggregator
    //  surface stays small and the test suite can hit every branch.
    // ─────────────────────────────────────────────────────────────────────

    private computeRaw(def: MetricDefinition): number {
        const rs = this.receipts;
        if (rs.length === 0) return 0;

        switch (def.id) {
            case "success_rate":
                return rs.filter((r) => r.status === "ok").length / rs.length;

            case "error_rate":
                return rs.filter((r) => r.status !== "ok").length / rs.length;

            case "tool_call_count":
                return rs.filter((r) => r.tool && r.tool.length > 0).length;

            case "unique_tools_used":
                return new Set(rs.map((r) => r.tool).filter((t) => t.length > 0)).size;

            case "cost_total":
                return rs.reduce((acc, r) => acc + (r.amount_usd ?? 0), 0);

            case "policy_violations_blocked":
                return rs.filter((r) => r.status === "denied").length;

            case "sessions_count":
                return new Set(rs.map((r) => r.agent_id)).size;

            case "latency_p50":
                return percentileNearestRank(this.collectLatencies(), 50);

            case "latency_p99":
                return percentileNearestRank(this.collectLatencies(), 99);

            case "avg_session_duration": {
                const lats = this.collectLatencies();
                if (lats.length === 0) return 0;
                // Express the average in *seconds* to match the catalog unit.
                const sumMs = lats.reduce((a, b) => a + b, 0);
                return sumMs / lats.length / 1000;
            }
        }
    }

    private collectLatencies(): number[] {
        return this.receipts
            .map((r) => r.latency_ms)
            .filter((v): v is number => typeof v === "number" && Number.isFinite(v));
    }
}

/**
 * Nearest-rank percentile (deterministic, no interpolation). Defined as
 * `values[ ceil(p/100 * N) - 1 ]` after sorting ascending; returns 0 on an
 * empty input so the catalog never throws.
 */
export function percentileNearestRank(values: number[], p: number): number {
    if (values.length === 0) return 0;
    if (p <= 0) return values.slice().sort((a, b) => a - b)[0];
    if (p >= 100) {
        const sorted = values.slice().sort((a, b) => a - b);
        return sorted[sorted.length - 1];
    }
    const sorted = values.slice().sort((a, b) => a - b);
    const idx = Math.max(0, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[idx];
}
