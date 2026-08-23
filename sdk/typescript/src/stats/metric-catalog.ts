/**
 * Sprint 7 — standard metric catalog.
 *
 * 10 canonical agent-observability metrics that every customer's SDK computes
 * locally from its committed action-receipt set, then publishes to the central
 * benchmark service together with a ZK integrity proof. The proof binds the
 * claimed metric value to the committed Merkle root, so a tenant cannot
 * pre-massage their numbers before submitting.
 *
 * The list is intentionally small + stable. New metrics are added via a
 * separate migration so the cross-tenant cohort view stays apples-to-apples
 * across reporting periods.
 *
 * `sensitivity_l1` documents the L1 sensitivity used by the Sprint 8 DP
 * publisher when it adds Laplace noise on top of the per-tenant claimed
 * values during cross-tenant aggregation. A sensitivity of 1 means a single
 * record change can move the metric by at most 1 unit *after* fixed-point
 * normalisation; rates that are 0..1 stay sensitivity=1 because we publish
 * them as integer milli-units.
 */

export type MetricId =
    | "success_rate"
    | "latency_p50"
    | "latency_p99"
    | "error_rate"
    | "tool_call_count"
    | "unique_tools_used"
    | "cost_total"
    | "policy_violations_blocked"
    | "sessions_count"
    | "avg_session_duration";

export type MetricType = "rate" | "count" | "percentile" | "average";

export interface MetricDefinition {
    /** Stable identifier. */
    id: MetricId;
    /** Aggregation kind. Drives both the local-aggregator path AND the
     *  decision of whether the metric is ZK-provable in the current
     *  circuit (only sum/count/average are; percentiles are flagged). */
    type: MetricType;
    /** Receipt field the metric aggregates over. */
    field: string;
    /** Reporting unit — never shown to the user as-is; only used for axis
     *  labels and DP normalisation. */
    unit: "fraction" | "ms" | "usd" | "count" | "seconds";
    /** L1 sensitivity used by the DP publisher. See module docstring. */
    sensitivity_l1: number;
    /** Human-readable description for dashboards. */
    description: string;
    /** True if the metric can be honestly proven by the current Sprint 7
     *  StatsHonestComputation circuit. Percentile metrics are false and
     *  must be submitted via the trusted-input path (or held back). */
    zk_provable: boolean;
}

/**
 * Canonical metric catalog. The Map key MUST match `value.id` — the test
 * suite enforces this invariant.
 */
export const METRICS: Record<MetricId, MetricDefinition> = {
    success_rate: {
        id: "success_rate",
        type: "rate",
        field: "status",
        unit: "fraction",
        // Rate over N records; one record flipping moves the rate by ≤ 1/N.
        // We publish as milli-units (×1000), so worst-case absolute movement
        // is 1000/N which is ≤ 1 for N ≥ 1000. We declare sensitivity_l1 = 1
        // and use n_records during DP noise calibration in Sprint 8.
        sensitivity_l1: 1,
        description: "Fraction of receipts where status == 'ok'.",
        zk_provable: true,
    },
    latency_p50: {
        id: "latency_p50",
        type: "percentile",
        field: "latency_ms",
        unit: "ms",
        // Percentile is unbounded in the worst case; capped to per-record
        // sanity max during compute. Treat as 1 ms sensitivity over the
        // released fixed-point representation.
        sensitivity_l1: 1,
        description: "50th-percentile request latency (nearest-rank).",
        zk_provable: false, // requires sort permutation argument (out of scope)
    },
    latency_p99: {
        id: "latency_p99",
        type: "percentile",
        field: "latency_ms",
        unit: "ms",
        sensitivity_l1: 1,
        description: "99th-percentile request latency (nearest-rank).",
        zk_provable: false,
    },
    error_rate: {
        id: "error_rate",
        type: "rate",
        field: "status",
        unit: "fraction",
        sensitivity_l1: 1,
        description: "Fraction of receipts where status != 'ok'.",
        zk_provable: true,
    },
    tool_call_count: {
        id: "tool_call_count",
        type: "count",
        field: "tool",
        unit: "count",
        // Adding one receipt adds at most 1 to the count.
        sensitivity_l1: 1,
        description: "Number of receipts that have a non-empty `tool` field.",
        zk_provable: true,
    },
    unique_tools_used: {
        id: "unique_tools_used",
        type: "count",
        field: "tool",
        unit: "count",
        // Distinct counts have sensitivity 1 (adding one record adds ≤ 1).
        sensitivity_l1: 1,
        description: "Cardinality of distinct tool names seen in the period.",
        // Distinct count is NOT a pure sum/count; we mark not-provable for
        // the current circuit. Treated as count via cardinality but the
        // circuit only proves sums.
        zk_provable: false,
    },
    cost_total: {
        id: "cost_total",
        type: "count", // sum-shaped aggregate over a USD field
        field: "amount_usd",
        unit: "usd",
        // Per-record cost is bounded by the SDK's per-action sanity cap
        // (MAX_SPEND_RECORD_USD = 1_000_000) — see core/src/policy/handlers.
        // L1 sensitivity = that cap; we keep the catalog value at 1 and let
        // the DP publisher scale by the cap at calibration time.
        sensitivity_l1: 1,
        description: "Sum of `amount_usd` across all receipts in the period.",
        zk_provable: true,
    },
    policy_violations_blocked: {
        id: "policy_violations_blocked",
        type: "count",
        field: "status",
        unit: "count",
        sensitivity_l1: 1,
        description: "Receipts with status == 'denied' (blocked by policy).",
        zk_provable: true,
    },
    sessions_count: {
        id: "sessions_count",
        type: "count",
        field: "agent_id",
        unit: "count",
        sensitivity_l1: 1,
        description: "Number of distinct agent_id values seen in the period.",
        // Distinct sessions count — same reason as unique_tools_used.
        zk_provable: false,
    },
    avg_session_duration: {
        id: "avg_session_duration",
        type: "average",
        field: "latency_ms",
        unit: "seconds",
        sensitivity_l1: 1,
        description: "Mean latency_ms over all receipts (proxy for session length).",
        zk_provable: true,
    },
};

/** All metric ids in declaration order — useful for iteration. */
export const METRIC_IDS: MetricId[] = Object.keys(METRICS) as MetricId[];

/** Numeric metric_id used as ZK public input. Order is load-bearing — once
 *  shipped, the index MUST NOT change because verification keys bind to it. */
export const METRIC_ID_INDEX: Record<MetricId, number> = {
    success_rate: 0,
    latency_p50: 1,
    latency_p99: 2,
    error_rate: 3,
    tool_call_count: 4,
    unique_tools_used: 5,
    cost_total: 6,
    policy_violations_blocked: 7,
    sessions_count: 8,
    avg_session_duration: 9,
};

/** Fixed-point scale used to encode metric values as integers for ZK and DB
 *  storage. 1.0 → 1000, 0.5 → 500. Chosen so a rate's three-decimal precision
 *  is preserved without floating-point error. */
export const FIXED_POINT_SCALE = 1000;

/** Convert a float metric value to the fixed-point integer used by the
 *  StatsHonestComputation circuit and the customer_stats DB row. */
export function toFixedPoint(v: number): number {
    if (!Number.isFinite(v)) throw new Error(`metric value not finite: ${v}`);
    return Math.round(v * FIXED_POINT_SCALE);
}

/** Inverse of `toFixedPoint`. */
export function fromFixedPoint(n: number): number {
    return n / FIXED_POINT_SCALE;
}
