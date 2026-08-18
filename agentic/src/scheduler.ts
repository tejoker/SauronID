/**
 * Legacy Circom/Groth16 weekly stats auto-submission scheduler.
 *
 * Long-running customers wire `createWeeklyScheduler` once at startup. Each
 * tick (default 7 days):
 *   1. pull the receipt set for the period via `receiptsProvider`
 *   2. resolve the Merkle root + per-receipt proofs via `merkleProofProvider`
 *   3. compute every catalog metric locally
 *   4. for each ZK-provable metric, prove StatsHonestComputation
 *   5. POST {stat, proof, root, ...} to `/v1/stats/submit`
 *
 * Non-provable metrics (percentiles, distinct counts) are surfaced via
 * `onSkip` so the operator can decide whether to submit them via the
 * trusted-input path or hold back. The scheduler never silently drops them.
 *
 * `runOnce()` is the imperative entry point used by tests and one-shot
 * `submitWeeklyStats(opts)`. `start()` / `stop()` wraps it on a timer.
 *
 * @deprecated The server no longer serves `/v1/stats/submit`. Production already
 * rejected it (Groth16 verification was development-only), and the verifier is
 * archived under `archive/removed-2026-08/groth16-zkp/`, so a current core
 * returns 404. Use `submitTransparentStats` with a receipt from the
 * version-pinned `transparent-zk` prover, which posts to
 * `/v1/stats/submit-transparent`.
 */

import {
    METRICS,
    type MetricId,
} from "./stats/metric-catalog";
import {
    LocalAggregator,
    type ReceiptLike,
    type MetricValue,
} from "./stats/local-aggregate";
import {
    StatsProver,
    type MerkleProof,
    type StatsHonestProof,
    NotProvableError,
} from "./stats/integrity-proof";

// ════════════════════════════════════════════════════════════════════════
// Types
// ════════════════════════════════════════════════════════════════════════

export interface MerkleBundle {
    root: string;
    /** Finalized server checkpoint that binds root + tree size + anchor. */
    checkpointId: string;
    /** 1:1 with `receipts` — pathElements + pathIndices per row. */
    proofs: MerkleProof[];
}

export interface WeeklyStatsSchedulerOptions {
    coreUrl: string;
    adminKey: string;
    /** Tenant header passed to the server. Defaults to `default`. */
    tenantId?: string;
    /** Per-agent submission; `undefined` → tenant-aggregate roll-up. */
    agentId?: string;
    /** Tick interval in ms. Defaults to 7 days. */
    intervalMs?: number;
    /** Path to compiled circuit artefacts (wasm + dev zkey). */
    circuitsDir: string;
    /** Receipt set producer. The scheduler calls this each tick. */
    receiptsProvider: (
        period: { start: number; end: number },
    ) => Promise<ReceiptLike[]>;
    /** Merkle bundle producer — root + per-receipt path. */
    merkleProofProvider: (receipts: ReceiptLike[]) => Promise<MerkleBundle>;
    /** Reporting period resolver. Default: previous 7 days ending at `Date.now()`. */
    periodProvider?: () => { start: number; end: number };
    /** Hook fired after each successful submission. */
    onSubmit?: (id: MetricId, response: SubmitResponse) => void;
    /** Hook fired when a metric is skipped (non-provable or zero records). */
    onSkip?: (id: MetricId, reason: string) => void;
    /** Hook fired on any per-metric error (network, verify rejection, …). */
    onError?: (id: MetricId, err: Error) => void;
    /** Pluggable fetch — defaults to global `fetch`. */
    httpFetch?: typeof fetch;
    /** Pluggable prover — defaults to a new `StatsProver({ circuitsDir })`. */
    prover?: StatsProver;
}

export interface SubmitResponse {
    stored: boolean;
    latency_ms_verify: number;
    statement_hash: string;
}

// ════════════════════════════════════════════════════════════════════════
// Scheduler
// ════════════════════════════════════════════════════════════════════════

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export class WeeklyStatsScheduler {
    private readonly opts: WeeklyStatsSchedulerOptions;
    private readonly prover: StatsProver;
    private timer: ReturnType<typeof setInterval> | null = null;

    constructor(opts: WeeklyStatsSchedulerOptions) {
        this.opts = opts;
        this.prover = opts.prover ?? new StatsProver({ circuitsDir: opts.circuitsDir });
    }

    /** Start the periodic ticker. Idempotent — calling twice is a no-op. */
    start(): void {
        if (this.timer !== null) return;
        const interval = this.opts.intervalMs ?? WEEK_MS;
        this.timer = setInterval(() => {
            void this.runOnce().catch((e) => {
                // Top-level safety net — per-metric errors already went through
                // `onError`. We log here to avoid an unhandled-rejection crash.
                // eslint-disable-next-line no-console
                console.error("[WeeklyStatsScheduler] runOnce unhandled:", e);
            });
        }, interval);
    }

    /** Stop the ticker. Safe to call before `start()`. */
    stop(): void {
        if (this.timer !== null) {
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    /**
     * One-shot tick: fetch receipts → compute → prove → POST. Returns the
     * per-metric submission outcome map. Errors on individual metrics are
     * surfaced via `onError` and do NOT abort the rest.
     */
    async runOnce(): Promise<Record<string, "submitted" | "skipped" | "error">> {
        const period = (this.opts.periodProvider ?? defaultWeeklyPeriod)();
        const receipts = await this.opts.receiptsProvider(period);

        const outcome: Record<string, "submitted" | "skipped" | "error"> = {};

        if (receipts.length === 0) {
            for (const id of Object.keys(METRICS)) {
                outcome[id] = "skipped";
                this.opts.onSkip?.(id as MetricId, "no receipts in period");
            }
            return outcome;
        }

        const bundle = await this.opts.merkleProofProvider(receipts);
        const aggregator = new LocalAggregator({
            receipts,
            periodStart: period.start,
            periodEnd: period.end,
        });
        const metrics = aggregator.computeAll();

        for (const id of Object.keys(METRICS) as MetricId[]) {
            try {
                const def = METRICS[id];
                if (!def.zk_provable) {
                    outcome[id] = "skipped";
                    this.opts.onSkip?.(id, "not ZK-provable in Sprint 7 circuit");
                    continue;
                }
                const m = metrics[id];
                if (m.n_records_used === 0) {
                    outcome[id] = "skipped";
                    this.opts.onSkip?.(id, "zero records");
                    continue;
                }
                const proof = await this.prover.proveStat(
                    m,
                    receipts,
                    bundle.proofs,
                    bundle.root,
                    {
                        tenantId: this.opts.tenantId ?? "default",
                        agentId: this.opts.agentId,
                        checkpointId: bundle.checkpointId,
                    },
                );
                const resp = await this.submitToCore(m, proof);
                outcome[id] = "submitted";
                this.opts.onSubmit?.(id, resp);
            } catch (e) {
                outcome[id] = "error";
                const err =
                    e instanceof Error
                        ? e
                        : new Error(`${typeof e === "string" ? e : "unknown"}`);
                if (err instanceof NotProvableError) {
                    outcome[id] = "skipped";
                    this.opts.onSkip?.(id, err.message);
                } else {
                    this.opts.onError?.(id, err);
                }
            }
        }
        return outcome;
    }

    private async submitToCore(
        metric: MetricValue,
        proof: StatsHonestProof,
    ): Promise<SubmitResponse> {
        const fetchImpl = this.opts.httpFetch ?? fetch;
        const url = `${this.opts.coreUrl.replace(/\/$/, "")}/v1/stats/submit`;
        const body = {
            tenant_id: this.opts.tenantId ?? "default",
            agent_id_or_none: this.opts.agentId ?? null,
            metric_id: metric.id,
            claimed_value: metric.value_fixed,
            n_records: metric.n_records_used,
            period_start: metric.period.start,
            period_end: metric.period.end,
            merkle_root: proof.root,
            proof_b64: Buffer.from(JSON.stringify(proof.proof)).toString("base64"),
            vk_id: "StatsHonestComputation.dev.vk@v1",
            checkpoint_id: proof.checkpointId,
            public_inputs: proof.public_inputs,
        };
        const res = await fetchImpl(url, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${this.opts.adminKey}`,
                "x-sauron-tenant-id": this.opts.tenantId ?? "default",
            },
            body: JSON.stringify(body),
        });
        if (!res.ok) {
            const detail = await res.text();
            throw new Error(`/v1/stats/submit ${res.status}: ${detail}`);
        }
        return (await res.json()) as SubmitResponse;
    }
}

/** Default period: previous 7 days, inclusive, ending at "now". */
function defaultWeeklyPeriod(): { start: number; end: number } {
    const nowSec = Math.floor(Date.now() / 1000);
    const weekSec = 7 * 24 * 60 * 60;
    return { start: nowSec - weekSec, end: nowSec };
}

// ════════════════════════════════════════════════════════════════════════
// Convenience top-level helpers (re-exported from index.ts)
// ════════════════════════════════════════════════════════════════════════

/**
 * One-shot weekly submission. Builds a scheduler, runs once, returns the
 * outcome map. Caller is responsible for tearing the scheduler down — but
 * since runOnce holds no state, no explicit stop is required.
 */
export async function submitWeeklyStats(
    opts: WeeklyStatsSchedulerOptions,
): Promise<Record<string, "submitted" | "skipped" | "error">> {
    const sched = new WeeklyStatsScheduler(opts);
    return sched.runOnce();
}

/** Factory for the cron use case. */
export function createWeeklyScheduler(
    opts: WeeklyStatsSchedulerOptions,
): WeeklyStatsScheduler {
    return new WeeklyStatsScheduler(opts);
}
