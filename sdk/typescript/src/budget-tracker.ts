/**
 * Budget tracker — in-memory ledger of spend and call timestamps. Used
 * by the local invariant evaluator to feed the budget + rate-limit
 * checks without a per-call HTTP roundtrip.
 *
 * Sprint 3 follow-up wires the optional server-side spend ledger:
 * pending records accumulate in `_pending` and a background timer
 * forwards them to `flushFn` every `flushIntervalMs`. The default
 * `BudgetTracker.serverPush()` builder POSTs each pending record to
 * `POST /v1/agents/:agent_id/spend` so the server can hold the
 * authoritative total (closes redteam A3 — local counter tampering).
 *
 * @module
 */

/** One record queued for the next `flush()`. */
export interface PendingSpendRecord {
    /** USD amount as supplied to `record()`. */
    amount_usd: number;
    /** Optional caller-supplied action id (free-form). */
    action_id?: string;
    /** Epoch milliseconds when `record()` was called. */
    timestamp: number;
}

/** Snapshot passed to {@link BudgetTrackerOptions.flushFn}. */
export interface BudgetState {
    /** Policy id this tracker belongs to. */
    policyId: string;
    /** Running USD total. */
    totalUsd: number;
    /** Epoch-millisecond timestamps of recent calls. */
    callTimestampsMs: number[];
    /** Pending records still to be persisted. The default flushFn drains them. */
    pending: PendingSpendRecord[];
}

/** Options for the {@link BudgetTracker} constructor. */
export interface BudgetTrackerOptions {
    /** Policy id whose spend this tracker covers. */
    policyId: string;
    /**
     * Auto-flush interval in ms. Default `30_000` (30s). Pass `0` to
     * disable the timer entirely — callers can still invoke `flush()`
     * manually.
     */
    flushIntervalMs?: number;
    /**
     * Hook invoked from the background timer (and on `stop()`). When
     * absent, pending records are silently dropped after each tick —
     * use `BudgetTracker.serverPush()` to wire the authoritative ledger.
     */
    flushFn?: (state: BudgetState) => Promise<void>;
}

/** Options for {@link BudgetTracker.serverPush}. */
export interface ServerPushOptions {
    /** Base URL of the SauronID core server (no trailing slash). */
    coreUrl: string;
    /** Admin bearer token; sent as `Authorization: Bearer <key>`. */
    adminKey?: string;
    /** Agent id whose ledger row should be incremented. */
    agentId: string;
    /** Policy id this tracker covers. */
    policyId: string;
    /** Override `fetch` (tests / Node < 18). */
    httpFetch?: typeof fetch;
}

/** Lightweight in-memory spend + rate ledger. */
export class BudgetTracker {
    private readonly policyId: string;
    private readonly flushFn: (state: BudgetState) => Promise<void>;
    private readonly flushIntervalMs: number;
    private flushTimer: ReturnType<typeof setInterval> | null = null;

    private totalUsd = 0;
    private readonly callTimestampsMs: number[] = [];
    /** Records added since the last successful `flush()`. */
    private _pending: PendingSpendRecord[] = [];
    private inflightFlush: Promise<void> | null = null;

    constructor(opts: BudgetTrackerOptions) {
        this.policyId = opts.policyId;
        this.flushFn = opts.flushFn ?? (async () => { /* no server wiring */ });
        this.flushIntervalMs = opts.flushIntervalMs ?? 30_000;
        if (this.flushIntervalMs > 0) {
            this.flushTimer = setInterval(() => {
                if (this._pending.length === 0) return;
                void this.flush();
            }, this.flushIntervalMs);
            const t = this.flushTimer as { unref?: () => void };
            if (typeof t.unref === "function") t.unref();
        }
    }

    /**
     * Record one tool invocation. Increments the running total by
     * `amountUsd` (0 if absent), appends a timestamp for rate checks,
     * and queues a `PendingSpendRecord` for the next `flush()`.
     */
    record(amountUsd: number, actionId?: string): void {
        this.totalUsd += amountUsd;
        const now = Date.now();
        this.callTimestampsMs.push(now);
        // Cap history so the array doesn't grow unboundedly. Keeping the
        // last 1024 entries is plenty for a 60s rate window.
        if (this.callTimestampsMs.length > 1024) {
            this.callTimestampsMs.splice(0, this.callTimestampsMs.length - 1024);
        }
        this._pending.push({ amount_usd: amountUsd, action_id: actionId, timestamp: now });
    }

    /** Current spend total in USD. */
    total(): number {
        return this.totalUsd;
    }

    /** Number of records waiting for the next flush. */
    pendingCount(): number {
        return this._pending.length;
    }

    /**
     * Return call timestamps (epoch ms) within the last `windowMs`.
     * Older entries are pruned as a side effect.
     */
    recentCalls(windowMs: number): number[] {
        const cutoff = Date.now() - windowMs;
        // Find the first timestamp inside the window via binary search-ish
        // linear scan from the end (history is append-only ordered).
        let firstFresh = 0;
        for (let i = 0; i < this.callTimestampsMs.length; i++) {
            if (this.callTimestampsMs[i] > cutoff) {
                firstFresh = i;
                break;
            }
            firstFresh = i + 1;
        }
        if (firstFresh > 0) this.callTimestampsMs.splice(0, firstFresh);
        return [...this.callTimestampsMs];
    }

    /**
     * Send the current state through `flushFn`. Drains `_pending` on
     * success; on failure the pending list is preserved so the next
     * tick retries.
     */
    async flush(): Promise<void> {
        // Serialise concurrent flushes — the timer callback can race with a
        // manual `flush()` from `stop()` or user code.
        if (this.inflightFlush) {
            await this.inflightFlush;
            return;
        }
        const snapshot = this._pending.slice();
        if (snapshot.length === 0) return;
        const p = (async () => {
            try {
                await this.flushFn({
                    policyId: this.policyId,
                    totalUsd: this.totalUsd,
                    callTimestampsMs: [...this.callTimestampsMs],
                    pending: snapshot,
                });
                // Drop only the records we sent; new ones may have been
                // appended during the await.
                this._pending.splice(0, snapshot.length);
            } catch (err) {
                // Keep `_pending` so the next tick retries. Log to stderr
                // since this is a background channel.
                // eslint-disable-next-line no-console
                console.warn(
                    `[BudgetTracker] flush failed for ${this.policyId}: ${(err as Error).message}`
                );
            }
        })();
        this.inflightFlush = p;
        try {
            await p;
        } finally {
            this.inflightFlush = null;
        }
    }

    /**
     * Build a `flushFn` that POSTs each pending record to
     * `POST /v1/agents/:agent_id/spend`. Use as:
     *
     * ```ts
     * const flushFn = BudgetTracker.serverPush({
     *   coreUrl, adminKey, agentId, policyId,
     * });
     * const bt = new BudgetTracker({ policyId, flushFn });
     * ```
     */
    static serverPush(opts: ServerPushOptions): (state: BudgetState) => Promise<void> {
        const coreUrl = opts.coreUrl.replace(/\/+$/, "");
        const f = opts.httpFetch ?? (typeof fetch === "function" ? fetch : undefined);
        if (!f) {
            throw new Error("BudgetTracker.serverPush: no fetch available — pass httpFetch");
        }
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (opts.adminKey) headers.authorization = `Bearer ${opts.adminKey}`;
        const url = `${coreUrl}/v1/agents/${encodeURIComponent(opts.agentId)}/spend`;
        return async (state) => {
            for (const rec of state.pending) {
                const body = JSON.stringify({
                    policy_id: opts.policyId,
                    action_id: rec.action_id,
                    amount_usd: rec.amount_usd,
                });
                const r = await f(url, { method: "POST", headers, body });
                if (!r.ok) {
                    throw new Error(
                        `POST ${url} -> ${r.status}: ${await r.text().catch(() => "")}`
                    );
                }
            }
        };
    }

    /**
     * Stop the auto-flush timer and trigger one final flush so no
     * pending records are lost. Idempotent.
     */
    async stop(): Promise<void> {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        if (this._pending.length > 0) {
            await this.flush();
        }
    }
}
