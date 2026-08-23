/**
 * Sprint 3 — runtime policy enforcement tests.
 *
 * Covers:
 *   - PolicyCache.load / get / refresh (with mocked fetch)
 *   - BudgetTracker.record / total / recentCalls
 *   - evaluator for each of the 7 invariants (allow + deny)
 *   - tool-proxy bind() allow / deny / not-loaded paths
 *
 * Standalone runner — mirrors `test/e2e.test.ts` style: assert counters,
 * exit non-zero on failure. Run via `npm run test:enforcement` (added
 * to package.json by Sprint 3).
 */

import {
    PolicyCache,
    BudgetTracker,
    evaluate,
    computeNowTzHhmm,
    bind,
    PolicyDeniedError,
    PolicyNotLoadedError,
    type BudgetState,
    type CompiledPolicy,
    type Action,
    type EvaluationContext,
} from "../src/enforcement";

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
    if (condition) {
        console.log(`  ✓ ${msg}`);
        passed++;
    } else {
        console.error(`  ✗ FAILED: ${msg}`);
        failed++;
    }
}

// ────────── helpers ──────────

function fakePolicy(overrides: Partial<CompiledPolicy["binding"]> = {}): CompiledPolicy {
    return {
        policy_id: "pol_fake",
        agent: "agent-fake",
        version: "1",
        raw_yaml: "",
        checks: [],
        binding: { ...overrides },
    };
}

function baseAction(over: Partial<Action> = {}): Action {
    return {
        actionId: "act-1",
        tool: "echo",
        signatures: [],
        delegationDepth: 0,
        timestamp: 1_700_000_000,
        ...over,
    };
}

function baseCtx(over: Partial<EvaluationContext> = {}): EvaluationContext {
    return {
        spendTotalUsd: 0,
        recentCallTimestamps: [],
        nowEpoch: 1_700_000_000,
        nowTzHhmm: "12:00",
        ...over,
    };
}

function mockFetch(responder: (url: string) => unknown): typeof fetch {
    const f = async (input: string | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input.toString();
        const body = responder(url);
        if (body === null) {
            return new Response("not found", { status: 404 });
        }
        return new Response(JSON.stringify(body), {
            status: 200,
            headers: { "content-type": "application/json" },
        });
    };
    return f as unknown as typeof fetch;
}

// ────────── 1. PolicyCache ──────────

async function testPolicyCache() {
    console.log("\n═══ Test 1: PolicyCache ═══");

    const policyAst = {
        version: "1",
        agent: "agent-x",
        binding: { allowed_tools: ["echo"], max_budget_usd: 100 },
    };
    let fetchCount = 0;
    const cache = new PolicyCache({
        coreUrl: "http://test",
        refreshIntervalMs: 0,
        httpFetch: mockFetch(() => {
            fetchCount++;
            return policyAst;
        }),
    });

    const p1 = await cache.load("pol_1");
    assert(p1.policy_id === "pol_1", "fresh load returns policy with id");
    assert(p1.agent === "agent-x", "agent field populated");
    assert(p1.binding.allowed_tools?.[0] === "echo", "binding.allowed_tools survives");
    assert(p1.checks.includes("allowlist"), "checks derived from binding (allowlist)");
    assert(p1.checks.includes("budget"), "checks derived from binding (budget)");

    const p2 = await cache.load("pol_1");
    assert(p2 === p1, "second load returns cached instance (same ref)");
    assert(fetchCount === 1, "cached hit does NOT re-fetch");

    await cache.refresh("pol_1");
    assert(fetchCount === 2, "refresh forces re-fetch");
    assert(cache.get("pol_1")?.agent === "agent-x", "refresh updates cache");

    // Refresh failure must keep last good copy.
    const failingCache = new PolicyCache({
        coreUrl: "http://test",
        refreshIntervalMs: 0,
        httpFetch: mockFetch(() => null),
    });
    // Prime entries map manually via load against a non-failing first responder.
    const okFetch = mockFetch(() => policyAst);
    const primed = new PolicyCache({
        coreUrl: "http://test",
        refreshIntervalMs: 0,
        httpFetch: okFetch,
    });
    await primed.load("pol_1");
    // Now patch fetch to fail and call refresh — last good copy survives.
    (primed as unknown as { httpFetch: typeof fetch }).httpFetch = mockFetch(() => null);
    const originalWarn = console.warn;
    console.warn = () => { /* silence expected refresh warning */ };
    await primed.refresh("pol_1");
    console.warn = originalWarn;
    assert(primed.get("pol_1")?.agent === "agent-x", "failed refresh keeps last good copy");

    cache.stop();
    primed.stop();
    failingCache.stop();
}

// ────────── 2. BudgetTracker ──────────

async function testBudgetTracker() {
    console.log("\n═══ Test 2: BudgetTracker ═══");

    const bt = new BudgetTracker({ policyId: "pol_x" });
    bt.record(10);
    bt.record(5.5, "act-2");
    assert(bt.total() === 15.5, "total sums recorded amounts");

    const recent = bt.recentCalls(60_000);
    assert(recent.length === 2, "recentCalls returns all entries within window");

    // Backdate one call beyond the window by manipulating internals.
    const internal = bt as unknown as { callTimestampsMs: number[] };
    internal.callTimestampsMs[0] = Date.now() - 120_000;
    const r2 = bt.recentCalls(60_000);
    assert(r2.length === 1, "recentCalls prunes entries outside window");

    bt.stop();
}

// ────────── 3. evaluator (7 invariants × allow/deny) ──────────

async function testEvaluator() {
    console.log("\n═══ Test 3: evaluator (7 invariants) ═══");

    // 3.1 allowlist
    {
        const p = fakePolicy({ allowed_tools: ["echo"] });
        assert(
            evaluate(p, baseAction({ tool: "echo" }), baseCtx()).kind === "allow",
            "allowlist: allow when tool in list"
        );
        const v = evaluate(p, baseAction({ tool: "shell" }), baseCtx());
        assert(v.kind === "deny" && v.check === "allowlist", "allowlist: deny when tool missing");
    }

    // 3.2 budget
    {
        const p = fakePolicy({ max_budget_usd: 50 });
        assert(
            evaluate(p, baseAction({ amountUsd: 10 }), baseCtx({ spendTotalUsd: 30 })).kind === "allow",
            "budget: allow under cap"
        );
        const v = evaluate(p, baseAction({ amountUsd: 100 }), baseCtx({ spendTotalUsd: 0 }));
        assert(v.kind === "deny" && v.check === "budget", "budget: deny when projected exceeds cap");
    }

    // 3.3 scope
    {
        const p = fakePolicy({ data_scope: { allow: ["public"], deny: ["pii"] } });
        assert(
            evaluate(p, baseAction({ dataClassification: "public" }), baseCtx()).kind === "allow",
            "scope: allow when classification in allow"
        );
        const v = evaluate(p, baseAction({ dataClassification: "PII" }), baseCtx());
        assert(v.kind === "deny" && v.check === "scope", "scope: deny on classification in deny list (case-insensitive)");
    }

    // 3.4 rate_limit
    {
        const p = fakePolicy({ rate_limit: { requests_per_minute: 3 } });
        const now = 1_700_000_000;
        assert(
            evaluate(p, baseAction(), baseCtx({ nowEpoch: now, recentCallTimestamps: [now - 30, now - 20] })).kind ===
                "allow",
            "rate_limit: allow under limit"
        );
        const v = evaluate(
            p,
            baseAction(),
            baseCtx({ nowEpoch: now, recentCallTimestamps: [now - 30, now - 20, now - 10] })
        );
        assert(v.kind === "deny" && v.check === "rate_limit", "rate_limit: deny at limit");
    }

    // 3.5 time_window
    {
        const p = fakePolicy({ time_window: { start: "09:00", end: "18:00", timezone: "UTC" } });
        assert(
            evaluate(p, baseAction(), baseCtx({ nowTzHhmm: "12:30" })).kind === "allow",
            "time_window: allow inside window"
        );
        const v = evaluate(p, baseAction(), baseCtx({ nowTzHhmm: "07:00" }));
        assert(v.kind === "deny" && v.check === "time_window", "time_window: deny before window");
    }

    // 3.6 signatures (M-of-N)
    {
        const p = fakePolicy({ required_signatures: [{ role: "approver", threshold: 2 }] });
        assert(
            evaluate(p, baseAction({ signatures: ["approver", "approver"] }), baseCtx()).kind === "allow",
            "signatures: allow when threshold met"
        );
        const v = evaluate(p, baseAction({ signatures: ["approver"] }), baseCtx());
        assert(v.kind === "deny" && v.check === "signatures", "signatures: deny below threshold");
    }

    // 3.7 delegation
    {
        const p = fakePolicy({ delegation: { max_depth: 1 } });
        assert(
            evaluate(p, baseAction({ delegationDepth: 1 }), baseCtx()).kind === "allow",
            "delegation: allow at max"
        );
        const v = evaluate(p, baseAction({ delegationDepth: 2 }), baseCtx());
        assert(v.kind === "deny" && v.check === "delegation_depth", "delegation: deny above max");
    }

    // Bonus: time-window wrap-around (overnight) — same as Rust semantics.
    {
        const p = fakePolicy({ time_window: { start: "22:00", end: "06:00", timezone: "UTC" } });
        assert(
            evaluate(p, baseAction(), baseCtx({ nowTzHhmm: "23:30" })).kind === "allow",
            "time_window wrap-around: allow 23:30"
        );
        assert(
            evaluate(p, baseAction(), baseCtx({ nowTzHhmm: "12:00" })).kind === "deny",
            "time_window wrap-around: deny 12:00"
        );
    }

    // Bonus: computeNowTzHhmm sanity.
    {
        const hhmm = computeNowTzHhmm(1_700_000_000, "UTC");
        assert(/^\d{2}:\d{2}$/.test(hhmm), `computeNowTzHhmm format ok (${hhmm})`);
    }
}

// ────────── 4b. BudgetTracker server-side ledger wiring ──────────

async function testBudgetTrackerServerSide() {
    console.log("\n═══ Test 4b: BudgetTracker server-side ledger ═══");

    // 1. Manual flush drains pending records.
    {
        const seen: BudgetState[] = [];
        const bt = new BudgetTracker({
            policyId: "pol_man",
            flushIntervalMs: 0, // disable timer; we drive flush manually
            flushFn: async (state) => {
                seen.push(state);
            },
        });
        bt.record(10, "a1");
        bt.record(2.5, "a2");
        assert(bt.pendingCount() === 2, "two records pending before flush");
        await bt.flush();
        assert(seen.length === 1, "flushFn invoked once");
        assert(seen[0].pending.length === 2, "flushFn saw two pending records");
        assert(bt.pendingCount() === 0, "pending drained after flush");
        await bt.stop();
    }

    // 2. Timer triggers flush when pending grows.
    {
        let calls = 0;
        const bt = new BudgetTracker({
            policyId: "pol_timer",
            flushIntervalMs: 25,
            flushFn: async () => {
                calls++;
            },
        });
        bt.record(1);
        // Wait ~80ms — at least two ticks should fire while pending is non-empty,
        // but flush itself drains pending, so we expect exactly 1 effective flush.
        await new Promise((r) => setTimeout(r, 80));
        assert(calls === 1, `timer fired exactly once with non-empty pending (got ${calls})`);
        // Record again -> another flush on next tick.
        bt.record(2);
        await new Promise((r) => setTimeout(r, 80));
        assert(calls === 2, `second tick flushed (got ${calls})`);
        await bt.stop();
    }

    // 3. serverPush builder POSTs each pending record to the configured route.
    {
        type Sent = { url: string; method: string; headers: Record<string, string>; body: string };
        const sent: Sent[] = [];
        const fakeFetch = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
            sent.push({
                url: typeof input === "string" ? input : input.toString(),
                method: (init?.method ?? "GET").toUpperCase(),
                headers: (init?.headers ?? {}) as Record<string, string>,
                body: typeof init?.body === "string" ? init!.body : "",
            });
            return new Response(JSON.stringify({ log_id: "splog_x", new_total_usd: 0 }), {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        }) as unknown as typeof fetch;

        const flushFn = BudgetTracker.serverPush({
            coreUrl: "http://core",
            adminKey: "dev",
            agentId: "agent-A",
            policyId: "pol_srv",
            httpFetch: fakeFetch,
        });
        const bt = new BudgetTracker({ policyId: "pol_srv", flushIntervalMs: 0, flushFn });
        bt.record(10, "act-1");
        bt.record(5);
        await bt.flush();
        assert(sent.length === 2, `serverPush POSTs once per pending record (got ${sent.length})`);
        assert(
            sent[0].url === "http://core/v1/agents/agent-A/spend",
            `URL composed correctly: ${sent[0].url}`
        );
        assert(sent[0].method === "POST", "method=POST");
        assert(
            (sent[0].headers as Record<string, string>).authorization === "Bearer dev",
            "Authorization header carried"
        );
        const first = JSON.parse(sent[0].body) as Record<string, unknown>;
        assert(first.policy_id === "pol_srv", "body.policy_id");
        assert(first.amount_usd === 10, "body.amount_usd");
        assert(first.action_id === "act-1", "body.action_id");
        await bt.stop();
    }

    // 4. stop() triggers a final flush so no record is lost.
    {
        let flushed: BudgetState | null = null;
        const bt = new BudgetTracker({
            policyId: "pol_stop",
            flushIntervalMs: 0,
            flushFn: async (state) => {
                flushed = state;
            },
        });
        bt.record(7);
        // Sanity: timer disabled, pending sitting there.
        assert(bt.pendingCount() === 1, "pending sits until stop()");
        await bt.stop();
        const f = flushed as unknown as BudgetState | null;
        assert(f !== null, "stop() called flushFn");
        if (f !== null) {
            assert(f.pending.length === 1, "final flush carried the pending record");
        }
        assert(bt.pendingCount() === 0, "stop() drained pending");
    }
}

// ────────── 4. tool-proxy ──────────

async function testToolProxy() {
    console.log("\n═══ Test 4: tool-proxy ═══");

    // Allow flow.
    {
        const cache = new PolicyCache({
            coreUrl: "http://t",
            refreshIntervalMs: 0,
            httpFetch: mockFetch(() => ({
                version: "1",
                agent: "a",
                binding: { allowed_tools: ["echo"] },
            })),
        });
        await cache.load("pol_a");

        let invoked = false;
        function echo(x: string) {
            invoked = true;
            return `echo:${x}`;
        }
        const guarded = bind(echo, {
            agentId: "ag",
            policyId: "pol_a",
            cache,
        });
        const out = guarded("hi");
        assert(invoked, "allow flow: original tool invoked");
        assert(out === "echo:hi", "allow flow: return value passes through");
        cache.stop();
    }

    // Deny flow.
    {
        const cache = new PolicyCache({
            coreUrl: "http://t",
            refreshIntervalMs: 0,
            httpFetch: mockFetch(() => ({
                version: "1",
                agent: "a",
                binding: { allowed_tools: ["only_this"] },
            })),
        });
        await cache.load("pol_d");

        let invoked = false;
        function echo(x: string) {
            invoked = true;
            return x;
        }
        let denySeen: { check: string; reason: string } | null = null;
        const guarded = bind(echo, {
            agentId: "ag",
            policyId: "pol_d",
            cache,
            onDeny: (v) => {
                denySeen = { check: v.check, reason: v.reason };
            },
        });
        let caught: unknown = null;
        try {
            guarded("x");
        } catch (e) {
            caught = e;
        }
        assert(caught instanceof PolicyDeniedError, "deny flow: throws PolicyDeniedError");
        assert(!invoked, "deny flow: original tool NOT invoked");
        assert(denySeen !== null, "deny flow: onDeny hook fired");
        if (caught instanceof PolicyDeniedError) {
            assert(caught.check === "allowlist", "deny flow: error.check = allowlist");
            assert(caught.policyId === "pol_d", "deny flow: error.policyId echoed");
        }
        cache.stop();
    }

    // Not-loaded flow.
    {
        const cache = new PolicyCache({
            coreUrl: "http://t",
            refreshIntervalMs: 0,
            httpFetch: mockFetch(() => null),
        });
        function echo(x: string) {
            return x;
        }
        const guarded = bind(echo, { agentId: "ag", policyId: "pol_missing", cache });
        let caught: unknown = null;
        try {
            guarded("x");
        } catch (e) {
            caught = e;
        }
        assert(caught instanceof PolicyNotLoadedError, "not-loaded: throws PolicyNotLoadedError");
        cache.stop();
    }
}

// ────────── main ──────────

async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  SauronID — Sprint 3 Enforcement Test           ║");
    console.log("╚══════════════════════════════════════════════════╝");

    try {
        await testPolicyCache();
        await testBudgetTracker();
        await testEvaluator();
        await testToolProxy();
        await testBudgetTrackerServerSide();

        console.log("\n══════════════════════════════════════════════════");
        console.log(`  Results: ${passed} passed, ${failed} failed`);
        console.log("══════════════════════════════════════════════════");

        if (failed > 0) process.exit(1);
    } catch (err) {
        const e = err as { message?: string; stack?: string };
        console.error("\n  ✗ FATAL:", e.message);
        console.error(e.stack);
        process.exit(1);
    }
}

void main();
