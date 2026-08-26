/**
 * Sprint 7 — local aggregator unit tests.
 *
 * One happy-path test per catalog metric + a couple of envelope tests
 * (period filtering, fixed-point encoding). Same standalone runner style
 * as `enforcement.test.ts` — assert counters, exit non-zero on failure.
 */

import {
    LocalAggregator,
    percentileNearestRank,
    type ReceiptLike,
} from "../src/stats/local-aggregate";
import { METRICS, toFixedPoint } from "../src/stats/metric-catalog";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
    if (cond) {
        console.log(`  ✓ ${msg}`);
        passed++;
    } else {
        console.error(`  ✗ FAILED: ${msg}`);
        failed++;
    }
}

function mkReceipt(over: Partial<ReceiptLike> = {}): ReceiptLike {
    return {
        receipt_id: "r1",
        action_hash: "h1",
        agent_id: "agent-A",
        status: "ok",
        tool: "echo",
        created_at: 100,
        ...over,
    };
}

const PERIOD = { start: 0, end: 1000 };

function aggregator(receipts: ReceiptLike[]): LocalAggregator {
    return new LocalAggregator({
        receipts,
        periodStart: PERIOD.start,
        periodEnd: PERIOD.end,
    });
}

async function testSuccessRate() {
    console.log("\n═══ metric: success_rate ═══");
    const rs = [
        mkReceipt({ status: "ok" }),
        mkReceipt({ status: "ok" }),
        mkReceipt({ status: "denied" }),
        mkReceipt({ status: "ok" }),
    ];
    const m = aggregator(rs).compute("success_rate");
    assert(m.value === 0.75, `value = 0.75 (got ${m.value})`);
    assert(m.value_fixed === 750, `fixed-point = 750 (got ${m.value_fixed})`);
    assert(m.n_records_used === 4, "n_records_used = 4");
    assert(m.period.start === 0 && m.period.end === 1000, "period propagated");
}

async function testErrorRate() {
    console.log("\n═══ metric: error_rate ═══");
    const rs = [
        mkReceipt({ status: "ok" }),
        mkReceipt({ status: "denied" }),
        mkReceipt({ status: "timeout" }),
    ];
    const m = aggregator(rs).compute("error_rate");
    // 2/3 non-ok
    assert(Math.abs(m.value - 2 / 3) < 1e-9, `value ≈ 0.6667 (got ${m.value})`);
    assert(m.value_fixed === toFixedPoint(2 / 3), "fixed-point matches helper");
}

async function testToolCallCount() {
    console.log("\n═══ metric: tool_call_count ═══");
    const rs = [
        mkReceipt({ tool: "echo" }),
        mkReceipt({ tool: "" }),
        mkReceipt({ tool: "shell" }),
        mkReceipt({ tool: "shell" }),
    ];
    const m = aggregator(rs).compute("tool_call_count");
    assert(m.value === 3, `count of non-empty tool = 3 (got ${m.value})`);
}

async function testUniqueToolsUsed() {
    console.log("\n═══ metric: unique_tools_used ═══");
    const rs = [
        mkReceipt({ tool: "echo" }),
        mkReceipt({ tool: "shell" }),
        mkReceipt({ tool: "echo" }),
        mkReceipt({ tool: "" }),
    ];
    const m = aggregator(rs).compute("unique_tools_used");
    assert(m.value === 2, `distinct non-empty tools = 2 (got ${m.value})`);
}

async function testCostTotal() {
    console.log("\n═══ metric: cost_total ═══");
    const rs = [
        mkReceipt({ amount_usd: 1.25 }),
        mkReceipt({ amount_usd: 2.5 }),
        mkReceipt({ amount_usd: 0 }),
        mkReceipt({ /* missing */ }),
    ];
    const m = aggregator(rs).compute("cost_total");
    assert(Math.abs(m.value - 3.75) < 1e-9, `cost_total = 3.75 (got ${m.value})`);
}

async function testPolicyViolationsBlocked() {
    console.log("\n═══ metric: policy_violations_blocked ═══");
    const rs = [
        mkReceipt({ status: "ok" }),
        mkReceipt({ status: "denied" }),
        mkReceipt({ status: "denied" }),
        mkReceipt({ status: "timeout" }),
    ];
    const m = aggregator(rs).compute("policy_violations_blocked");
    assert(m.value === 2, `denied count = 2 (got ${m.value})`);
}

async function testSessionsCount() {
    console.log("\n═══ metric: sessions_count ═══");
    const rs = [
        mkReceipt({ agent_id: "A" }),
        mkReceipt({ agent_id: "B" }),
        mkReceipt({ agent_id: "A" }),
        mkReceipt({ agent_id: "C" }),
    ];
    const m = aggregator(rs).compute("sessions_count");
    assert(m.value === 3, `distinct agent_id = 3 (got ${m.value})`);
}

async function testLatencyP50() {
    console.log("\n═══ metric: latency_p50 ═══");
    const rs = [
        mkReceipt({ latency_ms: 100 }),
        mkReceipt({ latency_ms: 200 }),
        mkReceipt({ latency_ms: 300 }),
        mkReceipt({ latency_ms: 400 }),
    ];
    const m = aggregator(rs).compute("latency_p50");
    // nearest-rank p50 of [100,200,300,400] → idx ceil(0.5*4)-1 = 1 → 200
    assert(m.value === 200, `p50 = 200 (got ${m.value})`);
}

async function testLatencyP99() {
    console.log("\n═══ metric: latency_p99 ═══");
    const rs = Array.from({ length: 100 }, (_, i) =>
        mkReceipt({ latency_ms: i + 1 }),
    );
    const m = aggregator(rs).compute("latency_p99");
    assert(m.value === 99, `p99 of 1..100 = 99 (got ${m.value})`);
}

async function testAvgSessionDuration() {
    console.log("\n═══ metric: avg_session_duration ═══");
    const rs = [
        mkReceipt({ latency_ms: 1000 }),
        mkReceipt({ latency_ms: 2000 }),
        mkReceipt({ latency_ms: 3000 }),
    ];
    const m = aggregator(rs).compute("avg_session_duration");
    // avg = 2000 ms = 2 s
    assert(Math.abs(m.value - 2) < 1e-9, `avg = 2 seconds (got ${m.value})`);
}

async function testEnvelopePeriodFilter() {
    console.log("\n═══ envelope: period filter ═══");
    const rs = [
        mkReceipt({ created_at: 50 }), // in
        mkReceipt({ created_at: 500 }), // in
        mkReceipt({ created_at: 5000 }), // out
    ];
    const agg = new LocalAggregator({ receipts: rs, periodStart: 0, periodEnd: 1000 });
    assert(agg.size() === 2, `period filter kept 2 (got ${agg.size()})`);
}

async function testEnvelopeComputeAll() {
    console.log("\n═══ envelope: computeAll covers catalog ═══");
    const rs = [
        mkReceipt({ status: "ok", latency_ms: 10, amount_usd: 1.0 }),
        mkReceipt({ status: "denied", latency_ms: 20, amount_usd: 2.0 }),
    ];
    const all = aggregator(rs).computeAll();
    const expectedKeys = Object.keys(METRICS).sort();
    const gotKeys = Object.keys(all).sort();
    assert(
        gotKeys.length === expectedKeys.length &&
            gotKeys.every((k, i) => k === expectedKeys[i]),
        "computeAll returns every catalog metric",
    );
}

async function testPercentileEdgeCases() {
    console.log("\n═══ percentileNearestRank: edge cases ═══");
    assert(percentileNearestRank([], 50) === 0, "empty → 0");
    assert(percentileNearestRank([42], 50) === 42, "singleton p50");
    assert(percentileNearestRank([1, 2, 3], 100) === 3, "p100 = max");
    assert(percentileNearestRank([1, 2, 3], 0) === 1, "p0 = min");
}

async function main() {
    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║  SauronID — Sprint 7 LocalAggregator tests      ║");
    console.log("╚══════════════════════════════════════════════════╝");
    try {
        await testSuccessRate();
        await testErrorRate();
        await testToolCallCount();
        await testUniqueToolsUsed();
        await testCostTotal();
        await testPolicyViolationsBlocked();
        await testSessionsCount();
        await testLatencyP50();
        await testLatencyP99();
        await testAvgSessionDuration();
        await testEnvelopePeriodFilter();
        await testEnvelopeComputeAll();
        await testPercentileEdgeCases();

        console.log("\n══════════════════════════════════════════════════");
        console.log(`  Results: ${passed} passed, ${failed} failed`);
        console.log("══════════════════════════════════════════════════");
        if (failed > 0) process.exit(1);
    } catch (e) {
        const err = e as Error;
        console.error("\n  ✗ FATAL:", err.message);
        console.error(err.stack);
        process.exit(1);
    }
}

void main();
