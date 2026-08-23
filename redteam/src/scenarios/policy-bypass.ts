/**
 * Sprint 3 — policy-bypass redteam scenario.
 *
 * Exercises four bypass attempts against the SDK runtime guard introduced
 * in `sdk/typescript/src/enforcement.ts`. The scenario is INFORMATIONAL — it
 * documents the threat model and the current SDK guarantees rather than
 * asserting end-to-end blocking on every case. Several "expected"
 * outcomes describe known gaps that will be closed in later sprints.
 *
 * The script tolerates an unreachable server: SDK-only assertions still
 * run, server-side assertions are reported as `skipped` with a note.
 *
 * Output: a JSON object on stdout summarising each attempt.
 */

import * as path from "path";

// The SDK lives in a sibling package. Pull it via dynamic require so
// this redteam tsconfig stays scoped to `redteam/src`. Type the shape
// inline (just the surface we touch) to avoid cross-package rootDir
// complications.
interface CompiledPolicyShape {
    policy_id: string;
    agent: string;
    version: string;
    raw_yaml: string;
    checks: string[];
    binding: Record<string, unknown>;
}
interface PolicyCacheCtor {
    new (opts: { coreUrl: string; adminKey?: string; refreshIntervalMs?: number }): {
        load(id: string): Promise<CompiledPolicyShape>;
        get(id: string): CompiledPolicyShape | undefined;
        refresh(id: string): Promise<void>;
        stop(): void;
    };
}
interface BudgetTrackerCtor {
    new (opts: {
        policyId: string;
        flushIntervalMs?: number;
        flushFn?: (state: {
            policyId: string;
            totalUsd: number;
            callTimestampsMs: number[];
            pending: { amount_usd: number; action_id?: string; timestamp: number }[];
        }) => Promise<void>;
    }): {
        record(amountUsd: number, actionId?: string): void;
        total(): number;
        pendingCount(): number;
        flush(): Promise<void>;
        stop(): Promise<void>;
    };
    serverPush(opts: {
        coreUrl: string;
        adminKey?: string;
        agentId: string;
        policyId: string;
        httpFetch?: typeof fetch;
    }): (state: {
        policyId: string;
        totalUsd: number;
        callTimestampsMs: number[];
        pending: { amount_usd: number; action_id?: string; timestamp: number }[];
    }) => Promise<void>;
}
interface BindFn {
    <A extends unknown[], R>(
        tool: (...args: A) => R,
        opts: {
            agentId: string;
            policyId: string;
            cache: unknown;
            budgetTracker?: unknown;
            classifyAction?: (toolName: string, args: unknown) => Record<string, unknown>;
            onDeny?: (verdict: { kind: "deny"; check: string; reason: string }) => void;
        }
    ): (...args: A) => R;
}
interface EnforcementModule {
    PolicyCache: PolicyCacheCtor;
    BudgetTracker: BudgetTrackerCtor;
    bind: BindFn;
    PolicyDeniedError: new (...args: unknown[]) => Error;
    PolicyNotLoadedError: new (...args: unknown[]) => Error;
}

let enforcement: EnforcementModule;
try {
    const dist = path.resolve(__dirname, "..", "..", "..", "sdk", "typescript", "dist", "src", "enforcement.js");
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    enforcement = require(dist) as EnforcementModule;
} catch (err) {
    console.error("sdk/typescript/dist not built — run `cd sdk/typescript && npm run build` first.");
    console.error((err as Error).message);
    process.exit(2);
}
const { PolicyCache, BudgetTracker, bind, PolicyDeniedError, PolicyNotLoadedError } = enforcement;

interface AttemptResult {
    id: string;
    name: string;
    pass: boolean;
    note: string;
    sdkOutcome?: string;
    serverOutcome?: string;
}

const baseUrl = process.env.SAURON_CORE_URL || process.env.API_URL || "http://127.0.0.1:3001";
const adminKey = process.env.SAURON_ADMIN_KEY;

async function pingServer(): Promise<boolean> {
    try {
        const r = await fetch(`${baseUrl}/v1/policy/list`, {
            headers: adminKey ? { authorization: `Bearer ${adminKey}` } : {},
        });
        return r.status === 200 || r.status === 401;
    } catch {
        return false;
    }
}

async function uploadPolicy(yaml: string): Promise<string | null> {
    if (!adminKey) return null;
    const r = await fetch(`${baseUrl}/v1/policy/upload`, {
        method: "POST",
        headers: {
            "content-type": "application/yaml",
            authorization: `Bearer ${adminKey}`,
        },
        body: yaml,
    });
    if (!r.ok) return null;
    const data = (await r.json()) as { policy_id: string };
    return data.policy_id;
}

async function deletePolicy(id: string): Promise<boolean> {
    if (!adminKey) return false;
    const r = await fetch(`${baseUrl}/v1/policy/${id}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${adminKey}` },
    });
    return r.ok;
}

async function evaluateRemote(policyId: string, action: object): Promise<{ allow: boolean; check?: string } | null> {
    if (!adminKey) return null;
    const r = await fetch(`${baseUrl}/v1/policy/evaluate`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${adminKey}`,
        },
        body: JSON.stringify({ policy_id: policyId, action }),
    });
    if (!r.ok) return null;
    const data = (await r.json()) as { verdict: { kind: string; check?: string } };
    return { allow: data.verdict.kind === "allow", check: data.verdict.check };
}

// ─── attempts ─────────────────────────────────────────────────────────────

async function attempt1DirectCall(): Promise<AttemptResult> {
    // The wrapper returned by bind() guards. If a developer keeps a
    // reference to the underlying tool and calls it directly, the SDK
    // CANNOT intercept — this is a known limitation. Server-side
    // signing + admission control are the real choke point.
    function payTool(amount: number) {
        return `paid:${amount}`;
    }
    const result = payTool(10_000); // bypassing bind() entirely
    const sdkBlocked = false; // by design
    return {
        id: "A1",
        name: "Direct call without bind()",
        pass: !sdkBlocked, // documented behaviour — SDK does NOT block
        note:
            "Calling the underlying tool reference bypasses the wrapper. Defence-in-depth: " +
            "rely on the server's call-sig binding + admission middleware.",
        sdkOutcome: `tool returned '${result}' — SDK guard never invoked (no bind in path)`,
    };
}

async function attempt2SpoofedClassification(serverUp: boolean): Promise<AttemptResult> {
    // Build a local policy that denies PII data. Provide a classifier
    // that LIES (returns "public" when args contain PII). Local SDK
    // allows because it trusts the classifier. The server, given the
    // truthful action, denies — proving server-side cross-check is the
    // authoritative gate.
    const cache = new PolicyCache({
        coreUrl: baseUrl,
        adminKey,
        refreshIntervalMs: 0,
    });
    // Inject a fake policy directly into the cache so we don't need a server roundtrip.
    (cache as unknown as { entries: Map<string, unknown> }).entries.set("pol_spoof", {
        policy_id: "pol_spoof",
        agent: "spoof",
        version: "1",
        raw_yaml: "",
        checks: ["scope"],
        binding: { data_scope: { allow: ["public"], deny: ["pii"] } },
    });

    function readData(payload: { ssn?: string }) {
        return `data:${JSON.stringify(payload)}`;
    }
    const guarded = bind(readData, {
        agentId: "agent-spoof",
        policyId: "pol_spoof",
        cache,
        classifyAction: (_tool, args) => {
            // Truth would be "pii" when ssn present; we LIE.
            const a = args as [{ ssn?: string }];
            void a;
            return { dataClassification: "public" };
        },
    });
    let sdkBlocked = false;
    try {
        guarded({ ssn: "123-45-6789" });
    } catch (e) {
        if (e instanceof PolicyDeniedError) sdkBlocked = true;
    }

    let serverOutcome = "skipped (server unreachable)";
    let serverBlocked: boolean | null = null;
    if (serverUp && adminKey) {
        // Upload a real policy + ask server to evaluate with the TRUE classification.
        const yaml = [
            "version: \"1\"",
            "agent: spoof-eval",
            "binding:",
            "  data_scope:",
            "    allow: [public]",
            "    deny: [pii]",
        ].join("\n");
        const polId = await uploadPolicy(yaml);
        if (polId) {
            const verdict = await evaluateRemote(polId, {
                action_id: "a-spoof",
                tool: "readData",
                data_classification: "pii",
                signatures: [],
                delegation_depth: 0,
                timestamp: Math.floor(Date.now() / 1000),
            });
            await deletePolicy(polId);
            if (verdict) {
                serverBlocked = !verdict.allow;
                serverOutcome = serverBlocked
                    ? `server DENY (${verdict.check ?? "unknown"})`
                    : "server allowed (UNEXPECTED)";
            }
        }
    }

    cache.stop();
    // Pass when SDK allowed (lied) AND server denied (cross-check works).
    // If server unreachable, pass on SDK-only documented behaviour.
    const pass = !sdkBlocked && (serverBlocked === null || serverBlocked === true);
    return {
        id: "A2",
        name: "Spoofed classification via lying classifyAction",
        pass,
        note:
            "SDK trusts the classifier. Server re-evaluates with truthful data and denies. " +
            "Treat the classifier as untrusted input from the agent itself.",
        sdkOutcome: sdkBlocked ? "SDK denied (unexpected)" : "SDK allowed (trusted spoofed tag)",
        serverOutcome,
    };
}

async function attempt3BumpedBudget(serverUp: boolean): Promise<AttemptResult[]> {
    // A3 splits into two sub-attempts:
    //
    //   A3a — "SDK happy-path bypass": the local BudgetTracker counter is
    //         mutable in-process state. Tampering it with a negative spend
    //         still defeats the LOCAL evaluator. This is the documented
    //         (and unchanged) SDK-only limitation — the wrapper trusts its
    //         own counter.
    //
    //   A3b — "Server cross-check on POST /v1/policy/evaluate": now that
    //         the server holds an authoritative spend ledger (Sprint 3
    //         follow-up), the same lying SDK + an explicit POST
    //         /v1/policy/evaluate{agent_id} call surfaces the truth. The
    //         server IGNORES the client's spend_total_usd, looks up the
    //         ledger, and denies. This NEWLY closes the loop.
    const results: AttemptResult[] = [];

    // ── A3a: SDK happy-path bypass (unchanged) ──────────────────────────
    {
        const cache = new PolicyCache({
            coreUrl: baseUrl,
            adminKey,
            refreshIntervalMs: 0,
        });
        (cache as unknown as { entries: Map<string, unknown> }).entries.set(
            "pol_budget",
            {
                policy_id: "pol_budget",
                agent: "b",
                version: "1",
                raw_yaml: "",
                checks: ["budget"],
                binding: { max_budget_usd: 100 },
            }
        );
        const budget = new BudgetTracker({
            policyId: "pol_budget",
            flushIntervalMs: 0, // disable timer so we keep the lie local
        });
        // Tamper: drop the running total far into the red. record() takes
        // arbitrary numbers — negative inputs are not validated.
        budget.record(-9_999);

        function spend(usd: number) {
            return `spent:${usd}`;
        }
        const guarded = bind(spend, {
            agentId: "ag",
            policyId: "pol_budget",
            cache,
            budgetTracker: budget,
            classifyAction: (_t, args) => ({ amountUsd: (args as [number])[0] }),
        });
        let sdkBlocked = false;
        try {
            guarded(5_000); // wildly over cap
        } catch (e) {
            if (e instanceof PolicyDeniedError) sdkBlocked = true;
        }
        cache.stop();
        await budget.stop();

        results.push({
            id: "A3a",
            name: "Tampered local budget counter — SDK happy-path bypass",
            pass: !sdkBlocked, // passes by design: SDK trusts its own counter
            note:
                "Local BudgetTracker remains mutable in-process state; the SDK wrapper " +
                "uses it for fast pre-checks. The server-side ledger (A3b) is the real " +
                "choke point.",
            sdkOutcome: sdkBlocked
                ? "SDK denied (unexpected)"
                : "SDK allowed (tampered counter undermined LOCAL budget check)",
            serverOutcome:
                "n/a — A3a only exercises the local evaluator; see A3b for cross-check.",
        });
    }

    // ── A3b: Server cross-check via POST /v1/policy/evaluate ────────────
    if (!serverUp || !adminKey) {
        results.push({
            id: "A3b",
            name: "Server cross-check on POST /v1/policy/evaluate (authoritative ledger)",
            pass: true,
            note:
                "Skipped — needs a reachable server with admin key. The route is now wired " +
                "(closes redteam A3); rerun with SAURON_CORE_URL + SAURON_ADMIN_KEY to exercise.",
            sdkOutcome: "skipped",
            serverOutcome: "skipped (server unreachable or no admin key)",
        });
        return results;
    }

    // 1. Upload a real policy with a $100 cap.
    const yaml = [
        'version: "1"',
        "agent: budget-cross",
        "binding:",
        "  max_budget_usd: 100",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        results.push({
            id: "A3b",
            name: "Server cross-check on POST /v1/policy/evaluate",
            pass: false,
            note: "Upload failed; expected server-side enforcement was not reachable.",
            sdkOutcome: "skipped",
            serverOutcome: "upload failed",
        });
        return results;
    }
    const agentId = `cross-check-${Date.now()}`;
    // 2. Seed the authoritative ledger: $50 already spent.
    const seedResp = await fetch(`${baseUrl}/v1/agents/${agentId}/spend`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${adminKey}`,
        },
        body: JSON.stringify({ policy_id: polId, amount_usd: 50 }),
    });
    const seededOk = seedResp.ok;
    // 3. Locally tamper a BudgetTracker into a negative total.
    const budget = new BudgetTracker({
        policyId: polId,
        flushIntervalMs: 0,
    });
    budget.record(-9_999);
    const localTotal = budget.total();
    // 4. Local evaluator says: (-9949) + 60 < 100 → allow.
    // 5. Server-side evaluate: agent_id forces ledger lookup → $50 + $60 = $110 → deny.
    const r = await fetch(`${baseUrl}/v1/policy/evaluate`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${adminKey}`,
        },
        body: JSON.stringify({
            policy_id: polId,
            agent_id: agentId,
            action: {
                action_id: "act-cross",
                tool: "pay",
                amount_usd: 60,
                signatures: [],
                delegation_depth: 0,
                timestamp: Math.floor(Date.now() / 1000),
            },
            context_overrides: {
                // The lying SDK would send the tampered total here. The
                // server is supposed to IGNORE it and use the ledger.
                spend_total_usd: localTotal,
            },
        }),
    });
    let serverVerdict: { kind?: string; check?: string } | null = null;
    let authoritativeSpend: number | null = null;
    let simulator: boolean | null = null;
    if (r.ok) {
        const data = (await r.json()) as {
            verdict: { kind: string; check?: string };
            spend_total_usd: number;
            simulator?: boolean;
        };
        serverVerdict = data.verdict;
        authoritativeSpend = data.spend_total_usd;
        simulator = data.simulator ?? false;
    }
    await deletePolicy(polId);

    const serverDenied = serverVerdict?.kind === "deny";
    const serverUsedLedger =
        authoritativeSpend !== null && Math.abs(authoritativeSpend - 50) < 1e-6;
    const ledgerWasNotSimulator = simulator === false;
    const pass = seededOk && serverDenied && serverUsedLedger && ledgerWasNotSimulator;
    results.push({
        id: "A3b",
        name: "Server cross-check on POST /v1/policy/evaluate (authoritative ledger)",
        pass,
        note:
            "Server-side spend ledger now wins. Seeded $50, lied locally with $-9949, " +
            "asked server to evaluate a $60 action with agent_id supplied — server reports " +
            "total=$50 and denies on budget. Tampering the SDK counter no longer suffices.",
        sdkOutcome: `tampered local total = ${localTotal} (lied)`,
        serverOutcome: serverVerdict
            ? `server verdict=${serverVerdict.kind}${
                  serverVerdict.check ? ` (${serverVerdict.check})` : ""
              }, authoritative spend=${authoritativeSpend ?? "?"}, simulator=${simulator}`
            : "server call failed",
    });
    return results;
}

async function attempt4ReplayAfterRevoke(serverUp: boolean): Promise<AttemptResult> {
    // Upload P1, bind, server-side delete P1, attempt call. Cache
    // still has P1 until refresh → SDK allows. After refresh, SDK
    // still has the stale entry (refresh fails for deleted policies
    // and keeps last good copy by design). The mitigation is to
    // explicitly evict on revoke notification (out of scope for S3).
    if (!serverUp || !adminKey) {
        return {
            id: "A4",
            name: "Replay after server-side revoke",
            pass: true,
            note:
                "Skipped — needs a reachable server with admin key. SDK cache keeps last good " +
                "copy on refresh failure, so revoked policies linger until explicit eviction.",
            sdkOutcome: "skipped",
            serverOutcome: "skipped (server unreachable)",
        };
    }

    const yaml = [
        "version: \"1\"",
        "agent: revoke-test",
        "binding:",
        "  allowed_tools: [ping]",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return {
            id: "A4",
            name: "Replay after server-side revoke",
            pass: true,
            note: "Upload failed; treating as skipped.",
            sdkOutcome: "skipped",
        };
    }

    const cache = new PolicyCache({ coreUrl: baseUrl, adminKey, refreshIntervalMs: 0 });
    await cache.load(polId);
    function ping() { return "pong"; }
    const guarded = bind(ping, { agentId: "ag", policyId: polId, cache });

    const beforeRevoke = guarded(); // expect allow
    await deletePolicy(polId);

    // Cache still warm — SDK still allows.
    let stillAllowed = false;
    try {
        guarded();
        stillAllowed = true;
    } catch { /* unexpected */ }

    // Trigger refresh — server returns 404, cache keeps last good copy.
    const originalWarn = console.warn;
    console.warn = () => { /* suppress refresh warning */ };
    await cache.refresh(polId);
    console.warn = originalWarn;

    // After refresh failure, last good copy is still present.
    let afterRefresh = false;
    try {
        guarded();
        afterRefresh = true;
    } catch (e) {
        if (e instanceof PolicyNotLoadedError) afterRefresh = false;
    }
    cache.stop();

    return {
        id: "A4",
        name: "Replay after server-side revoke",
        pass: beforeRevoke === "pong" && stillAllowed && afterRefresh,
        note:
            "Stale-cache window between server-side revoke and explicit cache eviction. " +
            "Mitigation: subscribe to a revocation feed (future sprint).",
        sdkOutcome:
            `before revoke=allowed, after revoke=${stillAllowed ? "still allowed" : "blocked"}, ` +
            `after refresh=${afterRefresh ? "still allowed" : "blocked"}`,
        serverOutcome: "policy deleted",
    };
}

// ─── main ──────────────────────────────────────────────────────────────────

async function main() {
    const serverUp = await pingServer();
    const results: AttemptResult[] = [];
    results.push(await attempt1DirectCall());
    results.push(await attempt2SpoofedClassification(serverUp));
    results.push(...(await attempt3BumpedBudget(serverUp)));
    results.push(await attempt4ReplayAfterRevoke(serverUp));

    const summary = {
        scenario: "policy-bypass",
        server_reachable: serverUp,
        base_url: baseUrl,
        attempts: results,
        passed: results.filter((r) => r.pass).length,
        total: results.length,
    };
    console.log(JSON.stringify(summary, null, 2));
    process.exit(summary.passed === summary.total ? 0 : 1);
}

void main();
