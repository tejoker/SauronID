/**
 * S12 redteam — binding-bypass #2: stale-cache race.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component → SDK
 * → Information disclosure: SDK caches stale policy after server-side
 * revoke". The PolicyCache keeps the last good copy on refresh failure,
 * by design. Operators can configure refreshIntervalMs.
 *
 * Scenario: agent forks process AFTER policy upload but BEFORE first
 * cache refresh — tries the action immediately. Either:
 *   (a) cache miss → PolicyNotLoadedError (SDK lazy-load behaviour), or
 *   (b) we explicitly load → policy returns and call evaluated.
 *
 * Expected behaviour is path (a) if `bind()` is invoked before `load()`,
 * which is the natural fork-and-go race. We assert PolicyNotLoadedError
 * is the thrown class.
 */

import * as path from "path";
import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    uploadPolicy,
    deletePolicy,
    runScenario,
    skipped,
} from "../lib/_s12_lib";

interface CompiledPolicyShape {
    policy_id: string;
    agent: string;
    version: string;
    raw_yaml: string;
    checks: string[];
    binding: Record<string, unknown>;
}
interface EnforcementModule {
    PolicyCache: new (opts: {
        coreUrl: string;
        adminKey?: string;
        refreshIntervalMs?: number;
    }) => {
        load(id: string): Promise<CompiledPolicyShape>;
        get(id: string): CompiledPolicyShape | undefined;
        stop(): void;
    };
    bind: <A extends unknown[], R>(
        tool: (...args: A) => R,
        opts: {
            agentId: string;
            policyId: string;
            cache: unknown;
        },
    ) => (...args: A) => R;
    PolicyNotLoadedError: new (...args: unknown[]) => Error;
}

function loadEnforcement(): EnforcementModule | null {
    try {
        const dist = path.resolve(
            __dirname,
            "..",
            "..",
            "..",
            "..",
            "sdk",
            "typescript",
            "dist",
            "src",
            "enforcement.js",
        );
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        return require(dist) as EnforcementModule;
    } catch {
        return null;
    }
}

async function main(): Promise<ScenarioResult> {
    const id = "B2";
    const name = "binding-stale-cache";

    const enforcement = loadEnforcement();
    if (!enforcement) {
        return skipped(id, name, "sdk/typescript/dist not built; run `cd sdk/typescript && npm run build`");
    }
    const { PolicyCache, bind, PolicyNotLoadedError } = enforcement;

    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const yaml = [
        'version: "1"',
        "agent: stale-cache",
        "binding:",
        "  allowed_tools: [ping]",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return { id, name, pass: false, note: "policy upload failed" };
    }

    const cache = new PolicyCache({
        coreUrl: BASE_URL,
        adminKey: ADMIN_KEY,
        refreshIntervalMs: 0, // simulate fork-and-go: no refresh yet
    });

    function ping(): string {
        return "pong";
    }

    // bind() WITHOUT having called cache.load() yet. The wrapper should
    // throw PolicyNotLoadedError on first invocation.
    const guarded = bind(ping, {
        agentId: "stale-agent",
        policyId: polId,
        cache,
    });

    let threw: Error | null = null;
    try {
        guarded();
    } catch (e) {
        threw = e as Error;
    }
    const isNotLoaded = threw instanceof PolicyNotLoadedError;

    cache.stop();
    await deletePolicy(polId);

    return {
        id,
        name,
        pass: isNotLoaded,
        note:
            "Fork-and-go race: SDK wrapper invoked before cache.load() throws " +
            "PolicyNotLoadedError. Operators MUST await cache.load() during agent " +
            "boot. Documented in sdk/typescript/src/enforcement.ts.",
        evidence: {
            threw_class: threw?.constructor.name ?? "none",
            threw_message: threw?.message,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
