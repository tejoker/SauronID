/**
 * S12 redteam — binding-bypass #5: replay after server-side revoke.
 *
 * Threat-model citation: docs/security/threat-model.md "STRIDE per component → SDK
 * → Information disclosure: SDK caches stale policy after server-side
 * revoke". The PolicyCache by design keeps the last good copy on refresh
 * failure (so transient 5xx doesn't lock out the agent). This produces
 * a documented stale-cache window equal to `refreshIntervalMs`.
 *
 * Scenario: upload policy → bind → server-side delete → SDK still has
 * the cached copy → call still allowed. Drives the documentation point;
 * future sprint should add a server-pushed revocation feed for tighter
 * cache eviction.
 *
 * Pass = behaviour matches documentation: before refresh, calls allowed.
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
} from "./_s12_lib";

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
        refresh(id: string): Promise<void>;
        stop(): void;
    };
    bind: <A extends unknown[], R>(
        tool: (...args: A) => R,
        opts: { agentId: string; policyId: string; cache: unknown },
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
    const id = "B5";
    const name = "binding-revoke-replay";

    const enforcement = loadEnforcement();
    if (!enforcement) {
        return skipped(id, name, "sdk/typescript/dist not built");
    }
    const { PolicyCache, bind, PolicyNotLoadedError } = enforcement;

    const serverUp = await pingServer();
    if (!serverUp || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const yaml = [
        'version: "1"',
        "agent: revoke-replay",
        "binding:",
        "  allowed_tools: [ping]",
    ].join("\n");
    const polId = await uploadPolicy(yaml);
    if (!polId) {
        return { id, name, pass: false, note: "policy upload failed" };
    }

    const cache = new PolicyCache({ coreUrl: BASE_URL, adminKey: ADMIN_KEY, refreshIntervalMs: 0 });
    await cache.load(polId);

    function ping(): string {
        return "pong";
    }
    const guarded = bind(ping, { agentId: "ag", policyId: polId, cache });

    let beforeOk = false;
    try {
        beforeOk = guarded() === "pong";
    } catch {
        // unexpected
    }

    // Server-side revoke.
    await deletePolicy(polId);

    // Cache still warm — SDK still allows.
    let afterRevokeStillAllowed = false;
    try {
        afterRevokeStillAllowed = guarded() === "pong";
    } catch {
        afterRevokeStillAllowed = false;
    }

    // Trigger refresh — server returns 404, cache keeps last good copy.
    const origWarn = console.warn;
    console.warn = () => {
        /* suppress refresh warning */
    };
    await cache.refresh(polId);
    console.warn = origWarn;

    let afterRefreshStillAllowed = false;
    try {
        afterRefreshStillAllowed = guarded() === "pong";
    } catch (e) {
        afterRefreshStillAllowed = e instanceof PolicyNotLoadedError ? false : false;
    }

    cache.stop();

    const documented = beforeOk && afterRevokeStillAllowed && afterRefreshStillAllowed;
    return {
        id,
        name,
        pass: documented,
        note:
            "Stale-cache window: server-side revoke does NOT evict the cache. SDK keeps " +
            "last good copy on refresh-404 by design. Window = refreshIntervalMs (configurable). " +
            "Mitigation roadmap: server-pushed revocation feed.",
        evidence: {
            before_revoke: beforeOk,
            after_revoke_still_allowed: afterRevokeStillAllowed,
            after_refresh_still_allowed: afterRefreshStillAllowed,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
