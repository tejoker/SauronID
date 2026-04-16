/**
 * Scripted KYA red-team / invariant suite (no LLM). Safe for CI.
 *
 * Env:
 *   API_URL | SAURON_CORE_URL — core base URL
 *   SAURON_ADMIN_KEY — admin key
 *   E2E_BANK_SITE — bank client name (default BNP Paribas)
 *   REDTEAM_ITERATIONS — repeat full suite N times (default 1)
 */

import { CoreApi } from "./core-api";
import { scenarioAutonomousPolicy } from "./scenarios/autonomous-policy";
import { scenarioDelegatedPolicy } from "./scenarios/delegated-policy";
import { scenarioDelegationScopeDenied } from "./scenarios/delegation-scope-denied";
import { scenarioInvalidAjwt } from "./scenarios/invalid-ajwt";
import { scenarioJtiReplay } from "./scenarios/jti-replay";
import { scenarioParentEmptyScopeDenied } from "./scenarios/parent-empty-scope-denied";
import { scenarioPopRequiredOnVerify } from "./scenarios/pop-required-on-verify";

const baseUrl = process.env.API_URL || process.env.SAURON_CORE_URL || "http://127.0.0.1:3001";
const adminKey = process.env.SAURON_ADMIN_KEY || "super_secret_hackathon_key";
const bankSite = process.env.E2E_BANK_SITE || "BNP Paribas";
const iterations = Math.max(1, parseInt(process.env.REDTEAM_ITERATIONS || "1", 10) || 1);

type ScenarioFn = (api: CoreApi, bank: string, label: string) => Promise<void>;

const scenarios: { name: string; run: ScenarioFn }[] = [
    { name: "invalid_ajwt", run: async (api, _b, _l) => scenarioInvalidAjwt(api) },
    { name: "jti_replay_blocked", run: scenarioJtiReplay },
    { name: "autonomous_policy_matrix", run: scenarioAutonomousPolicy },
    { name: "delegated_policy_matrix", run: scenarioDelegatedPolicy },
    { name: "delegation_scope_denied", run: scenarioDelegationScopeDenied },
    { name: "parent_empty_scope_denied", run: scenarioParentEmptyScopeDenied },
    { name: "pop_required_on_verify", run: scenarioPopRequiredOnVerify },
];

async function main(): Promise<void> {
    console.log(`\n╔══════════════════════════════════════════════════╗
║  KYA red-team (scripted)                         ║
║  ${baseUrl.padEnd(42)}║
╚══════════════════════════════════════════════════╝\n`);

    const api = new CoreApi({ baseUrl, adminKey });
    let failed = 0;

    for (let i = 0; i < iterations; i++) {
        const label = iterations > 1 ? `i${i}` : "run";
        for (const { name, run } of scenarios) {
            try {
                process.stdout.write(`  … ${name} (${label}) … `);
                await run(api, bankSite, label);
                console.log("OK");
            } catch (e) {
                failed++;
                console.log("FAIL");
                console.error(`    ${e instanceof Error ? e.message : e}`);
            }
        }
    }

    if (failed > 0) {
        console.error(`\n  Red-team: ${failed} scenario(s) failed\n`);
        process.exit(1);
    }
    console.log(`\n  Red-team: all ${scenarios.length * iterations} run(s) passed\n`);
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
