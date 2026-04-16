/**
 * Optional LLM-driven red-team: model selects which scripted scenarios to re-run.
 *
 * Requires: OPENAI_API_KEY
 * Env: REDTEAM_MODEL (default gpt-4o-mini), REDTEAM_LLM_TURNS (default 12)
 *
 * If OPENAI_API_KEY is unset, exits 0 (skip).
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
const apiKey = process.env.OPENAI_API_KEY;
const model = process.env.REDTEAM_MODEL || "gpt-4o-mini";
const maxTurns = Math.min(30, Math.max(1, parseInt(process.env.REDTEAM_LLM_TURNS || "12", 10) || 12));

const scenarioMap: Record<string, (api: CoreApi, bank: string, label: string) => Promise<void>> = {
    invalid_ajwt: async (a, _b, _l) => scenarioInvalidAjwt(a),
    jti_replay_blocked: scenarioJtiReplay,
    autonomous_policy_matrix: scenarioAutonomousPolicy,
    delegated_policy_matrix: scenarioDelegatedPolicy,
    delegation_scope_denied: scenarioDelegationScopeDenied,
    parent_empty_scope_denied: scenarioParentEmptyScopeDenied,
    pop_required_on_verify: scenarioPopRequiredOnVerify,
};

const toolDef = {
    type: "function" as const,
    function: {
        name: "run_kya_scenario",
        description:
            "Execute one KYA invariant check against the live Sauron core. Use different scenarios to probe policy, replay, delegation, and PoP.",
        parameters: {
            type: "object",
            properties: {
                scenario_id: {
                    type: "string",
                    enum: Object.keys(scenarioMap),
                },
                note: { type: "string", description: "Why you chose this scenario (audit trail)" },
            },
            required: ["scenario_id"],
        },
    },
};

async function openaiChat(messages: unknown[]): Promise<{
    message: { content: string | null; tool_calls?: { id: string; function: { name: string; arguments: string } }[] };
}> {
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
            model,
            messages,
            tools: [toolDef],
            tool_choice: "auto",
            temperature: 0.3,
        }),
    });
    if (!r.ok) {
        const t = await r.text();
        throw new Error(`OpenAI ${r.status}: ${t}`);
    }
    const j = (await r.json()) as {
        choices: { message: { content: string | null; tool_calls?: { id: string; function: { name: string; arguments: string } }[] } }[];
    };
    return { message: j.choices[0].message };
}

async function main(): Promise<void> {
    if (!apiKey) {
        console.log("[llm-runner] OPENAI_API_KEY unset — skip LLM red-team");
        process.exit(0);
    }

    const api = new CoreApi({ baseUrl, adminKey });
    const messages: unknown[] = [
        {
            role: "system",
            content: `You are a security auditor for SauronID KYA (Know Your Agent). The API is at ${baseUrl}.
You must call run_kya_scenario repeatedly with different scenario_id values to stress authorization, replay protection, delegation rules, and proof-of-possession.
After you believe coverage is sufficient, respond with a single word: DONE (no more tool calls).`,
        },
        {
            role: "user",
            content:
                "Run a red-team pass: prioritize scenarios that test deny paths (replay, bad delegation, PoP) and one allow path per assurance level. Max tool calls: " +
                String(maxTurns),
        },
    ];

    let turns = 0;
    while (turns < maxTurns) {
        turns++;
        const { message } = await openaiChat(messages);
        messages.push({ role: "assistant", content: message.content, tool_calls: message.tool_calls });

        if (message.content?.trim() === "DONE" && !message.tool_calls?.length) {
            console.log("[llm-runner] model finished with DONE");
            break;
        }

        if (!message.tool_calls?.length) {
            console.log("[llm-runner] no tool calls; stopping");
            break;
        }

        for (const tc of message.tool_calls) {
            if (tc.function.name !== "run_kya_scenario") continue;
            let args: { scenario_id?: string; note?: string };
            try {
                args = JSON.parse(tc.function.arguments || "{}");
            } catch {
                args = {};
            }
            const id = args.scenario_id ?? "";
            const fn = scenarioMap[id];
            let result: string;
            try {
                if (!fn) throw new Error(`unknown scenario_id: ${id}`);
                await fn(api, bankSite, `llm${turns}`);
                result = `OK: ${id}${args.note ? ` (${args.note})` : ""}`;
            } catch (e) {
                result = `FAIL: ${id} — ${e instanceof Error ? e.message : e}`;
            }
            messages.push({
                role: "tool",
                tool_call_id: tc.id,
                content: result,
            });
        }
    }

    console.log("[llm-runner] completed");
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
