/**
 * Shared subprocess aggregator for the S12 per-category meta-runners.
 * Spawns each compiled scenario script and collects its stdout JSON.
 */

import { spawn } from "child_process";
import * as path from "path";

export interface ScenarioRun {
    scenario: string;
    exit_code: number;
    stdout: string;
    parsed?: unknown;
}

export interface CategoryResult {
    category: string;
    server_url: string;
    strict: boolean;
    results: ScenarioRun[];
    summary: { total: number; passed: number; skipped: number };
}

export async function runOne(name: string): Promise<ScenarioRun> {
    const distFile = path.resolve(
        __dirname,
        "..",
        "..",
        "dist",
        "scenarios",
        `${name}.js`,
    );
    return new Promise((resolve) => {
        const child = spawn(process.execPath, [distFile], {
            stdio: ["ignore", "pipe", "inherit"],
            env: process.env,
        });
        let out = "";
        child.stdout.on("data", (chunk: Buffer) => {
            out += chunk.toString();
        });
        child.on("close", (code) => {
            let parsed: unknown;
            try {
                parsed = JSON.parse(out);
            } catch {
                parsed = undefined;
            }
            resolve({
                scenario: name,
                exit_code: code ?? -1,
                stdout: out,
                parsed,
            });
        });
    });
}

export async function runCategory(
    category: string,
    scenarios: string[],
): Promise<void> {
    const baseUrl =
        process.env.SAURON_CORE_URL || process.env.API_URL || "http://127.0.0.1:3001";
    const results: ScenarioRun[] = [];
    for (const s of scenarios) {
        results.push(await runOne(s));
    }
    const passed = results.filter((r) => r.exit_code === 0).length;
    // A skipped scenario exits 0, so exit codes alone cannot tell "the
    // invariant holds" from "nothing ran". Under strict mode a skip is a
    // failure: in CI the core is supposed to be up, so a skip means the
    // harness lost its target and the category proved nothing.
    const skipped = results.filter(
        (r) => (r.parsed as { skipped?: boolean } | undefined)?.skipped === true,
    ).length;
    const strict = process.env.SAURON_REDTEAM_STRICT === "1";
    const agg: CategoryResult = {
        category,
        server_url: baseUrl,
        strict,
        results,
        summary: { total: scenarios.length, passed, skipped },
    };
    console.log(JSON.stringify(agg, null, 2));
    if (passed !== scenarios.length) process.exit(1);
    if (strict && skipped > 0) {
        console.error(
            `SAURON_REDTEAM_STRICT=1 and ${skipped}/${scenarios.length} scenario(s) ` +
                `skipped in category '${category}' — the core was expected to be ` +
                `reachable, so nothing was actually tested.`,
        );
        process.exit(1);
    }
    process.exit(0);
}
