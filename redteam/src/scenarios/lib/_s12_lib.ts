/**
 * Sprint 12 redteam scenario shared envelope.
 *
 * Every standalone scenario in this directory (binding-*.ts, proof-*.ts,
 * replay-*.ts, tenant-*.ts, dp-*.ts, egress-*.ts, tee-*.ts) reuses these
 * helpers so the on-stdout JSON shape stays uniform.
 *
 * Envelope contract:
 *   stdout: a single JSON object matching `ScenarioResult`
 *   exit 0: scenario behaved as documented (incl. documented SDK gaps)
 *   exit 1: unexpected outcome (real bug to investigate)
 *   exit 2: harness misconfigured (missing env, server unreachable WHEN
 *           the scenario REQUIRES the server). Pure-SDK scenarios degrade
 *           to a "skipped" note and exit 0.
 */

export interface ScenarioResult {
    id: string;
    name: string;
    pass: boolean;
    note: string;
    evidence?: Record<string, unknown>;
    /**
     * Set when the scenario did not actually run (no server, no admin key).
     *
     * A skip still exits 0 on purpose — a developer without a core running
     * should not see red. But `pass: true` alone cannot distinguish "the
     * invariant holds" from "nothing was tested", and a category runner that
     * only reads exit codes reports the second as green. That is precisely how
     * the retired proof-forgery scenarios stayed green against a route that had
     * been deleted. This flag makes the difference machine-readable so
     * `_meta_runner` can refuse to call a skipped run a pass under
     * SAURON_REDTEAM_STRICT=1, which CI sets.
     */
    skipped?: boolean;
}

export const BASE_URL =
    process.env.SAURON_CORE_URL || process.env.API_URL || "http://127.0.0.1:3001";
export const ADMIN_KEY = process.env.SAURON_ADMIN_KEY;

export async function pingServer(): Promise<boolean> {
    try {
        const r = await fetch(`${BASE_URL}/v1/policy/list`, {
            headers: ADMIN_KEY ? { authorization: `Bearer ${ADMIN_KEY}` } : {},
        });
        return r.status === 200 || r.status === 401;
    } catch {
        return false;
    }
}

export async function uploadPolicy(yaml: string): Promise<string | null> {
    if (!ADMIN_KEY) return null;
    const r = await fetch(`${BASE_URL}/v1/policy/upload`, {
        method: "POST",
        headers: {
            "content-type": "application/yaml",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: yaml,
    });
    if (!r.ok) return null;
    const data = (await r.json()) as { policy_id: string };
    return data.policy_id;
}

export async function deletePolicy(id: string): Promise<boolean> {
    if (!ADMIN_KEY) return false;
    const r = await fetch(`${BASE_URL}/v1/policy/${id}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    return r.ok;
}

export async function evaluateRemote(
    policyId: string,
    action: Record<string, unknown>,
    agentId?: string,
): Promise<{ allow: boolean; check?: string; raw?: unknown } | null> {
    if (!ADMIN_KEY) return null;
    const body: Record<string, unknown> = { policy_id: policyId, action };
    if (agentId) body.agent_id = agentId;
    const r = await fetch(`${BASE_URL}/v1/policy/evaluate`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY}`,
        },
        body: JSON.stringify(body),
    });
    if (!r.ok) return null;
    const data = (await r.json()) as { verdict: { kind: string; check?: string } };
    return {
        allow: data.verdict.kind === "allow",
        check: data.verdict.check,
        raw: data,
    };
}

export function emit(result: ScenarioResult): void {
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.pass ? 0 : 1);
}

export function skipped(id: string, name: string, why: string): ScenarioResult {
    return {
        id,
        name,
        pass: true,
        skipped: true,
        note: `skipped — ${why}`,
        evidence: { skipped: true },
    };
}

/**
 * Wrap a scenario main fn. Each scenario file ends with:
 *
 *   if (require.main === module) runScenario(main);
 *
 * which (a) lets the file be imported by a meta-runner without running,
 * and (b) gives a uniform error-to-exit-code path.
 */
export async function runScenario(
    fn: () => Promise<ScenarioResult>,
): Promise<void> {
    try {
        const r = await fn();
        emit(r);
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.log(
            JSON.stringify(
                {
                    id: "ERR",
                    name: "harness error",
                    pass: false,
                    note: `unhandled exception: ${msg}`,
                },
                null,
                2,
            ),
        );
        process.exit(2);
    }
}
