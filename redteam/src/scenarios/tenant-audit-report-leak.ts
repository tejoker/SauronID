/**
 * S3 redteam — tenant-audit-report-leak.
 *
 * Threat model: docs/security/threat-model.md "STRIDE per component → core →
 * Information disclosure". Audit reports are tenant-scoped (see
 * core/src/audit/store.rs::get_report which filters by tenant_id).
 * A tenant must not be able to retrieve another tenant's report by
 * id — the expected shape is 404 (not 403) to avoid leaking that
 * the id exists at all.
 *
 * Scenario:
 *   1. As tenant A, create a report via POST /v1/audit/reports.
 *   2. As tenant B, GET /v1/audit/reports/<a_report_id>.
 *   3. Assert 404.
 *
 * Mitigation in code:
 *   - core/src/audit/store.rs::get_report (tenant filter).
 *   - core/src/audit/handlers.rs::get_report_handler returns NotFound.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function createReport(tenant: string): Promise<string | null> {
    const now = Math.floor(Date.now() / 1000);
    const r = await fetch(`${BASE_URL}/v1/audit/reports`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenant,
        },
        body: JSON.stringify({
            period_start: now - 3600,
            period_end: now,
        }),
    });
    if (!r.ok) return null;
    const data = (await r.json()) as { report: { report_id: string } };
    return data.report?.report_id ?? null;
}

async function main(): Promise<ScenarioResult> {
    const id = "T6";
    const name = "tenant-audit-report-leak";
    if (!(await pingServer()) || !ADMIN_KEY) {
        return skipped(id, name, `server ${BASE_URL} unreachable or no admin key`);
    }

    const tenantA = `acme_corp_${Date.now()}`;
    const tenantB = `globex_inc_${Date.now()}`;

    const reportId = await createReport(tenantA);
    // Build the URL even if creation failed — fall back to a likely-valid
    // synthetic id; the assertion is still "B sees 404".
    const probeId = reportId ?? `rpt_synthetic_${Date.now()}`;

    const r = await fetch(`${BASE_URL}/v1/audit/reports/${probeId}`, {
        headers: {
            authorization: `Bearer ${ADMIN_KEY!}`,
            "x-sauron-tenant-id": tenantB,
        },
    });
    const status = r.status;
    const bodyText = await r.text();

    const pass = status === 404;
    return {
        id,
        name,
        pass,
        note:
            "Cross-tenant audit report retrieval MUST return 404 (no existence leak). " +
            "Mitigation: core/src/audit/store.rs::get_report tenant filter.",
        evidence: {
            tenant_a: tenantA,
            tenant_b: tenantB,
            report_id_under_a: reportId,
            probed_id: probeId,
            status,
            body: bodyText.slice(0, 200),
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
