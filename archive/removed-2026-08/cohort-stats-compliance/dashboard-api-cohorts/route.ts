// Same-origin proxy for the Sprint 9 cohort surface.
//
//   GET /api/cohorts?mode=raw                  → proxies GET /v1/stats/cohort (S7)
//   GET /api/cohorts?mode=published            → proxies GET /v1/cohort list (S8)
//   GET /api/cohorts?mode=tenant_rank&metric=X → 501; no real source yet (no mock)
//
// Sprint 8 wired the real `/v1/cohort/published` endpoint. The list view
// pulls every cohort definition from `/v1/cohort` (operator-managed) and
// projects each into the `CohortSummary` shape the dashboard expects. When
// the operator has not defined any cohorts the data array is empty and the
// UI shows the no-cohorts-yet empty state.

import { NextRequest } from "next/server";
import { fetchCoreV1Json, proxyCoreV1 } from "../_proxy";

interface CoreCohortDefinition {
  cohort_id: string;
  label: string;
  vendor: string | null;
  sector: string | null;
  tenant_ids: string[];
  k_anonymity_threshold: number;
  epsilon_per_metric: number;
  delta: number;
}

interface DashboardCohortSummary {
  cohort_id: string;
  label: string;
  vendor: string;
  sector: string;
  n_tenants: number;
  period_start: number;
  period_end: number;
}

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const mode = url.searchParams.get("mode") ?? "published";

  if (mode === "raw") {
    // Admin-only operator view — forwards every query param (metric_id,
    // period_start, period_end) verbatim.
    return proxyCoreV1("stats/cohort", req, { method: "GET" });
  }

  if (mode === "tenant_rank") {
    // No real per-tenant rank source exists yet. We refuse rather than serve
    // fabricated data — the dashboard must never show a mocked rank.
    return Response.json(
      { error: "tenant_rank not available", data: null },
      { status: 501 },
    );
  }

  // Default: mode=published — list cohort definitions via the live /v1/cohort
  // endpoint and project each into the dashboard CohortSummary shape.
  // The summary needs a period window; the listing view uses the last
  // calendar week (rolling) which the detail page can refine.
  const result = await fetchCoreV1Json<CoreCohortDefinition[]>("cohort", "", req);
  if (!result.ok) {
    return result.response;
  }
  const cohorts = Array.isArray(result.data) ? result.data : [];

  const now = Math.floor(Date.now() / 1000);
  const ONE_WEEK = 7 * 24 * 3600;
  const data: DashboardCohortSummary[] = cohorts.map((c) => ({
    cohort_id: c.cohort_id,
    label: c.label,
    vendor: c.vendor ?? "",
    sector: c.sector ?? "",
    n_tenants: c.tenant_ids.length,
    period_start: now - ONE_WEEK,
    period_end: now,
  }));
  return Response.json({ data });
}
