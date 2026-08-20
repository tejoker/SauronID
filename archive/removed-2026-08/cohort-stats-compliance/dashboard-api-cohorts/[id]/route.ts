// Single-cohort detail proxy.
//
//   GET /api/cohorts/:id?mode=raw       → proxies /v1/stats/cohort with cohort filter (S7)
//   GET /api/cohorts/:id?mode=published → proxies /v1/cohort/published (S8)
//
// Sprint 8 wires the real DP-published cohort endpoint. The response from
// `/v1/cohort/published` already matches the dashboard `CohortDetail`
// interface so the proxy is a near-pass-through. We also fold the
// publication's `privacy_notice.note` into the top-level `privacy_notice`
// string so existing UI components keep working unchanged.

import { NextRequest } from "next/server";
import { fetchCoreV1Json, proxyCoreV1 } from "../../_proxy";

interface CorePublishedMetric {
  metric_id: string;
  value_p25: number;
  value_p50: number;
  value_p75: number;
  value_p95: number;
  noise_eps: number;
  suppressed: boolean;
}

interface CorePublishedCohort {
  cohort_id: string;
  label: string;
  vendor: string | null;
  sector: string | null;
  n_tenants: number;
  period_start: number;
  period_end: number;
  metrics: CorePublishedMetric[];
  privacy_notice: {
    epsilon_total: number;
    delta: number;
    k_anonymity_threshold: number;
    note: string;
  };
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const url = new URL(req.url);
  const mode = url.searchParams.get("mode") ?? "published";

  if (mode === "raw") {
    // No single-cohort "raw" endpoint in S7; forward the listing endpoint
    // with the cohort identifier appended as a filter.
    const qs = url.searchParams;
    qs.set("cohort_id", id);
    return proxyCoreV1(`stats/cohort?${qs.toString()}`, req, {
      method: "GET",
      forwardQuery: false,
    });
  }

  // Default mode=published: hit /v1/cohort/published with a default
  // rolling-week window unless the caller passed explicit period bounds.
  const now = Math.floor(Date.now() / 1000);
  const ONE_WEEK = 7 * 24 * 3600;
  const periodStart =
    Number(url.searchParams.get("period_start")) || now - ONE_WEEK;
  const periodEnd = Number(url.searchParams.get("period_end")) || now;

  const qs = new URLSearchParams({
    cohort_id: id,
    period_start: String(periodStart),
    period_end: String(periodEnd),
  });
  const result = await fetchCoreV1Json<CorePublishedCohort>(
    `cohort/published?${qs.toString()}`,
    "",
    req,
  );
  if (!result.ok) {
    return result.response;
  }
  const c = result.data;
  // Project to the dashboard CohortDetail shape: vendor/sector are strings
  // (not nullable) in the UI type, and privacy_notice is the prose note.
  const detail = {
    cohort_id: c.cohort_id,
    label: c.label,
    vendor: c.vendor ?? "",
    sector: c.sector ?? "",
    n_tenants: c.n_tenants,
    period_start: c.period_start,
    period_end: c.period_end,
    metrics: c.metrics,
    privacy_notice: c.privacy_notice?.note ?? "",
  };
  return Response.json({ data: detail });
}
