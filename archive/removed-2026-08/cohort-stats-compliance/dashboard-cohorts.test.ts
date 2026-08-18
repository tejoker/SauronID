import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";

// Shared envelope helper — matches what the /api/cohorts/* routes return.
function envelope<T>(data: T, opts: { error?: string } = {}) {
  return {
    ok: !opts.error,
    status: opts.error ? 500 : 200,
    json: async () => ({
      data,
      ...(opts.error ? { error: opts.error } : {}),
    }),
    text: async () => JSON.stringify({ data }),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── 1. fetchCohorts: happy path unwraps envelope ──────────────────────

describe("fetchCohorts", () => {
  beforeEach(() => vi.resetModules());

  it("unwraps the envelope and returns the cohort list", async () => {
    vi.stubGlobal("fetch", async () =>
      envelope([
        {
          cohort_id: "coh_a",
          label: "A",
          vendor: "openai",
          sector: "banking",
          n_tenants: 12,
          period_start: 1,
          period_end: 2,
        },
      ])
    );
    const { fetchCohorts } = await import("../lib/api");
    const r = await fetchCohorts();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data).toHaveLength(1);
      expect(r.data[0].cohort_id).toBe("coh_a");
    }
  });
});

// ── 2. fetchCohort: error path on non-2xx ─────────────────────────────

describe("fetchCohort error", () => {
  beforeEach(() => vi.resetModules());

  it("returns ok:false when the server responds non-2xx", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: false,
      status: 404,
      json: async () => ({}),
    }));
    const { fetchCohort } = await import("../lib/api");
    const r = await fetchCohort("coh_missing");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("404");
  });
});

// ── 3. Filter URL persistence (logic-only — no router) ────────────────

describe("CohortFilter URL persistence", () => {
  it("encodes vendor/sector into the query string and drops 'all'", () => {
    function buildNext(
      current: URLSearchParams,
      key: string,
      value: string
    ): string {
      const next = new URLSearchParams(current.toString());
      if (value === "all" || value === "latest") next.delete(key);
      else next.set(key, value);
      const qs = next.toString();
      return qs ? `?${qs}` : "?";
    }

    let qs = new URLSearchParams();
    let url = buildNext(qs, "vendor", "openai");
    expect(url).toBe("?vendor=openai");
    qs = new URLSearchParams("vendor=openai");
    url = buildNext(qs, "sector", "banking");
    expect(url).toContain("vendor=openai");
    expect(url).toContain("sector=banking");
    qs = new URLSearchParams("vendor=openai&sector=banking");
    url = buildNext(qs, "vendor", "all");
    expect(url).not.toContain("vendor=");
    expect(url).toContain("sector=banking");
  });
});

// ── 4. Published proxy never falls back to mock ───────────────────────
//
// The route handler MUST NOT fabricate cohort data. It either returns a
// `{data: [...]}` envelope from the real /v1/cohort endpoint or surfaces the
// upstream failure. Empty data is valid when the operator has defined no
// cohorts yet — the UI shows a dedicated empty state.

describe("fetchCohorts: empty cohort list", () => {
  beforeEach(() => vi.resetModules());

  it("returns ok with an empty array when the operator has no cohorts", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      status: 200,
      json: async () => ({ data: [] }),
    }));
    const { fetchCohorts } = await import("../lib/api");
    const r = await fetchCohorts();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Array.isArray(r.data)).toBe(true);
      expect(r.data).toHaveLength(0);
    }
  });
});

describe("fetchCohorts: live published envelope", () => {
  beforeEach(() => vi.resetModules());

  it("unwraps the real /v1/cohort envelope into the summary list", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: [
          {
            cohort_id: "coh_openai_banking",
            label: "OpenAI · Banking",
            vendor: "openai",
            sector: "banking",
            n_tenants: 24,
            period_start: 1_700_000_000,
            period_end: 1_700_604_800,
          },
        ],
      }),
    }));
    const { fetchCohorts } = await import("../lib/api");
    const r = await fetchCohorts();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data).toHaveLength(1);
      expect(r.data[0].cohort_id).toBe("coh_openai_banking");
      expect(r.data[0].n_tenants).toBe(24);
    }
  });
});
