import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { AnchorChainBadge } from "../components/compliance/AnchorChainBadge";
import { SectionCard } from "../components/compliance/SectionCard";
import type { AuditReport, AuditSection } from "../lib/api";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// Shared fixture — matches the shape that core/audit emits.
function sampleReport(): AuditReport {
  return {
    report_id: "deadbeef".repeat(4),
    tenant_id: "t1",
    agent_ids: ["agent-1"],
    period_start: 1_700_000_000,
    period_end: 1_700_604_800,
    generated_at: 1_700_605_000,
    merkle_root: "ab".repeat(32),
    sections: [
      {
        heading: "Anchor Chain",
        statement: "Latest Bitcoin OTS + Solana memo anchors",
        evidence: {
          kind: "AnchorChain",
          btc_root: "ab".repeat(32),
          btc_block: 850_000,
          solana_sig: "sig12345",
          solana_slot: 1234,
        },
        verdict: { state: "Confirmed" },
      },
      {
        heading: "Policy Evaluations",
        statement: "4 allowed, 1 denied",
        evidence: {
          kind: "PolicyEvaluations",
          allowed: 4,
          denied: 1,
          denial_breakdown: { allowlist: 1 },
        },
        verdict: { state: "Partial", gaps: ["1 denial unreviewed"] },
      },
      {
        heading: "Stats Commitment: success_rate",
        statement: "Tenant claims success_rate=0.95 over 100 records",
        evidence: {
          kind: "StatsCommitment",
          metric_id: "success_rate",
          value: 0.95,
          n_records: 100,
          vk_id: "StatsHonestComputation.dev.vk@v0",
        },
        verdict: { state: "Confirmed" },
      },
    ],
    anchors: {
      merkle_root: "ab".repeat(32),
      bitcoin_ots_receipt_b64: null,
      bitcoin_block_height: 850_000,
      solana_signature: "sig12345",
      solana_slot: 1234,
    },
    zk_proofs: [
      {
        circuit: "StatsHonestComputation",
        public_inputs: ["abab", "success_rate"],
        proof_b64: "e30=",
        vk_id: "StatsHonestComputation.dev.vk@v0",
      },
    ],
    raw_receipts_count: 5,
    policy_compliance_summary: {
      policy_ids_evaluated: ["pol1"],
      total_actions: 5,
      allowed: 4,
      denied: 1,
      policy_violation_rate: 0.2,
    },
  };
}

// ── 1. fetchAuditReports happy path ────────────────────────────────────

describe("fetchAuditReports", () => {
  beforeEach(() => vi.resetModules());

  it("returns the list when the proxy responds 200", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      status: 200,
      json: async () => [sampleReport()],
    }));
    const { fetchAuditReports } = await import("../lib/api");
    const r = await fetchAuditReports();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data).toHaveLength(1);
      expect(r.data[0].tenant_id).toBe("t1");
      expect(r.data[0].sections).toHaveLength(3);
    }
  });

  it("returns ok:false on a 5xx upstream", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: false,
      status: 503,
      json: async () => ({}),
    }));
    const { fetchAuditReports } = await import("../lib/api");
    const r = await fetchAuditReports();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("503");
  });
});

// ── 2. createAuditReport posts the period + parses the response ────────

describe("createAuditReport", () => {
  beforeEach(() => vi.resetModules());

  it("posts the period and unwraps the report from the envelope", async () => {
    const calls: { url: string; body: string }[] = [];
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      calls.push({ url, body: String(init?.body ?? "") });
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({
          report: sampleReport(),
          signature: "deadbeef".repeat(8),
        }),
      };
    });
    const { createAuditReport } = await import("../lib/api");
    const r = await createAuditReport({
      agent_ids: ["a1"],
      period_start: 0,
      period_end: 60,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.report.report_id).toBeDefined();
      expect(r.data.signature.length).toBe(64);
    }
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain("/api/audit/reports");
    expect(calls[0].body).toContain("period_start");
  });
});

// ── 3. SectionCard renders each evidence variant ───────────────────────

describe("SectionCard", () => {
  it("renders the Policy Evaluations bar with allowed/denied counts", () => {
    const r = sampleReport();
    const section = r.sections.find(
      (s: AuditSection) => s.heading === "Policy Evaluations"
    );
    expect(section).toBeDefined();
    const html = renderToStaticMarkup(
      createElement(SectionCard, {
        section: section!,
        merkleRoot: r.merkle_root,
      })
    );
    expect(html).toContain('data-testid="section-policy-evals"');
    expect(html).toContain("allowed: 4");
    expect(html).toContain("denied: 1");
    expect(html).toContain("allowlist: 1");
    // Partial verdict pill must show.
    expect(html).toContain("partial");
  });

  it("renders the Stats Commitment value + vk_id", () => {
    const r = sampleReport();
    const section = r.sections.find((s: AuditSection) =>
      s.heading.startsWith("Stats Commitment")
    );
    expect(section).toBeDefined();
    const html = renderToStaticMarkup(
      createElement(SectionCard, {
        section: section!,
        merkleRoot: r.merkle_root,
      })
    );
    expect(html).toContain('data-testid="section-stats-commitment"');
    expect(html).toContain("0.950");
    expect(html).toContain("StatsHonestComputation.dev.vk@v0");
  });

  it("renders the Anchor Chain badges with explorer hrefs", () => {
    const html = renderToStaticMarkup(
      createElement(AnchorChainBadge, {
        btcRoot: "abcdef0123",
        btcBlock: 12345,
        solanaSig: "sigXYZ",
        solanaSlot: 999,
      })
    );
    expect(html).toContain('data-testid="anchor-chain-badge"');
    expect(html).toContain("mempool.space");
    expect(html).toContain("explorer.solana.com");
    expect(html).toContain("block 12345");
    expect(html).toContain("slot 999");
  });
});
