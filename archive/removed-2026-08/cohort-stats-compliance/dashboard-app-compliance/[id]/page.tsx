// Sprint 19-20: single audit report detail.

import Link from "next/link";
import { notFound } from "next/navigation";
import { fetchAuditReport } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SectionCard } from "@/components/compliance/SectionCard";
import { AnchorChainBadge } from "@/components/compliance/AnchorChainBadge";

export const dynamic = "force-dynamic";

function fmtPeriod(start: number, end: number): string {
  const s = new Date(start * 1000).toISOString().slice(0, 10);
  const e = new Date(end * 1000).toISOString().slice(0, 10);
  return `${s} → ${e}`;
}

function fmtGeneratedAt(t: number): string {
  return new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19);
}

export default async function ComplianceReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const result = await fetchAuditReport(id);
  if (!result.ok) notFound();
  const r = result.data;

  const summary = r.policy_compliance_summary;
  const violationPct = (summary.policy_violation_rate * 100).toFixed(1);

  return (
    <PageShell>
      <Link
        href="/compliance"
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-6"
      >
        ← Back to reports
      </Link>

      <div className="flex items-center gap-3 mb-2 flex-wrap">
        <h1 className="text-xl font-semibold text-[var(--text-primary)] tracking-tight font-mono">
          {r.report_id.slice(0, 16)}…
        </h1>
        <Badge variant="neutral">{r.tenant_id}</Badge>
        <Badge variant="neutral">{r.agent_ids.length} agents</Badge>
        <Badge variant={summary.denied === 0 ? "ok" : "warning"}>
          {violationPct}% denied
        </Badge>
      </div>
      <p className="text-mono-sm text-[var(--text-muted)] mb-6">
        {fmtPeriod(r.period_start, r.period_end)} · generated{" "}
        {fmtGeneratedAt(r.generated_at)} · {r.raw_receipts_count} receipts
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-2">
              Anchor chain
            </p>
            <AnchorChainBadge
              btcRoot={r.anchors.bitcoin_ots_receipt_b64 ? r.anchors.merkle_root : r.anchors.merkle_root || null}
              btcBlock={r.anchors.bitcoin_block_height}
              solanaSig={r.anchors.solana_signature}
              solanaSlot={r.anchors.solana_slot}
            />
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-2">
              Compliance summary
            </p>
            <ul className="space-y-1 text-mono-sm">
              <li>
                <span className="text-[var(--status-ok)]">allowed:</span>{" "}
                {summary.allowed}
              </li>
              <li>
                <span className="text-[var(--status-stopped)]">denied:</span>{" "}
                {summary.denied}
              </li>
              <li className="text-[var(--text-muted)]">
                policies evaluated:{" "}
                {summary.policy_ids_evaluated.length === 0
                  ? "—"
                  : summary.policy_ids_evaluated.join(", ")}
              </li>
            </ul>
          </CardBody>
        </Card>
      </div>

      <div className="space-y-4">
        {r.sections.map((s, i) => (
          <SectionCard
            key={`${s.heading}-${i}`}
            section={s}
            merkleRoot={r.merkle_root}
          />
        ))}
      </div>

      {r.zk_proofs.length > 0 && (
        <Card className="mt-6">
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
              Attached proofs
            </p>
            <ul className="space-y-2">
              {r.zk_proofs.map((p, i) => (
                <li key={`${p.circuit}-${i}`} className="text-mono-sm">
                  <span className="text-[var(--text-primary)]">{p.circuit}</span>{" "}
                  <span className="text-[var(--text-muted)]">vk: {p.vk_id}</span>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      )}
    </PageShell>
  );
}
