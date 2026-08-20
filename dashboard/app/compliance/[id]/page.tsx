import Link from "next/link";
import { notFound } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CopyButton } from "@/components/ui/CopyButton";
import { fetchAuditReport, type AuditSectionVerdict } from "@/lib/api";
import { fmtNumber, fmtTimestamp } from "@/lib/format";

export const dynamic = "force-dynamic";

function verdictBadge(v: AuditSectionVerdict) {
  if (v.state === "Confirmed") return <Badge variant="ok">Confirmed</Badge>;
  if (v.state === "Partial") return <Badge variant="warning">Partial</Badge>;
  return <Badge variant="stopped">Insufficient</Badge>;
}

function verdictDetail(v: AuditSectionVerdict): string | null {
  if (v.state === "Partial") return v.gaps.join("; ");
  if (v.state === "Insufficient") return v.reason;
  return null;
}

/** Evidence is a tagged union of six shapes. Rendering the fields generically
 *  keeps this page correct when the core adds a seventh, which a per-kind
 *  switch would silently render as blank. */
function EvidenceRows({ evidence }: { evidence: Record<string, unknown> }) {
  const rows = Object.entries(evidence).filter(([k]) => k !== "kind");
  if (rows.length === 0) return null;
  return (
    <dl className="mt-3 grid gap-x-6 gap-y-1 text-mono-sm sm:grid-cols-[max-content_1fr]">
      {rows.map(([k, v]) => (
        <div key={k} className="sm:contents">
          <dt className="text-[var(--text-muted)]">{k}</dt>
          <dd className="font-[var(--font-mono)] break-all text-[var(--text-primary)]">
            {v === null || v === "" ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export default async function ComplianceReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const t = await getTranslations("compliance");
  const tc = await getTranslations("common");
  const res = await fetchAuditReport(id);
  if (!res.ok) notFound();
  const r = res.data;

  const period = `${new Date(r.period_start * 1000).toISOString().slice(0, 10)} → ${new Date(
    r.period_end * 1000
  ).toISOString().slice(0, 10)}`;

  return (
    <PageShell
      title={t("title")}
      subtitle={`${period} · ${fmtNumber(r.raw_receipts_count)} receipts · generated ${fmtTimestamp(
        new Date(r.generated_at * 1000).toISOString()
      )}`}
    >
      <Link
        href="/compliance"
        className="inline-block mb-6 text-sm text-[var(--text-muted)] underline decoration-dotted"
      >
        {t("back")}
      </Link>

      <div className="mb-6 flex items-center gap-2 text-mono-sm">
        <span className="text-[var(--text-muted)]">report_id</span>
        <span className="font-[var(--font-mono)] break-all">{r.report_id}</span>
        <CopyButton text={r.report_id} label={tc("copy")} copiedLabel={tc("copied")} />
      </div>

      {r.sections.map((s, i) => {
        const detail = verdictDetail(s.verdict);
        return (
          <Card key={`${s.heading}-${i}`} className="mb-4">
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-sm font-semibold text-[var(--text-primary)]">{s.heading}</h2>
                {verdictBadge(s.verdict)}
              </div>
            </CardHeader>
            <CardBody>
              <p className="text-sm text-[var(--text-primary)]">{s.statement}</p>
              {detail && <p className="mt-1 text-sm text-[var(--text-muted)]">{detail}</p>}
              <EvidenceRows evidence={s.evidence as unknown as Record<string, unknown>} />
            </CardBody>
          </Card>
        );
      })}

      <Card className="mb-4">
        <CardHeader>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">{t("summary")}</h2>
        </CardHeader>
        <CardBody>
          <dl className="grid gap-x-6 gap-y-1 text-mono-sm sm:grid-cols-[max-content_1fr]">
            <div className="sm:contents">
              <dt className="text-[var(--text-muted)]">total_actions</dt>
              <dd>{fmtNumber(r.policy_compliance_summary.total_actions)}</dd>
            </div>
            <div className="sm:contents">
              <dt className="text-[var(--text-muted)]">allowed</dt>
              <dd>{fmtNumber(r.policy_compliance_summary.allowed)}</dd>
            </div>
            <div className="sm:contents">
              <dt className="text-[var(--text-muted)]">denied</dt>
              <dd>{fmtNumber(r.policy_compliance_summary.denied)}</dd>
            </div>
            <div className="sm:contents">
              <dt className="text-[var(--text-muted)]">policy_violation_rate</dt>
              <dd>{r.policy_compliance_summary.policy_violation_rate.toFixed(4)}</dd>
            </div>
            <div className="sm:contents">
              <dt className="text-[var(--text-muted)]">policies_evaluated</dt>
              <dd className="font-[var(--font-mono)] break-all">
                {r.policy_compliance_summary.policy_ids_evaluated.join(", ") || "—"}
              </dd>
            </div>
          </dl>
        </CardBody>
      </Card>

      <Card className="mb-4">
        <CardHeader>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">{t("anchorChain")}</h2>
        </CardHeader>
        <CardBody>
          {r.merkle_root === "" ? (
            <p className="text-sm text-[var(--text-muted)]">
              No anchor exists for this period yet — treat the receipts as unanchored until the
              next batch commits.
            </p>
          ) : (
            <EvidenceRows evidence={r.anchors as unknown as Record<string, unknown>} />
          )}
        </CardBody>
      </Card>

      {r.zk_proofs.length > 0 && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              {t("attachedProofs")}
            </h2>
          </CardHeader>
          <CardBody>
            {r.zk_proofs.map((p, i) => (
              <div key={`${p.vk_id}-${i}`} className="mb-3 last:mb-0">
                <p className="text-mono-sm font-[var(--font-mono)] break-all">
                  {p.circuit} · {p.vk_id}
                </p>
                <p className="text-mono-sm text-[var(--text-muted)] break-all">
                  public_inputs: {p.public_inputs.join(", ") || "—"}
                </p>
              </div>
            ))}
          </CardBody>
        </Card>
      )}
    </PageShell>
  );
}
