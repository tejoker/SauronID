import { notFound } from "next/navigation";
import Link from "next/link";
import { fetchCohort } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CohortChart } from "@/components/cohorts/CohortChart";
import { PrivacyNotice } from "@/components/cohorts/PrivacyNotice";

export const dynamic = "force-dynamic";

function fmtPeriod(start: number, end: number): string {
  const s = new Date(start * 1000).toISOString().slice(0, 10);
  const e = new Date(end * 1000).toISOString().slice(0, 10);
  return `${s} → ${e}`;
}

export default async function CohortDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const result = await fetchCohort(id);
  if (!result.ok) notFound();
  const c = result.data;

  // ε across the publication is the sum of per-metric ε (sequential
  // composition). Honest accounting for the privacy notice card.
  const totalEpsilon = c.metrics
    .filter((m) => !m.suppressed)
    .reduce((sum, m) => sum + m.noise_eps, 0);
  const allSuppressed = c.metrics.every((m) => m.suppressed);

  return (
    <PageShell>
      <Link
        href="/cohorts"
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-6"
      >
        ← Back to cohorts
      </Link>

      <div className="flex items-center gap-3 mb-2">
        <h1 className="text-xl font-semibold text-[var(--text-primary)] tracking-tight">
          {c.label}
        </h1>
        <Badge variant="neutral">{c.n_tenants} tenants</Badge>
        {allSuppressed && <Badge variant="warning">Suppressed</Badge>}
      </div>
      <p className="text-mono-sm text-[var(--text-muted)] mb-6 break-all">
        {c.cohort_id} · {fmtPeriod(c.period_start, c.period_end)}
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        {c.metrics.map((m) => (
          <Card key={m.metric_id}>
            <CardBody>
              <div className="flex items-center justify-between mb-3">
                <p className="text-mono-sm text-[var(--text-muted)] uppercase">
                  {m.metric_id}
                </p>
                {m.suppressed ? (
                  <Badge variant="warning">suppressed</Badge>
                ) : (
                  <span className="text-mono-sm text-[var(--text-muted)]">
                    ε={m.noise_eps.toFixed(2)}
                  </span>
                )}
              </div>
              <CohortChart metric={m} />
            </CardBody>
          </Card>
        ))}
      </div>

      <div className="mb-6">
        <PrivacyNotice
          epsilon={totalEpsilon}
          notice={c.privacy_notice}
        />
      </div>
    </PageShell>
  );
}
