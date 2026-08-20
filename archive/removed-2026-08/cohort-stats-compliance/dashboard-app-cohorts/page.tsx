import Link from "next/link";
import { fetchCohorts } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { CohortFilter } from "@/components/cohorts/CohortFilter";

export const dynamic = "force-dynamic";

function unique<T>(xs: T[]): T[] {
  return Array.from(new Set(xs));
}

function fmtPeriod(start: number, end: number): string {
  const s = new Date(start * 1000).toISOString().slice(0, 10);
  const e = new Date(end * 1000).toISOString().slice(0, 10);
  return `${s} → ${e}`;
}

export default async function CohortsListPage({
  searchParams,
}: {
  searchParams: Promise<{
    vendor?: string;
    sector?: string;
    period?: string;
  }>;
}) {
  const sp = await searchParams;
  const result = await fetchCohorts();

  const all = result.ok ? result.data : [];
  const vendors = unique(all.map((c) => c.vendor)).sort();
  const sectors = unique(all.map((c) => c.sector)).sort();

  const filtered = all.filter((c) => {
    if (sp.vendor && c.vendor !== sp.vendor) return false;
    if (sp.sector && c.sector !== sp.sector) return false;
    return true;
  });

  return (
    <PageShell>
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
          Cohorts
        </h1>
        <p className="mt-1 text-sm text-[var(--text-muted)]">
          Differentially-private benchmarks across tenants who opted into stats
          sharing.
        </p>
      </div>

      <CohortFilter vendors={vendors} sectors={sectors} />

      {!result.ok ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--status-stopped)]">
              Failed to load cohorts: {result.error}
            </p>
          </CardBody>
        </Card>
      ) : all.length === 0 ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--text-muted)]">
              No published cohorts yet — operator must define cohorts via{" "}
              <span className="font-mono text-mono-sm">POST /v1/cohort</span>.
            </p>
          </CardBody>
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--text-muted)]">
              No cohorts match the current filters.
            </p>
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardBody>
            <Table>
              <Thead>
                <Tr>
                  <Th>Cohort</Th>
                  <Th>Vendor</Th>
                  <Th>Sector</Th>
                  <Th>Tenants</Th>
                  <Th>Period</Th>
                </Tr>
              </Thead>
              <Tbody>
                {filtered.map((c) => {
                  const suppressed = c.n_tenants < 5;
                  return (
                    <Tr key={c.cohort_id}>
                      <Td>
                        <Link
                          href={`/cohorts/${encodeURIComponent(c.cohort_id)}`}
                          className="text-[var(--accent-text)] hover:text-[var(--accent-hover)]"
                        >
                          {c.label}
                        </Link>
                      </Td>
                      <Td className="font-mono text-mono-sm">{c.vendor}</Td>
                      <Td className="font-mono text-mono-sm">{c.sector}</Td>
                      <Td className="text-mono-sm">
                        {suppressed ? (
                          <Badge variant="warning">{c.n_tenants} · suppressed</Badge>
                        ) : (
                          c.n_tenants
                        )}
                      </Td>
                      <Td className="text-mono-sm text-[var(--text-muted)]">
                        {fmtPeriod(c.period_start, c.period_end)}
                      </Td>
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </CardBody>
        </Card>
      )}
    </PageShell>
  );
}
