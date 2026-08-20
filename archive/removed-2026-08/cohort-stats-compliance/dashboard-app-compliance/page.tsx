// Sprint 19-20: list of previously-generated audit reports.

import Link from "next/link";
import { fetchAuditReports } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";

export const dynamic = "force-dynamic";

function fmtPeriod(start: number, end: number): string {
  const s = new Date(start * 1000).toISOString().slice(0, 10);
  const e = new Date(end * 1000).toISOString().slice(0, 10);
  return `${s} → ${e}`;
}

function fmtGeneratedAt(t: number): string {
  return new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16);
}

export default async function CompliancePage() {
  const result = await fetchAuditReports();
  const reports = result.ok ? result.data : [];

  return (
    <PageShell>
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
            Compliance
          </h1>
          <p className="mt-1 text-sm text-[var(--text-muted)]">
            Periodic ZK audit reports for compliance officers.
          </p>
        </div>
        <Link
          href="/compliance/new"
          className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium transition-colors duration-150 ease-out bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] px-5 py-2 text-sm"
        >
          New report
        </Link>
      </div>

      {!result.ok ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--status-stopped)]">
              Failed to load reports: {result.error}
            </p>
          </CardBody>
        </Card>
      ) : reports.length === 0 ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--text-muted)]">
              No reports yet — generate one via{" "}
              <Link
                className="text-[var(--accent-text)] hover:underline"
                href="/compliance/new"
              >
                New report
              </Link>
              .
            </p>
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardBody>
            <Table>
              <Thead>
                <Tr>
                  <Th>Report</Th>
                  <Th>Generated</Th>
                  <Th>Period</Th>
                  <Th>Agents</Th>
                  <Th>Receipts</Th>
                  <Th>Denials</Th>
                </Tr>
              </Thead>
              <Tbody>
                {reports.map((r) => {
                  const dens = r.policy_compliance_summary.denied;
                  return (
                    <Tr key={r.report_id}>
                      <Td>
                        <Link
                          href={`/compliance/${encodeURIComponent(r.report_id)}`}
                          className="text-[var(--accent-text)] hover:text-[var(--accent-hover)] font-mono text-mono-sm"
                        >
                          {r.report_id.slice(0, 12)}…
                        </Link>
                      </Td>
                      <Td className="text-mono-sm text-[var(--text-muted)]">
                        {fmtGeneratedAt(r.generated_at)}
                      </Td>
                      <Td className="text-mono-sm">
                        {fmtPeriod(r.period_start, r.period_end)}
                      </Td>
                      <Td className="text-mono-sm">{r.agent_ids.length}</Td>
                      <Td className="text-mono-sm">{r.raw_receipts_count}</Td>
                      <Td>
                        {dens === 0 ? (
                          <Badge variant="ok">none</Badge>
                        ) : (
                          <Badge variant="warning">{dens}</Badge>
                        )}
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
