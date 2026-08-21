import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { NewReportForm } from "@/components/compliance/NewReportForm";
import { fetchAuditReports } from "@/lib/api";
import { fmtNumber, fmtTimestamp, truncateHash } from "@/lib/format";

export const dynamic = "force-dynamic";

/** The core stores periods as epoch seconds; the formatters take ISO strings. */
function day(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().slice(0, 10);
}

export default async function CompliancePage() {
  const t = await getTranslations("compliance");
  const res = await fetchAuditReports();
  const reports = res.ok ? res.data : [];

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <NewReportForm />

      {!res.ok && (
        <p role="alert" className="mb-6 text-sm text-[var(--danger)]">
          {res.error}
        </p>
      )}

      <Card>
        <CardBody>
          {reports.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">{t("empty")}</p>
          ) : (
            <Table>
              <Thead>
                <Th>{t("colReport")}</Th>
                <Th>{t("colGenerated")}</Th>
                <Th>{t("colPeriod")}</Th>
                <Th>{t("colAgents")}</Th>
                <Th className="text-right">{t("colReceipts")}</Th>
                <Th className="text-right">{t("colDenials")}</Th>
              </Thead>
              <Tbody>
                {reports.map((r) => (
                  <Tr key={r.report_id}>
                    <Td className="font-[var(--font-mono)]">
                      <Link
                        href={`/compliance/${r.report_id}`}
                        className="underline decoration-dotted"
                        title={r.report_id}
                      >
                        {truncateHash(r.report_id)}
                      </Link>
                    </Td>
                    <Td>{fmtTimestamp(new Date(r.generated_at * 1000).toISOString())}</Td>
                    <Td className="font-[var(--font-mono)] text-mono-sm">
                      {day(r.period_start)} → {day(r.period_end)}
                    </Td>
                    <Td>
                      {r.agent_ids.length === 0 ? (
                        <span className="text-[var(--text-muted)]">all</span>
                      ) : (
                        fmtNumber(r.agent_ids.length)
                      )}
                    </Td>
                    <Td className="text-right">{fmtNumber(r.raw_receipts_count)}</Td>
                    <Td className="text-right">
                      {r.policy_compliance_summary.denied === 0 ? (
                        <span className="text-[var(--text-muted)]">{t("denialsNone")}</span>
                      ) : (
                        fmtNumber(r.policy_compliance_summary.denied)
                      )}
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>
    </PageShell>
  );
}
