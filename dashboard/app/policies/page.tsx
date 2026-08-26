import Link from "next/link";
import { fetchPolicies } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { truncateHash, fmtRelativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function PoliciesListPage() {
  const result = await fetchPolicies();

  return (
    <PageShell>
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
            Policies
          </h1>
          <p className="mt-1 text-sm text-[var(--text-muted)]">
            Declarative agent-binding policies. Edit, simulate, and deploy.
          </p>
        </div>
        <Link
          href="/policies/new"
          className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-colors"
        >
          New policy
        </Link>
      </div>

      {!result.ok ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--status-stopped)]">
              Failed to load policies: {result.error}
            </p>
          </CardBody>
        </Card>
      ) : result.data.length === 0 ? (
        <Card>
          <CardBody>
            <p className="text-sm text-[var(--text-muted)] mb-3">
              No policies yet. Start from a template or write one from scratch.
            </p>
            <div className="flex items-center gap-3">
              <Link
                href="/policies/new"
                className="text-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)]"
              >
                Create your first policy →
              </Link>
              <a
                href="/docs/architecture/policy-dsl.md"
                className="text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              >
                Read the DSL docs
              </a>
            </div>
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardBody>
            <Table>
              <Thead>
                <Tr>
                  <Th>Policy ID</Th>
                  <Th>Agent</Th>
                  <Th>Version</Th>
                  <Th>Updated</Th>
                </Tr>
              </Thead>
              <Tbody>
                {result.data.map((p) => (
                  <Tr key={p.policy_id}>
                    <Td>
                      <Link
                        href={`/policies/${encodeURIComponent(p.policy_id)}`}
                        className="text-mono-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)]"
                      >
                        {truncateHash(p.policy_id, 10)}
                      </Link>
                    </Td>
                    <Td className="font-mono">{p.agent}</Td>
                    <Td className="text-mono-sm text-[var(--text-muted)]">
                      {p.version}
                    </Td>
                    <Td className="text-mono-sm text-[var(--text-muted)]">
                      {fmtRelativeTime(new Date(p.updated_at * 1000).toISOString())}
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </CardBody>
        </Card>
      )}
    </PageShell>
  );
}
