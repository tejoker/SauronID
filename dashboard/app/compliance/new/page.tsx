"use client";

// Sprint 19-20: generate a new audit report.
//
// Compliance officer picks the agent scope (multi-select) + a date
// range. The form converts the dates to unix-epoch seconds and POSTs
// to /api/audit/reports.

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  AgentStatus,
  createAuditReport,
  fetchAgents,
} from "@/lib/api";

function toEpochSeconds(yyyyMmDd: string, endOfDay = false): number {
  // Treat input as UTC midnight — the period is INCLUSIVE of both
  // bounds on the server. For period_end we extend to end-of-day so
  // a user picking "2024-01-31" actually gets the whole 31st.
  const [y, m, d] = yyyyMmDd.split("-").map((n) => parseInt(n, 10));
  if (!y || !m || !d) return 0;
  const t = Date.UTC(y, m - 1, d, endOfDay ? 23 : 0, endOfDay ? 59 : 0, endOfDay ? 59 : 0);
  return Math.floor(t / 1000);
}

export default function NewCompliancePage() {
  const router = useRouter();
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [fromDate, setFromDate] = useState<string>(() => {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - 7);
    return d.toISOString().slice(0, 10);
  });
  const [toDate, setToDate] = useState<string>(() =>
    new Date().toISOString().slice(0, 10)
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void fetchAgents().then((r) => {
      if (r.ok) setAgents(r.data);
    });
  }, []);

  const periodValid = useMemo(() => {
    const a = toEpochSeconds(fromDate, false);
    const b = toEpochSeconds(toDate, true);
    return a > 0 && b > 0 && a <= b;
  }, [fromDate, toDate]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await createAuditReport({
        agent_ids: selected.length > 0 ? selected : undefined,
        period_start: toEpochSeconds(fromDate, false),
        period_end: toEpochSeconds(toDate, true),
      });
      if (!res.ok) {
        setError(res.error);
        setSubmitting(false);
        return;
      }
      router.push(`/compliance/${encodeURIComponent(res.data.report.report_id)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Submit failed");
      setSubmitting(false);
    }
  }

  function toggleAgent(id: string) {
    setSelected((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]
    );
  }

  return (
    <PageShell title="New audit report" subtitle="Generate a periodic ZK audit report for a tenant scope.">
      <Card>
        <CardBody>
          <form onSubmit={onSubmit} className="space-y-6">
            <fieldset>
              <legend className="block text-mono-sm text-[var(--text-muted)] uppercase mb-2">
                Agents (optional — leave empty for all)
              </legend>
              {agents.length === 0 ? (
                <p className="text-mono-sm text-[var(--text-muted)]">
                  No agents discovered yet.
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {agents.map((a) => {
                    const active = selected.includes(a.id);
                    return (
                      <button
                        type="button"
                        key={a.id}
                        onClick={() => toggleAgent(a.id)}
                        className={`px-3 py-1.5 rounded-full text-mono-sm border transition-colors duration-150 ease-out ${
                          active
                            ? "bg-[var(--accent)] text-white border-[var(--accent)]"
                            : "border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--border-hover)]"
                        }`}
                      >
                        {a.name}
                      </button>
                    );
                  })}
                </div>
              )}
            </fieldset>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor="report-from" className="block text-mono-sm text-[var(--text-muted)] uppercase mb-2">
                  From
                </label>
                <input
                  id="report-from"
                  type="date"
                  value={fromDate}
                  onChange={(e) => setFromDate(e.target.value)}
                  className="w-full px-3 py-2 rounded border border-[var(--border)] bg-[var(--bg-surface)] text-sm"
                />
              </div>
              <div>
                <label htmlFor="report-to" className="block text-mono-sm text-[var(--text-muted)] uppercase mb-2">
                  To
                </label>
                <input
                  id="report-to"
                  type="date"
                  value={toDate}
                  onChange={(e) => setToDate(e.target.value)}
                  className="w-full px-3 py-2 rounded border border-[var(--border)] bg-[var(--bg-surface)] text-sm"
                />
              </div>
            </div>

            {!periodValid && (
              <p className="text-mono-sm text-[var(--status-stopped)]">
                From date must be ≤ To date.
              </p>
            )}
            {error && (
              <p className="text-mono-sm text-[var(--status-stopped)]">{error}</p>
            )}

            <div className="flex items-center gap-3">
              <Button type="submit" disabled={!periodValid || submitting}>
                {submitting ? "Generating…" : "Generate report"}
              </Button>
              <Link
                href="/compliance"
                className="text-mono-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              >
                Cancel
              </Link>
            </div>
          </form>
        </CardBody>
      </Card>
    </PageShell>
  );
}
