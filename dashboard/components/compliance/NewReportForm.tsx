"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { createAuditReport } from "@/lib/api";

/** `<input type="date">` gives `YYYY-MM-DD`; the core wants epoch seconds. */
function toEpoch(day: string, endOfDay: boolean): number {
  const ms = Date.parse(`${day}T${endOfDay ? "23:59:59" : "00:00:00"}Z`);
  return Math.floor(ms / 1000);
}

function isoDay(offsetDays: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

export function NewReportForm() {
  const t = useTranslations("compliance");
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState(isoDay(-30));
  const [to, setTo] = useState(isoDay(0));
  const [agents, setAgents] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onGenerate() {
    setPending(true);
    setError(null);
    const agent_ids = agents
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const res = await createAuditReport({
      period_start: toEpoch(from, false),
      period_end: toEpoch(to, true),
      ...(agent_ids.length ? { agent_ids } : {}),
    });
    setPending(false);
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setOpen(false);
    router.push(`/compliance/${res.data.report.report_id}`);
  }

  if (!open) {
    return (
      <div className="mb-6">
        <Button onClick={() => setOpen(true)}>{t("newReport")}</Button>
      </div>
    );
  }

  return (
    <Card className="mb-6">
      <CardBody>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm">
            <span className="block mb-1 text-[var(--text-muted)]">{t("from")}</span>
            <input
              type="date"
              value={from}
              max={to}
              onChange={(e) => setFrom(e.target.value)}
              className="w-full px-3 py-2 rounded border border-[var(--border)] bg-[var(--bg-elevated)] text-[var(--text-primary)]"
            />
          </label>
          <label className="text-sm">
            <span className="block mb-1 text-[var(--text-muted)]">{t("to")}</span>
            <input
              type="date"
              value={to}
              min={from}
              onChange={(e) => setTo(e.target.value)}
              className="w-full px-3 py-2 rounded border border-[var(--border)] bg-[var(--bg-elevated)] text-[var(--text-primary)]"
            />
          </label>
        </div>
        <label className="block mt-4 text-sm">
          <span className="block mb-1 text-[var(--text-muted)]">{t("selectAgents")}</span>
          <input
            type="text"
            value={agents}
            placeholder="agent-a, agent-b"
            onChange={(e) => setAgents(e.target.value)}
            className="w-full px-3 py-2 rounded border border-[var(--border)] bg-[var(--bg-elevated)] text-[var(--text-primary)] font-[var(--font-mono)]"
          />
        </label>
        {error && (
          <p role="alert" className="mt-3 text-sm text-[var(--danger)]">
            {error}
          </p>
        )}
        <div className="mt-4 flex gap-2">
          <Button onClick={onGenerate} disabled={pending}>
            {pending ? t("generating") : t("generate")}
          </Button>
          <Button variant="ghost" onClick={() => setOpen(false)} disabled={pending}>
            {t("cancel")}
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
