"use client";

import { useTranslations } from "next-intl";
import { Badge } from "@/components/ui/Badge";

interface ScenarioResult {
  result: "allowed" | "stopped";
  status_code: number;
  why: string;
  detail: Record<string, unknown>;
}

export function ResultPanel({ result }: { result: ScenarioResult }) {
  const t = useTranslations("try");

  return (
    <div className="animate-fade-in bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5">
      <div className="flex items-center gap-3 mb-4">
        <Badge variant={result.result === "allowed" ? "ok" : "stopped"}>
          {t(result.result === "allowed" ? "resultAllowed" : "resultStopped")}
        </Badge>
        <span className="text-mono-sm text-[var(--text-muted)]">
          HTTP {result.status_code}
        </span>
      </div>

      <div className="mb-4">
        <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-2">
          {t("whyLabel")}
        </p>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {result.why}
        </p>
      </div>

      {Object.keys(result.detail).length > 0 && (
        <details className="group">
          <summary className="text-mono-sm text-[var(--text-muted)] uppercase cursor-pointer hover:text-[var(--text-secondary)] transition-colors duration-150 list-none flex items-center gap-1.5">
            <span className="transition-transform duration-150 group-open:rotate-90">›</span>
            {t("detailLabel")}
          </summary>
          <pre className="mt-3 text-xs text-[var(--text-muted)] font-mono overflow-x-auto bg-[var(--bg-elevated)] rounded p-3">
            {JSON.stringify(result.detail, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}
