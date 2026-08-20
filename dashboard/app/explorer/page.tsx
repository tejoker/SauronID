"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { CopyButton } from "@/components/ui/CopyButton";
import { Button } from "@/components/ui/Button";
import { currentTenant } from "@/lib/tenant";

interface Endpoint {
  /** i18n key under explorer.endpoints */
  key: string;
  method: "GET" | "POST";
  /** Dashboard proxy path (same-origin, session-cookie auth). */
  proxyPath: string;
  /** Core path for the direct-to-core curl; null when the proxy derives the data itself. */
  corePath: string | null;
  /** Example JSON body for POST endpoints. */
  body?: string;
}

// Static catalog of the useful read endpoints exposed through the dashboard
// proxy (app/api/* route handlers), plus the one useful POST.
const ENDPOINTS: Endpoint[] = [
  { key: "overview", method: "GET", proxyPath: "/api/overview", corePath: null },
  { key: "agents", method: "GET", proxyPath: "/api/agents", corePath: "/admin/agents" },
  { key: "activity", method: "GET", proxyPath: "/api/activity?limit=100", corePath: "/admin/egress/recent?limit=100" },
  { key: "policies", method: "GET", proxyPath: "/api/policies", corePath: "/v1/policy/list" },
  {
    key: "evaluate",
    method: "POST",
    proxyPath: "/api/policies/{policy_id}/evaluate",
    corePath: "/v1/policy/evaluate",
    body: '{"action":{"tool":"http.get","url":"https://example.com"}}',
  },
  { key: "proofs", method: "GET", proxyPath: "/api/proofs", corePath: "/admin/anchor/status" },
  { key: "batches", method: "GET", proxyPath: "/api/proofs/batches", corePath: "/admin/anchor/batches" },
  { key: "auditReports", method: "GET", proxyPath: "/api/audit/reports", corePath: "/v1/audit/reports" },
  { key: "tenants", method: "GET", proxyPath: "/api/tenants", corePath: null },
  { key: "users", method: "GET", proxyPath: "/api/users", corePath: "/admin/users" },
  { key: "clients", method: "GET", proxyPath: "/api/clients", corePath: "/admin/clients" },
];

function proxyCurl(ep: Endpoint): string {
  const origin =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:3000";
  const parts = ["curl -s", `-b "sauron_session=$SAURON_SESSION"`];
  if (ep.method === "POST") {
    parts.push("-X POST", `-H "content-type: application/json"`, `-d '${ep.body ?? "{}"}'`);
  }
  parts.push(`"${origin}${ep.proxyPath}"`);
  return parts.join(" \\\n  ");
}

function coreCurl(ep: Endpoint): string {
  const tenant = currentTenant();
  const parts = [
    "curl -s",
    `-H "x-admin-key: \${SAURON_ADMIN_KEY}"`,
    `-H "x-sauron-tenant-id: ${tenant}"`,
  ];
  if (ep.method === "POST") {
    parts.push("-X POST", `-H "content-type: application/json"`, `-d '${ep.body ?? "{}"}'`);
  }
  parts.push(`"\${SAURON_CORE_URL:-http://localhost:3001}${ep.corePath}"`);
  return parts.join(" \\\n  ");
}

export default function ExplorerPage() {
  const t = useTranslations("explorer");
  const tc = useTranslations("common");
  const [results, setResults] = useState<Record<string, string>>({});
  const [runningKey, setRunningKey] = useState<string | null>(null);

  async function run(ep: Endpoint) {
    setRunningKey(ep.key);
    try {
      const res = await fetch(ep.proxyPath, { cache: "no-store" });
      const text = await res.text();
      let pretty = text;
      try {
        pretty = JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        // non-JSON body — show raw
      }
      setResults((r) => ({ ...r, [ep.key]: pretty }));
    } catch {
      setResults((r) => ({ ...r, [ep.key]: t("runError") }));
    } finally {
      setRunningKey(null);
    }
  }

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <p className="text-mono-sm text-[var(--text-muted)] mb-8 max-w-3xl">
        {t("hint")}
      </p>

      <div className="space-y-3">
        {ENDPOINTS.map((ep) => {
          const runnable = ep.method === "GET" && !ep.proxyPath.includes("{");
          const result = results[ep.key];
          return (
            <div
              key={ep.key}
              className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-4"
            >
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`text-mono-sm px-2 py-0.5 rounded border ${
                    ep.method === "GET"
                      ? "text-[var(--status-ok)] border-[var(--status-ok)]/20"
                      : "text-[var(--status-warning)] border-[var(--status-warning)]/20"
                  }`}
                >
                  {ep.method}
                </span>
                <code className="font-mono text-sm text-[var(--text-primary)]">
                  {ep.proxyPath}
                </code>
                <div className="flex items-center gap-2 ml-auto">
                  <CopyButton
                    text={() => proxyCurl(ep)}
                    label={t("copyProxy")}
                    copiedLabel={tc("copied")}
                  />
                  {ep.corePath && (
                    <CopyButton
                      text={() => coreCurl(ep)}
                      label={t("copyCore")}
                      copiedLabel={tc("copied")}
                    />
                  )}
                  {runnable && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => run(ep)}
                      disabled={runningKey === ep.key}
                    >
                      {runningKey === ep.key ? t("running") : t("run")}
                    </Button>
                  )}
                </div>
              </div>
              <p className="mt-2 text-sm text-[var(--text-muted)]">
                {t(`endpoints.${ep.key}` as Parameters<typeof t>[0])}
              </p>
              {result !== undefined && (
                <div className="mt-3">
                  <pre className="bg-[var(--bg-elevated)] rounded p-3 max-h-80 overflow-auto text-xs font-mono text-[var(--text-secondary)] leading-relaxed">
                    {result}
                  </pre>
                  <button
                    type="button"
                    onClick={() =>
                      setResults((r) => {
                        const next = { ...r };
                        delete next[ep.key];
                        return next;
                      })
                    }
                    className="mt-2 text-xs text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded"
                  >
                    {t("close")}
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </PageShell>
  );
}
