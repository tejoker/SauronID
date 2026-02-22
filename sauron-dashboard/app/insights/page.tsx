"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";

interface InsightsData {
  top_clients?: Array<{ name: string; transactions?: number; revenue?: number }>;
  category_breakdown?: Array<{ category: string; count: number; amount?: number }>;
  growth_rate?: number;
  retention_rate?: number;
  [key: string]: unknown;
}

export default function InsightsPage() {
  const [data, setData] = useState<InsightsData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${DASH_API}/api/insights`)
      .then(r => r.json())
      .then(setData)
      .catch(() => setError(true));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Insights</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>Business analytics and trend intelligence</p>

      {error ? (
        <div className="px-4 py-4 rounded-lg" style={{ background: "rgba(239,68,68,.08)", border: "1px solid rgba(239,68,68,.2)", color: "#ef4444" }}>
          Analytics service unavailable.
        </div>
      ) : !data ? (
        <div style={{ color: "var(--text3)" }}>Loading…</div>
      ) : (
        <>
          {/* KPI row */}
          {(data.growth_rate != null || data.retention_rate != null) && (
            <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))" }}>
              {data.growth_rate != null && (
                <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                  <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Growth Rate</div>
                  <div className="text-2xl font-extrabold" style={{ color: "var(--success)" }}>
                    {typeof data.growth_rate === "number" ? `+${(data.growth_rate * 100).toFixed(1)}%` : String(data.growth_rate)}
                  </div>
                </div>
              )}
              {data.retention_rate != null && (
                <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                  <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Retention</div>
                  <div className="text-2xl font-extrabold" style={{ color: "var(--accent)" }}>
                    {typeof data.retention_rate === "number" ? `${(data.retention_rate * 100).toFixed(1)}%` : String(data.retention_rate)}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Top clients */}
          {Array.isArray(data.top_clients) && data.top_clients.length > 0 && (
            <div className="rounded-xl overflow-hidden mb-6" style={{ border: "1px solid var(--border)" }}>
              <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>
                Top Clients
              </div>
              <table className="w-full text-sm">
                <thead><tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                  <th className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Client</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Transactions</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Revenue</th>
                </tr></thead>
                <tbody>
                  {data.top_clients.map((c, i) => (
                    <tr key={c.name} style={{ borderBottom: i < (data.top_clients?.length ?? 0) - 1 ? "1px solid var(--border)" : undefined }}>
                      <td className="px-5 py-3 font-medium" style={{ color: "var(--text)" }}>{c.name}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--text2)" }}>{c.transactions ?? "—"}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--success)" }}>{c.revenue != null ? `$${c.revenue.toLocaleString()}` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Category breakdown */}
          {Array.isArray(data.category_breakdown) && data.category_breakdown.length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
              <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>
                Category Breakdown
              </div>
              <table className="w-full text-sm">
                <thead><tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                  <th className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Category</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Count</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Amount</th>
                </tr></thead>
                <tbody>
                  {data.category_breakdown.map((c, i) => (
                    <tr key={c.category} style={{ borderBottom: i < (data.category_breakdown?.length ?? 0) - 1 ? "1px solid var(--border)" : undefined }}>
                      <td className="px-5 py-3 capitalize" style={{ color: "var(--text)" }}>{c.category}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--accent)" }}>{c.count}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--text2)" }}>{c.amount != null ? `$${c.amount.toLocaleString()}` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Fallback: raw JSON */}
          {!data.top_clients && !data.category_breakdown && (
            <div className="rounded-xl p-5 font-mono text-xs overflow-auto" style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text2)", maxHeight: 400 }}>
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
