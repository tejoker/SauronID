"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";

interface PipelineStats {
  events_processed?: number;
  events_per_second?: number;
  pipeline_stages?: Array<{ name: string; status: string; processed?: number; errors?: number }>;
  last_updated?: string;
  [key: string]: unknown;
}

const STATUS_STYLE: Record<string, { bg: string; color: string }> = {
  running: { bg: "rgba(34,197,94,.12)",  color: "#22c55e" },
  idle:    { bg: "rgba(148,163,184,.1)", color: "#94a3b8" },
  error:   { bg: "rgba(239,68,68,.12)",  color: "#ef4444" },
};

export default function PipelinePage() {
  const [data, setData] = useState<PipelineStats | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    const load = () =>
      fetch(`${DASH_API}/api/pipeline-stats`)
        .then(r => r.json())
        .then(setData)
        .catch(() => setError(true));
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Pipeline</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>Data ingestion pipeline — refreshed every 5 s</p>

      {error ? (
        <div className="px-4 py-4 rounded-lg" style={{ background: "rgba(239,68,68,.08)", border: "1px solid rgba(239,68,68,.2)", color: "#ef4444" }}>
          Analytics service unavailable.
        </div>
      ) : !data ? (
        <div style={{ color: "var(--text3)" }}>Loading…</div>
      ) : (
        <>
          <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
            {data.events_processed != null && (
              <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Events Processed</div>
                <div className="text-3xl font-extrabold" style={{ color: "var(--accent)" }}>{data.events_processed.toLocaleString()}</div>
              </div>
            )}
            {data.events_per_second != null && (
              <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Events / sec</div>
                <div className="text-3xl font-extrabold" style={{ color: "var(--success)" }}>{Number(data.events_per_second).toFixed(1)}</div>
              </div>
            )}
            {data.last_updated && (
              <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Last Updated</div>
                <div className="text-sm font-semibold" style={{ color: "var(--text2)" }}>{String(data.last_updated)}</div>
              </div>
            )}
          </div>

          {Array.isArray(data.pipeline_stages) && data.pipeline_stages.length > 0 ? (
            <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
              <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>
                Pipeline Stages
              </div>
              <table className="w-full text-sm">
                <thead><tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                  {["Stage", "Status", "Processed", "Errors"].map(h => (
                    <th key={h} className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {data.pipeline_stages.map((s, i) => {
                    const style = STATUS_STYLE[s.status] ?? STATUS_STYLE.idle;
                    return (
                      <tr key={s.name} style={{ borderBottom: i < (data.pipeline_stages?.length ?? 0) - 1 ? "1px solid var(--border)" : undefined }}>
                        <td className="px-5 py-3 font-medium" style={{ color: "var(--text)" }}>{s.name}</td>
                        <td className="px-5 py-3">
                          <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ background: style.bg, color: style.color }}>{s.status}</span>
                        </td>
                        <td className="px-5 py-3 tabular-nums" style={{ color: "var(--text2)" }}>{s.processed?.toLocaleString() ?? "—"}</td>
                        <td className="px-5 py-3 tabular-nums" style={{ color: s.errors ? "var(--danger)" : "var(--text3)" }}>{s.errors ?? 0}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="rounded-xl p-5 font-mono text-xs overflow-auto" style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text2)", maxHeight: 400 }}>
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
