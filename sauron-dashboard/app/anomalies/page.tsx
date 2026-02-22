"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";

interface Anomaly {
  id?: string | number;
  type?: string;
  client?: string;
  severity?: "low" | "medium" | "high" | string;
  description?: string;
  timestamp?: string;
  [key: string]: unknown;
}

interface AnomalyData {
  total_anomalies?: number;
  anomalies?: Anomaly[];
  [key: string]: unknown;
}

const SEVERITY_STYLE: Record<string, { bg: string; color: string }> = {
  high:   { bg: "rgba(239,68,68,.12)",  color: "#ef4444" },
  medium: { bg: "rgba(245,158,11,.12)", color: "#f59e0b" },
  low:    { bg: "rgba(34,197,94,.12)",  color: "#22c55e" },
};

export default function AnomaliesPage() {
  const [data, setData] = useState<AnomalyData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${DASH_API}/api/anomalies`)
      .then(r => r.json())
      .then(setData)
      .catch(() => setError(true));
  }, []);

  const anomalies: Anomaly[] = data?.anomalies ?? (Array.isArray(data) ? (data as unknown as Anomaly[]) : []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Anomalies</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>Suspicious transactions and behavioral anomalies</p>

      {error ? (
        <div className="px-4 py-4 rounded-lg mb-4" style={{ background: "rgba(239,68,68,.08)", border: "1px solid rgba(239,68,68,.2)", color: "#ef4444" }}>
          Analytics service unavailable.
        </div>
      ) : !data ? (
        <div style={{ color: "var(--text3)" }}>Loading…</div>
      ) : (
        <>
          <div className="mb-6 inline-block rounded-xl px-6 py-4" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
            <div className="text-xs uppercase tracking-widest mb-1" style={{ color: "var(--text3)" }}>Detected Anomalies</div>
            <div className="text-3xl font-extrabold" style={{ color: "var(--danger)" }}>
              {data.total_anomalies ?? anomalies.length}
            </div>
          </div>

          <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ background: "var(--surface2)", borderBottom: "1px solid var(--border)" }}>
                    {["Type", "Client", "Severity", "Description", "Timestamp"].map(h => (
                      <th key={h} className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {anomalies.length === 0 ? (
                    <tr><td colSpan={5} className="px-5 py-12 text-center" style={{ color: "var(--text3)" }}>No anomalies detected.</td></tr>
                  ) : anomalies.map((a, i) => {
                    const sev = String(a.severity ?? "low");
                    const style = SEVERITY_STYLE[sev] ?? SEVERITY_STYLE.low;
                    return (
                      <tr key={String(a.id ?? i)} style={{ borderBottom: i < anomalies.length - 1 ? "1px solid var(--border)" : undefined, background: "var(--surface)" }}>
                        <td className="px-5 py-3 font-medium" style={{ color: "var(--text)" }}>{String(a.type ?? "—")}</td>
                        <td className="px-5 py-3" style={{ color: "var(--text2)" }}>{String(a.client ?? "—")}</td>
                        <td className="px-5 py-3">
                          <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ background: style.bg, color: style.color }}>{sev}</span>
                        </td>
                        <td className="px-5 py-3 max-w-[260px]" style={{ color: "var(--text3)" }}>{String(a.description ?? "—")}</td>
                        <td className="px-5 py-3 text-xs" style={{ color: "var(--text3)" }}>{String(a.timestamp ?? "—")}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
