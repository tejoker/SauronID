"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";

interface VerifData {
  total_verifications?: number;
  success_rate?: number;
  by_client?: Array<{ client: string; total: number; success: number }>;
  by_type?: Array<{ type: string; count: number }>;
  [key: string]: unknown;
}

export default function VerificationsPage() {
  const [data, setData] = useState<VerifData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${DASH_API}/api/verifications`)
      .then(r => r.json())
      .then(setData)
      .catch(() => setError(true));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Verifications</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>KYC / ZKP verification analytics</p>

      {error ? (
        <div className="px-4 py-4 rounded-lg" style={{ background: "rgba(239,68,68,.08)", border: "1px solid rgba(239,68,68,.2)", color: "#ef4444" }}>
          Analytics service unavailable. Make sure the Python dashboard (port 8002) is running.
        </div>
      ) : !data ? (
        <div style={{ color: "var(--text3)" }}>Loading…</div>
      ) : (
        <>
          <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
            <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
              <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Total Verifications</div>
              <div className="text-3xl font-extrabold" style={{ color: "var(--accent)" }}>{data.total_verifications ?? "—"}</div>
            </div>
            <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
              <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Success Rate</div>
              <div className="text-3xl font-extrabold" style={{ color: "var(--success)" }}>
                {data.success_rate != null ? `${(data.success_rate * 100).toFixed(1)}%` : "—"}
              </div>
            </div>
          </div>

          {Array.isArray(data.by_client) && data.by_client.length > 0 && (
            <div className="rounded-xl overflow-hidden mb-6" style={{ border: "1px solid var(--border)" }}>
              <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>By Client</div>
              <table className="w-full text-sm">
                <thead><tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                  <th className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Client</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Total</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Success</th>
                </tr></thead>
                <tbody>
                  {data.by_client.map((row, i) => (
                    <tr key={row.client} style={{ borderBottom: i < (data.by_client?.length ?? 0) - 1 ? "1px solid var(--border)" : undefined }}>
                      <td className="px-5 py-3" style={{ color: "var(--text)" }}>{row.client}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--text2)" }}>{row.total}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--success)" }}>{row.success}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {Array.isArray(data.by_type) && data.by_type.length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
              <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>By Type</div>
              <table className="w-full text-sm">
                <thead><tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                  <th className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Type</th>
                  <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Count</th>
                </tr></thead>
                <tbody>
                  {data.by_type.map((row, i) => (
                    <tr key={row.type} style={{ borderBottom: i < (data.by_type?.length ?? 0) - 1 ? "1px solid var(--border)" : undefined }}>
                      <td className="px-5 py-3" style={{ color: "var(--text)" }}>{row.type}</td>
                      <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--accent)" }}>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
