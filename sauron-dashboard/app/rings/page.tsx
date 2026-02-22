"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";

interface RingData {
  total_rings?: number;
  avg_ring_size?: number;
  rings?: Array<{ ring_id?: string; size?: number; client?: string; created_at?: string; [key: string]: unknown }>;
  [key: string]: unknown;
}

export default function RingsPage() {
  const [data, setData] = useState<RingData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${DASH_API}/api/rings`)
      .then(r => r.json())
      .then(setData)
      .catch(() => setError(true));
  }, []);

  const rings = data?.rings ?? (Array.isArray(data) ? (data as unknown as unknown[]) : []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Rings</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>Cryptographic ring sets for ZKP anonymization</p>

      {error ? (
        <div className="px-4 py-4 rounded-lg" style={{ background: "rgba(239,68,68,.08)", border: "1px solid rgba(239,68,68,.2)", color: "#ef4444" }}>
          Analytics service unavailable.
        </div>
      ) : !data ? (
        <div style={{ color: "var(--text3)" }}>Loading…</div>
      ) : (
        <>
          <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
            <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
              <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Total Rings</div>
              <div className="text-3xl font-extrabold" style={{ color: "var(--accent2)" }}>{data.total_rings ?? (rings as unknown[]).length}</div>
            </div>
            {data.avg_ring_size != null && (
              <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>Avg Ring Size</div>
                <div className="text-3xl font-extrabold" style={{ color: "var(--text)" }}>{typeof data.avg_ring_size === "number" ? data.avg_ring_size.toFixed(1) : data.avg_ring_size}</div>
              </div>
            )}
          </div>

          {(rings as unknown[]).length > 0 && (
            <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
              <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>
                Ring Details
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                    {["Ring ID", "Client", "Size", "Created"].map(h => (
                      <th key={h} className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {(rings as Record<string, unknown>[]).map((r, i) => (
                      <tr key={String(r.ring_id ?? i)} style={{ borderBottom: i < rings.length - 1 ? "1px solid var(--border)" : undefined }}>
                        <td className="px-5 py-3 font-mono text-xs" style={{ color: "var(--text3)" }}>{String(r.ring_id ?? i + 1).slice(0, 12)}…</td>
                        <td className="px-5 py-3" style={{ color: "var(--text)" }}>{String(r.client ?? "—")}</td>
                        <td className="px-5 py-3 tabular-nums" style={{ color: "var(--accent2)" }}>{String(r.size ?? "—")}</td>
                        <td className="px-5 py-3 text-xs" style={{ color: "var(--text3)" }}>{String(r.created_at ?? "—")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
