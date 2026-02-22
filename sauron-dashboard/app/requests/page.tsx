"use client";

import { useEffect, useState, useCallback } from "react";
import { API, ADMIN_KEY } from "../context/DashContext";

interface Request {
  id?: number;
  client_name?: string;
  request_type?: string;
  timestamp?: string;
  success?: boolean;
  [key: string]: unknown;
}

export default function RequestsPage() {
  const [requests, setRequests] = useState<Request[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API}/admin/requests`, { headers: { "X-Admin-Key": ADMIN_KEY } })
      .then(r => r.json())
      .then(d => { setRequests(Array.isArray(d) ? d : (d.requests ?? [])); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold mb-1" style={{ color: "var(--text)" }}>Activity</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text3)" }}>Live request log — auto-refreshed every 5 s</p>
        </div>
        <button onClick={load} className="px-4 py-2 rounded-lg text-sm font-medium transition-opacity hover:opacity-80"
          style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text2)" }}>
          ↺ Refresh
        </button>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "var(--surface2)", borderBottom: "1px solid var(--border)" }}>
                {["#", "Client", "Type", "Timestamp", "Status"].map(h => (
                  <th key={h} className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="px-5 py-12 text-center" style={{ color: "var(--text3)" }}>Loading…</td></tr>
              ) : requests.length === 0 ? (
                <tr><td colSpan={5} className="px-5 py-12 text-center" style={{ color: "var(--text3)" }}>No requests yet.</td></tr>
              ) : requests.map((r, i) => (
                <tr key={r.id ?? i} style={{ borderBottom: i < requests.length - 1 ? "1px solid var(--border)" : undefined, background: "var(--surface)" }}>
                  <td className="px-6 py-4 font-mono text-xs" style={{ color: "var(--text3)" }}>{r.id ?? i + 1}</td>
                  <td className="px-6 py-4 font-medium" style={{ color: "var(--text)" }}>{String(r.client_name ?? "—")}</td>
                  <td className="px-6 py-4">
                    <span className="text-xs px-2.5 py-1 rounded-full" style={{ background: "rgba(37,99,235,.08)", color: "#1d4ed8" }}>
                      {String(r.request_type ?? r.type ?? "—")}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-xs" style={{ color: "var(--text3)" }}>{String(r.timestamp ?? r.created_at ?? "—")}</td>
                  <td className="px-6 py-4">
                    <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{
                      background: r.success !== false ? "rgba(22,163,74,.1)" : "rgba(220,38,38,.1)",
                      color:      r.success !== false ? "#16a34a" : "#dc2626",
                    }}>{r.success !== false ? "OK" : "FAIL"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {requests.length > 0 && (
          <div className="px-6 py-4 text-xs" style={{ background: "var(--surface2)", borderTop: "1px solid var(--border)", color: "var(--text3)" }}>
            {requests.length} events
          </div>
        )}
      </div>
    </div>
  );
}
