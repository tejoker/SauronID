"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";

interface GdprStats {
  total_users?: number;
  purge_requests?: number;
  last_purge?: string;
  users_purged?: number;
  [key: string]: unknown;
}

export default function GdprPage() {
  const [stats, setStats] = useState<GdprStats | null>(null);
  const [error, setError] = useState(false);
  const [userId, setUserId] = useState("");
  const [purging, setPurging] = useState(false);
  const [purgeResult, setPurgeResult] = useState<string | null>(null);

  const load = () => {
    fetch(`${DASH_API}/api/gdpr/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => setError(true));
  };

  useEffect(() => { load(); }, []);

  const handlePurge = async () => {
    if (!userId.trim()) return;
    setPurging(true);
    setPurgeResult(null);
    try {
      const r = await fetch(`${DASH_API}/api/gdpr/purge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id: userId.trim() }),
      });
      const d = await r.json();
      setPurgeResult(r.ok ? `✓ ${d.message ?? "User data purged."}` : `✗ ${d.detail ?? "Purge failed."}`);
      setUserId("");
      load();
    } catch {
      setPurgeResult("✗ Service unavailable");
    } finally {
      setPurging(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>GDPR Compliance</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>Right-to-erasure and data compliance tooling</p>

      {error ? (
        <div className="px-4 py-4 rounded-lg mb-6" style={{ background: "rgba(239,68,68,.08)", border: "1px solid rgba(239,68,68,.2)", color: "#ef4444" }}>
          Analytics service unavailable.
        </div>
      ) : stats && (
        <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))" }}>
          {[
            { label: "Total Users",   value: stats.total_users   ?? "—" },
            { label: "Purge Requests",value: stats.purge_requests ?? "—", color: "var(--warning)" },
            { label: "Users Purged",  value: stats.users_purged  ?? "—", color: "var(--danger)" },
            { label: "Last Purge",    value: stats.last_purge    ?? "—", sm: true },
          ].map(({ label, value, color, sm }) => (
            <div key={label} className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
              <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>{label}</div>
              <div className={sm ? "text-sm font-semibold" : "text-2xl font-extrabold"} style={{ color: color || "var(--text)" }}>{String(value)}</div>
            </div>
          ))}
        </div>
      )}

      {/* Purge form */}
      <div className="rounded-xl p-6" style={{ background: "var(--surface)", border: "1px solid var(--border)", maxWidth: 480 }}>
        <h2 className="text-sm font-semibold mb-4" style={{ color: "var(--text)" }}>
          Request Data Erasure
        </h2>
        <div className="flex gap-3">
          <input
            className="flex-1 px-3 py-2 rounded-lg text-sm outline-none"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--text)" }}
            placeholder="User ID to purge…"
            value={userId}
            onChange={e => setUserId(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handlePurge()}
          />
          <button
            onClick={handlePurge}
            disabled={purging || !userId.trim()}
            className="px-4 py-2 rounded-lg text-sm font-semibold transition-opacity disabled:opacity-40"
            style={{ background: "rgba(220,38,38,.08)", color: "#dc2626", border: "1px solid rgba(220,38,38,.25)" }}
          >
            {purging ? "…" : "Purge"}
          </button>
        </div>
        {purgeResult && (
          <div className="mt-3 text-xs px-3 py-2 rounded" style={{
            background: purgeResult.startsWith("✓") ? "rgba(34,197,94,.08)" : "rgba(239,68,68,.08)",
            color:      purgeResult.startsWith("✓") ? "#16a34a" : "#dc2626",
          }}>
            {purgeResult}
          </div>
        )}
      </div>
    </div>
  );
}
