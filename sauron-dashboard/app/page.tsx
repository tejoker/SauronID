"use client";

import { useDash } from "./context/DashContext";

function KpiCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
      <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>{label}</div>
      <div className="text-3xl font-extrabold tabular-nums" style={{ color: accent || "var(--text)" }}>{value}</div>
      {sub && <div className="text-xs mt-1" style={{ color: "var(--text3)" }}>{sub}</div>}
    </div>
  );
}

export default function OverviewPage() {
  const { stats, clients, offline } = useDash();

  const fullKyc = clients.filter(c => c.client_type === "FULL_KYC").length;
  const zkpOnly = clients.filter(c => c.client_type === "ZKP_ONLY").length;
  const totalTokensA = clients.reduce((s, c) => s + (c.tokens_a || 0), 0);
  const totalTokensB = clients.reduce((s, c) => s + (c.tokens_b || 0), 0);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: "var(--text)" }}>Overview</h1>
          <p className="text-sm mt-1" style={{ color: "var(--text3)" }}>Live system snapshot — refreshed every 10 s</p>
        </div>
        {offline && <span className="text-xs px-3 py-1 rounded-full" style={{ background: "rgba(239,68,68,.12)", color: "#ef4444" }}>⚠ Backend offline</span>}
      </div>

      {/* KPI grid */}
      <div className="grid grid-cols-2 gap-4 mb-4" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
        <KpiCard label="Registered Users" value={stats?.total_users ?? "—"} accent="var(--accent)" />
        <KpiCard label="Partner Clients"  value={stats?.total_clients ?? "—"} />
        <KpiCard label="Tokens A Issued"  value={stats?.total_tokens_a_issued ?? "—"} sub={`burned: ${stats?.total_tokens_a_burned ?? "—"}`} accent="var(--warning)" />
        <KpiCard label="Tokens B Issued"  value={stats?.total_tokens_b_issued ?? "—"} sub={`spent: ${stats?.total_tokens_b_spent ?? "—"}`} accent="var(--success)" />
        <KpiCard label="Exchange Rate"    value={stats ? `${stats.exchange_rate} A/B` : "—"} />
        <KpiCard label="FULL_KYC Clients" value={fullKyc} sub={`ZKP_ONLY: ${zkpOnly}`} accent="var(--accent2)" />
      </div>

      {/* Clients table */}
      <div className="rounded-xl overflow-hidden mt-6" style={{ border: "1px solid var(--border)" }}>
        <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>
          Live Client Balances
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                {["Name", "Type", "Tokens A", "Tokens B"].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {clients.length === 0 ? (
                <tr><td colSpan={4} className="px-5 py-8 text-center" style={{ color: "var(--text3)" }}>No clients</td></tr>
              ) : clients.map((c, i) => (
                <tr key={c.name} style={{ borderBottom: i < clients.length - 1 ? "1px solid var(--border)" : undefined }}>
                  <td className="px-5 py-3 font-medium" style={{ color: "var(--text)" }}>{c.name}</td>
                  <td className="px-5 py-3">
                    <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{
                      background: c.client_type === "FULL_KYC" ? "rgba(59,130,246,.13)" : "rgba(124,58,237,.13)",
                      color:      c.client_type === "FULL_KYC" ? "#60a5fa" : "#a78bfa",
                    }}>{c.client_type}</span>
                  </td>
                  <td className="px-5 py-3 tabular-nums" style={{ color: "var(--warning)" }}>{c.tokens_a ?? 0}</td>
                  <td className="px-5 py-3 tabular-nums" style={{ color: "var(--success)" }}>{c.tokens_b ?? 0}</td>
                </tr>
              ))}
              {clients.length > 0 && (
                <tr style={{ background: "var(--surface2)", borderTop: "1px solid var(--border)" }}>
                  <td className="px-5 py-3 font-semibold text-xs uppercase tracking-widest" colSpan={2} style={{ color: "var(--text3)" }}>Total</td>
                  <td className="px-5 py-3 font-bold tabular-nums" style={{ color: "var(--warning)" }}>{totalTokensA}</td>
                  <td className="px-5 py-3 font-bold tabular-nums" style={{ color: "var(--success)" }}>{totalTokensB}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
