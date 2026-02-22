"use client";

import { useEffect, useState } from "react";
import { DASH_API } from "../context/DashContext";
import { useDash } from "../context/DashContext";

interface TokensData {
  credit_summary?: {
    total_a_issued?: number;
    total_a_burned?: number;
    total_b_issued?: number;
    total_b_spent?: number;
    exchange_rate?: number;
  };
  client_balances?: Array<{ name: string; tokens_a: number; tokens_b: number }>;
}

export default function TokensPage() {
  const { stats } = useDash();
  const [data, setData] = useState<TokensData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${DASH_API}/api/tokens`)
      .then(r => r.json())
      .then(setData)
      .catch(() => setError(true));
  }, []);

  const summary = data?.credit_summary;
  const balances = data?.client_balances ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Tokens</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>Token economy — live KPIs from Rust, analytics from Python</p>

      {error && (
        <div className="mb-4 px-4 py-3 rounded-lg text-sm" style={{ background: "rgba(239,68,68,.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,.2)" }}>
          Analytics service unavailable — showing live Rust data only.
        </div>
      )}

      {/* Summary grid */}
      <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))" }}>
        {[
          { label: "A Issued",  value: summary?.total_a_issued  ?? stats?.total_tokens_a_issued ?? "—", color: "var(--warning)" },
          { label: "A Burned",  value: summary?.total_a_burned  ?? stats?.total_tokens_a_burned ?? "—", color: "var(--danger)" },
          { label: "B Issued",  value: summary?.total_b_issued  ?? stats?.total_tokens_b_issued ?? "—", color: "var(--success)" },
          { label: "B Spent",   value: summary?.total_b_spent   ?? stats?.total_tokens_b_spent  ?? "—", color: "#f97316" },
          { label: "Rate (A→B)",value: summary?.exchange_rate   ?? stats?.exchange_rate          ?? "—", color: "var(--accent)" },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
            <div className="text-xs uppercase tracking-widest mb-2" style={{ color: "var(--text3)" }}>{label}</div>
            <div className="text-2xl font-extrabold tabular-nums" style={{ color }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Per-client balances */}
      {balances.length > 0 && (
        <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
          <div className="px-5 py-3 text-xs font-semibold uppercase tracking-widest" style={{ background: "var(--surface2)", color: "var(--text3)", borderBottom: "1px solid var(--border)" }}>
            Per-client Balances
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                <th className="px-5 py-3 text-left text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Client</th>
                <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Tokens A</th>
                <th className="px-5 py-3 text-right text-xs uppercase tracking-widest" style={{ color: "var(--text3)" }}>Tokens B</th>
              </tr>
            </thead>
            <tbody>
              {balances.map((b, i) => (
                <tr key={b.name} style={{ borderBottom: i < balances.length - 1 ? "1px solid var(--border)" : undefined }}>
                  <td className="px-5 py-3 font-medium" style={{ color: "var(--text)" }}>{b.name}</td>
                  <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--warning)" }}>{b.tokens_a}</td>
                  <td className="px-5 py-3 text-right tabular-nums" style={{ color: "var(--success)" }}>{b.tokens_b}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
