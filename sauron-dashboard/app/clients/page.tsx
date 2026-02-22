"use client";

import { useDash } from "../context/DashContext";

export default function ClientsPage() {
  const { clients } = useDash();

  return (
    <div>
      <h1 className="text-3xl font-bold mb-2" style={{ color: "var(--text)" }}>Clients</h1>
      <p className="text-sm mb-8" style={{ color: "var(--text3)" }}>Registered partner clients — live from Rust backend</p>

      <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "var(--surface2)", borderBottom: "1px solid var(--border)" }}>
                {["Name", "Type", "Tokens A", "Tokens B", "Public Key"].map(h => (
                  <th key={h} className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {clients.length === 0 ? (
                <tr><td colSpan={5} className="px-6 py-14 text-center" style={{ color: "var(--text3)" }}>Loading…</td></tr>
              ) : clients.map((c, i) => (
                <tr key={c.name} style={{ borderBottom: i < clients.length - 1 ? "1px solid var(--border)" : undefined, background: "var(--surface)" }}>
                  <td className="px-6 py-4 font-semibold" style={{ color: "var(--text)" }}>{c.name}</td>
                  <td className="px-6 py-4">
                    <span className="text-xs px-2.5 py-1 rounded-full font-semibold" style={{
                      background: c.client_type === "FULL_KYC" ? "rgba(59,130,246,.1)" : "rgba(124,58,237,.1)",
                      color:      c.client_type === "FULL_KYC" ? "#1d4ed8" : "#7e22ce",
                    }}>{c.client_type}</span>
                  </td>
                  <td className="px-6 py-4 tabular-nums font-mono" style={{ color: "var(--warning)" }}>{c.tokens_a ?? 0}</td>
                  <td className="px-6 py-4 tabular-nums font-mono" style={{ color: "var(--success)" }}>{c.tokens_b ?? 0}</td>
                  <td className="px-6 py-4 font-mono text-xs max-w-[160px] truncate" style={{ color: "var(--text3)" }} title={c.public_key_hex}>
                    {c.public_key_hex ? c.public_key_hex.slice(0, 16) + "…" : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
