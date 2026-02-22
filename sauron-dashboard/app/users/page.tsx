"use client";

import { useDash } from "../context/DashContext";
import type { LiveUser } from "../context/DashContext";

export default function UsersPage() {
  const { users } = useDash();

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>Users</h1>
      <p className="text-sm mb-6" style={{ color: "var(--text3)" }}>
        {users.length} registered users — live from Rust backend
      </p>

      <div className="rounded-xl overflow-hidden" style={{ border: "1px solid var(--border)" }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "var(--surface2)", borderBottom: "1px solid var(--border)" }}>
                {["First Name", "Last Name", "Nationality", "Key Image"].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text3)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr><td colSpan={4} className="px-5 py-12 text-center" style={{ color: "var(--text3)" }}>No users yet — seed the database first.</td></tr>
              ) : users.map((u: LiveUser, i: number) => (
                <tr key={u.key_image_hex + i} style={{ borderBottom: i < users.length - 1 ? "1px solid var(--border)" : undefined, background: "var(--surface)" }}>
                  <td className="px-5 py-3 font-medium" style={{ color: "var(--text)" }}>{u.first_name || "—"}</td>
                  <td className="px-5 py-3" style={{ color: "var(--text2)" }}>{u.last_name || "—"}</td>
                  <td className="px-5 py-3" style={{ color: "var(--text2)" }}>{u.nationality || "—"}</td>
                  <td className="px-5 py-3 font-mono text-xs max-w-[200px] truncate" style={{ color: "var(--text3)" }}
                    title={u.key_image_hex}>
                    {u.key_image_hex ? u.key_image_hex.slice(0, 20) + "…" : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {users.length > 0 && (
          <div className="px-5 py-3 text-xs" style={{ background: "var(--surface2)", borderTop: "1px solid var(--border)", color: "var(--text3)" }}>
            Showing {users.length} users
          </div>
        )}
      </div>
    </div>
  );
}
