"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useDash } from "../context/DashContext";

const NAV = [
  {
    section: "Platform",
    items: [
      { href: "/",             label: "Overview",      icon: "grid" },
      { href: "/clients",      label: "Clients",       icon: "building" },
      { href: "/tokens",       label: "Tokens",        icon: "coin" },
      { href: "/users",        label: "Users",         icon: "users" },
      { href: "/requests",     label: "Activity",      icon: "activity" },
    ],
  },
  {
    section: "Analytics",
    items: [
      { href: "/verifications", label: "Verifications", icon: "check" },
      { href: "/rings",         label: "Rings",         icon: "ring" },
      { href: "/anomalies",     label: "Anomalies",     icon: "alert" },
      { href: "/insights",      label: "Insights",      icon: "insights" },
    ],
  },
  {
    section: "Compliance",
    items: [
      { href: "/gdpr",          label: "GDPR",          icon: "shield" },
      { href: "/pipeline",      label: "Pipeline",      icon: "pipeline" },
    ],
  },
];

const ICONS: Record<string, React.ReactNode> = {
  grid:     <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
  building: <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><rect x="3" y="7" width="18" height="14" rx="1"/><path d="M8 7V5a2 2 0 014 0v2M1 7h22"/></svg>,
  coin:     <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="9"/><path d="M12 8v8M9 11h6M9 14h6"/></svg>,
  users:    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>,
  activity: <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  check:    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M9 12l2 2 4-4M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>,
  ring:     <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>,
  alert:    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  insights: <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M18 20V10M12 20V4M6 20v-6"/></svg>,
  shield:   <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  pipeline: <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><rect x="2" y="7" width="20" height="4" rx="1"/><rect x="2" y="14" width="20" height="4" rx="1"/></svg>,
};

export default function Sidebar() {
  const pathname = usePathname();
  const { stats, offline } = useDash();

  return (
    <nav
      style={{ width: "var(--sw)", background: "var(--surface)", borderRight: "1px solid var(--border)" }}
      className="fixed top-0 left-0 h-full flex flex-col z-10 overflow-y-auto"
    >
      {/* Logo */}
      <div style={{ borderBottom: "1px solid var(--border)" }} className="flex items-center gap-2.5 px-4 py-4">
        <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)" }}>
          <svg className="w-4 h-4 fill-white" viewBox="0 0 24 24">
            <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zm0 12.5a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/>
          </svg>
        </div>
        <div>
          <div className="text-sm font-extrabold tracking-widest" style={{ color: "var(--text)" }}>SAURON</div>
          <div className="text-[10px] tracking-widest uppercase" style={{ color: "var(--text3)" }}>Admin Console</div>
        </div>
      </div>

      {/* Nav */}
      <div className="flex-1 py-3">
        {NAV.map(({ section, items }) => (
          <div key={section} className="mb-2">
            <div className="px-4 pt-3 pb-1 text-[10px] font-semibold uppercase tracking-widest" style={{ color: "var(--text3)" }}>
              {section}
            </div>
            {items.map(({ href, label, icon }) => {
              const active = pathname === href;
              return (
                <Link key={href} href={href}
                  className="flex items-center gap-2.5 mx-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
                  style={{
                    color:      active ? "#a78bfa" : "var(--text2)",
                    background: active ? "rgba(124,58,237,.13)" : "transparent",
                  }}>
                  <span className="w-4 h-4 flex-shrink-0" style={{ opacity: active ? 1 : 0.7 }}>
                    {ICONS[icon]}
                  </span>
                  {label}
                </Link>
              );
            })}
          </div>
        ))}
      </div>

      {/* Footer: live status */}
      <div style={{ borderTop: "1px solid var(--border)", color: "var(--text3)" }} className="px-4 py-3 text-[11px]">
        {offline ? (
          <span className="text-red-500">⚠ Backend offline</span>
        ) : stats ? (
          <>
            <div>{stats.total_clients} clients · {stats.total_users} users</div>
            <div className="mt-0.5">A issued: {stats.total_tokens_a_issued} · B spent: {stats.total_tokens_b_spent}</div>
          </>
        ) : (
          <span className="opacity-50">Connecting…</span>
        )}
      </div>
    </nav>
  );
}
