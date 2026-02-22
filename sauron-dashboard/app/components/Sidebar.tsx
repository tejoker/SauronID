"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useDash } from "../context/DashContext";

const LINKS = [
  { href: "/",               label: "Overview",       icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" },
  { href: "/tokens",         label: "Tokens",         icon: "M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" },
  { href: "/credits",        label: "Credits",        icon: "M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z" },
  { href: "/verifications",  label: "Verifications",  icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
  { href: "/rings",          label: "Rings",          icon: "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" },
  { href: "/clients",        label: "Clients",        icon: "M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" },
  { href: "/users",          label: "Users",          icon: "M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 7a4 4 0 110-8 4 4 0 010 8zM23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" },
  { href: "/requests",       label: "Activity",       icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { href: "/anomalies",      label: "Anomalies",      icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
  { href: "/insights",       label: "ML Insights",    icon: "M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" },
  { href: "/gdpr",           label: "GDPR",           icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
  { href: "/pipeline",       label: "Pipeline",       icon: "M13 10V3L4 14h7v7l9-11h-7z" },
];

function SvgIcon({ d }: { d: string }) {
  return (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d={d} />
    </svg>
  );
}

export default function Sidebar() {
  const pathname = usePathname();
  const { stats, offline } = useDash();

  return (
    <aside className="w-52 flex-shrink-0 min-h-screen flex flex-col" style={{background:"#e8e8ed"}}>
      {/* Logo */}
      <div className="px-4 pt-6 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-[10px] flex items-center justify-center" style={{background:"#007AFF"}}>
            <svg className="w-5 h-5 fill-white" viewBox="0 0 24 24">
              <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zm0 12.5a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/>
            </svg>
          </div>
          <div>
            <div className="text-[15px] font-semibold text-[#1c1c1e] tracking-tight">Sauron</div>
            <div className="text-[11px] text-[#8e8e93]">Admin Console</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <div className="flex-1 px-2 space-y-0.5">
        {LINKS.map(({ href, label, icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-2.5 px-3 py-[7px] rounded-lg text-[14px] transition-colors ${
                active
                  ? "font-semibold text-white"
                  : "text-[#3a3a3c] hover:bg-black/5"
              }`}
              style={active ? {background:"#007AFF"} : {}}
            >
              <SvgIcon d={icon} />
              {label}
            </Link>
          );
        })}
      </div>

      {/* Footer */}
      <div className="px-4 py-4 text-[11px] text-[#8e8e93]">
        {offline ? (
          <span className="text-red-500 font-medium">Backend offline</span>
        ) : stats ? (
          <>
            <div>{stats.total_clients} clients &middot; {stats.total_users} users</div>
            <div className="mt-0.5">A: {stats.total_tokens_a_issued} &middot; B: {stats.total_tokens_b_spent}</div>
          </>
        ) : (
          <span>Connecting...</span>
        )}
      </div>
    </aside>
  );
}
