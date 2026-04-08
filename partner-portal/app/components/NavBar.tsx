"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useClient } from "../context/ClientContext";
import { useState, useRef, useEffect } from "react";

export default function NavBar() {
  const { clients, activeClient, setActiveClientName, offline } = useClient();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  const pathname = usePathname();

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const filtered = clients.filter(
    (c) =>
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.client_type.toLowerCase().includes(search.toLowerCase())
  );
  const fullKyc = filtered.filter((c) => c.client_type === "FULL_KYC");
  const zkpOnly = filtered.filter((c) => c.client_type === "ZKP_ONLY");
  const banks = filtered.filter((c) => c.client_type === "BANK");

  const isBank = activeClient?.client_type === "BANK";

  return (
    <header className="border-b border-neutral-200 bg-white sticky top-0 z-50">
      <div className="max-w-[1400px] mx-auto px-6 flex items-center h-14 gap-4">
        {/* Logo */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="w-7 h-7 rounded-lg bg-neutral-900 flex items-center justify-center">
            <span className="text-white text-xs font-bold">S</span>
          </div>
          <span className="text-sm font-bold tracking-tight text-neutral-900">Sauron</span>
        </div>

        {/* Portal Navigation */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <Link
            href="/"
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              pathname === "/" ? "bg-neutral-900 text-white" : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-100"
            }`}
          >
            Site Portal
          </Link>
          <Link
            href="/bank"
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              pathname === "/bank" ? "bg-neutral-900 text-white" : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-100"
            }`}
          >
            Bank Portal
          </Link>
          <Link
            href="/retail"
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              pathname === "/retail" ? "bg-neutral-900 text-white" : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-100"
            }`}
          >
            Retail Demo
          </Link>
        </div>

        {/* Separator */}
        <div className="h-6 w-px bg-neutral-200" />

        {/* Client Selector Dropdown */}
        <div ref={dropdownRef} className="relative flex-1 max-w-sm">
          <button
            onClick={() => { setOpen(!open); setSearch(""); }}
            className="flex items-center gap-2 w-full px-3 py-2 rounded-lg border border-neutral-200 hover:border-neutral-400 transition-colors bg-white text-left"
          >
            {activeClient ? (
              <>
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  activeClient.client_type === "FULL_KYC" ? "bg-blue-500" :
                  activeClient.client_type === "ZKP_ONLY" ? "bg-purple-500" : "bg-amber-500"
                }`} />
                <span className="text-sm font-medium text-neutral-900 truncate">{activeClient.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0 ${
                  activeClient.client_type === "FULL_KYC"
                    ? "bg-blue-50 text-blue-700 border-blue-200"
                    : activeClient.client_type === "ZKP_ONLY"
                    ? "bg-purple-50 text-purple-700 border-purple-200"
                    : "bg-amber-50 text-amber-700 border-amber-200"
                }`}>
                  {activeClient.client_type}
                </span>
              </>
            ) : (
              <span className="text-sm text-neutral-400">Select a client...</span>
            )}
            <svg className="w-4 h-4 ml-auto text-neutral-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {open && (
            <div className="absolute top-full left-0 mt-1 w-full bg-white border border-neutral-200 rounded-lg shadow-lg z-50 max-h-[420px] flex flex-col">
              {/* Search */}
              <div className="p-2 border-b border-neutral-100">
                <input
                  autoFocus
                  type="text"
                  placeholder="Search clients..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full px-3 py-1.5 text-sm border border-neutral-200 rounded-md focus:outline-none focus:border-neutral-400 bg-neutral-50"
                />
              </div>

              {/* Grouped results */}
              <div className="overflow-y-auto flex-1">
                {banks.length > 0 && (
                  <div>
                    <div className="px-3 py-1.5 text-[10px] font-semibold text-amber-600 uppercase tracking-widest bg-amber-50/50">
                      Banks ({banks.length})
                    </div>
                    {banks.map((c) => (
                      <button
                        key={c.name}
                        onClick={() => { setActiveClientName(c.name); setOpen(false); }}
                        className={`w-full px-3 py-2 text-left flex items-center gap-2 hover:bg-neutral-50 transition-colors ${
                          c.name === activeClient?.name ? "bg-amber-50" : ""
                        }`}
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500 flex-shrink-0" />
                        <span className="text-sm text-neutral-800">{c.name}</span>
                      </button>
                    ))}
                  </div>
                )}
                {fullKyc.length > 0 && (
                  <div>
                    <div className="px-3 py-1.5 text-[10px] font-semibold text-blue-600 uppercase tracking-widest bg-blue-50/50">
                      Full KYC ({fullKyc.length})
                    </div>
                    {fullKyc.map((c) => (
                      <button
                        key={c.name}
                        onClick={() => { setActiveClientName(c.name); setOpen(false); }}
                        className={`w-full px-3 py-2 text-left flex items-center gap-2 hover:bg-neutral-50 transition-colors ${
                          c.name === activeClient?.name ? "bg-blue-50" : ""
                        }`}
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 flex-shrink-0" />
                        <span className="text-sm text-neutral-800">{c.name}</span>
                        <span className="text-[10px] text-neutral-400 ml-auto tabular-nums">{c.tokens_b}B</span>
                      </button>
                    ))}
                  </div>
                )}
                {zkpOnly.length > 0 && (
                  <div>
                    <div className="px-3 py-1.5 text-[10px] font-semibold text-purple-600 uppercase tracking-widest bg-purple-50/50">
                      ZKP Only ({zkpOnly.length})
                    </div>
                    {zkpOnly.map((c) => (
                      <button
                        key={c.name}
                        onClick={() => { setActiveClientName(c.name); setOpen(false); }}
                        className={`w-full px-3 py-2 text-left flex items-center gap-2 hover:bg-neutral-50 transition-colors ${
                          c.name === activeClient?.name ? "bg-purple-50" : ""
                        }`}
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-500 flex-shrink-0" />
                        <span className="text-sm text-neutral-800">{c.name}</span>
                        <span className="text-[10px] text-neutral-400 ml-auto tabular-nums">{c.tokens_b}B</span>
                      </button>
                    ))}
                  </div>
                )}
                {filtered.length === 0 && (
                  <p className="p-4 text-sm text-neutral-400 text-center">No client found</p>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Status */}
        <div className="flex items-center gap-3 flex-shrink-0">
          {activeClient && !isBank && (
            <div className="hidden md:flex items-center gap-3 text-[11px] text-neutral-400">
              <span className="tabular-nums"><strong className={activeClient.tokens_b === 0 ? "text-red-500" : "text-orange-500"}>{activeClient.tokens_b}</strong> credits</span>
            </div>
          )}
          {offline ? (
            <span className="text-red-600 text-xs border border-red-200 bg-red-50 px-2 py-1 rounded">Offline</span>
          ) : (
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
              <span className="text-[10px] text-neutral-400">Live</span>
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
