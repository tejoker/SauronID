"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";

export const API      = process.env.NEXT_PUBLIC_API_URL      || "http://localhost:3001";
export const DASH_API = process.env.NEXT_PUBLIC_DASH_API_URL || "http://localhost:8002";
export const ADMIN_KEY = "super_secret_hackathon_key";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface LiveStats {
  total_users:            number;
  total_clients:          number;
  total_tokens_a_issued:  number;
  total_tokens_a_burned:  number;
  total_tokens_b_issued:  number;
  total_tokens_b_spent:   number;
  exchange_rate:          number;
}

export interface LiveClient {
  name:            string;
  public_key_hex:  string;
  private_key_hex: string;
  key_image_hex:   string;
  client_type:     "FULL_KYC" | "ZKP_ONLY";
  tokens_a:        number;
  tokens_b:        number;
}

export interface LiveUser {
  key_image_hex: string;
  first_name:    string;
  last_name:     string;
  nationality:   string;
}

// ── Context ───────────────────────────────────────────────────────────────────
interface DashContextType {
  stats:    LiveStats | null;
  clients:  LiveClient[];
  users:    LiveUser[];
  offline:  boolean;
  loading:  boolean;
  refresh:  () => Promise<void>;
}

const DashContext = createContext<DashContextType | null>(null);

export function DashProvider({ children }: { children: React.ReactNode }) {
  const [stats,   setStats]   = useState<LiveStats | null>(null);
  const [clients, setClients] = useState<LiveClient[]>([]);
  const [users,   setUsers]   = useState<LiveUser[]>([]);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const h = { "x-admin-key": ADMIN_KEY };
      const [sRes, cRes, uRes] = await Promise.all([
        fetch(`${API}/admin/stats`,   { headers: h }),
        fetch(`${API}/dev/clients`),
        fetch(`${API}/admin/users`,   { headers: h }),
      ]);
      if (sRes.ok)  setStats(await sRes.json());
      if (cRes.ok)  setClients(await cRes.json());
      if (uRes.ok)  setUsers(await uRes.json());
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10_000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <DashContext.Provider value={{ stats, clients, users, offline, loading, refresh }}>
      {children}
    </DashContext.Provider>
  );
}

export function useDash() {
  const ctx = useContext(DashContext);
  if (!ctx) throw new Error("useDash must be inside DashProvider");
  return ctx;
}
