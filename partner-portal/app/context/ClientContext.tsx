"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";

// ─── API ──────────────────────────────────────────────────────────────────────
export const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";
export const KYC_API = process.env.NEXT_PUBLIC_KYC_URL || "/api/kyc/api";
// ─── Types ────────────────────────────────────────────────────────────────────
export interface Client {
  name: string;
  public_key_hex: string;
  key_image_hex: string;
  client_type: "FULL_KYC" | "ZKP_ONLY" | "BANK";
  tokens_b: number;
}

export interface ClientUser {
  first_name: string;
  last_name: string;
  email: string;
  nationality: string;
  source: "register" | "kyc_retrieval";
  timestamp: number;
}

export interface Stats {
  total_users: number;
  total_clients: number;
  total_tokens_b_issued: number;
  total_tokens_b_spent: number;
}

// ─── Context ──────────────────────────────────────────────────────────────────
interface ClientContextType {
  clients: Client[];
  activeClient: Client | null;
  setActiveClientName: (name: string) => void;
  stats: Stats | null;
  loading: boolean;
  offline: boolean;
  refreshClients: () => Promise<void>;
  refreshActiveClient: () => Promise<void>;
}

const ClientContext = createContext<ClientContextType | null>(null);

export function ClientProvider({ children }: { children: React.ReactNode }) {
  const [clients, setClients] = useState<Client[]>([]);
  const [activeClientName, setActiveClientNameRaw] = useState<string>("");
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  const activeClient = clients.find((c) => c.name === activeClientName) ?? null;

  // Fetch all clients + stats
  const refreshClients = useCallback(async () => {
    try {
      const [clientsRes, statsRes] = await Promise.all([
        fetch(`${API}/dev/clients`),
        fetch(`/api/stats`),
      ]);
      if (clientsRes.ok) {
        const data: Client[] = await clientsRes.json();
        setClients(data);
        // Auto-select first client if none selected
        if (!activeClientName && data.length > 0) {
          setActiveClientNameRaw(data[0].name);
        }
      }
      if (statsRes.ok) setStats(await statsRes.json());
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, [activeClientName]);

  // Refresh just the active client's data (after an action)
  const refreshActiveClient = useCallback(async () => {
    if (!activeClientName) return;
    try {
      const res = await fetch(`${API}/dev/client/${encodeURIComponent(activeClientName)}`);
      if (res.ok) {
        const updated: Client = await res.json();
        setClients((prev) => prev.map((c) => (c.name === updated.name ? updated : c)));
      }
    } catch { /* ignore */ }
  }, [activeClientName]);

  const setActiveClientName = useCallback((name: string) => {
    setActiveClientNameRaw(name);
  }, []);

  // Initial fetch + poll every 5s
  useEffect(() => {
    refreshClients();
    const i = setInterval(refreshClients, 5000);
    return () => clearInterval(i);
  }, [refreshClients]);

  return (
    <ClientContext.Provider
      value={{
        clients,
        activeClient,
        setActiveClientName,
        stats,
        loading,
        offline,
        refreshClients,
        refreshActiveClient,
      }}
    >
      {children}
    </ClientContext.Provider>
  );
}

export function useClient() {
  const ctx = useContext(ClientContext);
  if (!ctx) throw new Error("useClient must be inside ClientProvider");
  return ctx;
}
