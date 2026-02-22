"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";

export type SiteName =
  | "Monzo" | "Revolut" | "Binance" | "N26"
  | "Discord" | "Tinder" | "Airbnb" | "Uber" | "Twitch";

export const FULL_KYC_SITES: SiteName[] = ["Monzo", "Revolut", "Binance", "N26"];
export const ZKP_SITES: SiteName[]      = ["Discord", "Tinder", "Airbnb", "Uber", "Twitch"];
export const SITE_NAMES: SiteName[]     = [...FULL_KYC_SITES, ...ZKP_SITES];

export const SITE_TYPE: Record<SiteName, "FULL_KYC" | "ZKP_ONLY"> = {
  Monzo: "FULL_KYC", Revolut: "FULL_KYC", Binance: "FULL_KYC", N26: "FULL_KYC",
  Discord: "ZKP_ONLY", Tinder: "ZKP_ONLY", Airbnb: "ZKP_ONLY", Uber: "ZKP_ONLY", Twitch: "ZKP_ONLY",
};

export const EXCHANGE_RATE = 3;
export const API = "http://localhost:3000";

export const SITES: { name: SiteName; color: string; bg: string; border: string; logo: string }[] = [
  // FULL_KYC
  { name: "Monzo",   color: "text-orange-600", bg: "bg-orange-50",  border: "border-orange-300", logo: "🏦" },
  { name: "Revolut", color: "text-violet-600", bg: "bg-violet-50",  border: "border-violet-300", logo: "💳" },
  { name: "Binance", color: "text-amber-600",  bg: "bg-amber-50",   border: "border-amber-300",  logo: "₿"  },
  { name: "N26",     color: "text-sky-700",    bg: "bg-sky-50",     border: "border-sky-300",    logo: "🏧" },
  // ZKP_ONLY
  { name: "Discord", color: "text-indigo-600", bg: "bg-indigo-50",  border: "border-indigo-300", logo: "💬" },
  { name: "Tinder",  color: "text-pink-600",   bg: "bg-pink-50",    border: "border-pink-300",   logo: "🔥" },
  { name: "Airbnb",  color: "text-rose-600",   bg: "bg-rose-50",    border: "border-rose-300",   logo: "🏠" },
  { name: "Uber",    color: "text-neutral-700", bg: "bg-neutral-50", border: "border-neutral-300", logo: "🚗" },
  { name: "Twitch",  color: "text-purple-600", bg: "bg-purple-50",  border: "border-purple-300", logo: "🎮" },
];

export function getSiteTheme(name: SiteName) {
  return SITES.find((s) => s.name === name) ?? SITES[0];
}

export interface SiteWallet {
  tokensA: string[];
  tokensB: string[];
}

interface WalletContextType {
  activeSite: SiteName;
  setActiveSite: (s: SiteName) => void;
  wallets: Record<SiteName, SiteWallet>;
  addTokensA: (site: SiteName, tokens: string[]) => void;
  addTokensB: (site: SiteName, tokens: string[]) => void;
  takeTokensA: (site: SiteName, count: number) => string[] | null;
  spendTokenB: (site: SiteName) => string | null;
  returnTokensA: (site: SiteName, tokens: string[]) => void;
  returnTokenB: (site: SiteName, token: string) => void;
}

function buildDefault(): Record<SiteName, SiteWallet> {
  return Object.fromEntries(SITE_NAMES.map((n) => [n, { tokensA: [], tokensB: [] }])) as unknown as Record<SiteName, SiteWallet>;
}

const STORAGE_KEY = "sauron_wallets_v5";
const WalletContext = createContext<WalletContextType | null>(null);

export function WalletProvider({ children }: { children: React.ReactNode }) {
  const [activeSite, setActiveSiteRaw] = useState<SiteName>("Monzo");
  const [wallets, setWallets] = useState<Record<SiteName, SiteWallet>>(buildDefault);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setWallets(JSON.parse(raw));
      const site = localStorage.getItem("sauron_active_site_v5") as SiteName | null;
      if (site && SITE_NAMES.includes(site)) setActiveSiteRaw(site);
    } catch {}
  }, []);

  const persist = useCallback((w: Record<SiteName, SiteWallet>) => {
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, JSON.stringify(w));
  }, []);

  const setActiveSite = useCallback((s: SiteName) => {
    setActiveSiteRaw(s);
    if (typeof window !== "undefined") localStorage.setItem("sauron_active_site_v5", s);
  }, []);

  const update = useCallback((site: SiteName, fn: (w: SiteWallet) => SiteWallet) => {
    setWallets((prev) => {
      const next = { ...prev, [site]: fn({ ...prev[site] }) };
      persist(next);
      return next;
    });
  }, [persist]);

  const addTokensA = useCallback((site: SiteName, tokens: string[]) => {
    update(site, (w) => ({ ...w, tokensA: [...w.tokensA, ...tokens] }));
  }, [update]);

  const addTokensB = useCallback((site: SiteName, tokens: string[]) => {
    update(site, (w) => ({ ...w, tokensB: [...w.tokensB, ...tokens] }));
  }, [update]);

  const takeTokensA = useCallback((site: SiteName, count: number): string[] | null => {
    const current = wallets[site].tokensA;
    if (current.length < count) return null;
    const taken = current.slice(0, count);
    update(site, (w) => ({ ...w, tokensA: w.tokensA.slice(count) }));
    return taken;
  }, [wallets, update]);

  const spendTokenB = useCallback((site: SiteName): string | null => {
    const token = wallets[site].tokensB[0] ?? null;
    if (!token) return null;
    update(site, (w) => ({ ...w, tokensB: w.tokensB.slice(1) }));
    return token;
  }, [wallets, update]);

  const returnTokensA = useCallback((site: SiteName, tokens: string[]) => {
    update(site, (w) => ({ ...w, tokensA: [...tokens, ...w.tokensA] }));
  }, [update]);

  const returnTokenB = useCallback((site: SiteName, token: string) => {
    update(site, (w) => ({ ...w, tokensB: [token, ...w.tokensB] }));
  }, [update]);

  return (
    <WalletContext.Provider value={{
      activeSite, setActiveSite,
      wallets,
      addTokensA, addTokensB,
      takeTokensA, spendTokenB,
      returnTokensA, returnTokenB,
    }}>
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet() {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWallet must be inside WalletProvider");
  return ctx;
}
