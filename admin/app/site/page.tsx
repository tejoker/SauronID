"use client";

import { useState, useEffect, useCallback } from "react";
import { useWallet, SITES, getSiteTheme, EXCHANGE_RATE, API, SITE_TYPE, type SiteName } from "../context/WalletContext";
import { showToast } from "../components/Toast";

const ADMIN_HEADERS = { "x-admin-key": "super_secret_hackathon_key" };

// ─── Token pill ───────────────────────────────────────────────────────────────

function TokenPill({ token, kind }: { token: string; kind: "A" | "B" }) {
  const short = `${token.slice(0, 10)}...`;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono border ${
      kind === "A"
        ? "bg-green-50 border-green-200 text-green-700"
        : "bg-orange-50 border-orange-200 text-orange-700"
    }`}>
      {short}
    </span>
  );
}

// ─── Balance card ─────────────────────────────────────────────────────────────

function BalanceCard({
  kind,
  count,
  tokens,
  label,
  sub,
}: {
  kind: "A" | "B";
  count: number;
  tokens: string[];
  label: string;
  sub: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const colors = kind === "A"
    ? "bg-green-50 border-green-200 text-green-800"
    : "bg-orange-50 border-orange-200 text-orange-700";

  return (
    <div className={`border rounded-lg p-5 ${colors}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase tracking-widest opacity-70">{label}</p>
          <p className="text-5xl font-bold tabular-nums mt-1">{count}</p>
          <p className="text-xs opacity-50 mt-1">{sub}</p>
        </div>
        <span className={`text-xs font-semibold px-2 py-1 rounded border ${
          kind === "A" ? "border-green-300 text-green-700" : "border-orange-300 text-orange-700"
        }`}>{kind === "A" ? "A" : "B"}</span>
      </div>
      {tokens.length > 0 && (
        <div className="mt-4 border-t border-current/20 pt-3">
          <button
            onClick={() => setExpanded((e) => !e)}
            className="text-xs opacity-60 hover:opacity-100 transition-opacity"
          >
            {expanded ? "Hide" : `Show ${tokens.length} token${tokens.length > 1 ? "s" : ""}`}
          </button>
          {expanded && (
            <div className="mt-2 flex flex-wrap gap-1 max-h-32 overflow-y-auto">
              {tokens.map((t, i) => <TokenPill key={i} token={t} kind={kind} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Exchange panel ───────────────────────────────────────────────────────────

function ExchangePanel({ site }: { site: SiteName }) {
  const { wallets, takeTokensA, addTokensB, returnTokensA } = useWallet();
  const wallet = wallets[site];
  const [count, setCount] = useState(1);
  const [busy, setBusy] = useState(false);
  const [lastResult, setLastResult] = useState<{ burned: number; received: number } | null>(null);
  const [error, setError] = useState("");

  const maxA = wallet.tokensA.length;
  const willReceive = count * EXCHANGE_RATE;

  const run = async () => {
    if (count < 1 || count > maxA) return;
    setBusy(true);
    setLastResult(null);
    setError("");

    // Atomically remove tokens A before the request (will roll back on failure)
    const tokensA = takeTokensA(site, count);
    if (!tokensA) {
      setError("Not enough Token A in wallet.");
      setBusy(false);
      return;
    }

    try {
      const blindedTokensB = Array.from({ length: willReceive }, () =>
        Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map((b) => b.toString(16).padStart(2, "0")).join("")
      );

      const res = await fetch(`${API}/exchange_tokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: site, tokens_a: tokensA, blinded_tokens_b: blindedTokensB }),
      });
      const data = await res.json();
      if (!res.ok) {
        returnTokensA(site, tokensA); // rollback
        throw new Error(data.error ?? "Exchange failed");
      }

      addTokensB(site, data.signed_tokens_b ?? []);
      const received = (data.signed_tokens_b ?? []).length;
      setLastResult({ burned: count, received });
      showToast("success", `Exchange complete — ${site}`, `Burned ${count} Token A, received ${received} Token B (rate 1:${EXCHANGE_RATE})`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg);
      showToast("error", "Exchange failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-neutral-900">Exchange Token A to Token B</h3>
        <span className="text-xs border border-neutral-200 text-neutral-500 px-2 py-1 rounded">
          Rate: 1 A = {EXCHANGE_RATE} B
        </span>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex-1">
          <label className="text-xs text-neutral-500 mb-1 block">Token A to burn</label>
          <input
            type="number"
            min={1}
            max={maxA}
            value={count}
            onChange={(e) => setCount(Math.max(1, Math.min(maxA, parseInt(e.target.value) || 1)))}
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
          />
        </div>
        <div className="text-center text-neutral-400 text-xl mt-5">=&gt;</div>
        <div className="flex-1 bg-neutral-50 border border-neutral-200 rounded-lg px-3 py-2 text-sm">
          <p className="text-xs text-neutral-400 mb-1">Receive</p>
          <p className="text-orange-600 font-bold tabular-nums">{willReceive} Token B</p>
        </div>
      </div>

      <button
        onClick={run}
        disabled={busy || maxA === 0}
        className="w-full border border-neutral-300 hover:border-neutral-500 disabled:border-neutral-100 disabled:text-neutral-300 text-neutral-700 font-medium py-2.5 rounded-lg transition-all text-sm"
      >
        {busy ? "Processing..." : maxA === 0 ? "No Token A available" : `Exchange ${count} A for ${willReceive} B`}
      </button>

      {lastResult && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-sm">
          <p className="text-green-700 font-semibold">Exchange successful</p>
          <p className="text-neutral-500 text-xs mt-1">
            Burned <span className="text-green-700 font-mono">{lastResult.burned}</span> Token A —
            received <span className="text-orange-600 font-mono">{lastResult.received}</span> Token B
          </p>
        </div>
      )}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-600">
          {error}
        </div>
      )}
    </div>
  );
}

// ─── Buy tokens panel ─────────────────────────────────────────────────────────

function BuyPanel({ site }: { site: SiteName }) {
  const { addTokensB } = useWallet();
  const [amount, setAmount] = useState(5);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const presets = [1, 3, 5, 10, 20];

  const run = async () => {
    setBusy(true);
    setMsg("");
    try {
      const res = await fetch(`${API}/client/add_tokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: site, amount }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Purchase failed");
      const tokens: string[] = data.tokens ?? [];
      addTokensB(site, tokens);
      const result = `Purchased ${tokens.length} Token B`;
      setMsg(result);
      showToast("success", `Purchase — ${site}`, result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setMsg(`[ERROR] ${msg}`);
      showToast("error", "Purchase failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-neutral-900">Buy Token B (Fiat)</h3>
        <span className="text-xs border border-neutral-200 text-neutral-400 px-2 py-1 rounded">
          POST /client/add_tokens
        </span>
      </div>
      <p className="text-xs text-neutral-400">
        Purchase Token B directly with fiat. No Token A required.
      </p>

      <div className="flex flex-wrap gap-2">
        {presets.map((n) => (
          <button
            key={n}
            onClick={() => setAmount(n)}
            className={`px-3 py-1.5 rounded text-sm border transition-colors ${
              amount === n
                ? "border-neutral-900 bg-neutral-900 text-white"
                : "border-neutral-200 text-neutral-600 hover:border-neutral-400"
            }`}
          >
            {n} B
          </button>
        ))}
        <input
          type="number"
          min={1}
          value={amount}
          onChange={(e) => setAmount(Math.max(1, parseInt(e.target.value) || 1))}
          className="w-20 bg-white border border-neutral-300 text-neutral-900 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-neutral-500"
        />
      </div>

      <button
        onClick={run}
        disabled={busy}
        className="w-full border border-neutral-300 hover:border-neutral-500 disabled:border-neutral-100 disabled:text-neutral-300 text-neutral-700 font-medium py-2.5 rounded-lg transition-all text-sm"
      >
        {busy ? "Processing..." : `Buy ${amount} Token B`}
      </button>

      {msg && (
        <div className={`border rounded-lg p-3 text-sm ${
          msg.startsWith("[ERROR]")
            ? "bg-red-50 border-red-200 text-red-600"
            : "bg-green-50 border-green-200 text-green-700"
        }`}>
          {msg}
        </div>
      )}
    </div>
  );
}

// ─── Site ZKP proofs panel ───────────────────────────────────────────────────

interface SiteZkpProofRecord {
  id: number;
  timestamp: number;
  ring_size: number;
  proved_claims: string[];
}

function SiteZkpPanel({ site }: { site: SiteName }) {
  const [proofs, setProofs] = useState<SiteZkpProofRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const theme = getSiteTheme(site);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/admin/site/${site}/zkp_proofs`, { headers: ADMIN_HEADERS });
      const data = await res.json();
      setProofs(Array.isArray(data) ? data : []);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [site]);

  useEffect(() => { load(); }, [load]);

  const fmt = (ts: number) =>
    new Date(ts * 1000).toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-neutral-500">
          {loading ? "Loading..." : `${proofs.length} ZKP proof${proofs.length !== 1 ? "s" : ""} verified by ${site}`}
        </p>
        <button onClick={load} className="text-xs text-neutral-400 hover:text-neutral-600 border border-neutral-200 px-2 py-1 rounded transition-colors">
          Refresh
        </button>
      </div>

      {proofs.length === 0 && !loading && (
        <div className="border border-neutral-200 rounded-lg p-8 text-center text-sm text-neutral-400">
          No ZKP proofs yet. Use the ZKP Login tab on the User Experience page.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {proofs.map((p) => (
          <div key={p.id} className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors">
            <div className="flex items-start justify-between mb-2">
              <p className={`font-semibold text-sm ${theme.color}`}>Anonymous user #{p.id}</p>
              <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${theme.bg} ${theme.color} ${theme.border}`}>
                ZKP
              </span>
            </div>
            <div className="flex flex-wrap gap-1 mb-2">
              {p.proved_claims.map((c) => (
                <span key={c} className={`text-[10px] px-2 py-0.5 rounded-full border ${theme.bg} ${theme.color} ${theme.border}`}>
                  {c}
                </span>
              ))}
            </div>
            <p className="text-xs text-neutral-400">Ring size: {p.ring_size} members</p>
            <p className="text-[10px] text-neutral-300 mt-1 font-mono">{fmt(p.timestamp)}</p>
          </div>
        ))}
      </div>

      <div className={`border ${theme.border} ${theme.bg} rounded-lg p-3 text-xs ${theme.color} opacity-70`}>
        <strong>ZKP_ONLY</strong> — {site} receives zero-knowledge proofs. No personal data is ever transmitted.
        Ring size = k-anonymity level. Claims are cryptographically verified by Sauron.
      </div>
    </div>
  );
}

// ─── Site users panel ─────────────────────────────────────────────────────────

interface SiteUserRecord {
  first_name: string;
  last_name: string;
  email: string;
  country: string;
  source: "full_kyc" | "fast_login";
  acquired_at: number;
}

function SiteUsersPanel({ site }: { site: SiteName }) {
  const [users, setUsers] = useState<SiteUserRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const theme = getSiteTheme(site);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/admin/site/${site}/users`, { headers: ADMIN_HEADERS });
      const data = await res.json();
      setUsers(Array.isArray(data) ? data : []);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [site]);

  useEffect(() => { load(); }, [load]);

  const fmt = (ts: number) =>
    new Date(ts * 1000).toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-neutral-500">
          {loading ? "Loading..." : `${users.length} user${users.length !== 1 ? "s" : ""} known to ${site}`}
        </p>
        <button onClick={load} className="text-xs text-neutral-400 hover:text-neutral-600 border border-neutral-200 px-2 py-1 rounded transition-colors">
          Refresh
        </button>
      </div>

      {users.length === 0 && !loading && (
        <div className="border border-neutral-200 rounded-lg p-8 text-center text-sm text-neutral-400">
          No users yet. Register a user or use Fast Login to acquire KYC data.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {users.map((u, i) => (
          <div key={i} className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors">
            <div className="flex items-start justify-between mb-2">
              <p className="font-semibold text-neutral-900 text-sm">{u.first_name} {u.last_name}</p>
              <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                u.source === "full_kyc"
                  ? "bg-green-50 text-green-700 border-green-200"
                  : "bg-orange-50 text-orange-700 border-orange-200"
              }`}>
                {u.source === "full_kyc" ? "FULL KYC" : "FAST LOGIN"}
              </span>
            </div>
            <p className="text-xs text-neutral-500">{u.email}</p>
            <p className="text-xs text-neutral-400 mt-0.5">{u.country}</p>
            <p className="text-[10px] text-neutral-300 mt-2 font-mono">{fmt(u.acquired_at)}</p>
          </div>
        ))}
      </div>

      <div className={`border ${theme.border} ${theme.bg} rounded-lg p-3 text-xs ${theme.color} opacity-70`}>
        <strong>Full KYC</strong> — user registered directly on {site} (Flux 1, {site} had the original KYC data).
        {" "}<strong>Fast Login</strong> — user authenticated via Sauron, spending 1 Token B (Flux 3, {site} now has the profile).
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function SiteTreasury() {
  const { activeSite, setActiveSite, wallets } = useWallet();
  const wallet = wallets[activeSite];
  const theme = getSiteTheme(activeSite);
  const [tab, setTab] = useState<"treasury" | "users">("treasury");
  const isZkp = SITE_TYPE[activeSite] === "ZKP_ONLY";

  return (
    <div className="min-h-screen bg-white text-neutral-900">
      <div className={`${theme.bg} ${theme.border} border-b px-8 py-4`}>
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div>
            <h1 className={`text-base font-bold ${theme.color}`}>{activeSite} — Token Treasury</h1>
            <p className="text-xs text-neutral-400 mt-0.5">Partner site wallet · Sauron is blind to token balances</p>
          </div>
          <div className="flex gap-2">
            {SITES.map((s) => (
              <button
                key={s.name}
                onClick={() => setActiveSite(s.name)}
                className={`px-3 py-1.5 rounded text-sm border font-medium transition-all ${
                  activeSite === s.name
                    ? `${s.bg} ${s.color} ${s.border}`
                    : "text-neutral-400 border-neutral-200 hover:border-neutral-400 hover:text-neutral-700"
                }`}
              >
                {s.name}
              </button>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div className="max-w-7xl mx-auto mt-3 flex gap-1">
          {(["treasury", "users"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded text-xs font-semibold border transition-all ${
                tab === t
                  ? `${theme.bg} ${theme.color} ${theme.border}`
                  : "text-neutral-400 border-transparent hover:text-neutral-600"
              }`}
            >
              {t === "treasury" ? "Treasury" : isZkp ? "ZKP Proofs" : "Users"}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-8 py-8 space-y-8">
        {tab === "treasury" ? (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <BalanceCard
                kind="A"
                count={wallet.tokensA.length}
                tokens={wallet.tokensA}
                label="Token A — Earned"
                sub="Gained by registering users with KYC"
              />
              <BalanceCard
                kind="B"
                count={wallet.tokensB.length}
                tokens={wallet.tokensB}
                label="Token B — Spendable"
                sub="Used to anonymously retrieve a user's KYC"
              />
            </div>

            <div className="border border-neutral-200 rounded-lg p-5">
              <h3 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Token Economy</h3>
              <div className="grid grid-cols-3 gap-4 text-center text-xs">
                <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3">
                  <p className="text-green-600 font-semibold mb-1">FLUX 1 — Register</p>
                  <p className="text-neutral-500">User submits KYC — {activeSite} earns <strong className="text-green-600">1 Token A</strong></p>
                </div>
                <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3">
                  <p className="text-orange-500 font-semibold mb-1">FLUX 2 — Exchange</p>
                  <p className="text-neutral-500">Burn N Token A — receive N×{EXCHANGE_RATE} <strong className="text-orange-500">Token B</strong></p>
                </div>
                <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3">
                  <p className="text-red-500 font-semibold mb-1">FLUX 3 — Get KYC</p>
                  <p className="text-neutral-500">Spend <strong className="text-red-500">1 Token B</strong> — get KYC anonymously. Sauron doesn&apos;t know who asked.</p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ExchangePanel site={activeSite} />
              <BuyPanel site={activeSite} />
            </div>
          </>
        ) : isZkp ? (
          <SiteZkpPanel site={activeSite} />
        ) : (
          <SiteUsersPanel site={activeSite} />
        )}
      </div>
    </div>
  );
}
