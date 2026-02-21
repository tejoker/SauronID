"use client";

import { useEffect, useState, useCallback } from "react";

const API = "http://localhost:3000";
const HEADERS = { "x-admin-key": "super_secret_hackathon_key" };

// ─── Types ────────────────────────────────────────────────────────────────────

interface UserProfile {
  first_name: string;
  last_name: string;
  email: string;
  age: number;
  country: string;
}
interface UserRecord {
  public_key_hex: string;
  profile: UserProfile | null;
}
interface MemberProfile {
  public_key_hex: string;
  profile: UserProfile | null;
}
interface VerificationRecord {
  timestamp: number;
  message: string;
  ring_size: number;
  ring_members: MemberProfile[];
  is_valid: boolean;
}
interface IssuerBalance {
  name: string;
  token_balance: number;
  purchased_tokens: number;
  kyc_provided: number;
  kyc_consumed: number;
  reimbursed: number;
  claimable: number;
}
interface Stats {
  total_users: number;
  kyc_injected: number;
  kyc_consumed: number;
  issuer_balances: IssuerBalance[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const truncateHex = (hex: string) =>
  hex ? `${hex.slice(0, 6)}…${hex.slice(-6)}` : "";

const fmt = (ts: number) =>
  new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

// ─── Sub-components ───────────────────────────────────────────────────────────

function KpiCard({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 flex flex-col gap-1">
      <span className="text-xs uppercase tracking-widest text-zinc-500">{label}</span>
      <span className="text-4xl font-bold text-white tabular-nums">{value}</span>
      {sub && <span className="text-xs text-zinc-500">{sub}</span>}
    </div>
  );
}

function BalanceBadge({ value }: { value: number }) {
  const positive = value >= 0;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-sm font-mono font-bold ${positive ? "bg-emerald-950 text-emerald-400" : "bg-red-950 text-red-400"}`}>
      <span className="text-xs">{positive ? "▲" : "▼"}</span>
      {value > 0 ? `+${value}` : value}
    </span>
  );
}

function SiteBalanceTable({ balances }: { balances: IssuerBalance[] }) {
  if (!balances.length) return <p className="text-zinc-500 italic text-sm">No data.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-zinc-500 text-xs uppercase tracking-wider border-b border-zinc-800">
            <th className="pb-3 pr-4">Site</th>
            <th className="pb-3 pr-4 text-right">Balance</th>
            <th className="pb-3 pr-4 text-right">Purchased</th>
            <th className="pb-3 pr-4 text-right">KYC Provided</th>
            <th className="pb-3 pr-4 text-right">KYC Consumed</th>
            <th className="pb-3 text-right">Claimable</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/60">
          {balances.map((s) => (
            <tr key={s.name} className="hover:bg-zinc-800/30 transition-colors">
              <td className="py-3 pr-4 font-semibold text-white">{s.name}</td>
              <td className="py-3 pr-4 text-right">
                <BalanceBadge value={s.token_balance} />
              </td>
              <td className="py-3 pr-4 text-right text-zinc-300 tabular-nums">{s.purchased_tokens}</td>
              <td className="py-3 pr-4 text-right">
                <span className="text-emerald-400 tabular-nums font-mono">{s.kyc_provided}</span>
              </td>
              <td className="py-3 pr-4 text-right">
                <span className="text-amber-400 tabular-nums font-mono">{s.kyc_consumed}</span>
              </td>
              <td className="py-3 text-right">
                {s.claimable > 0
                  ? <span className="bg-blue-900/60 text-blue-300 px-2 py-0.5 rounded font-mono text-xs">{s.claimable} pending</span>
                  : <span className="text-zinc-600 text-xs">—</span>
                }
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UserCard({ u }: { u: UserRecord }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:border-zinc-700 transition-colors">
      {u.profile ? (
        <>
          <div className="flex justify-between items-start">
            <div>
              <p className="font-semibold text-white">
                {u.profile.first_name} {u.profile.last_name}
              </p>
              <p className="text-xs text-zinc-500 mt-0.5">{u.profile.email}</p>
            </div>
            <span className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded">
              {u.profile.age} ans · {u.profile.country}
            </span>
          </div>
          <p className="text-xs text-zinc-600 font-mono mt-3 truncate">
            {truncateHex(u.public_key_hex)}
          </p>
        </>
      ) : (
        <p className="text-xs text-zinc-500 font-mono">
          {truncateHex(u.public_key_hex)}
        </p>
      )}
    </div>
  );
}

function VerifyCard({ req }: { req: VerificationRecord }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:border-zinc-700 transition-colors">
      <div className="flex justify-between items-center mb-2">
        <span className="text-xs text-zinc-600 font-mono">{fmt(req.timestamp)}</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded ${req.is_valid ? "bg-emerald-950 text-emerald-400" : "bg-red-950 text-red-400"}`}>
          {req.is_valid ? "VALID" : "INVALID"}
        </span>
      </div>
      <p className="text-sm text-zinc-300 mb-3 truncate" title={req.message}>
        "{req.message}"
      </p>
      <div className="text-xs text-zinc-600 bg-zinc-950 rounded p-2">
        <span className="text-zinc-500">ring of {req.ring_size}: </span>
        {req.ring_members.slice(0, 3).map((m, i) => (
          <span key={i} className="text-zinc-400">
            {m.profile ? `${m.profile.first_name} ${m.profile.last_name}` : truncateHex(m.public_key_hex)}
            {i < Math.min(req.ring_members.length, 3) - 1 ? ", " : ""}
          </span>
        ))}
        {req.ring_members.length > 3 && <span className="text-zinc-600"> +{req.ring_members.length - 3} more</span>}
      </div>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export default function Dashboard() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [requests, setRequests] = useState<VerificationRecord[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [usersRes, requestsRes, statsRes] = await Promise.all([
        fetch(`${API}/admin/users`, { headers: HEADERS }),
        fetch(`${API}/admin/requests`, { headers: HEADERS }),
        fetch(`${API}/admin/stats`, { headers: HEADERS }),
      ]);
      if (usersRes.ok) setUsers(await usersRes.json());
      if (requestsRes.ok) setRequests(await requestsRes.json());
      if (statsRes.ok) setStats(await statsRes.json());
      setLastRefresh(new Date());
    } catch (e) {
      console.error("Cannot reach Sauron server:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 4000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-black text-zinc-500">
        <span className="text-lg">Connecting to Sauron…</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans">
      {/* ── Header ── */}
      <header className="border-b border-zinc-800 px-8 py-5 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">
            👁 Sauron KYC Network
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            Anonymous identity infrastructure — ring signatures over Ristretto255
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-xs text-zinc-500">
            {lastRefresh ? `Updated ${lastRefresh.toLocaleTimeString("fr-FR")}` : "Connecting…"}
          </span>
          <button
            onClick={fetchAll}
            className="text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-3 py-1.5 rounded transition-colors"
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="px-8 py-8 space-y-10 max-w-7xl mx-auto">

        {/* ── KPI Row ── */}
        <div className="grid grid-cols-3 gap-4">
          <KpiCard label="Users Registered" value={stats?.total_users ?? 0} sub="adult group members" />
          <KpiCard label="KYC Injected" value={stats?.kyc_injected ?? 0} sub="commitments on-chain" />
          <KpiCard label="KYC Consumed" value={stats?.kyc_consumed ?? 0} sub="anonymous verifications" />
        </div>

        {/* ── Partner Balances ── */}
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-widest text-zinc-500 mb-4">
            Partner Sites — Token Balances
          </h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <SiteBalanceTable balances={stats?.issuer_balances ?? []} />
            <p className="text-xs text-zinc-600 mt-5 leading-relaxed">
              <span className="text-emerald-500">KYC Provided</span> = a site registered a user → earns 1 claimable token ·{" "}
              <span className="text-amber-500">KYC Consumed</span> = a site verified a user → costs 1 token ·{" "}
              <span className="text-blue-400">Claimable</span> = reimbursements not yet claimed via <code className="bg-zinc-800 px-1 rounded">/client/claim_reimbursement</code>
            </p>
          </div>
        </section>

        {/* ── Users + History ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <section>
            <h2 className="text-sm font-semibold uppercase tracking-widest text-zinc-500 mb-4">
              Users ({users.length})
            </h2>
            {users.length === 0 ? (
              <p className="text-zinc-600 italic text-sm">No users registered yet.</p>
            ) : (
              <div className="flex flex-col gap-2 max-h-[480px] overflow-y-auto pr-1">
                {users.map((u, i) => <UserCard key={i} u={u} />)}
              </div>
            )}
          </section>

          <section>
            <h2 className="text-sm font-semibold uppercase tracking-widest text-zinc-500 mb-4">
              Verification History ({requests.length})
            </h2>
            {requests.length === 0 ? (
              <p className="text-zinc-600 italic text-sm">No verifications yet.</p>
            ) : (
              <div className="flex flex-col gap-2 max-h-[480px] overflow-y-auto pr-1">
                {[...requests].reverse().map((r, i) => <VerifyCard key={i} req={r} />)}
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
