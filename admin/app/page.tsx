"use client";

import { useEffect, useState, useCallback } from "react";

const API = "http://localhost:3000";
const HEADERS = { "x-admin-key": "super_secret_hackathon_key" };

interface UserRecord { key_image_hex: string; first_name: string; last_name: string; country: string; }
interface VerificationRecord { timestamp: number; message: string; ring_size: number; is_valid: boolean; }
interface ClientBalance { name: string; purchased_tokens: number; kyc_provided: number; }
interface Stats {
  total_users: number;
  total_tokens_a_issued: number;
  total_tokens_a_burned: number;
  total_tokens_b_issued: number;
  total_tokens_b_burned: number;
  exchange_rate: number;
  client_balances: ClientBalance[];
}

const truncateHex = (hex: string) => hex ? `${hex.slice(0, 8)}…${hex.slice(-6)}` : "—";
const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

function KpiCard({ label, value, sub, accent }: { label: string; value: number | string; sub?: string; accent?: string }) {
  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-5 flex flex-col gap-1">
      <span className="text-xs uppercase tracking-widest text-neutral-400">{label}</span>
      <span className={`text-4xl font-bold tabular-nums ${accent ?? "text-neutral-900"}`}>{value}</span>
      {sub && <span className="text-xs text-neutral-400">{sub}</span>}
    </div>
  );
}

function TokenFlowBar({ issued, burned, label }: { issued: number; burned: number; label: string }) {
  const pct = issued > 0 ? Math.round((burned / issued) * 100) : 0;
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-xs">
        <span className="text-neutral-500">{label}</span>
        <span className="text-neutral-400 tabular-nums">{burned}/{issued} ({pct}%)</span>
      </div>
      <div className="h-1.5 rounded-full bg-neutral-100 overflow-hidden">
        <div className="h-full rounded-full bg-green-500 transition-all duration-500" style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
    </div>
  );
}

function ClientTable({ balances }: { balances: ClientBalance[] }) {
  if (!balances.length) return <p className="text-neutral-400 italic text-sm">No partner data.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-neutral-400 text-xs uppercase tracking-wider border-b border-neutral-200">
            <th className="pb-3 pr-4">Partner</th>
            <th className="pb-3 pr-4 text-right">Purchased Tokens</th>
            <th className="pb-3 text-right">KYC Provided</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-neutral-100">
          {balances.map((s) => (
            <tr key={s.name} className="hover:bg-neutral-50 transition-colors">
              <td className="py-3 pr-4 font-semibold text-neutral-900">{s.name}</td>
              <td className="py-3 pr-4 text-right tabular-nums text-neutral-600">{s.purchased_tokens}</td>
              <td className="py-3 text-right"><span className="text-green-600 tabular-nums font-mono">{s.kyc_provided}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UserCard({ u }: { u: UserRecord }) {
  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-3 hover:border-neutral-300 transition-colors">
      <p className="text-sm font-semibold text-neutral-900">{u.first_name} {u.last_name}</p>
      <p className="text-xs text-neutral-500 mt-0.5">{u.country}</p>
      <p className="text-[10px] text-neutral-300 font-mono mt-1">{truncateHex(u.key_image_hex)}</p>
    </div>
  );
}

function VerifyCard({ req }: { req: VerificationRecord }) {
  let flux = "FLUX ?";
  if (req.message.startsWith("GET_KYC")) flux = "FLUX 3";
  else if (req.message.length > 20) flux = "FLUX 1";
  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors">
      <div className="flex justify-between items-center mb-2">
        <div className="flex items-center gap-2">
          <span className="text-[10px] bg-neutral-100 text-neutral-500 px-2 py-0.5 rounded font-mono">{flux}</span>
          <span className="text-xs text-neutral-400 font-mono">{fmt(req.timestamp)}</span>
        </div>
        <span className={`text-xs font-bold px-2 py-0.5 rounded ${req.is_valid ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-600 border border-red-200"}`}>
          {req.is_valid ? "VALID" : "INVALID"}
        </span>
      </div>
      <p className="text-sm text-neutral-700 truncate font-mono text-xs" title={req.message}>
        {req.message.slice(0, 60)}{req.message.length > 60 ? "..." : ""}
      </p>
      <p className="text-xs text-neutral-400 mt-2">Ring of <span className="text-neutral-600">{req.ring_size}</span> anonymous members</p>
    </div>
  );
}

export default function AdminDashboard() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [requests, setRequests] = useState<VerificationRecord[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
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
      setOffline(false);
      setLastRefresh(new Date());
    } catch { setOffline(true); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAll(); const i = setInterval(fetchAll, 4000); return () => clearInterval(i); }, [fetchAll]);

  if (loading) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="animate-pulse text-sm">Connecting to Sauron...</span></div>;

  return (
    <div className="min-h-screen bg-white text-neutral-900">
      <div className="border-b border-neutral-200 px-8 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-neutral-900">Sauron Network — Admin</h1>
          <p className="text-xs text-neutral-400 mt-0.5">Ring signatures · Ristretto255 · Read-only view</p>
        </div>
        <div className="flex items-center gap-3">
          {offline
            ? <span className="text-red-600 text-xs border border-red-200 bg-red-50 px-3 py-1 rounded">Backend offline</span>
            : <span className="flex items-center gap-1.5 text-xs text-neutral-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                {lastRefresh ? lastRefresh.toLocaleTimeString("fr-FR") : "—"}
              </span>
          }
          <button onClick={fetchAll} className="text-xs border border-neutral-200 hover:border-neutral-400 text-neutral-600 px-3 py-1.5 rounded transition-colors">Refresh</button>
        </div>
      </div>

      <div className="px-8 py-8 space-y-10 max-w-7xl mx-auto">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard label="Users in Network" value={stats?.total_users ?? 0} sub="anonymous members" />
          <KpiCard label="Token A Issued" value={stats?.total_tokens_a_issued ?? 0} sub="registration rewards" accent="text-green-600" />
          <KpiCard label="Token B Issued" value={stats?.total_tokens_b_issued ?? 0} sub="after exchange" accent="text-orange-500" />
          <KpiCard label="Token B Burned" value={stats?.total_tokens_b_burned ?? 0} sub="KYC retrievals" accent="text-red-500" />
        </div>

        <section>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Token Flow</h2>
          <div className="bg-white border border-neutral-200 rounded-lg p-6 space-y-4">
            <TokenFlowBar issued={stats?.total_tokens_a_issued ?? 0} burned={stats?.total_tokens_a_burned ?? 0} label="Token A — issued / exchanged for B" />
            <TokenFlowBar issued={stats?.total_tokens_b_issued ?? 0} burned={stats?.total_tokens_b_burned ?? 0} label="Token B — issued / spent on KYC" />
            <div className="pt-4 border-t border-neutral-100 grid grid-cols-3 text-xs text-center gap-4">
              <div><p className="text-neutral-400">Exchange Rate</p><p className="text-neutral-900 font-bold text-2xl mt-1">1 A = {stats?.exchange_rate ?? "?"} B</p></div>
              <div><p className="text-neutral-400">Total Ops</p><p className="text-neutral-900 font-bold text-2xl mt-1">{requests.length}</p></div>
              <div><p className="text-neutral-400">Network Size</p><p className="text-neutral-900 font-bold text-2xl mt-1">{users.length}</p></div>
            </div>
          </div>
        </section>

        <section>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Partner Clients</h2>
          <div className="bg-white border border-neutral-200 rounded-lg p-6">
            <ClientTable balances={stats?.client_balances ?? []} />
            <p className="text-xs text-neutral-400 mt-4 pt-4 border-t border-neutral-100 leading-relaxed">
              Sauron is blind — it cannot see which site holds which tokens. Token A/B balances exist only in each site&apos;s local wallet.
            </p>
          </div>
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <section>
            <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Anonymous Users ({users.length})</h2>
            {users.length === 0
              ? <div className="bg-white border border-neutral-200 rounded-lg p-6 text-neutral-400 italic text-sm">No users yet.</div>
              : <div className="flex flex-col gap-2 max-h-[420px] overflow-y-auto pr-1">{users.map((u, i) => <UserCard key={i} u={u} />)}</div>
            }
          </section>
          <section>
            <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Request Log ({requests.length})</h2>
            {requests.length === 0
              ? <div className="bg-white border border-neutral-200 rounded-lg p-6 text-neutral-400 italic text-sm">No verifications yet.</div>
              : <div className="flex flex-col gap-2 max-h-[420px] overflow-y-auto pr-1">{[...requests].reverse().map((r, i) => <VerifyCard key={i} req={r} />)}</div>
            }
          </section>
        </div>
      </div>
    </div>
  );
}
