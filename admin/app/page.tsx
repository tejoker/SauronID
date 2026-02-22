"use client";

import { useEffect, useState, useCallback } from "react";

const API = "http://localhost:3000";
const HEADERS = { "x-admin-key": "super_secret_hackathon_key" };

interface UserRecord { key_image_hex: string; first_name: string; last_name: string; nationality: string; }
interface RequestLogRecord { id: number; timestamp: number; action_type: string; status: string; detail: string; }
interface ClientRecord { name: string; public_key_hex: string; key_image_hex: string; client_type: string; }
interface Stats {
  total_users: number;
  total_clients: number;
  total_tokens_a_issued: number;
  total_tokens_a_burned: number;
  total_tokens_b_issued: number;
  total_tokens_b_spent: number;
  exchange_rate: number;
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

function ClientList({ clients, type }: { clients: ClientRecord[]; type: "FULL_KYC" | "ZKP_ONLY" }) {
  const isZkp = type === "ZKP_ONLY";
  const color = isZkp
    ? { dot: "bg-purple-400", badge: "bg-purple-50 text-purple-700 border-purple-200", ring: "hover:border-purple-200" }
    : { dot: "bg-blue-400",   badge: "bg-blue-50 text-blue-700 border-blue-200",       ring: "hover:border-blue-200" };

  if (!clients.length) return <p className="text-neutral-400 italic text-sm">No clients yet.</p>;
  return (
    <div className="flex flex-col gap-2">
      {clients.map((c) => (
        <div key={c.name} className={`flex items-center justify-between rounded-lg border border-neutral-200 ${color.ring} transition-colors px-4 py-3`}>
          <div className="flex items-center gap-3">
            <span className={`w-2 h-2 rounded-full ${color.dot} flex-shrink-0`} />
            <span className="text-sm font-semibold text-neutral-900">{c.name}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-mono text-neutral-300">{truncateHex(c.key_image_hex)}</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${color.badge}`}>{c.client_type}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function UserCard({ u }: { u: UserRecord }) {
  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-3 hover:border-neutral-300 transition-colors">
      <p className="text-sm font-semibold text-neutral-900">{u.first_name} {u.last_name}</p>
      <p className="text-xs text-neutral-500 mt-0.5">{u.nationality}</p>
      <p className="text-[10px] text-neutral-300 font-mono mt-1">{truncateHex(u.key_image_hex)}</p>
    </div>
  );
}

function RequestCard({ req }: { req: RequestLogRecord }) {
  const isOk = req.status === "OK";
  const badgeColor: Record<string, string> = {
    REGISTER:     "bg-green-50 text-green-700 border-green-200",
    DEV_REGISTER: "bg-green-50 text-green-600 border-green-200",
    EXCHANGE:     "bg-orange-50 text-orange-700 border-orange-200",
    GET_KYC:      "bg-blue-50 text-blue-700 border-blue-200",
    DEV_GET_KYC:  "bg-blue-50 text-blue-600 border-blue-200",
    ZKP_VERIFY:   "bg-purple-50 text-purple-700 border-purple-200",
  };
  const badge = badgeColor[req.action_type] ?? "bg-neutral-100 text-neutral-500 border-neutral-200";
  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors">
      <div className="flex justify-between items-center mb-2">
        <div className="flex items-center gap-2">
          <span className={`text-[10px] px-2 py-0.5 rounded font-mono border ${badge}`}>{req.action_type}</span>
          <span className="text-xs text-neutral-400 font-mono">{fmt(req.timestamp)}</span>
        </div>
        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${isOk ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-600 border-red-200"}`}>
          {req.status}
        </span>
      </div>
      {req.detail && (
        <p className="text-[10px] text-neutral-400 font-mono truncate" title={req.detail}>{req.detail}</p>
      )}
    </div>
  );
}

function ZkpConnectionCard({ req }: { req: RequestLogRecord }) {
  const isOk = req.status === "OK";
  return (
    <div className="bg-white border border-purple-100 rounded-lg p-4 hover:border-purple-200 transition-colors">
      <div className="flex justify-between items-center mb-1.5">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
          <span className="text-xs font-semibold text-purple-800">ZKP Proof verified</span>
          <span className="text-[10px] text-neutral-400 font-mono">{fmt(req.timestamp)}</span>
        </div>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${isOk ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-600 border-red-200"}`}>
          {req.status}
        </span>
      </div>
      {req.detail && (
        <p className="text-[10px] text-neutral-500 font-mono truncate mt-1" title={req.detail}>{req.detail}</p>
      )}
    </div>
  );
}

export default function AdminDashboard() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [requests, setRequests] = useState<RequestLogRecord[]>([]);
  const [clients, setClients] = useState<ClientRecord[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [usersRes, requestsRes, statsRes, clientsRes] = await Promise.all([
        fetch(`${API}/admin/users`, { headers: HEADERS }),
        fetch(`${API}/admin/requests`, { headers: HEADERS }),
        fetch(`${API}/admin/stats`, { headers: HEADERS }),
        fetch(`${API}/admin/clients`, { headers: HEADERS }),
      ]);
      if (usersRes.ok) setUsers(await usersRes.json());
      if (requestsRes.ok) setRequests(await requestsRes.json());
      if (statsRes.ok) setStats(await statsRes.json());
      if (clientsRes.ok) setClients(await clientsRes.json());
      setOffline(false);
      setLastRefresh(new Date());
    } catch { setOffline(true); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAll(); const i = setInterval(fetchAll, 4000); return () => clearInterval(i); }, [fetchAll]);

  const fullKycClients = clients.filter((c) => c.client_type === "FULL_KYC");
  const zkpClients     = clients.filter((c) => c.client_type === "ZKP_ONLY");
  const zkpRequests    = requests.filter((r) => r.action_type === "ZKP_VERIFY");

  if (loading) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="animate-pulse text-sm">Connecting to Sauron...</span></div>;

  return (
    <div className="min-h-screen bg-white text-neutral-900">
      <div className="border-b border-neutral-200 px-8 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-neutral-900">Sauron Network — Admin</h1>
          <p className="text-xs text-neutral-400 mt-0.5">Ring signatures · Ristretto255 · ZKP · Read-only view</p>
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

        {/* KPIs */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          <KpiCard label="Users in Network" value={stats?.total_users ?? 0} sub="anonymous members" />
          <KpiCard label="Token A Issued" value={stats?.total_tokens_a_issued ?? 0} sub="real Flux 1 only" accent="text-green-600" />
          <KpiCard label="Token B Issued" value={stats?.total_tokens_b_issued ?? 0} sub="after exchange" accent="text-orange-500" />
          <KpiCard label="Token B Spent" value={stats?.total_tokens_b_spent ?? 0} sub="KYC retrievals" accent="text-red-500" />
          <KpiCard label="ZKP Proofs" value={zkpRequests.length} sub="anonymous age / nationality" accent="text-purple-600" />
        </div>

        {/* Token Flow */}
        <section>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Token Flow</h2>
          <div className="bg-white border border-neutral-200 rounded-lg p-6 space-y-4">
            <TokenFlowBar issued={stats?.total_tokens_a_issued ?? 0} burned={stats?.total_tokens_a_burned ?? 0} label="Token A — issued / exchanged for B" />
            <TokenFlowBar issued={stats?.total_tokens_b_issued ?? 0} burned={stats?.total_tokens_b_spent ?? 0} label="Token B — issued / spent on KYC" />
            <div className="pt-4 border-t border-neutral-100 grid grid-cols-3 text-xs text-center gap-4">
              <div><p className="text-neutral-400">Exchange Rate</p><p className="text-neutral-900 font-bold text-2xl mt-1">1 A = {stats?.exchange_rate ?? "?"} B</p></div>
              <div><p className="text-neutral-400">Total Ops</p><p className="text-neutral-900 font-bold text-2xl mt-1">{requests.length}</p></div>
              <div><p className="text-neutral-400">Network Size</p><p className="text-neutral-900 font-bold text-2xl mt-1">{users.length}</p></div>
            </div>
          </div>
        </section>

        {/* Partner Clients — split by type */}
        <section>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Partner Clients ({clients.length})</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white border border-neutral-200 rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <span className="w-2 h-2 rounded-full bg-blue-400" />
                <h3 className="text-xs font-semibold text-neutral-700 uppercase tracking-wide">Full KYC</h3>
                <span className="text-[10px] text-blue-500 ml-auto">{fullKycClients.length} sites</span>
              </div>
              <p className="text-[10px] text-neutral-400 mb-3">Receives full user profile after Flux 3. Consumes Token B.</p>
              <ClientList clients={fullKycClients} type="FULL_KYC" />
            </div>
            <div className="bg-white border border-neutral-200 rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <span className="w-2 h-2 rounded-full bg-purple-400" />
                <h3 className="text-xs font-semibold text-neutral-700 uppercase tracking-wide">ZKP Only</h3>
                <span className="text-[10px] text-purple-500 ml-auto">{zkpClients.length} sites · {zkpRequests.length} proofs</span>
              </div>
              <p className="text-[10px] text-neutral-400 mb-3">Receives only a zero-knowledge proof (age ≥ threshold, nationality). No personal data shared.</p>
              <ClientList clients={zkpClients} type="ZKP_ONLY" />
            </div>
          </div>
          <p className="text-xs text-neutral-400 mt-3 leading-relaxed">
            Sauron is blind — it cannot see which site holds which tokens. Token A/B balances exist only in each site&apos;s local wallet.
          </p>
        </section>

        {/* ZKP Connections */}
        <section>
          <div className="flex items-center gap-3 mb-4">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-400">ZKP Connections</h2>
            <span className="text-[10px] bg-purple-50 text-purple-600 border border-purple-200 px-2 py-0.5 rounded font-mono">{zkpRequests.length} proofs verified</span>
          </div>
          {zkpRequests.length === 0 ? (
            <div className="bg-white border border-neutral-200 rounded-lg p-8 text-center">
              <p className="text-neutral-400 italic text-sm">No ZKP connections yet.</p>
              <p className="text-xs text-neutral-300 mt-1">ZKP_ONLY sites (Discord, Tinder, Airbnb…) will appear here when users prove age or nationality anonymously.</p>
            </div>
          ) : (
            <div className="flex flex-col gap-2 max-h-[320px] overflow-y-auto pr-1">
              {zkpRequests.map((r) => <ZkpConnectionCard key={r.id} req={r} />)}
            </div>
          )}
        </section>

        {/* Users + Full Request Log */}
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
              ? <div className="bg-white border border-neutral-200 rounded-lg p-6 text-neutral-400 italic text-sm">No requests yet.</div>
              : <div className="flex flex-col gap-2 max-h-[420px] overflow-y-auto pr-1">{requests.map((r) => <RequestCard key={r.id} req={r} />)}</div>
            }
          </section>
        </div>

      </div>
    </div>
  );
}