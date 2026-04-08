"use client";

import { useState, useEffect, useCallback } from "react";
import { useClient, API, type Client, type ClientUser } from "../context/ClientContext";
import { showToast } from "../components/Toast";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

type Tab = "dashboard" | "users" | "link" | "agents";

// ─── KPI Card ─────────────────────────────────────────────────────────────────
function KpiCard({ label, value, sub, accent }: { label: string; value: number | string; sub?: string; accent?: string }) {
  return (
    <div className="bg-white border border-neutral-200 rounded-lg p-5 flex flex-col gap-1">
      <span className="text-xs uppercase tracking-widest text-neutral-400">{label}</span>
      <span className={`text-3xl font-bold tabular-nums ${accent ?? "text-neutral-900"}`}>{value}</span>
      {sub && <span className="text-xs text-neutral-400">{sub}</span>}
    </div>
  );
}

// ─── Success Overlay ──────────────────────────────────────────────────────────
function SuccessOverlay({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-6">
      <div className="bg-white border border-neutral-200 rounded-xl p-8 max-w-md w-full shadow-xl">
        <h2 className="text-base font-bold text-neutral-900 mb-6">{title}</h2>
        {children}
        <button onClick={onClose} className="mt-6 w-full border border-neutral-200 hover:border-neutral-400 text-neutral-700 py-2.5 rounded-lg transition-colors text-sm">Close</button>
      </div>
    </div>
  );
}


// ─── Bank Dashboard ───────────────────────────────────────────────────────────
function BankDashboard({ client }: { client: Client }) {
  const [userCount, setUserCount] = useState<number | null>(null);

  useEffect(() => {
    fetch(`${API}/dev/client/${encodeURIComponent(client.name)}/users`)
      .then((r) => r.json())
      .then((data: ClientUser[]) => setUserCount(data.filter((u) => u.source === "register").length))
      .catch(() => setUserCount(0));
  }, [client.name]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard label="Users Enrolled" value={userCount ?? "…"} sub="KYC committed to Sauron" accent="text-amber-600" />
        <KpiCard label="Client Type" value="BANK" sub="free KYC submission" accent="text-amber-600" />
        <KpiCard label="Cost per Submission" value="Free" sub="banks are not charged" accent="text-green-600" />
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 text-xs text-amber-800 space-y-1">
        <p className="font-semibold">How it works</p>
        <p>Your bank submits user KYC data to Sauron for free. The user&apos;s identity is cryptographically committed to the network and can be retrieved anonymously by authorised retail sites — with the user&apos;s consent via zero-knowledge proof.</p>
      </div>

      <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-4 text-xs text-neutral-500 space-y-1">
        <p><span className="font-semibold text-neutral-700">Public Key:</span> <span className="font-mono text-[10px]">{client.public_key_hex.slice(0, 16)}…{client.public_key_hex.slice(-8)}</span></p>
        <p><span className="font-semibold text-neutral-700">Key Image:</span> <span className="font-mono text-[10px]">{client.key_image_hex.slice(0, 16)}…{client.key_image_hex.slice(-8)}</span></p>
      </div>
    </div>
  );
}

// ─── Bank Users Tab ───────────────────────────────────────────────────────────
function BankUsersTab({ client }: { client: Client }) {
  const [users, setUsers] = useState<ClientUser[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetch(`${API}/dev/client/${encodeURIComponent(client.name)}/users`);
      if (res.ok) setUsers(await res.json());
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [client.name]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  if (loading) return <div className="text-center py-12 text-neutral-400 animate-pulse text-sm">Loading users…</div>;

  const registered = users.filter((u) => u.source === "register");

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <KpiCard label="Users Enrolled" value={registered.length} sub="KYC submitted by this bank" accent="text-amber-600" />
        <KpiCard label="Total Interactions" value={users.length} sub="all user touchpoints" />
      </div>

      {registered.length === 0 ? (
        <div className="bg-white border border-neutral-200 rounded-lg p-8 text-center">
          <p className="text-neutral-400 italic text-sm">No users enrolled yet.</p>
          <p className="text-xs text-neutral-300 mt-1">Use the Register tab to enrol a user.</p>
        </div>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {registered.map((u, i) => (
            <div key={i} className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full flex-shrink-0 bg-amber-400" />
                <div>
                  <p className="text-sm font-semibold text-neutral-900">{u.first_name} {u.last_name}</p>
                  <p className="text-xs text-neutral-500">{u.email} · {u.nationality}</p>
                </div>
              </div>
              <span className="text-[10px] text-neutral-400 font-mono">{fmt(u.timestamp)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Link Customer Tab ────────────────────────────────────────────────────────
// The bank already has the customer's KYC from their own onboarding.
// This form simply attests those verified attributes to Sauron.
// No camera, no document scanning needed.
function LinkCustomerTab({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [form, setForm] = useState({
    email: "", password: "",
    first_name: "", last_name: "",
    date_of_birth: "", nationality: "FRA",
  });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ first_name: string; last_name: string } | null>(null);
  const [error, setError] = useState("");

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm((p) => ({ ...p, [k]: e.target.value }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      const res = await fetch(`${API}/dev/register_user`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          site_name: client.name,
          email: form.email,
          password: form.password,
          first_name: form.first_name,
          last_name: form.last_name,
          date_of_birth: form.date_of_birth,
          nationality: form.nationality.toUpperCase(),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Linking failed");
      setResult({ first_name: form.first_name, last_name: form.last_name });
      setForm({ email: "", password: "", first_name: "", last_name: "", date_of_birth: "", nationality: "FRA" });
      showToast("success", `${client.name}: customer linked`, `${form.first_name} ${form.last_name} is now on SauronID.`);
      await refreshActiveClient();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "Link failed", msg);
    } finally { setBusy(false); }
  };

  const ready = form.email && form.password && form.first_name && form.last_name && form.date_of_birth && form.nationality;

  return (
    <>
      {result && (
        <SuccessOverlay title="Customer Linked" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
              <p className="text-amber-700 font-semibold mb-1">{result.first_name} {result.last_name} is now on SauronID</p>
              <p className="text-neutral-500 text-xs">
                The customer can now use SauronID to authenticate on any partner site with a ZKP — no PII is ever shared with third parties.
              </p>
            </div>
            <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} attested the customer&apos;s identity to Sauron at no cost. Ring signature committed on-chain.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <div className="max-w-lg mx-auto space-y-5">
        {/* Explainer */}
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 text-xs text-amber-800 space-y-1">
          <p className="font-semibold">How linking works</p>
          <ol className="list-decimal list-inside space-y-1 text-amber-700">
            <li>Your bank already holds verified KYC for this customer</li>
            <li>Enter their details below — {client.name} signs the commitment with a ring signature</li>
            <li>The customer gets a SauronID credential derived from your attestation</li>
            <li>They can now ZKP-authenticate on retail sites — their data never leaves Sauron</li>
          </ol>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-500 mb-1 block">First name</label>
              <input value={form.first_name} onChange={set("first_name")} required placeholder="Alice"
                className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-amber-400" />
            </div>
            <div>
              <label className="text-xs text-neutral-500 mb-1 block">Last name</label>
              <input value={form.last_name} onChange={set("last_name")} required placeholder="Dupont"
                className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-amber-400" />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-500 mb-1 block">Date of birth</label>
              <input type="date" value={form.date_of_birth} onChange={set("date_of_birth")} required
                className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-amber-400" />
            </div>
            <div>
              <label className="text-xs text-neutral-500 mb-1 block">Nationality (ISO 3)</label>
              <input value={form.nationality} onChange={set("nationality")} maxLength={3} placeholder="FRA"
                className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm uppercase focus:outline-none focus:border-amber-400" />
            </div>
          </div>

          <div className="border-t border-neutral-100 pt-4 space-y-3">
            <p className="text-xs text-neutral-500 font-medium">Customer SauronID credentials</p>
            <p className="text-xs text-neutral-400">
              The customer will use these to log in on retail sites via the SauronID consent popup.
            </p>
            <div>
              <label className="text-xs text-neutral-500 mb-1 block">Email</label>
              <input type="email" value={form.email} onChange={set("email")} required placeholder="alice@example.com"
                className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-amber-400" />
            </div>
            <div>
              <label className="text-xs text-neutral-500 mb-1 block">Password</label>
              <input type="password" value={form.password} onChange={set("password")} required placeholder="••••••••"
                className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-amber-400" />
            </div>
          </div>

          {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

          <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-3 text-xs text-neutral-400">
            Password blinded via OPRF — {client.name} signs the registration with a ring signature — KYC committed to Sauron at no cost.
          </div>

          <button type="submit" disabled={busy || !ready}
            className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${!ready || busy
                ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
                : "bg-amber-500 text-white border-amber-500 hover:bg-amber-600"
              }`}>
            {busy ? "Linking..." : `Link customer to SauronID via ${client.name}`}
          </button>
        </form>
      </div>
    </>
  );
}

// ─── Agents Tab ───────────────────────────────────────────────────────────────
interface AgentRecord {
  agent_id: string;
  human_key_image: string;
  agent_checksum: string;
  intent_json: string;
  issued_at: number;
  expires_at: number;
  revoked: boolean;
}

function AgentsTab(_: { client: Client }) {
  const [humanKeyImage, setHumanKeyImage] = useState("");
  const [humanSession, setHumanSession] = useState("");
  const [agentChecksum, setAgentChecksum] = useState("");
  const [intentJson, setIntentJson] = useState('{"action":"kyc_lookup","resource":"sauron_api"}');
  const [ttl, setTtl] = useState("3600");
  const [busy, setBusy] = useState(false);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState<{ agent_id: string; ajwt: string } | null>(null);

  const register = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    setError(""); setSuccess(null);
    if (!humanSession || !humanKeyImage || !agentChecksum) {
      setError("x-sauron-session, human_key_image and agent_checksum required");
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${API}/agent/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-sauron-session": humanSession },
        body: JSON.stringify({
          human_key_image: humanKeyImage,
          agent_checksum: agentChecksum,
          intent_json: intentJson,
          ttl_secs: parseInt(ttl, 10) || 3600,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Agent registration failed");
      setSuccess({ agent_id: data.agent_id, ajwt: data.ajwt });
      showToast("success", "Agent registered", `agent_id: ${data.agent_id}`);
      if (humanKeyImage) loadAgents(humanKeyImage);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setError(msg); showToast("error", "Registration failed", msg);
    } finally { setBusy(false); }
  };

  const loadAgents = async (ki: string) => {
    if (!ki || !humanSession) return;
    try {
      const res = await fetch(`${API}/agent/list/${encodeURIComponent(ki)}`, {
        headers: { "x-sauron-session": humanSession },
      });
      if (res.ok) setAgents(await res.json());
    } catch { /* ignore */ }
  };

  const revoke = async (agentId: string) => {
    if (!humanSession || !humanKeyImage) return;
    try {
      const res = await fetch(`${API}/agent/${encodeURIComponent(agentId)}`, {
        method: "DELETE",
        headers: { "x-sauron-session": humanSession },
      });
      if (res.ok) {
        showToast("success", "Agent revoked", agentId);
        loadAgents(humanKeyImage);
      }
    } catch { /* ignore */ }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-neutral-900 mb-1">Register an AI Agent</h2>
        <p className="text-xs text-neutral-500">
          An A-JWT (Agentic JWT) allows an AI agent to call the Sauron API on behalf of a registered user.
          The token encodes the agent checksum and intent so any drift is immediately detectable.
        </p>
      </div>

      <form onSubmit={register} className="space-y-4 max-w-xl">
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">User session token (x-sauron-session)</label>
          <textarea value={humanSession} onChange={(e) => setHumanSession(e.target.value)} rows={2}
            placeholder="Paste session from /user/auth"
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-xs font-mono focus:outline-none focus:border-neutral-500" />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Human key_image_hex</label>
          <input value={humanKeyImage} onChange={(e) => setHumanKeyImage(e.target.value)}
            onBlur={() => loadAgents(humanKeyImage)}
            placeholder="64-char hex from /dev/register_user response"
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-xs font-mono focus:outline-none focus:border-neutral-500" />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Agent checksum (SHA-256 of agent config)</label>
          <input value={agentChecksum} onChange={(e) => setAgentChecksum(e.target.value)}
            placeholder="sha256 hex"
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-xs font-mono focus:outline-none focus:border-neutral-500" />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Intent JSON</label>
          <textarea value={intentJson} onChange={(e) => setIntentJson(e.target.value)} rows={3}
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-xs font-mono focus:outline-none focus:border-neutral-500" />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">TTL (seconds)</label>
          <input type="number" value={ttl} onChange={(e) => setTtl(e.target.value)} min={60} max={86400}
            className="w-32 bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" />
        </div>

        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button type="submit" disabled={busy}
          className={`py-2.5 px-6 rounded-lg font-semibold text-sm border ${busy
            ? "border-neutral-200 text-neutral-400 cursor-not-allowed"
            : "bg-amber-500 text-white border-amber-500 hover:bg-amber-600"}`}>
          {busy ? "Registering..." : "Register Agent"}
        </button>
      </form>

      {success && (
        <div className="border border-green-200 bg-green-50 rounded-lg p-4 space-y-2">
          <p className="text-xs font-semibold text-green-800">Agent registered successfully</p>
          <p className="text-xs text-neutral-600">agent_id: <span className="font-mono">{success.agent_id}</span></p>
          <div>
            <p className="text-xs text-neutral-500 mb-1">A-JWT (pass this in x-agent-jwt header):</p>
            <textarea readOnly value={success.ajwt} rows={4}
              className="w-full bg-white border border-neutral-200 rounded text-xs font-mono p-2 resize-none" />
          </div>
        </div>
      )}

      {agents.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-neutral-800 mb-3">Agents for this user</h3>
          <div className="space-y-2">
            {agents.map((a) => (
              <div key={a.agent_id} className={`border rounded-lg p-3 flex items-start justify-between gap-4 ${a.revoked ? "border-red-200 bg-red-50" : "border-neutral-200 bg-white"}`}>
                <div className="space-y-0.5 min-w-0">
                  <p className="text-xs font-mono text-neutral-700 truncate">{a.agent_id}</p>
                  <p className="text-xs text-neutral-500">checksum: <span className="font-mono">{a.agent_checksum.slice(0, 16)}...</span></p>
                  <p className="text-xs text-neutral-400">expires: {new Date(a.expires_at * 1000).toLocaleString()}</p>
                  {a.revoked && <span className="text-xs text-red-600 font-semibold">REVOKED</span>}
                </div>
                {!a.revoked && (
                  <button onClick={() => revoke(a.agent_id)}
                    className="text-xs text-red-500 border border-red-200 rounded px-2 py-1 hover:bg-red-50 whitespace-nowrap shrink-0">
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Bank Portal Page ────────────────────────────────────────────────────
export default function BankPortal() {
  const { clients, activeClient, loading, offline } = useClient();
  const [tab, setTab] = useState<Tab>("dashboard");

  const bankClients = clients.filter((c) => c.client_type === "BANK");
  const client: Client | null = activeClient?.client_type === "BANK" ? activeClient : bankClients[0] ?? null;

  if (loading) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="animate-pulse text-sm">Connecting to Sauron…</span></div>;
  if (offline) return <div className="flex min-h-[80vh] items-center justify-center"><span className="text-red-600 text-sm border border-red-200 bg-red-50 px-4 py-2 rounded-lg">Backend offline — start the Sauron core on port 3001</span></div>;
  if (!client) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="text-sm">No bank clients found. Add a BANK client via the admin API.</span></div>;

  const tabs: { key: Tab; label: string }[] = [
    { key: "dashboard", label: "Dashboard" },
    { key: "users", label: "Linked Customers" },
    { key: "link", label: "Link Customer" },
    { key: "agents", label: "AI Agents" },
  ];

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900">
      {/* Tab bar */}
      <div className="bg-white border-b border-neutral-200">
        <div className="max-w-[1200px] mx-auto px-6 flex items-center gap-1">
          {tabs.map((t) => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-all ${tab === t.key
                  ? "border-amber-500 text-amber-700"
                  : "border-transparent text-neutral-400 hover:text-neutral-700"
                }`}>
              {t.label}
            </button>
          ))}
          <div className="flex-1" />
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-amber-50 text-amber-700 border-amber-200">BANK</span>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-[1200px] mx-auto px-6 py-8">
        {tab === "dashboard" && <BankDashboard client={client} />}
        {tab === "users" && <BankUsersTab client={client} />}
        {tab === "link" && <LinkCustomerTab client={client} />}
        {tab === "agents" && <AgentsTab client={client} />}
      </div>
    </div>
  );
}
