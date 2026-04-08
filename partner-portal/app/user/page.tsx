"use client";

/**
 * SauronID User Portal
 * End-user self-service: view & revoke consents, manage agents.
 * Consumer-facing — clean white design.
 */

import React, { useState, useEffect, useCallback } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

// ── Types ─────────────────────────────────────────────────────────────────────

interface UserSession {
  session: string;
  key_image: string;
  first_name: string;
  last_name: string;
  expires_at: number;
}

interface Consent {
  request_id: string;
  site_name: string;
  granted_at: number;
  used: boolean;
  revoked: boolean;
}

interface Agent {
  agent_id: string;
  agent_checksum: string;
  intent_json: string;
  issued_at: number;
  expires_at: number;
  revoked: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function ts(unix: number) {
  return new Date(unix * 1000).toLocaleString();
}

function authHeaders(session: string) {
  return { "x-sauron-session": session };
}

// ── Login screen ──────────────────────────────────────────────────────────────

function LoginScreen({ onLogin }: { onLogin: (s: UserSession) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!email || !password) { setError("Enter email and password."); return; }
    setLoading(true); setError("");
    try {
      const res = await fetch("/api/user/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Authentication failed");
      onLogin(data as UserSession);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.loginWrap}>
      <div style={styles.loginCard}>
        <div style={styles.logo}>
          <div style={styles.logoDot} />
          <span style={styles.logoText}>SauronID</span>
        </div>
        <p style={styles.loginSub}>Your identity, your control.</p>
        <div style={styles.field}>
          <label style={styles.label}>Email</label>
          <input
            style={styles.input}
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            onKeyDown={e => e.key === "Enter" && submit()}
            placeholder="you@example.com"
            disabled={loading}
          />
        </div>
        <div style={styles.field}>
          <label style={styles.label}>Password</label>
          <input
            style={styles.input}
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === "Enter" && submit()}
            placeholder="••••••••"
            disabled={loading}
          />
        </div>
        {error && <p style={styles.err}>{error}</p>}
        <button style={styles.primaryBtn} onClick={submit} disabled={loading}>
          {loading ? "Signing in..." : "Sign in"}
        </button>
        <p style={styles.hint}>
          Don&apos;t have an account?{" "}
          <a href="/" style={styles.link}>Register via a partner site</a>
        </p>
      </div>
    </div>
  );
}

// ── Consents tab ──────────────────────────────────────────────────────────────

function ConsentsTab({ session }: { session: UserSession }) {
  const [consents, setConsents] = useState<Consent[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/user/consents", {
        headers: authHeaders(session.session),
      });
      const data = await res.json();
      setConsents(data.consents || []);
    } finally {
      setLoading(false);
    }
  }, [session]);

  useEffect(() => { load(); }, [load]);

  const revoke = async (request_id: string) => {
    setRevoking(request_id);
    try {
      await fetch(`/api/user/revoke/${encodeURIComponent(request_id)}`, {
        method: "DELETE",
        headers: authHeaders(session.session),
      });
      await load();
    } finally {
      setRevoking(null);
    }
  };

  if (loading) return <div style={styles.loading}>Loading consents...</div>;

  const active = consents.filter(c => !c.revoked);
  const revoked = consents.filter(c => c.revoked);

  return (
    <div>
      <div style={styles.sectionHead}>
        <h2 style={styles.sectionTitle}>Active consents <span style={styles.badge}>{active.length}</span></h2>
        <p style={styles.sectionSub}>Sites that have received your verified data. Revoke access at any time.</p>
      </div>
      {active.length === 0 && (
        <div style={styles.empty}>No active consents yet. Visit a SauronID-enabled site to get started.</div>
      )}
      {active.map(c => (
        <div key={c.request_id} style={styles.card}>
          <div style={styles.cardRow}>
            <div>
              <div style={styles.siteName}>{c.site_name}</div>
              <div style={styles.meta}>Granted {ts(c.granted_at)}</div>
              <div style={{ marginTop: 4, display: "flex", gap: 8 }}>
                {c.used && <span style={styles.tagGreen}>Data accessed</span>}
              </div>
            </div>
            <button
              style={styles.revokeBtn}
              onClick={() => revoke(c.request_id)}
              disabled={revoking === c.request_id}
            >
              {revoking === c.request_id ? "Revoking..." : "Revoke"}
            </button>
          </div>
        </div>
      ))}
      {revoked.length > 0 && (
        <>
          <h3 style={{ ...styles.sectionTitle, marginTop: 32, opacity: 0.5, fontSize: 14 }}>
            Revoked ({revoked.length})
          </h3>
          {revoked.map(c => (
            <div key={c.request_id} style={{ ...styles.card, opacity: 0.45 }}>
              <div style={styles.siteName}>{c.site_name}</div>
              <div style={styles.meta}>Revoked — was granted {ts(c.granted_at)}</div>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ── Agents tab ────────────────────────────────────────────────────────────────

function AgentsTab({ session }: { session: UserSession }) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [intent, setIntent] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [newAgent, setNewAgent] = useState<{ agent_id: string; token: string } | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/agent/list/${session.key_image}`, {
        headers: authHeaders(session.session),
      });
      const data = await res.json();
      setAgents(data.agents || []);
    } finally {
      setLoading(false);
    }
  }, [session.key_image]);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!intent.trim()) { setError("Describe what the agent is allowed to do."); return; }
    setCreating(true); setError(""); setNewAgent(null);
    try {
      const res = await fetch(`${API_BASE}/agent/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders(session.session) },
        body: JSON.stringify({
          human_key_image: session.key_image,
          intent: intent.trim(),
          description: description.trim() || intent.trim(),
          ttl_hours: 24,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to create agent");
      setNewAgent({ agent_id: data.agent_id, token: data.agent_token || "" });
      setIntent(""); setDescription("");
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (agent_id: string) => {
    setRevoking(agent_id);
    try {
      await fetch(`${API_BASE}/agent/${agent_id}`, {
        method: "DELETE",
        headers: authHeaders(session.session),
      });
      await load();
    } finally {
      setRevoking(null);
    }
  };

  const active = agents.filter(a => !a.revoked);
  const inactive = agents.filter(a => a.revoked);
  const now = Math.floor(Date.now() / 1000);

  return (
    <div>
      <div style={styles.sectionHead}>
        <h2 style={styles.sectionTitle}>AI Agents <span style={styles.badge}>{active.length}</span></h2>
        <p style={styles.sectionSub}>
          Delegate identity operations to trusted AI agents. Each agent gets a scoped token — revoke anytime.
        </p>
      </div>

      {/* Create agent */}
      <div style={styles.createBox}>
        <h3 style={styles.createTitle}>Delegate to a new agent</h3>
        <div style={styles.field}>
          <label style={styles.label}>What is this agent allowed to do?</label>
          <textarea
            style={{ ...styles.input, height: 72, resize: "none" }}
            value={intent}
            onChange={e => setIntent(e.target.value)}
            placeholder="e.g. Book flights on my behalf, access nationality and age proofs only"
          />
        </div>
        <div style={styles.field}>
          <label style={styles.label}>Agent name / description (optional)</label>
          <input
            style={styles.input}
            value={description}
            onChange={e => setDescription(e.target.value)}
            placeholder="e.g. Travel booking assistant"
          />
        </div>
        {error && <p style={styles.err}>{error}</p>}
        <button style={styles.primaryBtn} onClick={create} disabled={creating}>
          {creating ? "Creating..." : "Create agent"}
        </button>
      </div>

      {newAgent && (
        <div style={styles.successBox}>
          <div style={{ fontWeight: 600, marginBottom: 8 }}>Agent created</div>
          <div style={styles.meta}>ID: <code style={styles.code}>{newAgent.agent_id}</code></div>
          {newAgent.token && (
            <div style={{ marginTop: 8 }}>
              <div style={styles.meta}>A-JWT token (share with your agent):</div>
              <textarea
                readOnly
                style={{ ...styles.input, marginTop: 4, height: 80, fontSize: 11, fontFamily: "monospace" }}
                value={newAgent.token}
              />
            </div>
          )}
        </div>
      )}

      {loading ? (
        <div style={styles.loading}>Loading agents...</div>
      ) : active.length === 0 ? (
        <div style={styles.empty}>No active agents. Create one above.</div>
      ) : (
        active.map(a => {
          const expired = a.expires_at < now;
          return (
            <div key={a.agent_id} style={{ ...styles.card, opacity: expired ? 0.5 : 1 }}>
              <div style={styles.cardRow}>
                <div style={{ flex: 1 }}>
                  <div style={styles.siteName}>
                    {(() => { try { return JSON.parse(a.intent_json).description || a.agent_id.slice(0, 16); } catch { return a.agent_id.slice(0, 16); } })()}
                    {expired && <span style={{ ...styles.tagRed, marginLeft: 8 }}>Expired</span>}
                  </div>
                  <div style={styles.meta}>
                    ID: {a.agent_id.slice(0, 20)}...
                    &nbsp;·&nbsp;
                    {expired ? "Expired" : "Expires"} {ts(a.expires_at)}
                  </div>
                  <div style={{ marginTop: 4 }}>
                    <span style={{ ...styles.tagGrey, fontFamily: "monospace", fontSize: 11 }}>
                      {a.agent_checksum.slice(0, 16)}
                    </span>
                  </div>
                </div>
                <button
                  style={styles.revokeBtn}
                  onClick={() => revoke(a.agent_id)}
                  disabled={revoking === a.agent_id}
                >
                  {revoking === a.agent_id ? "Revoking..." : "Revoke"}
                </button>
              </div>
            </div>
          );
        })
      )}

      {inactive.length > 0 && (
        <p style={{ ...styles.meta, marginTop: 24 }}>+ {inactive.length} revoked agent(s)</p>
      )}
    </div>
  );
}

// ── Privacy tab ───────────────────────────────────────────────────────────────

function PrivacyTab({ session }: { session: UserSession }) {
  return (
    <div>
      <div style={styles.sectionHead}>
        <h2 style={styles.sectionTitle}>How your data is protected</h2>
      </div>
      <div style={styles.card}>
        <div style={{ display: "grid", gap: 20 }}>
          {[
            ["Zero-knowledge proofs", "Sites receive mathematical proofs (e.g. 'age ≥ 18', 'EU citizen') — never your actual date of birth or passport number."],
            ["Ring signatures", "Your activity is unlinkable across sites. No site can track you or correlate your logins with other sites."],
            ["You control consent", "Every site access requires your explicit approval. You can revoke it here at any time."],
            ["Bank-attested data", "Your identity was verified by your bank. SauronID doesn't store raw documents — only cryptographic commitments."],
            ["Agent isolation", "AI agents you create get scoped tokens with limited permissions. They cannot access more than you explicitly allow."],
          ].map(([title, desc]) => (
            <div key={title} style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#6366f1", marginTop: 6, flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: 14, color: "#0f172a", marginBottom: 4 }}>{title}</div>
                <div style={{ fontSize: 13, color: "#64748b", lineHeight: 1.6 }}>{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div style={styles.card}>
        <div style={{ fontWeight: 600, fontSize: 14, color: "#0f172a", marginBottom: 8 }}>Your identity key</div>
        <div style={styles.meta}>This is your anonymous identifier — derived from your credentials, never reversible.</div>
        <code style={{ ...styles.code, display: "block", marginTop: 8, wordBreak: "break-all", fontSize: 11 }}>
          {session.key_image}
        </code>
      </div>
    </div>
  );
}

// ── Dashboard shell ───────────────────────────────────────────────────────────

type Tab = "consents" | "agents" | "privacy";

function Dashboard({ session, onLogout }: { session: UserSession; onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>("consents");

  return (
    <div style={styles.dashWrap}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <div style={styles.logo}>
            <div style={styles.logoDot} />
            <span style={styles.logoText}>SauronID</span>
          </div>
        </div>
        <div style={styles.headerRight}>
          <span style={styles.userName}>
            {session.first_name || "User"} {session.last_name || ""}
          </span>
          <button style={styles.logoutBtn} onClick={onLogout}>Sign out</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={styles.tabs}>
        {(["consents", "agents", "privacy"] as Tab[]).map(t => (
          <button
            key={t}
            style={{ ...styles.tab, ...(tab === t ? styles.tabActive : {}) }}
            onClick={() => setTab(t)}
          >
            {t === "consents" ? "Consents" : t === "agents" ? "AI Agents" : "Privacy"}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={styles.content}>
        {tab === "consents" && <ConsentsTab session={session} />}
        {tab === "agents" && <AgentsTab session={session} />}
        {tab === "privacy" && <PrivacyTab session={session} />}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function UserPage() {
  const [session, setSession] = useState<UserSession | null>(null);

  const logout = () => setSession(null);

  if (!session) return <LoginScreen onLogin={setSession} />;
  return <Dashboard session={session} onLogout={logout} />;
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles: Record<string, React.CSSProperties> = {
  loginWrap: {
    minHeight: "100vh",
    background: "#f8fafc",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontFamily: "system-ui, -apple-system, sans-serif",
  },
  loginCard: {
    background: "#fff",
    border: "1px solid #e2e8f0",
    borderRadius: 16,
    padding: "40px 44px",
    width: 400,
    maxWidth: "92vw",
    boxShadow: "0 4px 24px rgba(0,0,0,0.06)",
  },
  logo: { display: "flex", alignItems: "center", gap: 10, marginBottom: 4 },
  logoDot: { width: 28, height: 28, borderRadius: "50%", background: "linear-gradient(135deg,#6366f1,#8b5cf6)", flexShrink: 0 },
  logoText: { fontSize: 20, fontWeight: 700, color: "#0f172a", letterSpacing: -0.5 },
  loginSub: { fontSize: 14, color: "#64748b", marginBottom: 28, marginTop: 2 },
  field: { marginBottom: 16 },
  label: { display: "block", fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 6 },
  input: {
    width: "100%",
    padding: "10px 12px",
    border: "1px solid #d1d5db",
    borderRadius: 8,
    fontSize: 14,
    color: "#0f172a",
    background: "#fff",
    boxSizing: "border-box",
    outline: "none",
  } as React.CSSProperties,
  err: { color: "#ef4444", fontSize: 13, marginBottom: 12 },
  primaryBtn: {
    width: "100%",
    padding: "11px 0",
    background: "#6366f1",
    color: "#fff",
    border: "none",
    borderRadius: 9,
    fontSize: 15,
    fontWeight: 600,
    cursor: "pointer",
    marginTop: 4,
  } as React.CSSProperties,
  hint: { fontSize: 13, color: "#94a3b8", textAlign: "center", marginTop: 16 },
  link: { color: "#6366f1", textDecoration: "none" },

  dashWrap: { minHeight: "100vh", background: "#f8fafc", fontFamily: "system-ui, -apple-system, sans-serif" },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "0 32px",
    height: 60,
    background: "#fff",
    borderBottom: "1px solid #e2e8f0",
  },
  headerLeft: { display: "flex", alignItems: "center", gap: 16 },
  headerRight: { display: "flex", alignItems: "center", gap: 16 },
  userName: { fontSize: 14, color: "#374151", fontWeight: 500 },
  logoutBtn: {
    padding: "6px 14px",
    border: "1px solid #d1d5db",
    borderRadius: 8,
    background: "#fff",
    color: "#374151",
    fontSize: 13,
    cursor: "pointer",
  } as React.CSSProperties,

  tabs: { display: "flex", padding: "0 32px", borderBottom: "1px solid #e2e8f0", background: "#fff" },
  tab: {
    padding: "14px 20px",
    border: "none",
    background: "none",
    fontSize: 14,
    color: "#64748b",
    cursor: "pointer",
    borderBottom: "2px solid transparent",
    fontWeight: 500,
  } as React.CSSProperties,
  tabActive: { color: "#6366f1", borderBottom: "2px solid #6366f1" },

  content: { maxWidth: 720, margin: "0 auto", padding: "32px 20px" },
  sectionHead: { marginBottom: 20 },
  sectionTitle: { fontSize: 18, fontWeight: 700, color: "#0f172a", margin: 0, display: "flex", alignItems: "center", gap: 8 },
  sectionSub: { fontSize: 13, color: "#64748b", marginTop: 4 },
  badge: {
    display: "inline-flex",
    alignItems: "center",
    padding: "2px 8px",
    background: "#ede9fe",
    color: "#6d28d9",
    borderRadius: 12,
    fontSize: 12,
    fontWeight: 600,
  } as React.CSSProperties,

  card: {
    background: "#fff",
    border: "1px solid #e2e8f0",
    borderRadius: 12,
    padding: "16px 20px",
    marginBottom: 12,
  },
  cardRow: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 },
  siteName: { fontSize: 15, fontWeight: 600, color: "#0f172a", marginBottom: 4 },
  meta: { fontSize: 12, color: "#94a3b8" },
  tagGreen: { display: "inline-block", padding: "2px 8px", background: "#f0fdf4", color: "#166534", borderRadius: 10, fontSize: 11, fontWeight: 500 },
  tagRed: { display: "inline-block", padding: "2px 8px", background: "#fef2f2", color: "#991b1b", borderRadius: 10, fontSize: 11, fontWeight: 500 },
  tagGrey: { display: "inline-block", padding: "2px 8px", background: "#f1f5f9", color: "#64748b", borderRadius: 10, fontSize: 11 },
  revokeBtn: {
    padding: "6px 14px",
    border: "1px solid #fca5a5",
    borderRadius: 8,
    background: "#fff",
    color: "#ef4444",
    fontSize: 13,
    cursor: "pointer",
    whiteSpace: "nowrap",
    flexShrink: 0,
  } as React.CSSProperties,

  loading: { color: "#94a3b8", fontSize: 14, padding: "20px 0" },
  empty: { color: "#94a3b8", fontSize: 14, textAlign: "center", padding: "40px 0" },

  createBox: {
    background: "#fafafa",
    border: "1px dashed #d1d5db",
    borderRadius: 12,
    padding: "20px 20px 16px",
    marginBottom: 24,
  },
  createTitle: { fontSize: 15, fontWeight: 600, color: "#0f172a", margin: "0 0 16px" },

  successBox: {
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
    fontSize: 13,
    color: "#166534",
  },
  code: {
    background: "#f1f5f9",
    padding: "2px 6px",
    borderRadius: 4,
    fontFamily: "monospace",
    fontSize: 12,
    color: "#334155",
  },
};
