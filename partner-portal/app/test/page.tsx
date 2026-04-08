"use client";

/**
 * SauronID Integration Test Suite
 * One page to test every flow: KYC, ZKP, KYA (bank + self-sovereign), ring verification.
 */

import React, { useState, useEffect, useCallback } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

// ── Helpers ───────────────────────────────────────────────────────────────────

async function post(url: string, body: unknown, headers?: Record<string, string>) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(headers || {}) },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}

async function get(url: string, headers?: Record<string, string>) {
  const r = await fetch(url, { headers });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}

function JsonBox({ data, label }: { data: unknown; label?: string }) {
  if (data === null || data === undefined) return null;
  const json = JSON.stringify(data, null, 2);
  const ok = typeof data === "object" && data !== null && !("error" in (data as any));
  return (
    <div style={{ marginTop: 10 }}>
      {label && <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>{label}</div>}
      <pre style={{
        background: ok ? "#0f2418" : "#200",
        border: `1px solid ${ok ? "#1a4731" : "#500"}`,
        borderRadius: 8,
        padding: "10px 14px",
        fontSize: 12,
        fontFamily: "monospace",
        color: ok ? "#86efac" : "#fca5a5",
        overflowX: "auto",
        maxHeight: 320,
        overflowY: "auto",
        margin: 0,
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
      }}>{json}</pre>
    </div>
  );
}

function Section({ title, children, color = "#6366f1" }: { title: string; children: React.ReactNode; color?: string }) {
  return (
    <div style={{
      background: "#0f172a",
      border: `1px solid ${color}33`,
      borderRadius: 12,
      padding: 20,
      marginBottom: 16,
    }}>
      <div style={{
        fontSize: 13,
        fontWeight: 700,
        color,
        textTransform: "uppercase",
        letterSpacing: 1,
        marginBottom: 16,
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}>
        <div style={{ width: 6, height: 6, borderRadius: "50%", background: color }} />
        {title}
      </div>
      {children}
    </div>
  );
}

function Field({ label, value, onChange, placeholder, type = "text", mono = false }: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; type?: string; mono?: boolean;
}) {
  return (
    <div style={{ marginBottom: 10 }}>
      <label style={{ display: "block", fontSize: 11, color: "#64748b", marginBottom: 4 }}>{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%",
          padding: "8px 10px",
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: 6,
          color: "#f1f5f9",
          fontSize: mono ? 12 : 13,
          fontFamily: mono ? "monospace" : "system-ui",
          boxSizing: "border-box",
          outline: "none",
        }}
      />
    </div>
  );
}

function Btn({ onClick, loading, children, color = "#6366f1", small = false }: {
  onClick: () => void; loading?: boolean; children: React.ReactNode; color?: string; small?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      style={{
        padding: small ? "6px 14px" : "9px 18px",
        background: loading ? "#334155" : color,
        color: "#fff",
        border: "none",
        borderRadius: 7,
        fontSize: small ? 12 : 13,
        fontWeight: 600,
        cursor: loading ? "not-allowed" : "pointer",
        opacity: loading ? 0.6 : 1,
        marginRight: 8,
        marginTop: 4,
      }}
    >{loading ? "..." : children}</button>
  );
}

// ── State per flow ────────────────────────────────────────────────────────────

type Result = { ok: boolean; data: unknown } | null;

export default function TestPage() {
  // Shared state — user session persists across flows
  const [session, setSession] = useState("");
  const [keyImage, setKeyImage] = useState("");
  const [publicKeyHex, setPublicKeyHex] = useState("");

  // ── Flow 0: Register user (dev) ───────────────────────────────────────────
  const [regEmail, setRegEmail] = useState("alice@test.com");
  const [regPass, setRegPass] = useState("password123");
  const [regFirst, setRegFirst] = useState("Alice");
  const [regLast, setRegLast] = useState("Martin");
  const [regDob, setRegDob] = useState("1990-03-15");
  const [regNat, setRegNat] = useState("FR");
  const [regSite, setRegSite] = useState("Discord");
  const [regLoading, setRegLoading] = useState(false);
  const [regResult, setRegResult] = useState<Result>(null);

  const doRegister = async () => {
    setRegLoading(true);
    const r = await post(`${API}/dev/register_user`, {
      email: regEmail, password: regPass, first_name: regFirst, last_name: regLast,
      date_of_birth: regDob, nationality: regNat, site_name: regSite,
    });
    setRegResult(r);
    if (r.ok && (r.data as any).public_key_hex) {
      setPublicKeyHex((r.data as any).public_key_hex);
    }
    setRegLoading(false);
  };

  // ── Flow 1: User auth → session ───────────────────────────────────────────
  const [authEmail, setAuthEmail] = useState("alice@test.com");
  const [authPass, setAuthPass] = useState("password123");
  const [authLoading, setAuthLoading] = useState(false);
  const [authResult, setAuthResult] = useState<Result>(null);

  const doAuth = async () => {
    setAuthLoading(true);
    const r = await post(`${API}/user/auth`, { email: authEmail, password: authPass });
    setAuthResult(r);
    if (r.ok && (r.data as any).session) {
      setSession((r.data as any).session);
      setKeyImage((r.data as any).key_image || "");
    }
    setAuthLoading(false);
  };

  // ── Flow 2: Get ZKP credential (frictionless) ─────────────────────────────
  const [credLoading, setCredLoading] = useState(false);
  const [credResult, setCredResult] = useState<Result>(null);

  const doGetCredential = async () => {
    setCredLoading(true);
    const r = await get(`${API}/user/credential`, session ? { "x-sauron-session": session } : {});
    setCredResult(r);
    setCredLoading(false);
  };

  // ── Flow 3: Human KYC consent → retrieve (shows ring) ────────────────────
  const [kycSite, setKycSite] = useState("Discord");
  const [kycLoading, setKycLoading] = useState(false);
  const [kycResult, setKycResult] = useState<Result>(null);
  const [kycConsentToken, setKycConsentToken] = useState("");

  const doKycFlow = useCallback(async () => {
    setKycLoading(true);
    setKycResult(null);

    // 1. Create consent request
    const reqR = await post(`${API}/kyc/request`, {
      site_name: kycSite,
      requested_claims: ["age_over_threshold", "age_threshold"],
    });
    if (!reqR.ok) { setKycResult(reqR); setKycLoading(false); return; }
    const { request_id, consent_url } = reqR.data as any;

    // 2. Open consent popup
    const myOrigin = window.location.origin;
    const popupUrl = `${consent_url}${consent_url.includes("?") ? "&" : "?"}origin=${encodeURIComponent(myOrigin)}`;
    const popup = window.open(popupUrl, "sauron_consent", "width=460,height=640,top=80,left=200");
    if (!popup) { setKycResult({ ok: false, data: { error: "Popup blocked" } }); setKycLoading(false); return; }

    // 3. Wait for postMessage
    const consent_token: string = await (new Promise<string>((resolve, reject) => {
      const t = setTimeout(() => { window.removeEventListener("message", h); reject(new Error("Timed out")); }, 3 * 60 * 1000);
      function h(e: MessageEvent) {
        if (e.origin !== myOrigin || e.data?.request_id !== request_id) return;
        clearTimeout(t); window.removeEventListener("message", h);
        if (e.data?.type === "sauron_consent") resolve(e.data.consent_token);
        else reject(new Error("User denied"));
      }
      window.addEventListener("message", h);
    }) as Promise<string>).catch((err: Error) => { setKycResult({ ok: false, data: { error: err.message } }); setKycLoading(false); return ""; });

    if (!consent_token) return;
    setKycConsentToken(consent_token);

    // 4. Retrieve — server returns identity.is_agent + ring membership
    const retR = await post(`${API}/kyc/retrieve`, {
      consent_token,
      site_name: kycSite,
      required_action: "prove_age",
      zkp_proof: { dev_mock: true },
      zkp_circuit: "AgeVerification",
      zkp_public_signals: ["1", "18"],
    });
    setKycResult(retR);
    setKycLoading(false);
  }, [kycSite]);

  // ── Flow 4: KYA bank path — register agent ────────────────────────────────
  const [agentHuman, setAgentHuman] = useState("");
  const [agentChecksum, setAgentChecksum] = useState("sha256:abc123testchecksum");
  const [agentDesc, setAgentDesc] = useState("Travel booking assistant");
  const [agentTtl, setAgentTtl] = useState("3600");
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentResult, setAgentResult] = useState<Result>(null);
  const [storedAjwt, setStoredAjwt] = useState("");
  const [storedAgentId, setStoredAgentId] = useState("");

  useEffect(() => { if (keyImage) setAgentHuman(keyImage); }, [keyImage]);

  const doRegisterAgent = async () => {
    setAgentLoading(true);
    const r = await post(`${API}/agent/register`, {
      human_key_image: agentHuman,
      agent_checksum: agentChecksum,
      intent_json: JSON.stringify({ description: agentDesc, scope: ["prove:age", "prove:nationality"] }),
      public_key_hex: publicKeyHex,
      ttl_secs: parseInt(agentTtl),
    }, session ? { "x-sauron-session": session } : undefined);
    setAgentResult(r);
    if (r.ok && (r.data as any).ajwt) {
      setStoredAjwt((r.data as any).ajwt);
      setStoredAgentId((r.data as any).agent_id || "");
    }
    setAgentLoading(false);
  };

  // ── Flow 5: KYA self-sovereign VC ────────────────────────────────────────
  const [vcHuman, setVcHuman] = useState("");
  const [vcChecksum, setVcChecksum] = useState("sha256:self-sovereign-agent-001");
  const [vcDesc, setVcDesc] = useState("Shopping assistant (self-sovereign)");
  const [vcScope, setVcScope] = useState("prove:age,prove:nationality");
  const [vcLiveness, setVcLiveness] = useState("0.92");
  const [vcTtl, setVcTtl] = useState("24");
  const [vcLoading, setVcLoading] = useState(false);
  const [vcResult, setVcResult] = useState<Result>(null);

  useEffect(() => { if (keyImage) setVcHuman(keyImage); }, [keyImage]);

  const doIssueVc = async () => {
    setVcLoading(true);
    const r = await post(`${API}/agent/vc/issue`, {
      human_key_image: vcHuman,
      agent_checksum: vcChecksum,
      description: vcDesc,
      scope: vcScope.split(",").map(s => s.trim()),
      liveness_proof: { alive: true, confidence: parseFloat(vcLiveness), method: "passive", provider: "mock" },
      ttl_hours: parseInt(vcTtl),
    }, session ? { "x-sauron-session": session } : undefined);
    setVcResult(r);
    if (r.ok && (r.data as any).ajwt) {
      setStoredAjwt((r.data as any).ajwt);
      setStoredAgentId((r.data as any).agent_id || "");
    }
    setVcLoading(false);
  };

  // ── Flow 6: Agent KYC consent (agent acts for human) ─────────────────────
  const [agKycSite, setAgKycSite] = useState("Discord");
  const [agKycAjwt, setAgKycAjwt] = useState("");
  const [agKycLoading, setAgKycLoading] = useState(false);
  const [agKycResult, setAgKycResult] = useState<Result>(null);

  useEffect(() => { if (storedAjwt) setAgKycAjwt(storedAjwt); }, [storedAjwt]);

  const doAgentKycFlow = useCallback(async () => {
    setAgKycLoading(true);
    setAgKycResult(null);

    // 1. Site creates consent request
    const reqR = await post(`${API}/kyc/request`, {
      site_name: agKycSite,
      requested_claims: ["age_over_threshold", "age_threshold"],
    });
    if (!reqR.ok) { setAgKycResult(reqR); setAgKycLoading(false); return; }
    const { request_id } = reqR.data as any;

    // 2. Agent grants consent (no popup — agent acts autonomously)
    const consentR = await post(`${API}/agent/kyc/consent`, {
      ajwt: agKycAjwt,
      site_name: agKycSite,
      request_id,
    });
    if (!consentR.ok) { setAgKycResult(consentR); setAgKycLoading(false); return; }
    const { consent_token } = consentR.data as any;

    // 3. Site retrieves — response includes identity.is_agent=true + ring verification
    const retR = await post(`${API}/kyc/retrieve`, {
      consent_token,
      site_name: agKycSite,
      required_action: "prove_age",
      zkp_proof: { dev_mock: true },
      zkp_circuit: "AgeVerification",
      zkp_public_signals: ["1", "18"],
    }, agKycAjwt ? { "x-agent-ajwt": agKycAjwt } : undefined);
    setAgKycResult({
      ok: retR.ok,
      data: {
        step1_consent_request: { request_id },
        step2_agent_consent: consentR.data,
        step3_kyc_retrieve: retR.data,
        ring_check: {
          is_agent: (retR.data as any)?.identity?.is_agent,
          human_in_user_ring: (retR.data as any)?.identity?.human_in_user_ring,
          agent_in_agent_ring: (retR.data as any)?.identity?.agent_in_agent_ring,
          trust_verified: (retR.data as any)?.identity?.trust_verified,
        }
      }
    });
    setAgKycLoading(false);
  }, [agKycSite, agKycAjwt]);

  // ── Flow 7: Verify A-JWT ──────────────────────────────────────────────────
  const [verifyAjwt, setVerifyAjwt] = useState("");
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verifyResult, setVerifyResult] = useState<Result>(null);

  useEffect(() => { if (storedAjwt) setVerifyAjwt(storedAjwt); }, [storedAjwt]);

  const doVerify = async () => {
    setVerifyLoading(true);
    const r = await post(`${API}/agent/verify`, { ajwt: verifyAjwt });
    setVerifyResult(r);
    setVerifyLoading(false);
  };

  // ── Flow 8: Revoke agent ──────────────────────────────────────────────────
  const [revokeId, setRevokeId] = useState("");
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [revokeResult, setRevokeResult] = useState<Result>(null);

  useEffect(() => { if (storedAgentId) setRevokeId(storedAgentId); }, [storedAgentId]);

  const doRevoke = async () => {
    setRevokeLoading(true);
    const r = await fetch(`${API}/agent/${revokeId}`, {
      method: "DELETE",
      headers: session ? { "x-sauron-session": session } : undefined,
    });
    setRevokeResult({ ok: r.ok, data: await r.json().catch(() => ({})) });
    setRevokeLoading(false);
  };

  // ── Flow 9: User profile + consents ──────────────────────────────────────
  const [profileLoading, setProfileLoading] = useState(false);
  const [profileResult, setProfileResult] = useState<Result>(null);
  const [consentsLoading, setConsentsLoading] = useState(false);
  const [consentsResult, setConsentsResult] = useState<Result>(null);

  const doProfile = async () => {
    setProfileLoading(true);
    const r = await get(`${API}/user/profile`, session ? { "x-sauron-session": session } : {});
    setProfileResult(r);
    setProfileLoading(false);
  };

  const doConsents = async () => {
    setConsentsLoading(true);
    const r = await get(`${API}/user/consents`, session ? { "x-sauron-session": session } : {});
    setConsentsResult(r);
    setConsentsLoading(false);
  };

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div style={{
      minHeight: "100vh",
      background: "#020817",
      color: "#f1f5f9",
      fontFamily: "system-ui, -apple-system, sans-serif",
      padding: "24px 20px 60px",
    }}>
      <div style={{ maxWidth: 820, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 28 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", background: "linear-gradient(135deg,#6366f1,#8b5cf6)" }} />
            <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: -0.5 }}>SauronID Test Suite</span>
          </div>
          <p style={{ fontSize: 13, color: "#64748b", margin: 0 }}>
            End-to-end test: KYC · ZKP credential · KYA bank path · KYA self-sovereign · Ring verification
          </p>
        </div>

        {/* Session status */}
        <div style={{
          background: "#1e293b",
          border: `1px solid ${session ? "#16a34a55" : "#33415555"}`,
          borderRadius: 10,
          padding: "10px 16px",
          marginBottom: 20,
          display: "flex",
          alignItems: "center",
          gap: 12,
          fontSize: 12,
        }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: session ? "#22c55e" : "#475569", flexShrink: 0 }} />
          {session
            ? <span>Session active &nbsp;<code style={{ color: "#86efac", fontFamily: "monospace" }}>{keyImage.slice(0, 20)}...</code></span>
            : <span style={{ color: "#64748b" }}>No session — authenticate in Flow 1 first</span>
          }
          {session && <button onClick={() => { setSession(""); setKeyImage(""); }} style={{ marginLeft: "auto", padding: "3px 10px", background: "none", border: "1px solid #475569", borderRadius: 6, color: "#94a3b8", fontSize: 11, cursor: "pointer" }}>Clear</button>}
        </div>

        {/* ── FLOW 0: Register ─────────────────────────────────────────── */}
        <Section title="Flow 0 — Register user (dev endpoint)" color="#f59e0b">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <Field label="Email" value={regEmail} onChange={setRegEmail} />
            <Field label="Password" value={regPass} onChange={setRegPass} type="password" />
            <Field label="First name" value={regFirst} onChange={setRegFirst} />
            <Field label="Last name" value={regLast} onChange={setRegLast} />
            <Field label="Date of birth (YYYY-MM-DD)" value={regDob} onChange={setRegDob} />
            <Field label="Nationality (ISO 2)" value={regNat} onChange={setRegNat} />
          </div>
          <Field label="Site name (client must exist)" value={regSite} onChange={setRegSite} />
          <Btn onClick={doRegister} loading={regLoading} color="#d97706">POST /dev/register_user</Btn>
          <JsonBox data={regResult?.data} label="Response" />
        </Section>

        {/* ── FLOW 1: Auth ─────────────────────────────────────────────── */}
        <Section title="Flow 1 — User auth → session token" color="#22c55e">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <Field label="Email" value={authEmail} onChange={setAuthEmail} />
            <Field label="Password" value={authPass} onChange={setAuthPass} type="password" />
          </div>
          <Btn onClick={doAuth} loading={authLoading} color="#16a34a">POST /user/auth</Btn>
          <JsonBox data={authResult?.data} label="Response (session stored automatically)" />
        </Section>

        {/* ── FLOW 2: ZKP Credential ───────────────────────────────────── */}
        <Section title="Flow 2 — Fetch ZKP credential (frictionless, auto after login)" color="#8b5cf6">
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 12px" }}>
            Requires session from Flow 1. Silently claims pre-authorized BabyJubJub credential from issuer.
            Browser can then run snarkjs to generate Groth16 proofs without sending raw data.
          </p>
          <Btn onClick={doGetCredential} loading={credLoading} color="#7c3aed">GET /user/credential</Btn>
          <JsonBox data={credResult?.data} label="Credential (cached in user_credentials table)" />
        </Section>

        {/* ── FLOW 3: Human KYC consent ────────────────────────────────── */}
        <Section title="Flow 3 — Human KYC consent popup → retrieve + ring check" color="#0ea5e9">
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 12px" }}>
            Opens SauronID consent popup. After user approves, retrieves KYC. Response includes
            <code style={{ color: "#38bdf8" }}> identity.is_agent=false</code> and ring membership status.
          </p>
          <Field label="Site name" value={kycSite} onChange={setKycSite} />
          <Btn onClick={doKycFlow} loading={kycLoading} color="#0284c7">Open consent popup → retrieve</Btn>
          {kycConsentToken && <div style={{ fontSize: 11, color: "#64748b", marginTop: 6 }}>
            consent_token: <code style={{ color: "#7dd3fc" }}>{kycConsentToken.slice(0, 24)}...</code>
          </div>}
          <JsonBox data={kycResult?.data} label="KYC retrieve response" />
        </Section>

        {/* ── FLOW 4: KYA bank path ────────────────────────────────────── */}
        <Section title="Flow 4 — KYA (bank path): register agent from user key_image" color="#f97316">
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 12px" }}>
            Human exists in user_group (bank-verified). Agent derives trust from human.
            Agent key pushed to agent_group ring immediately on register.
          </p>
          <Field label="Human key_image (auto-filled from session)" value={agentHuman} onChange={setAgentHuman} mono />
          <Field label="Agent checksum (SHA-256 of agent config)" value={agentChecksum} onChange={setAgentChecksum} mono />
          <Field label="Description" value={agentDesc} onChange={setAgentDesc} />
          <Field label="TTL seconds" value={agentTtl} onChange={setAgentTtl} />
          <Btn onClick={doRegisterAgent} loading={agentLoading} color="#ea580c">POST /agent/register</Btn>
          {storedAjwt && <div style={{ fontSize: 11, color: "#64748b", marginTop: 6 }}>
            A-JWT stored: <code style={{ color: "#fdba74" }}>{storedAjwt.slice(0, 24)}...</code>
          </div>}
          <JsonBox data={agentResult?.data} label="Registered agent + A-JWT" />
        </Section>

        {/* ── FLOW 5: KYA self-sovereign ───────────────────────────────── */}
        <Section title="Flow 5 — KYA self-sovereign VC (no bank needed)" color="#ec4899">
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 12px" }}>
            Trust chain: SauronID IdP → liveness check → OPRF key_image (Sybil-resistant) → Agent VC.
            No bank. No Worldcoin. SauronID is sole root of trust.
          </p>
          <Field label="Human key_image" value={vcHuman} onChange={setVcHuman} mono />
          <Field label="Agent checksum" value={vcChecksum} onChange={setVcChecksum} mono />
          <Field label="Description" value={vcDesc} onChange={setVcDesc} />
          <Field label="Scope (comma-separated)" value={vcScope} onChange={setVcScope} />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <Field label="Liveness confidence (0-1, min 0.70)" value={vcLiveness} onChange={setVcLiveness} />
            <Field label="TTL hours" value={vcTtl} onChange={setVcTtl} />
          </div>
          <Btn onClick={doIssueVc} loading={vcLoading} color="#be185d">POST /agent/vc/issue</Btn>
          <JsonBox data={vcResult?.data} label="Self-sovereign VC + A-JWT" />
        </Section>

        {/* ── FLOW 6: Agent acts for human ─────────────────────────────── */}
        <Section title="Flow 6 — Agent acts on behalf of human (dual-ring verification)" color="#14b8a6">
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 12px" }}>
            Agent presents A-JWT → server verifies agent in agent_group AND human in user_group.
            No popup — agent acts autonomously. Site receives <code style={{ color: "#5eead4" }}>identity.is_agent=true</code>.
          </p>
          <Field label="A-JWT (auto-filled from Flow 4 or 5)" value={agKycAjwt} onChange={setAgKycAjwt} mono />
          <Field label="Site name" value={agKycSite} onChange={setAgKycSite} />
          <Btn onClick={doAgentKycFlow} loading={agKycLoading} color="#0f766e">
            Full agent flow: request → agent consent → retrieve
          </Btn>
          <JsonBox data={agKycResult?.data} label="Step-by-step result + ring check" />
        </Section>

        {/* ── FLOW 7: Verify A-JWT ─────────────────────────────────────── */}
        <Section title="Flow 7 — Verify A-JWT" color="#a3e635">
          <Field label="A-JWT" value={verifyAjwt} onChange={setVerifyAjwt} mono />
          <Btn onClick={doVerify} loading={verifyLoading} color="#65a30d">POST /agent/verify</Btn>
          <JsonBox data={verifyResult?.data} label="Decoded claims" />
        </Section>

        {/* ── FLOW 8: Revoke agent ─────────────────────────────────────── */}
        <Section title="Flow 8 — Revoke agent" color="#ef4444">
          <Field label="Agent ID" value={revokeId} onChange={setRevokeId} mono />
          <Btn onClick={doRevoke} loading={revokeLoading} color="#b91c1c">DELETE /agent/{"{agent_id}"}</Btn>
          <JsonBox data={revokeResult?.data} label="Revoke result (try Flow 6 again after — should fail)" />
        </Section>

        {/* ── FLOW 9: User dashboard ───────────────────────────────────── */}
        <Section title="Flow 9 — User self-service (profile + consent history)" color="#94a3b8">
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 12px" }}>
            Requires session from Flow 1.
          </p>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Btn onClick={doProfile} loading={profileLoading} color="#475569">GET /user/profile</Btn>
            <Btn onClick={doConsents} loading={consentsLoading} color="#475569">GET /user/consents</Btn>
          </div>
          <JsonBox data={profileResult?.data} label="Profile" />
          <JsonBox data={consentsResult?.data} label="Consents (each shows if issued by agent)" />
        </Section>

        {/* Ring legend */}
        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10, padding: 16, fontSize: 12, color: "#64748b" }}>
          <div style={{ fontWeight: 700, color: "#f1f5f9", marginBottom: 10 }}>Ring verification cheat sheet</div>
          <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 16px" }}>
            <code style={{ color: "#86efac" }}>identity.is_agent = false</code><span>Human acted directly</span>
            <code style={{ color: "#86efac" }}>identity.is_agent = true</code><span>Agent acted on behalf of human</span>
            <code style={{ color: "#7dd3fc" }}>human_in_user_ring = true</code><span>Human key in user_group Ristretto ring (bank-verified)</span>
            <code style={{ color: "#fdba74" }}>agent_in_agent_ring = true</code><span>Agent key in agent_group Ristretto ring</span>
            <code style={{ color: "#f472b6" }}>trust_verified = true</code><span>Both checks pass — safe to proceed</span>
            <code style={{ color: "#ef4444" }}>trust_verified = false</code><span>Reject — unknown human or unregistered agent</span>
          </div>
        </div>

      </div>
    </div>
  );
}
