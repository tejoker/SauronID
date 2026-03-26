"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { useClient, API, KYC_API, type Client, type ClientUser } from "../context/ClientContext";
import { showToast } from "../components/Toast";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const NAT_TO_COUNTRY: Record<string, string> = {
  FRA: "FR", DEU: "DE", GBR: "GB", ESP: "ES", ITA: "IT",
  NLD: "NL", BEL: "BE", POL: "PL", SWE: "SE", PRT: "PT",
  USA: "US", JPN: "JP", BRA: "BR", IND: "IN",
};
const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

type Tab = "dashboard" | "users" | "register";
type KYCStep = "idle" | "id_cam" | "selfie_cam" | "loading" | "result";

interface KYCAPIResult {
  decision: "pass" | "review" | "fail";
  decision_reason: string;
  face_match_score: number;
  face_match_label: string;
  face_match_reasoning: string;
  extracted_fields: {
    document_type: string; full_name: string; first_name: string; last_name: string;
    date_of_birth: string; nationality: string; document_number: string; expiry_date: string;
    gender: string | null;
  };
}

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

// ─── KYC Camera Flow ──────────────────────────────────────────────────────────
function KYCCameraFlow({ onDone, onClose }: { onDone: (result: KYCAPIResult) => void; onClose: () => void }) {
  const [step, setStep] = useState<KYCStep>("id_cam");
  const [idImage, setIdImage] = useState<string | null>(null);
  const [kycResult, setKycResult] = useState<KYCAPIResult | null>(null);
  const [kycError, setKycError] = useState("");
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  const stopStream = () => { streamRef.current?.getTracks().forEach((t) => t.stop()); streamRef.current = null; };

  const startCamera = async (facingMode: "environment" | "user") => {
    stopStream();
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode, width: { ideal: 1280 }, height: { ideal: 960 } }, audio: false });
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      streamRef.current = stream;
    } catch {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      streamRef.current = stream;
    }
  };

  useEffect(() => {
    if (step === "id_cam") startCamera("environment");
    else if (step === "selfie_cam") startCamera("user");
    return stopStream;
  }, [step]);

  const captureId = () => {
    if (!videoRef.current || !canvasRef.current) return;
    const canvas = canvasRef.current;
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    canvas.getContext("2d")!.drawImage(videoRef.current, 0, 0);
    setIdImage(canvas.toDataURL("image/jpeg", 0.85));
    setStep("selfie_cam");
  };

  const captureSelfie = async () => {
    if (!videoRef.current || !canvasRef.current || !idImage) return;
    const canvas = canvasRef.current;
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    canvas.getContext("2d")!.drawImage(videoRef.current, 0, 0);
    const selfieImage = canvas.toDataURL("image/jpeg", 0.85);
    stopStream();
    setStep("loading");
    try {
      const res = await fetch(`${KYC_API}/verify`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_image: idImage, selfie_image: selfieImage }),
      });
      const data: KYCAPIResult = await res.json();
      setKycResult(data);
      setStep("result");
    } catch {
      setKycError("KYC API unavailable. Check that the service is running.");
      setStep("result");
    }
  };

  useEffect(() => {
    if (step === "result" && kycResult) {
      if (kycResult.decision === "pass") onDone(kycResult);
    }
  }, [step, kycResult, onDone]);

  const isId = step === "id_cam";

  if (step === "loading") return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
      <div className="bg-white rounded-xl p-8 text-center space-y-3">
        <div className="w-8 h-8 border-2 border-neutral-900 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-sm text-neutral-600">Verifying identity…</p>
      </div>
    </div>
  );

  if (step === "result") return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-6">
      <div className="bg-white rounded-xl p-8 max-w-sm w-full space-y-4">
        {kycError ? (
          <><p className="text-red-600 text-sm font-semibold">Error</p><p className="text-xs text-neutral-500">{kycError}</p></>
        ) : kycResult ? (
          <>
            <p className={`text-sm font-bold ${kycResult.decision === "pass" ? "text-green-700" : "text-yellow-700"}`}>
              {kycResult.decision === "pass" ? "Identity Verified" : "Review Required"}
            </p>
            <p className="text-xs text-neutral-500">{kycResult.decision_reason}</p>
          </>
        ) : null}
        <button onClick={onClose} className="w-full border border-neutral-200 rounded-lg py-2.5 text-sm text-neutral-700 hover:border-neutral-400 transition-colors">Close</button>
      </div>
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black z-50 flex flex-col">
      <div className="flex items-center justify-between p-4 bg-black/80">
        <p className="text-white text-sm font-medium">{isId ? "Scan ID Document" : "Take Selfie"}</p>
        <button onClick={() => { stopStream(); onClose(); }} className="text-white/60 hover:text-white text-xs border border-white/20 px-3 py-1.5 rounded-lg transition-colors">Cancel</button>
      </div>
      <div className="flex-1 relative overflow-hidden">
        <video ref={videoRef} className="absolute inset-0 w-full h-full object-cover" playsInline muted />
        <canvas ref={canvasRef} className="hidden" />
        {isId ? (
          <div className="absolute inset-0 pointer-events-none">
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[82%] rounded-xl border-2 border-blue-400" style={{ aspectRatio: "1.586/1", boxShadow: "0 0 0 9999px rgba(0,0,0,0.4)" }} />
          </div>
        ) : (
          <div className="absolute inset-0 pointer-events-none">
            <div className="absolute inset-0 bg-black/40" />
            <div className="absolute top-[46%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[50%]" style={{ aspectRatio: "1/1", borderRadius: "50%", boxShadow: "0 0 0 9999px rgba(0,0,0,0.4)", border: "2px solid rgb(96,165,250)" }} />
          </div>
        )}
        <div className="absolute bottom-3 left-1/2 -translate-x-1/2 bg-black/60 text-white text-[11px] px-3 py-1.5 rounded-full border border-white/10 whitespace-nowrap">
          {isId ? "Align your ID in the frame" : "Centre your face and look ahead"}
        </div>
      </div>
      <div className="flex flex-col items-center gap-1.5 py-4 bg-white">
        <button onClick={isId ? captureId : captureSelfie} className="rounded-full border-4 border-neutral-900 p-1 hover:border-neutral-600 transition-colors" style={{ width: 56, height: 56 }}>
          <div className="w-full h-full rounded-full bg-neutral-900 hover:bg-neutral-700 transition-colors" />
        </button>
        <p className="text-[11px] text-neutral-400">{isId ? "Capture ID document" : "Take selfie"}</p>
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

// ─── Register User Tab ────────────────────────────────────────────────────────
function RegisterTab({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [form, setForm] = useState({ email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [showKYC, setShowKYC] = useState(false);
  const [kyc, setKyc] = useState<KYCAPIResult | null>(null);
  const [result, setResult] = useState<{ first_name: string; last_name: string; email: string } | null>(null);
  const [error, setError] = useState("");

  const handleKYCDone = (r: KYCAPIResult) => {
    setKyc(r); setShowKYC(false);
    showToast("success", "Identity verified", `${r.extracted_fields.full_name} — ${r.extracted_fields.document_type}`);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.email || !form.password || !kyc) return;
    const f = kyc.extracted_fields;
    const country = NAT_TO_COUNTRY[f.nationality] ?? "FR";
    setBusy(true); setError("");
    try {
      const res = await fetch(`${API}/dev/register_user`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: client.name, email: form.email, password: form.password, first_name: f.first_name, last_name: f.last_name, country, date_of_birth: f.date_of_birth, nationality: f.nationality }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Registration failed");
      setResult({ first_name: f.first_name, last_name: f.last_name, email: form.email });
      showToast("success", `${client.name}: user enrolled`, `${f.first_name} ${f.last_name} KYC committed to Sauron.`);
      await refreshActiveClient();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "Registration failed", msg);
    } finally { setBusy(false); }
  };

  const handleMobileConnect = async () => {
    const phoneNumber = window.prompt("Enter your phone number for CAMARA Mobile Connect verification (e.g. +33612345678):");
    if (!phoneNumber) return;
    setBusy(true);
    try {
      const res = await fetch("/api/camara/issue-tier2", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phoneNumber }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Mobile Connect failed");
      const mappedResult: KYCAPIResult = {
        decision: "pass",
        decision_reason: "Verified via CAMARA Network Auth",
        face_match_score: 1.0,
        face_match_label: "high",
        face_match_reasoning: "Not applicable (Tier 2 Telecom Auth)",
        extracted_fields: {
          document_type: "tier_2_telecom",
          full_name: "Mobile Verified User",
          first_name: "Mobile",
          last_name: "Verified",
          date_of_birth: "01/01/2000",
          nationality: "FRA",
          document_number: data.credentialSubject.phoneNumberHash.substring(0, 10),
          expiry_date: "31/12/2099",
          gender: "U",
        },
      };
      handleKYCDone(mappedResult);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Mobile Connect Error";
      setError(msg);
      showToast("error", "Mobile Connect failed", msg);
    } finally { setBusy(false); }
  };

  return (
    <>
      {showKYC && <KYCCameraFlow onDone={handleKYCDone} onClose={() => setShowKYC(false)} />}
      {result && (
        <SuccessOverlay title="User Enrolled" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
              <p className="text-amber-700 font-semibold mb-1">Welcome, {result.first_name}!</p>
              <p className="text-neutral-500 text-xs">KYC committed to the Sauron network via ring signature.</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} enrolled this user at no cost. The user&apos;s identity is now stored in Sauron and can be retrieved anonymously by authorised retail sites.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        <div className={`rounded-xl border-2 p-4 ${kyc ? (kyc.decision === "pass" ? "border-green-300 bg-green-50" : "border-yellow-300 bg-yellow-50") : "border-dashed border-neutral-300"}`}>
          {kyc ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className={`text-xs font-bold uppercase tracking-wide ${kyc.decision === "pass" ? "text-green-700" : "text-yellow-700"}`}>
                  {kyc.decision === "pass" ? "Identity Verified" : "Review Needed"}
                </p>
                <button type="button" onClick={() => setKyc(null)} className="text-[10px] text-neutral-400 hover:text-red-500 border border-neutral-200 px-2 py-0.5 rounded">Reset</button>
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {([["Name", kyc.extracted_fields.full_name], ["DOB", kyc.extracted_fields.date_of_birth], ["Nationality", kyc.extracted_fields.nationality], ["Method", kyc.extracted_fields.document_type === "tier_2_telecom" ? "Mobile Connect" : `Face Match: ${Math.round(kyc.face_match_score * 100)}%`]] as [string, string][]).filter(([, v]) => v).map(([k, v]) => (
                  <div key={k}><span className="text-neutral-400">{k}: </span><span className="font-mono text-neutral-700">{v}</span></div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center space-y-3">
              <p className="text-sm text-neutral-500">Step 1 — Verify customer identity</p>
              <div className="flex flex-col gap-2">
                <button type="button" onClick={() => setShowKYC(true)} className="w-full px-5 py-2.5 rounded-lg text-sm font-semibold border transition-all bg-blue-50 text-blue-700 border-blue-200 hover:opacity-80">
                  Full KYC (Camera + ID)
                </button>
                <div className="flex items-center gap-2">
                  <div className="h-px bg-neutral-200 flex-1"></div>
                  <span className="text-[10px] text-neutral-400 uppercase font-bold tracking-widest">OR</span>
                  <div className="h-px bg-neutral-200 flex-1"></div>
                </div>
                <button type="button" onClick={handleMobileConnect} className="w-full px-5 py-2.5 rounded-lg text-sm font-semibold border transition-all bg-purple-50 text-purple-700 border-purple-200 hover:opacity-80 flex items-center justify-center gap-2">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" /></svg>
                  Mobile Connect (Tier 2 / Fast)
                </button>
              </div>
              <p className="text-[10px] text-neutral-300 mt-2">Powered by GSMA Open Gateway Network Auth & Gemini Vision</p>
            </div>
          )}
        </div>

        <div className={`space-y-3 transition-opacity ${kyc ? "opacity-100" : "opacity-40 pointer-events-none"}`}>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Customer Email</label>
            <input type="email" value={form.email} onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))} required={!!kyc}
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="alice@example.com" />
          </div>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Customer Password</label>
            <input type="password" value={form.password} onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))} required={!!kyc}
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="••••••••" />
          </div>
        </div>

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Password blinded via OPRF (Ristretto255) — {client.name} signs with ring signature — KYC committed to Sauron at no cost.
        </div>
        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button type="submit" disabled={busy || !kyc || !form.email || !form.password}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${busy || !kyc || !form.email || !form.password
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : "bg-amber-500 text-white border-amber-500 hover:bg-amber-600"
            }`}>
          {busy ? "Enrolling..." : kyc ? `Enrol Customer via ${client.name}` : "Complete KYC first"}
        </button>
      </form>
    </>
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
    { key: "users", label: "Enrolled Users" },
    { key: "register", label: "Enrol Customer" },
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
        {tab === "register" && <RegisterTab client={client} />}
      </div>
    </div>
  );
}
