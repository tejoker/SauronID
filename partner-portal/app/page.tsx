"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { useClient, API, KYC_API, EXCHANGE_RATE, type Client, type ClientUser } from "./context/ClientContext";
import { showToast } from "./components/Toast";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const NAT_TO_COUNTRY: Record<string, string> = {
  FRA: "FR", DEU: "DE", GBR: "GB", ESP: "ES", ITA: "IT",
  NLD: "NL", BEL: "BE", POL: "PL", SWE: "SE", PRT: "PT",
  USA: "US", JPN: "JP", BRA: "BR", IND: "IN",
};
const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

type Tab = "dashboard" | "users" | "journey";
type JourneyTab = "register" | "login";
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

  const captureFrame = (): string => {
    const v = videoRef.current!, c = canvasRef.current!;
    c.width = v.videoWidth; c.height = v.videoHeight;
    c.getContext("2d")!.drawImage(v, 0, 0);
    return c.toDataURL("image/jpeg", 0.92);
  };

  useEffect(() => {
    if (step === "id_cam") startCamera("environment");
    else if (step === "selfie_cam") startCamera("user");
    return stopStream;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const captureId = () => { const img = captureFrame(); setIdImage(img); stopStream(); setStep("selfie_cam"); };

  const captureSelfie = async () => {
    const selfie = captureFrame(); stopStream(); setStep("loading"); setKycError("");
    try {
      const res = await fetch(`${KYC_API}/api/kyc`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id_image: idImage, selfie }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "KYC failed");
      setKycResult(data as KYCAPIResult); setStep("result");
    } catch (e: unknown) { setKycError(e instanceof Error ? e.message : "Unknown error"); setKycResult(null); setStep("result"); }
  };

  if (step === "loading") {
    return (
      <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-xl p-8 max-w-xs w-full flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-neutral-900 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm font-semibold text-neutral-900">Verifying identity…</p>
          <div className="space-y-1 text-xs text-neutral-400 text-center">
            <p>Reading ID document</p><p>Comparing faces with Gemini</p><p>Finalizing result</p>
          </div>
        </div>
      </div>
    );
  }

  if (step === "result") {
    const r = kycResult;
    const isPass = r?.decision === "pass", isReview = r?.decision === "review";
    const pct = r ? Math.round(r.face_match_score * 100) : 0;
    const f = r?.extracted_fields;
    return (
      <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-xl p-6 max-w-sm w-full">
          <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wide mb-4">KYC Result</p>
          {kycError && !r ? (
            <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-4 text-center">
              <p className="text-red-700 font-bold">Error</p>
              <p className="text-sm text-neutral-500 mt-1">{kycError}</p>
            </div>
          ) : (
            <>
              <div className={`rounded-xl p-3 mb-3 flex items-center gap-3 ${isPass ? "bg-green-50 border border-green-200" : isReview ? "bg-yellow-50 border border-yellow-200" : "bg-red-50 border border-red-200"}`}>
                <span className={`text-xl font-bold ${isPass ? "text-green-600" : isReview ? "text-yellow-600" : "text-red-600"}`}>{isPass ? "✓" : isReview ? "!" : "✕"}</span>
                <div>
                  <p className={`text-sm font-semibold ${isPass ? "text-green-700" : isReview ? "text-yellow-700" : "text-red-700"}`}>
                    {isPass ? "Identity Verified" : isReview ? "Review Needed" : "Verification Failed"}
                  </p>
                  <p className="text-xs text-neutral-500">{r?.decision_reason}</p>
                </div>
              </div>
              <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-3 mb-3">
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs text-neutral-400">Face match</span>
                  <span className="text-xs font-bold text-neutral-700">{pct}%</span>
                </div>
                <div className="h-1.5 bg-neutral-200 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${r?.face_match_label === "high" ? "bg-green-500" : r?.face_match_label === "medium" ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${pct}%` }} />
                </div>
                {r?.face_match_reasoning && <p className="text-[11px] text-neutral-400 mt-1">{r.face_match_reasoning}</p>}
              </div>
              {f && (
                <div className="border border-neutral-100 rounded-lg p-3 mb-4 space-y-1">
                  {([["Name", f.full_name], ["DOB", f.date_of_birth], ["Nationality", f.nationality], ["Document", f.document_type?.replace(/_/g, " ")], ["Expiry", f.expiry_date]] as [string, string][]).filter(([, v]) => v).map(([k, v]) => (
                    <div key={k} className="flex justify-between text-xs"><span className="text-neutral-400">{k}</span><span className="font-mono text-neutral-700">{v}</span></div>
                  ))}
                </div>
              )}
            </>
          )}
          <div className="flex gap-2">
            {(isPass || isReview) && r && <button onClick={() => onDone(r)} className="flex-1 bg-neutral-900 text-white py-2 rounded-lg text-sm font-semibold">Confirm</button>}
            <button onClick={() => { setKycResult(null); setKycError(""); setIdImage(null); setStep("id_cam"); }} className="flex-1 border border-neutral-200 text-neutral-600 py-2 rounded-lg text-sm">Retry</button>
            <button onClick={() => { stopStream(); onClose(); }} className="flex-1 border border-red-200 text-red-500 py-2 rounded-lg text-sm">Cancel</button>
          </div>
        </div>
      </div>
    );
  }

  // Camera view
  const isId = step === "id_cam";
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl overflow-hidden w-full max-w-sm">
        <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-100">
          <div className="flex gap-3">
            {[{ n: 1, label: "ID Document" }, { n: 2, label: "Selfie" }].map(({ n, label }) => {
              const current = isId ? 1 : 2;
              return (
                <div key={n} className={`flex items-center gap-1.5 text-xs ${current > n ? "text-green-600" : current === n ? "text-neutral-900" : "text-neutral-300"}`}>
                  <div className={`w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold border ${current > n ? "bg-green-500 border-green-500 text-white" : current === n ? "border-neutral-900 text-neutral-900" : "border-neutral-200 text-neutral-300"}`}>{current > n ? "✓" : n}</div>
                  <span className="font-medium">{label}</span>
                </div>
              );
            })}
          </div>
          <button onClick={() => { stopStream(); onClose(); }} className="text-xs text-neutral-400 hover:text-neutral-700">Cancel</button>
        </div>
        <div className="relative bg-black" style={{ aspectRatio: "4/3" }}>
          <video ref={videoRef} className="absolute inset-0 w-full h-full object-cover" playsInline muted />
          <canvas ref={canvasRef} className="hidden" />
          {isId ? (
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute inset-0 bg-black/40" />
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
    </div>
  );
}

// ─── Dashboard Tab ────────────────────────────────────────────────────────────
function DashboardTab({ client }: { client: Client }) {
  const { refreshActiveClient, stats } = useClient();
  const [exchangeCount, setExchangeCount] = useState(1);
  const [buyAmount, setBuyAmount] = useState(10);
  const [busy, setBusy] = useState<"exchange" | "buy" | null>(null);

  const doExchange = async () => {
    setBusy("exchange");
    try {
      const res = await fetch(`${API}/dev/exchange`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: client.name, count: exchangeCount }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Exchange failed");
      showToast("success", "Exchange OK", `${exchangeCount} Token A → ${data.tokens_b_received} Token B`);
      await refreshActiveClient();
    } catch (err: unknown) {
      showToast("error", "Exchange failed", err instanceof Error ? err.message : "Unknown error");
    } finally { setBusy(null); }
  };

  const doBuy = async () => {
    setBusy("buy");
    try {
      const res = await fetch(`${API}/dev/buy_tokens`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: client.name, amount: buyAmount }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Purchase failed");
      showToast("success", "Purchase OK", `+${buyAmount} Token B (total: ${data.new_tokens_b})`);
      await refreshActiveClient();
    } catch (err: unknown) {
      showToast("error", "Purchase failed", err instanceof Error ? err.message : "Unknown error");
    } finally { setBusy(null); }
  };

  const isZkp = client.client_type === "ZKP_ONLY";

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard label="Token A (earned)" value={client.tokens_a} sub="from user registrations" accent="text-green-600" />
        <KpiCard label="Token B (available)" value={client.tokens_b} sub="for KYC / ZKP queries" accent={client.tokens_b === 0 ? "text-red-500" : "text-orange-500"} />
        <KpiCard label="Client Type" value={client.client_type} sub={isZkp ? "anonymous proofs only" : "full KYC retrieval"} accent={isZkp ? "text-purple-600" : "text-blue-600"} />
        <KpiCard label="Exchange Rate" value={`1:${EXCHANGE_RATE}`} sub="Token A → Token B" />
      </div>

      {/* Network stats */}
      {stats && (
        <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Network Overview</p>
          <div className="grid grid-cols-4 gap-4 text-center text-xs">
            <div><p className="text-neutral-400">Users</p><p className="text-lg font-bold text-neutral-900 mt-0.5">{stats.total_users}</p></div>
            <div><p className="text-neutral-400">Clients</p><p className="text-lg font-bold text-neutral-900 mt-0.5">{stats.total_clients}</p></div>
            <div><p className="text-neutral-400">Token A Issued</p><p className="text-lg font-bold text-green-600 mt-0.5">{stats.total_tokens_a_issued}</p></div>
            <div><p className="text-neutral-400">Token B Spent</p><p className="text-lg font-bold text-red-500 mt-0.5">{stats.total_tokens_b_spent}</p></div>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Exchange A → B */}
        <div className="bg-white border border-neutral-200 rounded-lg p-5">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Exchange Token A → B</h3>
          <p className="text-xs text-neutral-500 mb-4">Burn Token A to receive Token B at rate 1:{EXCHANGE_RATE}</p>
          <div className="flex items-center gap-3 mb-4">
            <div className="flex-1">
              <label className="text-[10px] text-neutral-400 mb-1 block">Token A to burn</label>
              <input type="number" min={1} max={client.tokens_a} value={exchangeCount}
                onChange={(e) => setExchangeCount(Math.max(1, parseInt(e.target.value) || 1))}
                className="w-full bg-white border border-neutral-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
              />
            </div>
            <div className="text-neutral-300 text-lg pt-4">→</div>
            <div className="flex-1">
              <label className="text-[10px] text-neutral-400 mb-1 block">Token B received</label>
              <div className="border border-neutral-200 rounded-lg px-3 py-2 text-sm font-bold text-orange-600 bg-neutral-50">
                {exchangeCount * EXCHANGE_RATE}
              </div>
            </div>
          </div>
          <button onClick={doExchange} disabled={busy !== null || client.tokens_a < exchangeCount}
            className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
              client.tokens_a < exchangeCount || busy !== null
                ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
                : "border-green-600 bg-green-600 text-white hover:bg-green-700"
            }`}>
            {busy === "exchange" ? "Exchanging..." : client.tokens_a < exchangeCount ? "Not enough Token A" : `Exchange ${exchangeCount} Token A`}
          </button>
        </div>

        {/* Buy Token B directly */}
        <div className="bg-white border border-neutral-200 rounded-lg p-5">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Buy Token B (Direct)</h3>
          <p className="text-xs text-neutral-500 mb-4">Purchase Token B directly (simulated billing)</p>
          <div className="mb-4">
            <label className="text-[10px] text-neutral-400 mb-1 block">Amount</label>
            <input type="number" min={1} value={buyAmount}
              onChange={(e) => setBuyAmount(Math.max(1, parseInt(e.target.value) || 1))}
              className="w-full bg-white border border-neutral-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
            />
          </div>
          <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-3 mb-4 text-xs text-neutral-500">
            Simulated cost: <span className="font-bold text-neutral-700">{(buyAmount * 0.10).toFixed(2)} €</span>
            <span className="text-neutral-400"> (0.10 € / Token B)</span>
          </div>
          <button onClick={doBuy} disabled={busy !== null}
            className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
              busy !== null
                ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
                : "border-orange-500 bg-orange-500 text-white hover:bg-orange-600"
            }`}>
            {busy === "buy" ? "Processing..." : `Buy ${buyAmount} Token B`}
          </button>
        </div>
      </div>

      {/* Crypto info */}
      <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-4 text-xs text-neutral-500 space-y-1">
        <p><span className="font-semibold text-neutral-700">Public Key:</span> <span className="font-mono text-[10px]">{client.public_key_hex.slice(0, 16)}…{client.public_key_hex.slice(-8)}</span></p>
        <p><span className="font-semibold text-neutral-700">Key Image:</span> <span className="font-mono text-[10px]">{client.key_image_hex.slice(0, 16)}…{client.key_image_hex.slice(-8)}</span></p>
      </div>
    </div>
  );
}

// ─── Users Tab ────────────────────────────────────────────────────────────────
function UsersTab({ client }: { client: Client }) {
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
  const retrieved  = users.filter((u) => u.source === "kyc_retrieval");

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <KpiCard label="Total Interactions" value={users.length} sub="all user touchpoints" />
        <KpiCard label="Registrations" value={registered.length} sub="users onboarded via KYC" accent="text-green-600" />
        <KpiCard label="KYC Retrievals" value={retrieved.length} sub="identity lookups" accent="text-blue-600" />
      </div>

      {users.length === 0 ? (
        <div className="bg-white border border-neutral-200 rounded-lg p-8 text-center">
          <p className="text-neutral-400 italic text-sm">No users yet.</p>
          <p className="text-xs text-neutral-300 mt-1">Use the Journey Simulator to register or look up users.</p>
        </div>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {users.map((u, i) => (
            <div key={i} className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${u.source === "register" ? "bg-green-400" : "bg-blue-400"}`} />
                <div>
                  <p className="text-sm font-semibold text-neutral-900">{u.first_name} {u.last_name}</p>
                  <p className="text-xs text-neutral-500">{u.email} · {u.nationality}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[10px] text-neutral-400 font-mono">{fmt(u.timestamp)}</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  u.source === "register"
                    ? "bg-green-50 text-green-700 border-green-200"
                    : "bg-blue-50 text-blue-700 border-blue-200"
                }`}>{u.source === "register" ? "REGISTERED" : "KYC LOOKUP"}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Journey: Register Tab ────────────────────────────────────────────────────
function RegisterJourney({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [form, setForm] = useState({ email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [showKYC, setShowKYC] = useState(false);
  const [kyc, setKyc] = useState<KYCAPIResult | null>(null);
  const [result, setResult] = useState<{ profile: { first_name: string; last_name: string; email: string } } | null>(null);
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
      setResult({ profile: { first_name: f.first_name, last_name: f.last_name, email: form.email } });
      showToast("success", `Registered — ${client.name}`, `${f.first_name} ${f.last_name} enrolled. ${client.name} earned 1 Token A.`);
      await refreshActiveClient();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "Registration failed", msg);
    } finally { setBusy(false); }
  };

  return (
    <>
      {showKYC && <KYCCameraFlow onDone={handleKYCDone} onClose={() => setShowKYC(false)} />}
      {result && (
        <SuccessOverlay title="Registration Successful!" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <p className="text-green-700 font-semibold mb-1">Welcome, {result.profile.first_name}!</p>
              <p className="text-neutral-500 text-xs">KYC committed to the Sauron network via ring signature.</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} earned 1 Token A. The user&apos;s identity is now stored in Sauron and can be retrieved anonymously.
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
                  {kyc.decision === "pass" ? "✓ Identity Verified" : "! Review Needed"}
                </p>
                <button type="button" onClick={() => setKyc(null)} className="text-[10px] text-neutral-400 hover:text-red-500 border border-neutral-200 px-2 py-0.5 rounded">Reset</button>
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {([["Name", kyc.extracted_fields.full_name], ["DOB", kyc.extracted_fields.date_of_birth], ["Nationality", kyc.extracted_fields.nationality], ["Face match", `${Math.round(kyc.face_match_score * 100)}%`]] as [string, string][]).filter(([, v]) => v).map(([k, v]) => (
                  <div key={k}><span className="text-neutral-400">{k}: </span><span className="font-mono text-neutral-700">{v}</span></div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center">
              <p className="text-sm text-neutral-500 mb-3">Step 1 — verify identity with ID document + selfie</p>
              <button type="button" onClick={() => setShowKYC(true)} className="px-5 py-2.5 rounded-lg text-sm font-semibold border transition-all bg-blue-50 text-blue-700 border-blue-200 hover:opacity-80">
                Start Identity Verification
              </button>
              <p className="text-[10px] text-neutral-300 mt-2">Camera · ID scan + selfie · face match · Powered by Gemini Vision</p>
            </div>
          )}
        </div>

        <div className={`space-y-3 transition-opacity ${kyc ? "opacity-100" : "opacity-40 pointer-events-none"}`}>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Email</label>
            <input type="email" value={form.email} onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))} required={!!kyc}
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="alice@example.com" />
          </div>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Password</label>
            <input type="password" value={form.password} onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))} required={!!kyc}
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="••••••••" />
          </div>
        </div>

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Password blinded via OPRF (Ristretto255) — {client.name} signs with ring signature — {client.name} earns 1 Token A.
        </div>
        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button type="submit" disabled={busy || !kyc || !form.email || !form.password}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            busy || !kyc || !form.email || !form.password
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : "bg-blue-600 text-white border-blue-600 hover:bg-blue-700"
          }`}>
          {busy ? "Enrolling..." : kyc ? `Create ${client.name} Account` : "Complete KYC first"}
        </button>
      </form>
    </>
  );
}

// ─── Journey: Login / KYC Retrieval ───────────────────────────────────────────
function LoginJourney({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [form, setForm] = useState({ email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ first_name: string; last_name: string; email: string; country: string } | null>(null);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setError("");
    if (client.tokens_b === 0) {
      setError(`${client.name} has no Token B. Exchange Token A or buy some in the Dashboard tab.`);
      showToast("error", "No Token B", `${client.name} needs Token B to retrieve KYC.`);
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${API}/dev/get_kyc`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: client.name, email: form.email, password: form.password, token_b: "db_managed" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "KYC lookup failed");
      setResult(data.profile);
      showToast("success", `KYC Retrieved — ${client.name}`, `${client.name} spent 1 Token B. Sauron does not know which site asked.`);
      await refreshActiveClient();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "KYC failed", msg);
    } finally { setBusy(false); }
  };

  return (
    <>
      {result && (
        <SuccessOverlay title="Identity Verified" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <p className="text-blue-700 font-bold">{result.first_name} {result.last_name}</p>
              <p className="text-neutral-500 text-xs mt-1">{result.email}</p>
              <p className="text-neutral-400 text-xs">Country: {result.country}</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} spent 1 Token B to retrieve this identity. Sauron verified the ring signature but does not know which site asked.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        <div className={`rounded-lg p-4 border ${client.tokens_b > 0 ? "bg-neutral-50 border-neutral-200" : "bg-red-50 border-red-200"}`}>
          <div className="flex items-center justify-between">
            <p className="text-sm text-neutral-600">{client.name} Token B</p>
            <span className={`text-2xl font-bold tabular-nums ${client.tokens_b > 0 ? "text-neutral-900" : "text-red-600"}`}>{client.tokens_b}</span>
          </div>
          {client.tokens_b === 0 && <p className="text-xs text-red-600 mt-1">No Token B. Go to Dashboard to exchange or buy.</p>}
        </div>

        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Email</label>
          <input type="email" value={form.email} onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="alice@example.com" />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Password</label>
          <input type="password" value={form.password} onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="••••••••" />
        </div>

        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Password re-blinded via OPRF — {client.name} signs GET_KYC with ring sig — Sauron burns Token B and returns KYC — Sauron does not know which site asked.
        </div>

        <button type="submit" disabled={busy || client.tokens_b === 0}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            client.tokens_b === 0
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : busy
              ? "border-neutral-200 text-neutral-400"
              : "border-neutral-900 bg-neutral-900 text-white hover:bg-neutral-700"
          }`}>
          {busy ? "Fetching KYC..." : client.tokens_b === 0 ? "No Token B" : "Login with Sauron KYC (1 Token B)"}
        </button>
      </form>
    </>
  );
}

// ─── Journey: ZKP Login ──────────────────────────────────────────────────────
function ZkpJourney({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [minAge, setMinAge] = useState("");
  const [nationality, setNationality] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ proved_claims: string[]; ring_size: number; client_ring_size: number } | null>(null);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setError("");
    if (client.tokens_b === 0) {
      const msg = `${client.name} has no Token B. Buy some in the Dashboard tab.`;
      setError(msg); showToast("error", "No Token B", msg); return;
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = { email, password, site_name: client.name, token_b: "db_managed" };
      const parsedAge = minAge ? parseInt(minAge, 10) : null;
      if (parsedAge && !isNaN(parsedAge)) body.min_age = parsedAge;
      if (nationality.trim()) body.required_nationality = nationality.trim().toUpperCase();

      const res = await fetch(`${API}/dev/zkp_login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? data ?? "ZKP login failed");
      setResult({ proved_claims: data.proved_claims, ring_size: data.ring_size, client_ring_size: data.client_ring_size });
      showToast("success", `ZKP Login — ${client.name}`, `Proved: ${data.proved_claims.join(", ")} • ring size ${data.ring_size}`);
      await refreshActiveClient();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "ZKP Login failed", msg);
    } finally { setBusy(false); }
  };

  return (
    <>
      {result && (
        <SuccessOverlay title={`ZKP Login Verified — ${client.name}`} onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <p className="text-purple-700 font-bold mb-2">Proof Accepted ✓</p>
              <div className="flex flex-wrap gap-1.5">
                {result.proved_claims.map((c) => (
                  <span key={c} className="inline-block text-xs px-2.5 py-1 rounded-full font-medium bg-purple-50 text-purple-700 border border-purple-200">{c}</span>
                ))}
              </div>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4 space-y-1">
              <p className="text-xs text-neutral-400">User ring: <span className="font-mono text-neutral-700">{result.ring_size} members</span></p>
              <p className="text-xs text-neutral-400">Client ring: <span className="font-mono text-neutral-700">{result.client_ring_size} ZKP_ONLY clients</span></p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} proved it&apos;s a registered ZKP_ONLY client (client ring sig) and that a Sauron-registered user meets the criteria (user ring sig). Sauron does not learn who the user is or which site asked.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        <div className="rounded-xl border-2 border-dashed border-purple-200 p-4 text-center">
          <p className="text-xs font-bold uppercase tracking-wide text-purple-700 mb-1">Zero-Knowledge Proof Login</p>
          <p className="text-xs text-neutral-400">Prove you hold a valid Sauron identity — no personal data is revealed to {client.name}.</p>
        </div>

        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Sauron Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="alice@example.com" />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Sauron Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500" placeholder="••••••••" />
        </div>

        <div className="border border-neutral-100 rounded-lg p-4 space-y-3 bg-neutral-50">
          <p className="text-xs font-medium text-neutral-500 uppercase tracking-wide">Optional ZKP Claims</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Min Age</label>
              <input type="number" min={0} max={120} value={minAge} onChange={(e) => setMinAge(e.target.value)}
                className="w-full bg-white border border-neutral-200 text-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-400" placeholder="e.g. 18" />
            </div>
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Nationality (3-letter)</label>
              <input type="text" maxLength={3} value={nationality} onChange={(e) => setNationality(e.target.value)}
                className="w-full bg-white border border-neutral-200 text-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-400 uppercase" placeholder="e.g. FRA" />
            </div>
          </div>
        </div>

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Dual ring signature — user ring (filtered) + {client.name} client ring. No PII leaves the server.
        </div>
        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button type="submit" disabled={busy || !email || !password || client.tokens_b === 0}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            client.tokens_b === 0
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : busy || !email || !password
              ? "border-neutral-200 text-neutral-400"
              : "bg-purple-600 text-white border-purple-600 hover:bg-purple-700"
          }`}>
          {busy ? "Proving..." : client.tokens_b === 0 ? "No Token B" : `Prove Identity to ${client.name} (1 Token B)`}
        </button>
      </form>
    </>
  );
}

// ─── Journey Simulator Tab ────────────────────────────────────────────────────
function JourneyTab({ client }: { client: Client }) {
  const isZkp = client.client_type === "ZKP_ONLY";
  const [journeyTab, setJourneyTab] = useState<JourneyTab>("register");

  if (isZkp) {
    return (
      <div className="border border-neutral-200 rounded-xl p-8">
        <div className="mb-6">
          <h2 className="text-base font-semibold text-neutral-900">ZKP Login — {client.name}</h2>
          <p className="text-xs text-neutral-400 mt-1">Prove membership anonymously. {client.name} learns only your ZKP claims, not your identity.</p>
        </div>
        <ZkpJourney client={client} />
      </div>
    );
  }

  return (
    <>
      <div className="flex border border-neutral-200 rounded-lg overflow-hidden mb-6">
        <button onClick={() => setJourneyTab("register")}
          className={`flex-1 py-2.5 text-sm font-medium transition-all ${journeyTab === "register" ? "bg-blue-50 text-blue-700 border-b-2 border-blue-400" : "text-neutral-400 hover:text-neutral-700"}`}>
          Create Account (KYC)
        </button>
        <button onClick={() => setJourneyTab("login")}
          className={`flex-1 py-2.5 text-sm font-medium transition-all relative ${journeyTab === "login" ? "bg-neutral-900 text-white" : "text-neutral-400 hover:text-neutral-700"}`}>
          Login (Retrieve KYC)
          {client.tokens_b === 0 && <span className="absolute top-1.5 right-3 w-1.5 h-1.5 rounded-full bg-red-500" />}
        </button>
      </div>
      <div className="border border-neutral-200 rounded-xl p-8">
        {journeyTab === "register" ? (
          <>
            <div className="mb-6">
              <h2 className="text-base font-semibold text-neutral-900">Open a {client.name} Account</h2>
              <p className="text-xs text-neutral-400 mt-1">Identity committed once to Sauron, anonymously, forever reusable.</p>
            </div>
            <RegisterJourney client={client} />
          </>
        ) : (
          <>
            <div className="mb-6">
              <h2 className="text-base font-semibold text-neutral-900">Quick Login via Sauron</h2>
              <p className="text-xs text-neutral-400 mt-1">{client.name} retrieves your KYC anonymously, spending 1 Token B.</p>
            </div>
            <LoginJourney client={client} />
          </>
        )}
      </div>
    </>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function ClientPortal() {
  const { activeClient, loading, offline } = useClient();
  const [tab, setTab] = useState<Tab>("dashboard");

  if (loading) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="animate-pulse text-sm">Connecting to Sauron…</span></div>;
  if (offline) return <div className="flex min-h-[80vh] items-center justify-center"><span className="text-red-600 text-sm border border-red-200 bg-red-50 px-4 py-2 rounded-lg">Backend offline — start the Sauron core on port 3001</span></div>;
  if (!activeClient) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="text-sm">No clients found. Run the seeder first.</span></div>;

  const tabs: { key: Tab; label: string; badge?: string }[] = [
    { key: "dashboard", label: "Dashboard" },
    { key: "users", label: "My Users" },
    { key: "journey", label: activeClient.client_type === "ZKP_ONLY" ? "ZKP Simulator" : "Journey Simulator" },
  ];

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900">
      {/* Tab bar */}
      <div className="bg-white border-b border-neutral-200">
        <div className="max-w-[1200px] mx-auto px-6 flex items-center gap-1">
          {tabs.map((t) => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-all ${
                tab === t.key
                  ? "border-neutral-900 text-neutral-900"
                  : "border-transparent text-neutral-400 hover:text-neutral-700"
              }`}>
              {t.label}
              {t.badge && <span className="ml-1.5 text-[10px] bg-neutral-100 text-neutral-500 px-1.5 py-0.5 rounded">{t.badge}</span>}
            </button>
          ))}
          <div className="flex-1" />
          <div className="flex items-center gap-2">
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              activeClient.client_type === "FULL_KYC"
                ? "bg-blue-50 text-blue-700 border-blue-200"
                : "bg-purple-50 text-purple-700 border-purple-200"
            }`}>{activeClient.client_type}</span>
            <span className="text-xs text-neutral-400">
              <span className="text-green-600 font-bold">{activeClient.tokens_a}</span>
              <span className="text-neutral-300 mx-1">A</span>
              <span className={activeClient.tokens_b === 0 ? "text-red-500 font-bold" : "text-orange-500 font-bold"}>{activeClient.tokens_b}</span>
              <span className="text-neutral-300 ml-1">B</span>
            </span>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-[1200px] mx-auto px-6 py-8">
        {tab === "dashboard" && <DashboardTab client={activeClient} />}
        {tab === "users" && <UsersTab client={activeClient} />}
        {tab === "journey" && <JourneyTab client={activeClient} />}
      </div>
    </div>
  );
}