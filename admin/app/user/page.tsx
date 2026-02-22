"use client";

import { useState, useRef, useEffect } from "react";
import { useWallet, SITES, getSiteTheme, API, SITE_TYPE, type SiteName } from "../context/WalletContext";
import { showToast } from "../components/Toast";

const KYC_API = process.env.NEXT_PUBLIC_KYC_URL || "http://localhost:8000";

// ISO 3-letter nationality → 2-letter country code
const NAT_TO_COUNTRY: Record<string, string> = {
  FRA: "FR", DEU: "DE", GBR: "GB", ESP: "ES", ITA: "IT",
  NLD: "NL", BEL: "BE", POL: "PL", SWE: "SE", PRT: "PT",
  USA: "US", JPN: "JP", BRA: "BR", IND: "IN",
};

// Local type for API responses
interface UserData { first_name: string; last_name: string; email: string; country: string; }

// ─── Types ────────────────────────────────────────────────────────────────────

type Tab = "register" | "login";
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

interface RegisterForm { email: string; password: string; }
interface LoginForm    { email: string; password: string; }



const SITE_DESCRIPTIONS: Record<SiteName, string> = {
  // FULL_KYC
  Monzo:   "Digital bank account",
  Revolut: "Financial super-app",
  Binance: "Crypto exchange",
  N26:     "Mobile banking",
  // ZKP_ONLY
  Discord: "Age-verified chat",
  Tinder:  "Verified identity dating",
  Airbnb:  "Trusted host & guest",
  Uber:    "Verified rider",
  Twitch:  "Age-restricted streams",
};

// ─── Site banner ──────────────────────────────────────────────────────────────

function SiteBanner({ site, onSwitch }: { site: SiteName; onSwitch: (s: SiteName) => void }) {
  const theme = getSiteTheme(site);
  return (
    <div className={`${theme.bg} border-b ${theme.border} px-8 py-4`}>
      <div className="max-w-4xl mx-auto flex items-center justify-between">
        <div>
          <h1 className={`text-lg font-bold ${theme.color}`}>{site}</h1>
          <p className="text-xs text-neutral-500">{SITE_DESCRIPTIONS[site]}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-neutral-400 mr-1">Site:</span>
          {SITES.map((s) => (
            <button
              key={s.name}
              onClick={() => onSwitch(s.name)}
              className={`px-2.5 py-1 rounded text-xs font-medium border transition-all ${
                site === s.name
                  ? `${s.bg} ${s.color} ${s.border}`
                  : "text-neutral-400 border-transparent hover:border-neutral-300 hover:text-neutral-700"
              }`}
            >
              {s.name}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Result overlay ───────────────────────────────────────────────────────────

function SuccessOverlay({
  title,
  children,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-6">
      <div className="bg-white border border-neutral-200 rounded-xl p-8 max-w-md w-full shadow-xl">
        <div className="mb-6">
          <h2 className="text-base font-bold text-neutral-900">{title}</h2>
        </div>
        {children}
        <button
          onClick={onClose}
          className="mt-6 w-full border border-neutral-200 hover:border-neutral-400 text-neutral-700 py-2.5 rounded-lg transition-colors text-sm"
        >
          Close
        </button>
      </div>
    </div>
  );
}

// ─── KYC Camera Flow ──────────────────────────────────────────────────────────

function KYCCameraFlow({
  onDone,
  onClose,
}: {
  onDone: (result: KYCAPIResult) => void;
  onClose: () => void;
}) {
  const [step, setStep] = useState<KYCStep>("id_cam");
  const [idImage, setIdImage] = useState<string | null>(null);
  const [kycResult, setKycResult] = useState<KYCAPIResult | null>(null);
  const [kycError, setKycError] = useState("");
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  const stopStream = () => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  };

  const startCamera = async (facingMode: "environment" | "user") => {
    stopStream();
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode, width: { ideal: 1280 }, height: { ideal: 960 } },
        audio: false,
      });
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      streamRef.current = stream;
    } catch {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      streamRef.current = stream;
    }
  };

  const captureFrame = (): string => {
    const v = videoRef.current!;
    const c = canvasRef.current!;
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

  const captureId = () => {
    const img = captureFrame();
    setIdImage(img);
    stopStream();
    setStep("selfie_cam");
  };

  const captureSelfie = async () => {
    const selfie = captureFrame();
    stopStream();
    setStep("loading");
    setKycError("");
    try {
      const res = await fetch(`${KYC_API}/api/kyc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_image: idImage, selfie }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "KYC failed");
      setKycResult(data as KYCAPIResult);
      setStep("result");
    } catch (e: unknown) {
      setKycError(e instanceof Error ? e.message : "Unknown error");
      setKycResult(null);
      setStep("result");
    }
  };

  if (step === "loading") {
    return (
      <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-xl p-8 max-w-xs w-full flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-neutral-900 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm font-semibold text-neutral-900">Verifying identity…</p>
          <div className="space-y-1 text-xs text-neutral-400 text-center">
            <p>Reading ID document</p>
            <p>Comparing faces with Gemini</p>
            <p>Finalizing result</p>
          </div>
        </div>
      </div>
    );
  }

  if (step === "result") {
    const r = kycResult;
    const isPass   = r?.decision === "pass";
    const isReview = r?.decision === "review";
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
              <div className={`rounded-xl p-3 mb-3 flex items-center gap-3 ${
                isPass ? "bg-green-50 border border-green-200" :
                isReview ? "bg-yellow-50 border border-yellow-200" :
                "bg-red-50 border border-red-200"
              }`}>
                <span className={`text-xl font-bold ${
                  isPass ? "text-green-600" : isReview ? "text-yellow-600" : "text-red-600"
                }`}>{isPass ? "✓" : isReview ? "!" : "✕"}</span>
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
                  <div className={`h-full rounded-full ${ r?.face_match_label === "high" ? "bg-green-500" : r?.face_match_label === "medium" ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${pct}%` }} />
                </div>
                {r?.face_match_reasoning && <p className="text-[11px] text-neutral-400 mt-1">{r.face_match_reasoning}</p>}
              </div>
              {f && (
                <div className="border border-neutral-100 rounded-lg p-3 mb-4 space-y-1">
                  {([
                    ["Name",        f.full_name],
                    ["DOB",         f.date_of_birth],
                    ["Nationality", f.nationality],
                    ["Document",    f.document_type?.replace(/_/g, " ")],
                    ["Expiry",      f.expiry_date],
                  ] as [string, string][]).filter(([, v]) => v).map(([k, v]) => (
                    <div key={k} className="flex justify-between text-xs">
                      <span className="text-neutral-400">{k}</span>
                      <span className="font-mono text-neutral-700">{v}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
          <div className="flex gap-2">
            {(isPass || isReview) && r && (
              <button onClick={() => onDone(r)} className="flex-1 bg-neutral-900 text-white py-2 rounded-lg text-sm font-semibold">
                Confirm
              </button>
            )}
            <button onClick={() => { setKycResult(null); setKycError(""); setIdImage(null); setStep("id_cam"); }} className="flex-1 border border-neutral-200 text-neutral-600 py-2 rounded-lg text-sm">
              Retry
            </button>
            <button onClick={() => { stopStream(); onClose(); }} className="flex-1 border border-red-200 text-red-500 py-2 rounded-lg text-sm">
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Camera view (id_cam | selfie_cam)
  const isId = step === "id_cam";
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl overflow-hidden w-full max-w-sm">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-100">
          <div className="flex gap-3">
            {[{ n: 1, label: "ID Document" }, { n: 2, label: "Selfie" }].map(({ n, label }) => {
              const current = isId ? 1 : 2;
              return (
                <div key={n} className={`flex items-center gap-1.5 text-xs ${
                  current > n ? "text-green-600" : current === n ? "text-neutral-900" : "text-neutral-300"
                }`}>
                  <div className={`w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold border ${
                    current > n ? "bg-green-500 border-green-500 text-white" :
                    current === n ? "border-neutral-900 text-neutral-900" :
                    "border-neutral-200 text-neutral-300"
                  }`}>{current > n ? "✓" : n}</div>
                  <span className="font-medium">{label}</span>
                </div>
              );
            })}
          </div>
          <button onClick={() => { stopStream(); onClose(); }} className="text-xs text-neutral-400 hover:text-neutral-700">Cancel</button>
        </div>

        {/* Camera viewport */}
        <div className="relative bg-black" style={{ aspectRatio: "4/3" }}>
          <video ref={videoRef} className="absolute inset-0 w-full h-full object-cover" playsInline muted />
          <canvas ref={canvasRef} className="hidden" />
          {isId && (
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute inset-0 bg-black/40" />
              <div
                className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[82%] rounded-xl border-2 border-blue-400"
                style={{ aspectRatio: "1.586/1", boxShadow: "0 0 0 9999px rgba(0,0,0,0.4)" }}
              />
            </div>
          )}
          {!isId && (
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute inset-0 bg-black/40" />
              <div
                className="absolute top-[46%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[50%]"
                style={{ aspectRatio: "1/1", borderRadius: "50%", boxShadow: "0 0 0 9999px rgba(0,0,0,0.4)", border: "2px solid rgb(96,165,250)" }}
              />
            </div>
          )}
          <div className="absolute bottom-3 left-1/2 -translate-x-1/2 bg-black/60 text-white text-[11px] px-3 py-1.5 rounded-full border border-white/10 whitespace-nowrap">
            {isId ? "Align your ID in the frame" : "Centre your face and look ahead"}
          </div>
        </div>

        {/* Capture button */}
        <div className="flex flex-col items-center gap-1.5 py-4 bg-white">
          <button
            onClick={isId ? captureId : captureSelfie}
            className="rounded-full border-4 border-neutral-900 p-1 hover:border-neutral-600 transition-colors"
            style={{ width: 56, height: 56 }}
          >
            <div className="w-full h-full rounded-full bg-neutral-900 hover:bg-neutral-700 transition-colors" />
          </button>
          <p className="text-[11px] text-neutral-400">{isId ? "Capture ID document" : "Take selfie"}</p>
        </div>
      </div>
    </div>
  );
}

// ─── Register tab ─────────────────────────────────────────────────────────────

function RegisterTab({ site }: { site: SiteName }) {
  const { addTokensA } = useWallet();
  const theme = getSiteTheme(site);
  const [form, setForm] = useState<RegisterForm>({ email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [showKYC, setShowKYC] = useState(false);
  const [kyc, setKyc] = useState<KYCAPIResult | null>(null);
  const [result, setResult] = useState<{ tokenA: string; profile: UserData } | null>(null);
  const [error, setError] = useState("");

  const set = (k: keyof RegisterForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((p) => ({ ...p, [k]: e.target.value }));

  const handleKYCDone = (r: KYCAPIResult) => {
    setKyc(r);
    setShowKYC(false);
    showToast("success", "Identity verified", `${r.extracted_fields.full_name} — ${r.extracted_fields.document_type}`);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.email || !form.password || !kyc) return;
    const f = kyc.extracted_fields;
    const country = NAT_TO_COUNTRY[f.nationality] ?? "FR";

    setBusy(true);
    setError("");
    try {
      const res = await fetch(`${API}/dev/register_user`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          site_name:     site,
          email:         form.email,
          password:      form.password,
          first_name:    f.first_name,
          last_name:     f.last_name,
          country,
          date_of_birth: f.date_of_birth,
          nationality:   f.nationality,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Registration failed");

      addTokensA(site, [data.signed_token_a]);
      setResult({
        tokenA: data.signed_token_a,
        profile: { first_name: f.first_name, last_name: f.last_name, email: form.email, country },
      });
      showToast("success", `Registered — ${site}`, `${f.first_name} ${f.last_name} enrolled. ${site} earned 1 Token A.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg);
      showToast("error", "Registration failed", msg);
    } finally {
      setBusy(false);
    }
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
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4">
              <p className="text-xs text-neutral-400 mb-1">Token A earned by {site}</p>
              <p className="font-mono text-[10px] text-green-700 break-all">{result.tokenA}</p>
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        {/* KYC step */}
        <div className={`rounded-xl border-2 p-4 ${
          kyc
            ? kyc.decision === "pass" ? "border-green-300 bg-green-50" : "border-yellow-300 bg-yellow-50"
            : "border-dashed border-neutral-300"
        }`}>
          {kyc ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className={`text-xs font-bold uppercase tracking-wide ${
                  kyc.decision === "pass" ? "text-green-700" : "text-yellow-700"
                }`}>
                  {kyc.decision === "pass" ? "✓ Identity Verified" : "! Review Needed"}
                </p>
                <button type="button" onClick={() => setKyc(null)}
                  className="text-[10px] text-neutral-400 hover:text-red-500 border border-neutral-200 px-2 py-0.5 rounded">
                  Reset
                </button>
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {([
                  ["Name",        kyc.extracted_fields.full_name],
                  ["DOB",         kyc.extracted_fields.date_of_birth],
                  ["Nationality", kyc.extracted_fields.nationality],
                  ["Face match",  `${Math.round(kyc.face_match_score * 100)}%`],
                ] as [string, string][]).filter(([, v]) => v).map(([k, v]) => (
                  <div key={k}>
                    <span className="text-neutral-400">{k}: </span>
                    <span className="font-mono text-neutral-700">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center">
              <p className="text-sm text-neutral-500 mb-3">Step 1 — verify identity with ID document + selfie</p>
              <button
                type="button"
                onClick={() => setShowKYC(true)}
                className={`px-5 py-2.5 rounded-lg text-sm font-semibold border transition-all ${theme.bg} ${theme.color} ${theme.border} hover:opacity-80`}
              >
                Start Identity Verification
              </button>
              <p className="text-[10px] text-neutral-300 mt-2">Camera · ID scan + selfie · face match · Powered by Gemini Vision</p>
            </div>
          )}
        </div>

        {/* Email + Password (greyed out until KYC done) */}
        <div className={`space-y-3 transition-opacity ${kyc ? "opacity-100" : "opacity-40 pointer-events-none"}`}>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Email</label>
            <input
              type="email" value={form.email} onChange={set("email")} required={!!kyc}
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
              placeholder="alice@example.com"
            />
          </div>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Password</label>
            <input
              type="password" value={form.password} onChange={set("password")} required={!!kyc}
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
              placeholder="••••••••"
            />
          </div>
        </div>

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Password blinded via OPRF (Ristretto255) — {site} signs with ring signature — {site} earns 1 Token A.
        </div>

        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button
          type="submit"
          disabled={busy || !kyc || !form.email || !form.password}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            busy || !kyc || !form.email || !form.password
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : `${getSiteTheme(site).bg} ${getSiteTheme(site).color} ${getSiteTheme(site).border} hover:opacity-80`
          }`}
        >
          {busy ? "Enrolling..." : kyc ? `Create ${site} Account` : "Complete KYC first"}
        </button>
      </form>
    </>
  );
}

// ─── Login / Get KYC tab ──────────────────────────────────────────────────────

function LoginTab({ site }: { site: SiteName }) {
  const { wallets, spendTokenB, returnTokenB } = useWallet();
  const wallet = wallets[site];
  const theme = getSiteTheme(site);
  const [form, setForm] = useState<LoginForm>({ email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ profile: UserData; tokenBSpent: string } | null>(null);
  const [error, setError] = useState("");

  const set = (k: keyof LoginForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((p) => ({ ...p, [k]: e.target.value }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (wallet.tokensB.length === 0) {
      setError(`${site} has no Token B. Exchange Token A first (Site Treasury tab) or buy some.`);
      showToast("error", "No Token B", `${site} wallet is empty. Go to Site Treasury to exchange or buy Token B.`);
      return;
    }

    // Optimistic spend — we'll roll back on failure
    const tokenB = spendTokenB(site);
    if (!tokenB) {
      setError("Token B was consumed by a concurrent request.");
      return;
    }

    setBusy(true);
    try {
      const res = await fetch(`${API}/dev/get_kyc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: site, email: form.email, password: form.password, token_b: tokenB }),
      });
      const data = await res.json();
      if (!res.ok) {
        returnTokenB(site, tokenB); // rollback
        throw new Error(data.error ?? "KYC lookup failed");
      }

      setResult({ profile: data.profile, tokenBSpent: tokenB });
      showToast("success", `KYC Retrieved — ${site}`, `${site} spent 1 Token B. Sauron does not know which site asked.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg);
      showToast("error", "KYC failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {result && (
        <SuccessOverlay title="Identity Verified" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className={`${theme.bg} ${theme.border} border rounded-lg p-4`}>
              <p className={`${theme.color} font-bold`}>
                {result.profile.first_name} {result.profile.last_name}
              </p>
              <p className="text-neutral-500 text-xs mt-1">{result.profile.email}</p>
              <p className="text-neutral-400 text-xs">Country: {result.profile.country}</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4">
              <p className="text-xs text-neutral-400 mb-1">Token B spent by {site}</p>
              <p className="font-mono text-[10px] text-orange-600 break-all">{result.tokenBSpent}</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {site} spent 1 Token B to retrieve this identity. Sauron verified the ring signature but does not know which site asked.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        <div className={`rounded-lg p-4 border ${
          wallet.tokensB.length > 0
            ? "bg-neutral-50 border-neutral-200"
            : "bg-red-50 border-red-200"
        }`}>
          <div className="flex items-center justify-between">
            <p className="text-sm text-neutral-600">{site} Token B</p>
            <span className={`text-2xl font-bold tabular-nums ${
              wallet.tokensB.length > 0 ? "text-neutral-900" : "text-red-600"
            }`}>
              {wallet.tokensB.length}
            </span>
          </div>
          {wallet.tokensB.length === 0 && (
            <p className="text-xs text-red-600 mt-1">No Token B. Go to Treasury to exchange or buy.</p>
          )}
        </div>

        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Email</label>
          <input
            type="email" value={form.email} onChange={set("email")} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
            placeholder="alice@example.com"
          />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Password</label>
          <input
            type="password" value={form.password} onChange={set("password")} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
            placeholder="••••••••"
          />
        </div>

        {error && (
          <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>
        )}

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Password re-blinded via OPRF — {site} signs GET_KYC with ring sig — Sauron burns Token B and returns KYC — Sauron does not know which site asked.
        </div>

        <button
          type="submit"
          disabled={busy || wallet.tokensB.length === 0}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            wallet.tokensB.length === 0
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : busy
              ? "border-neutral-200 text-neutral-400"
              : "border-neutral-900 bg-neutral-900 text-white hover:bg-neutral-700"
          }`}
        >
          {busy ? "Fetching KYC..." : wallet.tokensB.length === 0 ? "No Token B" : `Login with Sauron KYC (1 Token B)`}
        </button>
      </form>
    </>
  );
}

// ─── ZKP Login tab ────────────────────────────────────────────────────────────

interface ZkpProofResult {
  proved_claims: string[];
  ring_size: number;
  client_ring_size: number;
  tokenBSpent: string;
}

function ZkpLoginTab({ site }: { site: SiteName }) {
  const { wallets, spendTokenB, returnTokenB } = useWallet();
  const wallet = wallets[site];
  const theme = getSiteTheme(site);
  const [email,       setEmail]       = useState("");
  const [password,    setPassword]    = useState("");
  const [minAge,      setMinAge]      = useState("");
  const [nationality, setNationality] = useState("");
  const [busy,        setBusy]        = useState(false);
  const [result,      setResult]      = useState<ZkpProofResult | null>(null);
  const [error,       setError]       = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (wallet.tokensB.length === 0) {
      const msg = `${site} has no Token B. Exchange Token A first (Site Treasury tab).`;
      setError(msg);
      showToast("error", "No Token B", msg);
      return;
    }

    const tokenB = spendTokenB(site);
    if (!tokenB) { setError("Token B was consumed by a concurrent request."); return; }

    setBusy(true);
    try {
      const body: Record<string, unknown> = {
        email,
        password,
        site_name: site,
        token_b: tokenB,
      };
      const parsedAge = minAge ? parseInt(minAge, 10) : null;
      if (parsedAge && !isNaN(parsedAge)) body.min_age = parsedAge;
      if (nationality.trim()) body.required_nationality = nationality.trim().toUpperCase();

      const res = await fetch(`${API}/dev/zkp_login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        returnTokenB(site, tokenB);
        throw new Error(data.error ?? data ?? "ZKP login failed");
      }

      setResult({
        proved_claims:    data.proved_claims,
        ring_size:        data.ring_size,
        client_ring_size: data.client_ring_size,
        tokenBSpent:      tokenB,
      });
      showToast("success", `ZKP Login — ${site}`,
        `Proved: ${data.proved_claims.join(", ")} • ring size ${data.ring_size}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg);
      showToast("error", "ZKP Login failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {result && (
        <SuccessOverlay title={`ZKP Login Verified — ${site}`} onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className={`${theme.bg} ${theme.border} border rounded-lg p-4`}>
              <p className={`${theme.color} font-bold mb-2`}>Proof Accepted ✓</p>
              <div className="flex flex-wrap gap-1.5">
                {result.proved_claims.map((c) => (
                  <span key={c}
                    className={`inline-block text-xs px-2.5 py-1 rounded-full font-medium ${theme.bg} ${theme.color} border ${theme.border}`}>
                    {c}
                  </span>
                ))}
              </div>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4 space-y-1">
              <p className="text-xs text-neutral-400">
                User ring: <span className="font-mono text-neutral-700">{result.ring_size} members</span>
              </p>
              <p className="text-xs text-neutral-400">
                Client ring: <span className="font-mono text-neutral-700">{result.client_ring_size} ZKP_ONLY clients</span>
              </p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4">
              <p className="text-xs text-neutral-400 mb-1">Token B spent by {site}</p>
              <p className="font-mono text-[10px] text-orange-600 break-all">{result.tokenBSpent}</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {site} proved it's a registered ZKP_ONLY client (client ring sig) and that a Sauron-registered user
              meets the criteria (user ring sig). Sauron does not learn who the user is or which site asked.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        <div className={`rounded-xl border-2 border-dashed ${theme.border} p-4 text-center`}>
          <p className={`text-xs font-bold uppercase tracking-wide ${theme.color} mb-1`}>Zero-Knowledge Proof Login</p>
          <p className="text-xs text-neutral-400">
            Prove you hold a valid Sauron identity — no personal data is revealed to {site}.
          </p>
        </div>

        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Sauron Email</label>
          <input
            type="email" value={email} onChange={(e) => setEmail(e.target.value)} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
            placeholder="alice@example.com"
          />
        </div>
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Sauron Password</label>
          <input
            type="password" value={password} onChange={(e) => setPassword(e.target.value)} required
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
            placeholder="••••••••"
          />
        </div>

        <div className="border border-neutral-100 rounded-lg p-4 space-y-3 bg-neutral-50">
          <p className="text-xs font-medium text-neutral-500 uppercase tracking-wide">Optional ZKP Claims</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Min Age</label>
              <input
                type="number" min={0} max={120} value={minAge}
                onChange={(e) => setMinAge(e.target.value)}
                className="w-full bg-white border border-neutral-200 text-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-400"
                placeholder="e.g. 18"
              />
            </div>
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Nationality (3-letter)</label>
              <input
                type="text" maxLength={3} value={nationality}
                onChange={(e) => setNationality(e.target.value)}
                className="w-full bg-white border border-neutral-200 text-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-400 uppercase"
                placeholder="e.g. FRA"
              />
            </div>
          </div>
        </div>

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400">
          Dual ring signature — user ring (filtered) + {site} client ring. No PII leaves the server.
        </div>

        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button
          type="submit"
          disabled={busy || !email || !password || wallet.tokensB.length === 0}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            wallet.tokensB.length === 0
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : busy || !email || !password
              ? "border-neutral-200 text-neutral-400"
              : `${theme.bg} ${theme.color} ${theme.border} hover:opacity-80`
          }`}
        >
          {busy
            ? "Proving..."
            : wallet.tokensB.length === 0
            ? "No Token B"
            : `Prove Identity to ${site} (1 Token B)`}
        </button>
      </form>
    </>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function UserExperience() {
  const { activeSite, setActiveSite, wallets } = useWallet();
  const wallet = wallets[activeSite];
  const theme = getSiteTheme(activeSite);
  const [tab, setTab] = useState<Tab>("register");
  const isZkp = SITE_TYPE[activeSite] === "ZKP_ONLY";

  return (
    <div className="min-h-screen bg-white text-neutral-900">
      <SiteBanner site={activeSite} onSwitch={setActiveSite} />

      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="flex items-center gap-4 mb-6 border border-neutral-200 rounded-lg px-5 py-3">
          <span className="text-xs text-neutral-400 flex-1">{activeSite} wallet</span>
          {isZkp && (
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${theme.bg} ${theme.color} ${theme.border}`}>
              ZKP_ONLY
            </span>
          )}
          <span className="flex items-center gap-1.5 text-sm">
            <span className="text-green-600 font-bold tabular-nums">{wallet.tokensA.length}</span>
            <span className="text-neutral-400 text-xs">Token A</span>
          </span>
          <span className="text-neutral-200">|</span>
          <span className="flex items-center gap-1.5 text-sm">
            <span className={`font-bold tabular-nums ${wallet.tokensB.length === 0 ? "text-red-500" : "text-orange-500"}`}>{wallet.tokensB.length}</span>
            <span className="text-neutral-400 text-xs">Token B</span>
          </span>
        </div>

        {isZkp ? (
          /* ── ZKP_ONLY sites: just show the ZKP login panel ── */
          <div className="border border-neutral-200 rounded-xl p-8">
            <div className="mb-6">
              <h2 className="text-base font-semibold text-neutral-900">ZKP Login — {activeSite}</h2>
              <p className="text-xs text-neutral-400 mt-1">
                Prove membership anonymously. {activeSite} learns only your ZKP claims, not your identity.
              </p>
            </div>
            <ZkpLoginTab site={activeSite} />
          </div>
        ) : (
          /* ── FULL_KYC sites: Register + KYC Login tabs ── */
          <>
            <div className="flex border border-neutral-200 rounded-lg overflow-hidden mb-6">
              <button
                onClick={() => setTab("register")}
                className={`flex-1 py-2.5 text-sm font-medium transition-all ${
                  tab === "register"
                    ? `${theme.bg} ${theme.color} border-b-2 ${theme.border}`
                    : "text-neutral-400 hover:text-neutral-700"
                }`}
              >
                Create Account
              </button>
              <button
                onClick={() => setTab("login")}
                className={`flex-1 py-2.5 text-sm font-medium transition-all relative ${
                  tab === "login"
                    ? "bg-neutral-900 text-white"
                    : "text-neutral-400 hover:text-neutral-700"
                }`}
              >
                Login (KYC)
                {wallet.tokensB.length === 0 && (
                  <span className="absolute top-1.5 right-3 w-1.5 h-1.5 rounded-full bg-red-500" />
                )}
              </button>
            </div>

            <div className="border border-neutral-200 rounded-xl p-8">
              {tab === "register" && (
                <>
                  <div className="mb-6">
                    <h2 className="text-base font-semibold text-neutral-900">Open a {activeSite} Account</h2>
                    <p className="text-xs text-neutral-400 mt-1">Identity committed once to Sauron, anonymously, forever reusable.</p>
                  </div>
                  <RegisterTab site={activeSite} />
                </>
              )}
              {tab === "login" && (
                <>
                  <div className="mb-6">
                    <h2 className="text-base font-semibold text-neutral-900">Quick Login via Sauron</h2>
                    <p className="text-xs text-neutral-400 mt-1">{activeSite} retrieves your KYC anonymously, spending 1 Token B.</p>
                  </div>
                  <LoginTab site={activeSite} />
                </>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
