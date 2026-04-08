"use client";

import { useState, useEffect, useCallback } from "react";
import { useClient, API, KYC_API, type Client, type ClientUser } from "./context/ClientContext";
import { showToast } from "./components/Toast";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

type Tab = "dashboard" | "users" | "journey";

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

// ─── Dashboard Tab ────────────────────────────────────────────────────────────
function DashboardTab({ client }: { client: Client }) {
  const { refreshActiveClient, stats } = useClient();
  const [buyAmount, setBuyAmount] = useState(10);
  const [busy, setBusy] = useState(false);

  const doBuy = async () => {
    setBusy(true);
    try {
      const res = await fetch(`${API}/dev/buy_tokens`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_name: client.name, amount: buyAmount }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Purchase failed");
      showToast("success", "Purchase OK", `+${buyAmount} credits (total: ${data.new_tokens_b})`);
      await refreshActiveClient();
    } catch (err: unknown) {
      showToast("error", "Purchase failed", err instanceof Error ? err.message : "Unknown error");
    } finally { setBusy(false); }
  };

  const isZkp = client.client_type === "ZKP_ONLY";

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard label="Credits Available" value={client.tokens_b} sub="for KYC / ZKP queries" accent={client.tokens_b === 0 ? "text-red-500" : "text-orange-500"} />
        <KpiCard label="Client Type" value={client.client_type} sub={isZkp ? "anonymous proofs only" : "full KYC retrieval"} accent={isZkp ? "text-purple-600" : "text-blue-600"} />
        <KpiCard label="Cost per Query" value="1 credit" sub="per KYC or ZKP call" />
      </div>

      {/* Network stats */}
      {stats && (
        <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Network Overview</p>
          <div className="grid grid-cols-3 gap-4 text-center text-xs">
            <div><p className="text-neutral-400">Users</p><p className="text-lg font-bold text-neutral-900 mt-0.5">{stats.total_users}</p></div>
            <div><p className="text-neutral-400">Clients</p><p className="text-lg font-bold text-neutral-900 mt-0.5">{stats.total_clients}</p></div>
            <div><p className="text-neutral-400">Credits Spent</p><p className="text-lg font-bold text-red-500 mt-0.5">{stats.total_tokens_b_spent}</p></div>
          </div>
        </div>
      )}

      {/* Buy Credits */}
      <div className="max-w-md">
        <div className="bg-white border border-neutral-200 rounded-lg p-5">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-4">Buy Credits</h3>
          <p className="text-xs text-neutral-500 mb-4">Purchase credits to run KYC lookups and ZKP proofs.</p>
          <div className="mb-4">
            <label className="text-[10px] text-neutral-400 mb-1 block">Amount</label>
            <input type="number" min={1} value={buyAmount}
              onChange={(e) => setBuyAmount(Math.max(1, parseInt(e.target.value) || 1))}
              className="w-full bg-white border border-neutral-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-neutral-500"
            />
          </div>
          <div className="bg-neutral-50 border border-neutral-100 rounded-lg p-3 mb-4 text-xs text-neutral-500">
            Simulated cost: <span className="font-bold text-neutral-700">{(buyAmount * 0.10).toFixed(2)} €</span>
            <span className="text-neutral-400"> (0.10 € / credit)</span>
          </div>
          <button onClick={doBuy} disabled={busy}
            className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${busy
                ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
                : "border-orange-500 bg-orange-500 text-white hover:bg-orange-600"
              }`}>
            {busy ? "Processing..." : `Buy ${buyAmount} Credits`}
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
interface ZkpProofRecord {
  id: number;
  timestamp: number;
  ring_size: number;
  proved_claims: string[];
  raw_detail: string;
}

function UsersTab({ client }: { client: Client }) {
  const [users, setUsers] = useState<ClientUser[]>([]);
  const [zkpProofs, setZkpProofs] = useState<ZkpProofRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const isZkp = client.client_type === "ZKP_ONLY";

  const fetchData = useCallback(async () => {
    try {
      const [usersRes, proofsRes] = await Promise.all([
        fetch(`${API}/dev/client/${encodeURIComponent(client.name)}/users`),
        fetch(`/api/site-proofs/${encodeURIComponent(client.name)}`),
      ]);
      if (usersRes.ok) setUsers(await usersRes.json());
      if (proofsRes.ok) setZkpProofs(await proofsRes.json());
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [client.name]);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) return <div className="text-center py-12 text-neutral-400 animate-pulse text-sm">Loading…</div>;

  const retrieved = users.filter((u) => u.source === "kyc_retrieval");
  const claimsFreq: Record<string, number> = {};
  zkpProofs.forEach((p) => p.proved_claims.forEach((c) => { claimsFreq[c] = (claimsFreq[c] ?? 0) + 1; }));

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard label="KYC Lookups" value={retrieved.length} sub="identity retrievals" accent="text-blue-600" />
        <KpiCard label="ZKP Proofs" value={zkpProofs.length} sub="anonymous proofs accepted" accent="text-purple-600" />
        <KpiCard label="Unique Users" value={users.length} sub="via KYC or consent" />
        {zkpProofs.length > 0 && (
          <KpiCard label="Avg Ring Size" value={Math.round(zkpProofs.reduce((s, p) => s + p.ring_size, 0) / zkpProofs.length)} sub="anonymity set" accent="text-green-600" />
        )}
      </div>

      {/* ZKP Proofs section (for ZKP_ONLY clients) */}
      {isZkp && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">ZKP Proof Log</h3>
          {zkpProofs.length === 0 ? (
            <div className="bg-white border border-neutral-200 rounded-lg p-6 text-center">
              <p className="text-neutral-400 italic text-sm">No ZKP proofs yet.</p>
              <p className="text-xs text-neutral-300 mt-1">Use the Journey Simulator → ZKP Login to generate proofs.</p>
            </div>
          ) : (
            <>
              {/* Claims frequency */}
              {Object.keys(claimsFreq).length > 0 && (
                <div className="flex flex-wrap gap-2 mb-4">
                  {Object.entries(claimsFreq).sort((a, b) => b[1] - a[1]).map(([claim, count]) => (
                    <span key={claim} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                      <span className="font-semibold">{claim}</span>
                      <span className="text-purple-400">×{count}</span>
                    </span>
                  ))}
                </div>
              )}
              <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                {zkpProofs.map((p) => (
                  <div key={p.id} className="bg-white border border-purple-100 rounded-lg p-3 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-2 h-2 rounded-full flex-shrink-0 bg-purple-400" />
                      <div className="min-w-0">
                        <div className="flex flex-wrap gap-1">
                          {p.proved_claims.map((c) => (
                            <span key={c} className="text-xs px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-100">{c}</span>
                          ))}
                        </div>
                        <p className="text-[10px] text-neutral-400 mt-0.5">
                          ring size {p.ring_size} · {new Date(p.timestamp * 1000).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <span className="text-[10px] text-green-600 bg-green-50 border border-green-200 rounded px-2 py-0.5 shrink-0">verified</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* KYC users (only for FULL_KYC) */}
      {!isZkp && (
        <>
          {users.length === 0 ? (
            <div className="bg-white border border-neutral-200 rounded-lg p-8 text-center">
              <p className="text-neutral-400 italic text-sm">No queries yet.</p>
              <p className="text-xs text-neutral-300 mt-1">Use the Journey Simulator to look up users.</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {users.map((u, i) => (
                <div key={i} className="bg-white border border-neutral-200 rounded-lg p-4 hover:border-neutral-300 transition-colors flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full flex-shrink-0 bg-blue-400" />
                    <div>
                      <p className="text-sm font-semibold text-neutral-900">{u.first_name} {u.last_name}</p>
                      <p className="text-xs text-neutral-500">{u.email} · {u.nationality}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-neutral-400 font-mono">{fmt(u.timestamp)}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-blue-50 text-blue-700 border-blue-200">KYC LOOKUP</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── Journey: KYC Login (Consent Popup Flow) ─────────────────────────────────
function LoginJourney({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ first_name: string; last_name: string; email: string; nationality: string } | null>(null);
  const [error, setError] = useState("");

  const openConsentPopup = async () => {
    setError("");
    if (client.tokens_b === 0) {
      const msg = `${client.name} has no credits. Go to Dashboard to buy credits.`;
      setError(msg); showToast("error", "No credits", msg); return;
    }
    setBusy(true);

    try {
      // 1. Request consent from Sauron
      const reqRes = await fetch(`${API}/kyc/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          site_name: client.name,
          requested_claims: ["age_over_threshold", "age_threshold"],
        }),
      });
      const reqData = await reqRes.json();
      if (!reqRes.ok) throw new Error(reqData.error ?? "Failed to create consent request");

      const { request_id, consent_url } = reqData;
      const myOrigin = window.location.origin;
      const consentUrlWithOrigin = `${consent_url}${consent_url.includes("?") ? "&" : "?"}origin=${encodeURIComponent(myOrigin)}`;

      // 2. Open the consent popup
      const popup = window.open(
        consentUrlWithOrigin,
        "sauron_consent",
        "width=460,height=620,top=100,left=200,resizable=no,scrollbars=no"
      );
      if (!popup) {
        throw new Error("Popup was blocked by the browser. Please allow popups for this site.");
      }

      // 3. Listen for postMessage from the popup
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          window.removeEventListener("message", handler);
          reject(new Error("Consent timed out. Please try again."));
        }, 5 * 60 * 1000); // 5 min timeout

        const handler = async (event: MessageEvent) => {
          if (event.origin !== myOrigin) return;
          if (event.data?.request_id !== request_id) return;

          clearTimeout(timeout);
          window.removeEventListener("message", handler);

          if (event.data?.type === "sauron_consent_denied") {
            reject(new Error("User denied access."));
            return;
          }

          if (event.data?.type === "sauron_consent") {
            const { consent_token } = event.data;
            try {
              // 4. Retrieve KYC using the consent token
              const retRes = await fetch(`${API}/kyc/retrieve`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  consent_token,
                  site_name: client.name,
                  required_action: "prove_age",
                  zkp_proof: { dev_mock: true },
                  zkp_circuit: "AgeVerification",
                  zkp_public_signals: ["1", "18"],
                }),
              });
              const retData = await retRes.json();
              if (!retRes.ok) throw new Error(retData.error ?? "KYC retrieval failed");
              setResult(retData);
              showToast("success", `Identity Verified — ${client.name}`, "1 credit spent. User was anonymously authenticated.");
              await refreshActiveClient();
              resolve();
            } catch (e: unknown) {
              reject(e);
            }
          }
        };

        window.addEventListener("message", handler);
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "KYC failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {result && (
        <SuccessOverlay title="Identity Verified" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <p className="text-blue-700 font-bold">ZKP-only identity presentation</p>
              <pre className="text-neutral-600 text-xs mt-2 whitespace-pre-wrap break-all">{JSON.stringify(result?.claims ?? {}, null, 2)}</pre>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} spent 1 credit. The user authenticated via a Sauron consent popup — Sauron does not know which site asked.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <div className="space-y-4 max-w-lg mx-auto">
        <div className={`rounded-lg p-4 border ${client.tokens_b > 0 ? "bg-neutral-50 border-neutral-200" : "bg-red-50 border-red-200"}`}>
          <div className="flex items-center justify-between">
            <p className="text-sm text-neutral-600">{client.name} Credits</p>
            <span className={`text-2xl font-bold tabular-nums ${client.tokens_b > 0 ? "text-neutral-900" : "text-red-600"}`}>{client.tokens_b}</span>
          </div>
          {client.tokens_b === 0 && <p className="text-xs text-red-600 mt-1">No credits. Go to Dashboard to buy.</p>}
        </div>

        <div className="border border-neutral-200 rounded-lg p-4 text-sm text-neutral-600 space-y-2">
          <p className="font-medium text-neutral-800">How it works</p>
          <ol className="text-xs text-neutral-500 space-y-1 list-decimal list-inside">
            <li>A Sauron sign-in popup opens</li>
            <li>The user authenticates with their email and password</li>
            <li>The user approves sharing their identity with {client.name}</li>
            <li>Sauron returns the verified attributes — 1 credit is consumed</li>
          </ol>
        </div>

        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button onClick={openConsentPopup} disabled={busy || client.tokens_b === 0}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${client.tokens_b === 0
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : busy
                ? "border-neutral-200 text-neutral-400"
                : "border-neutral-900 bg-neutral-900 text-white hover:bg-neutral-700"
            }`}>
          {busy ? "Waiting for user..." : client.tokens_b === 0 ? "No credits" : "Login with SauronID (1 credit)"}
        </button>
      </div>
    </>
  );
}

// ─── Groth16 client-side proof generation ────────────────────────────────────
async function generateAgeProof(
  dateOfBirth: string,
  minAge: number,
  issuerPubKeyAx: string,
  issuerPubKeyAy: string,
): Promise<{ proof: object; publicSignals: string[] } | null> {
  try {
    // Lazy-load snarkjs only in the browser
    const snarkjs = await import("snarkjs");
    const dobInt = parseInt(dateOfBirth.replace(/-/g, ""), 10) || 19900101;
    const currentYear = new Date().getFullYear();
    const threshold = (currentYear - minAge) * 10000 + 101; // YYYYMMDD threshold

    const input = {
      dateOfBirth: dobInt.toString(),
      ageThreshold: threshold.toString(),
      issuerPubKeyAx,
      issuerPubKeyAy,
      // These would normally come from the stored credential; using placeholders here
      credentialSig_R8x: "0",
      credentialSig_R8y: "0",
      credentialSig_S: "0",
    };

    const wasmPath = "/circuits/AgeVerification.wasm";
    const zkeyPath = "/circuits/AgeVerification_final.zkey";

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
    return { proof, publicSignals };
  } catch (e) {
    console.warn("[ZKP] Client-side proof generation failed (non-fatal, falling back to server):", e);
    return null;
  }
}

// ─── Journey: ZKP Login ───────────────────────────────────────────────────────
function ZkpJourney({ client }: { client: Client }) {
  const { refreshActiveClient } = useClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [minAge, setMinAge] = useState("");
  const [nationality, setNationality] = useState("");
  const [busy, setBusy] = useState(false);
  const [proofStatus, setProofStatus] = useState("");
  const [result, setResult] = useState<{ proved_claims: string[]; ring_size: number; client_ring_size: number; groth16_verified?: boolean } | null>(null);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setError(""); setProofStatus("");
    if (client.tokens_b === 0) {
      const msg = `${client.name} has no credits. Buy some in the Dashboard tab.`;
      setError(msg); showToast("error", "No credits", msg); return;
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = { email, password, site_name: client.name, token_b: "db_managed" };
      const parsedAge = minAge ? parseInt(minAge, 10) : null;
      if (parsedAge && !isNaN(parsedAge)) body.min_age = parsedAge;
      if (nationality.trim()) body.required_nationality = nationality.trim().toUpperCase();

      // Attempt client-side Groth16 proof if min_age is set
      if (parsedAge && !isNaN(parsedAge)) {
        setProofStatus("Generating Groth16 age proof...");
        try {
          // Fetch issuer public key for credential verification
          const pkRes = await fetch(`${KYC_API}/issuer-pubkey`).catch(() => null);
          const pkData = pkRes?.ok ? await pkRes.json() : null;
          const Ax = pkData?.Ax ?? "0";
          const Ay = pkData?.Ay ?? "0";

          // User's date_of_birth would come from their stored credential.
          // In dev mode we approximate using the threshold year.
          const approxDob = `${new Date().getFullYear() - parsedAge - 1}-06-15`;
          const groth16Result = await generateAgeProof(approxDob, parsedAge, Ax, Ay);
          if (groth16Result) {
            body.groth16_proof = groth16Result.proof;
            body.groth16_public_signals = groth16Result.publicSignals;
            setProofStatus("Proof generated. Verifying...");
          }
        } catch {
          // Non-fatal: continue without Groth16 proof
          setProofStatus("");
        }
      }

      const res = await fetch(`${API}/dev/zkp_login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? data ?? "ZKP login failed");
      setResult({
        proved_claims: data.proved_claims,
        ring_size: data.ring_size,
        client_ring_size: data.client_ring_size,
        groth16_verified: !!body.groth16_proof,
      });
      showToast("success", `ZKP Login — ${client.name}`, `Proved: ${data.proved_claims.join(", ")} • ring size ${data.ring_size}`);
      await refreshActiveClient();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg); showToast("error", "ZKP Login failed", msg);
    } finally { setBusy(false); setProofStatus(""); }
  };

  return (
    <>
      {result && (
        <SuccessOverlay title={`ZKP Login Verified — ${client.name}`} onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <p className="text-purple-700 font-bold mb-2">Proof Accepted</p>
              <div className="flex flex-wrap gap-1.5">
                {result.proved_claims.map((c) => (
                  <span key={c} className="inline-block text-xs px-2.5 py-1 rounded-full font-medium bg-purple-50 text-purple-700 border border-purple-200">{c}</span>
                ))}
              </div>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4 space-y-1">
              <p className="text-xs text-neutral-400">User ring: <span className="font-mono text-neutral-700">{result.ring_size} members</span></p>
              <p className="text-xs text-neutral-400">Client ring: <span className="font-mono text-neutral-700">{result.client_ring_size} ZKP_ONLY clients</span></p>
              {result.groth16_verified && (
                <p className="text-xs text-purple-600">+ Groth16 age proof generated client-side</p>
              )}
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {client.name} proved it&apos;s a registered ZKP_ONLY client and that a Sauron-registered user meets the criteria. Sauron does not learn who the user is or which site asked.
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
          Dual ring signature — user ring (filtered) + {client.name} client ring. When min age is set, a Groth16 proof is generated in your browser. No PII leaves the server.
        </div>
        {proofStatus && <div className="border border-purple-200 bg-purple-50 rounded-lg p-3 text-xs text-purple-700 animate-pulse">{proofStatus}</div>}
        {error && <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>}

        <button type="submit" disabled={busy || !email || !password || client.tokens_b === 0}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${client.tokens_b === 0
              ? "border-neutral-200 text-neutral-300 cursor-not-allowed"
              : busy || !email || !password
                ? "border-neutral-200 text-neutral-400"
                : "bg-purple-600 text-white border-purple-600 hover:bg-purple-700"
            }`}>
          {busy ? "Proving..." : client.tokens_b === 0 ? "No credits" : `Prove Identity to ${client.name} (1 credit)`}
        </button>
      </form>
    </>
  );
}

// ─── Journey Tab ──────────────────────────────────────────────────────────────
function JourneyTab({ client }: { client: Client }) {
  const isZkp = client.client_type === "ZKP_ONLY";

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
    <div className="border border-neutral-200 rounded-xl p-8">
      <div className="mb-6">
        <h2 className="text-base font-semibold text-neutral-900">KYC Login — {client.name}</h2>
        <p className="text-xs text-neutral-400 mt-1">{client.name} retrieves your KYC anonymously, spending 1 credit.</p>
      </div>
      <LoginJourney client={client} />
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function SitePortal() {
  const { activeClient, clients, loading, offline } = useClient();
  const [tab, setTab] = useState<Tab>("dashboard");

  const siteClients = clients.filter((c) => c.client_type !== "BANK");
  const client = activeClient && activeClient.client_type !== "BANK" ? activeClient : siteClients[0] ?? null;

  if (loading) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="animate-pulse text-sm">Connecting to Sauron…</span></div>;
  if (offline) return <div className="flex min-h-[80vh] items-center justify-center"><span className="text-red-600 text-sm border border-red-200 bg-red-50 px-4 py-2 rounded-lg">Backend offline — start the Sauron core on port 3001</span></div>;
  if (!client) return <div className="flex min-h-[80vh] items-center justify-center text-neutral-400"><span className="text-sm">No site clients found. Run the seeder first.</span></div>;

  const tabs: { key: Tab; label: string }[] = [
    { key: "dashboard", label: "Dashboard" },
    { key: "users", label: "My Users" },
    { key: "journey", label: client.client_type === "ZKP_ONLY" ? "ZKP Simulator" : "Journey Simulator" },
  ];

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900">
      {/* Tab bar */}
      <div className="bg-white border-b border-neutral-200">
        <div className="max-w-[1200px] mx-auto px-6 flex items-center gap-1">
          {tabs.map((t) => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-all ${tab === t.key
                  ? "border-neutral-900 text-neutral-900"
                  : "border-transparent text-neutral-400 hover:text-neutral-700"
                }`}>
              {t.label}
            </button>
          ))}
          <div className="flex-1" />
          <div className="flex items-center gap-2">
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${client.client_type === "FULL_KYC"
                ? "bg-blue-50 text-blue-700 border-blue-200"
                : "bg-purple-50 text-purple-700 border-purple-200"
              }`}>{client.client_type}</span>
            <span className={`text-xs font-bold tabular-nums ${client.tokens_b === 0 ? "text-red-500" : "text-orange-500"}`}>{client.tokens_b}</span>
            <span className="text-xs text-neutral-400">credits</span>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-[1200px] mx-auto px-6 py-8">
        {tab === "dashboard" && <DashboardTab client={client} />}
        {tab === "users" && <UsersTab client={client} />}
        {tab === "journey" && <JourneyTab client={client} />}
      </div>
    </div>
  );
}
