"use client";

import { useState } from "react";
import { useWallet, SITES, getSiteTheme, API, type SiteName } from "../context/WalletContext";
import { showToast } from "../components/Toast";

// Local type for API responses
interface UserData { first_name: string; last_name: string; email: string; country: string; }

// ─── Types ────────────────────────────────────────────────────────────────────

type Tab = "register" | "login";

interface RegisterForm { firstName: string; lastName: string; email: string; password: string; country: string; }
interface LoginForm    { email: string; password: string; }

const COUNTRIES = ["FR", "DE", "GB", "ES", "IT", "NL", "BE", "PL", "SE", "PT", "US", "JP", "BR", "IN"];

const SITE_DESCRIPTIONS: Record<SiteName, string> = {
  Monzo:   "Digital bank account",
  Revolut: "Financial super-app",
  Binance: "Crypto exchange",
  N26:     "Mobile banking",
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

// ─── Register tab ─────────────────────────────────────────────────────────────

function RegisterTab({ site }: { site: SiteName }) {
  const { addTokensA } = useWallet();
  const theme = getSiteTheme(site);
  const [form, setForm] = useState<RegisterForm>({
    firstName: "", lastName: "", email: "", password: "", country: "FR",
  });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ tokenA: string; profile: UserData } | null>(null);
  const [error, setError] = useState("");

  const set = (k: keyof RegisterForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm((p) => ({ ...p, [k]: e.target.value }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.email || !form.password || !form.firstName || !form.lastName) return;

    setBusy(true);
    setError("");
    try {
      const res = await fetch(`${API}/dev/register_user`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          site_name:  site,
          email:      form.email,
          password:   form.password,
          first_name: form.firstName,
          last_name:  form.lastName,
          country:    form.country,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Registration failed");

      addTokensA(site, [data.signed_token_a]);

      const profile: UserData = {
        first_name: form.firstName,
        last_name:  form.lastName,
        email:      form.email,
        country:    form.country,
      };
      setResult({ tokenA: data.signed_token_a, profile });
      showToast("success", `User registered — ${site}`, `${form.firstName} ${form.lastName} enrolled. ${site} earned 1 Token A.`);
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
      {result && (
        <SuccessOverlay title="Registration Successful!" onClose={() => setResult(null)}>
          <div className="space-y-3 text-sm">
            <div className="bg-emerald-950/50 border border-emerald-800 rounded-xl p-4">
              <p className="text-emerald-300 font-semibold mb-2">🎉 Welcome, {result.profile.first_name}!</p>
              <p className="text-neutral-600 text-xs leading-relaxed">
                KYC committed to the Sauron network via ring signature. {site} does not know your identity.
              </p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-4">
              <p className="text-xs text-neutral-400 mb-1">Token A earned by {site}</p>
              <p className="font-mono text-[10px] text-green-700 break-all">{result.tokenA}</p>
            </div>
            <div className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-neutral-500">
              {site} can exchange this Token A for {3} Token B to retrieve anonymous KYC data.
            </div>
          </div>
        </SuccessOverlay>
      )}

      <form onSubmit={submit} className="space-y-4 max-w-lg mx-auto">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">First Name</label>
            <input
              value={form.firstName} onChange={set("firstName")} required
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
              placeholder="Alice"
            />
          </div>
          <div>
            <label className="text-xs text-neutral-500 mb-1 block">Last Name</label>
            <input
              value={form.lastName} onChange={set("lastName")} required
              className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
              placeholder="Martin"
            />
          </div>
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
        <div>
          <label className="text-xs text-neutral-500 mb-1 block">Country</label>
          <select
            value={form.country} onChange={set("country")}
            className="w-full bg-white border border-neutral-300 text-neutral-900 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-neutral-500"
          >
            {COUNTRIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>

        <div className="border border-neutral-200 rounded-lg p-3 text-xs text-neutral-400 space-y-0.5">
          <p>What happens: password blinded via OPRF (Ristretto255) — identity key derived — {site} signs with ring signature — Sauron adds key to anonymous group — {site} earns 1 Token A.</p>
        </div>

        {error && (
          <div className="border border-red-200 bg-red-50 rounded-lg p-3 text-xs text-red-600">{error}</div>
        )}

        <button
          type="submit"
          disabled={busy || !form.email || !form.firstName}
          className={`w-full py-2.5 rounded-lg font-semibold text-sm transition-all border ${
            busy
              ? "border-neutral-200 text-neutral-400"
              : `${getSiteTheme(site).bg} ${getSiteTheme(site).color} ${getSiteTheme(site).border} hover:opacity-80`
          }`}
        >
          {busy ? "Enrolling..." : `Create ${site} Account`}
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

// ─── Main page ────────────────────────────────────────────────────────────────

export default function UserExperience() {
  const { activeSite, setActiveSite, wallets } = useWallet();
  const wallet = wallets[activeSite];
  const theme = getSiteTheme(activeSite);
  const [tab, setTab] = useState<Tab>("register");

  return (
    <div className="min-h-screen bg-white text-neutral-900">
      <SiteBanner site={activeSite} onSwitch={setActiveSite} />

      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="flex items-center gap-4 mb-6 border border-neutral-200 rounded-lg px-5 py-3">
          <span className="text-xs text-neutral-400 flex-1">{activeSite} wallet</span>
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
      </div>
    </div>
  );
}
