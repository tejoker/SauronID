"use client";

import { useEffect, useMemo, useState } from "react";
import { API } from "../context/ClientContext";
import { showToast } from "../components/Toast";

type Product = {
  id: string;
  name: string;
  subtitle: string;
  price: number;
  category: string;
  ageRestricted?: boolean;
};

type CartItem = Product & { qty: number };

const PRODUCTS: Product[] = [
  {
    id: "p1",
    name: "Nebula Headphones",
    subtitle: "Wireless ANC, 38h battery",
    price: 189.0,
    category: "Electronics",
  },
  {
    id: "p2",
    name: "Arc Runner Sneakers",
    subtitle: "Lightweight knit, all-day comfort",
    price: 129.0,
    category: "Fashion",
  },
  {
    id: "p3",
    name: "Reserve Single Malt",
    subtitle: "12-year, 700ml bottle",
    price: 74.0,
    category: "Spirits",
    ageRestricted: true,
  },
];

const DEMO_MIN_CREDITS = 1;

type MerchantClient = {
  name: string;
  client_type: "FULL_KYC" | "ZKP_ONLY" | "BANK";
  tokens_b: number;
};

type ConsentMessage = {
  type: "sauron_consent";
  request_id: string;
  consent_token: string;
};

type ConsentRequestResponse = {
  request_id: string;
  consent_url: string;
};

type RetrieveResponse = {
  claims?: Record<string, unknown>;
  proof?: {
    verified?: boolean;
  };
  identity?: {
    is_agent?: boolean;
    trust_verified?: boolean;
    agent_id?: string | null;
  };
};

type ActorMode = "user" | "agent";

type UserProfile = {
  first_name: string;
  last_name: string;
  email: string;
  date_of_birth: string;
  nationality: string;
};

type AgeCheckResponse = UserProfile & {
  min_age: number;
  is_over_threshold: boolean;
  profile_complete: boolean;
  missing_fields: string[];
};

export default function RetailPage() {
  const [actorMode, setActorMode] = useState<ActorMode>("user");
  const [agentAjwt, setAgentAjwt] = useState("");
  const [cart, setCart] = useState<Record<string, number>>({});
  const [step, setStep] = useState<"cart" | "checkout" | "paid">("cart");
  const [merchant, setMerchant] = useState<MerchantClient | null>(null);
  const [loadingMerchant, setLoadingMerchant] = useState(true);
  const [loggingIn, setLoggingIn] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const [proofClaims, setProofClaims] = useState<Record<string, unknown> | null>(null);
  const [identitySummary, setIdentitySummary] = useState<RetrieveResponse["identity"] | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isAdult, setIsAdult] = useState<boolean | null>(null);
  const [orderId, setOrderId] = useState("");
  const [paying, setPaying] = useState(false);

  const [email, setEmail] = useState("buyer@example.com");
  const [fullName, setFullName] = useState("Alex Buyer");
  const [address, setAddress] = useState("12 Market Street, Paris");
  const [cardNumber, setCardNumber] = useState("4242 4242 4242 4242");
  const [expiry, setExpiry] = useState("12/28");
  const [cvc, setCvc] = useState("123");

  const cartItems: CartItem[] = useMemo(
    () =>
      PRODUCTS.filter((p) => (cart[p.id] ?? 0) > 0).map((p) => ({
        ...p,
        qty: cart[p.id],
      })),
    [cart]
  );

  const subtotal = useMemo(
    () => cartItems.reduce((sum, i) => sum + i.price * i.qty, 0),
    [cartItems]
  );
  const shipping = subtotal > 0 ? 6.9 : 0;
  const total = subtotal + shipping;

  const resetJourney = () => {
    setCart({});
    setStep("cart");
    setLoggedIn(false);
    setProofClaims(null);
    setIdentitySummary(null);
    setProfile(null);
    setIsAdult(null);
    setOrderId("");
    setPaying(false);
  };

  const loadProfileFromDbAgeCheck = async (consentToken: string) => {
    if (!merchant) throw new Error("Merchant not configured");

    const res = await fetch(`${API}/kyc/age_check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        consent_token: consentToken,
        site_name: merchant.name,
        min_age: 18,
        required_fields: ["first_name", "last_name", "email", "date_of_birth", "nationality"],
      }),
    });
    const data = (await res.json()) as Partial<AgeCheckResponse> & { error?: string; detail?: string };
    if (!res.ok) {
      throw new Error(data.error || data.detail || "Unable to verify age from DB");
    }
    if (data.profile_complete !== true) {
      const missing = Array.isArray(data.missing_fields) ? data.missing_fields.join(", ") : "unknown fields";
      throw new Error(`Persona missing required data: ${missing}`);
    }
    if (typeof data.first_name !== "string" || typeof data.last_name !== "string" || typeof data.email !== "string") {
      throw new Error("DB persona payload invalid");
    }

    const profileData: UserProfile = {
      first_name: data.first_name,
      last_name: data.last_name,
      email: data.email,
      date_of_birth: typeof data.date_of_birth === "string" ? data.date_of_birth : "",
      nationality: typeof data.nationality === "string" ? data.nationality : "",
    };

    setProfile(profileData);
    setFullName(`${profileData.first_name} ${profileData.last_name}`.trim());
    setEmail(profileData.email);
    setIsAdult(data.is_over_threshold === true);
  };

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API}/dev/clients`);
        const clients = (await res.json()) as MerchantClient[];
        const chosen = clients.find((c) => c.client_type === "ZKP_ONLY") || clients[0] || null;
        if (!chosen) {
          showToast("error", "No merchant client", "Create a client first in Site Portal or seed data.");
          setLoadingMerchant(false);
          return;
        }

        const detail = await fetch(`${API}/dev/client/${encodeURIComponent(chosen.name)}`);
        if (detail.ok) {
          setMerchant(await detail.json());
        } else {
          setMerchant(chosen);
        }
      } catch {
        showToast("error", "Backend offline", "Start core API on port 3001.");
      } finally {
        setLoadingMerchant(false);
      }
    })();
  }, []);

  const refreshMerchant = async () => {
    if (!merchant) return;
    const detail = await fetch(`${API}/dev/client/${encodeURIComponent(merchant.name)}`);
    if (detail.ok) setMerchant(await detail.json());
  };

  const ensureMerchantCredits = async () => {
    if (!merchant) return;

    let current = merchant;
    const detail = await fetch(`${API}/dev/client/${encodeURIComponent(merchant.name)}`);
    if (detail.ok) {
      current = (await detail.json()) as MerchantClient;
      setMerchant(current);
    }

    const currentBalance = current.tokens_b ?? 0;
    if (currentBalance >= DEMO_MIN_CREDITS) return;

    const refillAmount = DEMO_MIN_CREDITS - currentBalance;

    const topUp = await fetch(`${API}/dev/buy_tokens`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ site_name: merchant.name, amount: refillAmount }),
    });
    if (!topUp.ok) {
      throw new Error("Cannot add demo credits for merchant");
    }
    await refreshMerchant();
  };

  const addToCart = (p: Product) => {
    if (!loggedIn) {
      showToast("error", "Login first", "Run Sauron login simulation before shopping.");
      return;
    }
    if (p.ageRestricted && isAdult !== true) {
      showToast("error", "Age restricted", "This product is 18+ and this persona is not in 18+ eligibility.");
      return;
    }
    setCart((prev) => ({ ...prev, [p.id]: (prev[p.id] ?? 0) + 1 }));
  };

  const changeQty = (id: string, qty: number) => {
    setCart((prev) => {
      if (qty <= 0) {
        const next = { ...prev };
        delete next[id];
        return next;
      }
      return { ...prev, [id]: qty };
    });
  };

  const openConsentPopup = async (requestId: string, consentUrl: string): Promise<ConsentMessage> => {
    const popupUrl = `${consentUrl}${consentUrl.includes("?") ? "&" : "?"}origin=${encodeURIComponent(window.location.origin)}`;
    const popup = window.open(
      popupUrl,
      "sauron_chrome_extension",
      "width=460,height=640,top=80,left=200,resizable=no,scrollbars=no"
    );
    if (!popup) throw new Error("Popup blocked. Allow popups and retry.");

    return new Promise<ConsentMessage>((resolve, reject) => {
      const timeout = setTimeout(() => {
        window.removeEventListener("message", handler);
        reject(new Error("Consent timed out"));
      }, 5 * 60 * 1000);

      const handler = (event: MessageEvent<unknown>) => {
        if (event.origin !== window.location.origin) return;
        if (!event.data || typeof event.data !== "object") return;
        const payload = event.data as Record<string, unknown>;
        if (payload.request_id !== requestId) return;

        clearTimeout(timeout);
        window.removeEventListener("message", handler);

        if (
          payload.type === "sauron_consent" &&
          typeof payload.request_id === "string" &&
          typeof payload.consent_token === "string"
        ) {
          resolve({
            type: "sauron_consent",
            request_id: payload.request_id,
            consent_token: payload.consent_token,
          });
          return;
        }
        reject(new Error("Consent denied"));
      };

      window.addEventListener("message", handler);
    });
  };

  const createConsentRequest = async (): Promise<ConsentRequestResponse> => {
    if (!merchant) throw new Error("Merchant not configured");

    const reqRes = await fetch(`${API}/kyc/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        site_name: merchant.name,
        requested_claims: ["age_over_threshold", "age_threshold"],
      }),
    });
    const reqData = (await reqRes.json()) as Record<string, unknown>;
    if (!reqRes.ok || typeof reqData.request_id !== "string" || typeof reqData.consent_url !== "string") {
      throw new Error((reqData.error as string) || (reqData.detail as string) || "Unable to start Sauron consent");
    }

    return {
      request_id: reqData.request_id,
      consent_url: reqData.consent_url,
    };
  };

  const retrieveWithConsent = async (consentToken: string, agentToken?: string) => {
    if (!merchant) throw new Error("Merchant not configured");

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (agentToken) headers["x-agent-ajwt"] = agentToken;

    const retRes = await fetch(`${API}/kyc/retrieve`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        consent_token: consentToken,
        site_name: merchant.name,
        required_action: "prove_age",
        zkp_proof: { dev_mock: true },
        zkp_circuit: "AgeVerification",
        zkp_public_signals: ["1", "18"],
      }),
    });
    const retData = (await retRes.json()) as Record<string, unknown>;
    if (!retRes.ok) {
      throw new Error((retData.error as string) || (retData.detail as string) || "Sauron verification failed");
    }

    const typed = retData as RetrieveResponse;
    if (typed.proof?.verified !== true) {
      throw new Error("ID proof verification failed");
    }
    if (typed.identity?.trust_verified !== true) {
      throw new Error("Identity trust verification failed");
    }

    setLoggedIn(true);
    setProofClaims(typed.claims || null);
    setIdentitySummary(typed.identity || null);
    await refreshMerchant();
  };

  const loginAsUserWithPopup = async () => {
    if (!merchant) return;
    setLoggingIn(true);
    try {
      await ensureMerchantCredits();
      const reqData = await createConsentRequest();
      const consentData = await openConsentPopup(reqData.request_id, reqData.consent_url);
      await loadProfileFromDbAgeCheck(consentData.consent_token);
      await retrieveWithConsent(consentData.consent_token);
      showToast("success", "User login verified", "Sauron flow complete. You can now shop and pay.");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      showToast("error", "User login failed", message);
    } finally {
      setLoggingIn(false);
    }
  };

  const loginAsAgent = async () => {
    if (!merchant) return;
    if (!agentAjwt.trim()) {
      showToast("error", "A-JWT required", "Paste a delegated or autonomous agent token first.");
      return;
    }

    setLoggingIn(true);
    try {
      await ensureMerchantCredits();
      const reqData = await createConsentRequest();

      const consentRes = await fetch(`${API}/agent/kyc/consent`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ajwt: agentAjwt.trim(),
          site_name: merchant.name,
          request_id: reqData.request_id,
        }),
      });
      const consentData = (await consentRes.json()) as Record<string, unknown>;
      if (!consentRes.ok || typeof consentData.consent_token !== "string") {
        throw new Error((consentData.error as string) || (consentData.detail as string) || "Agent consent failed");
      }

      await loadProfileFromDbAgeCheck(consentData.consent_token);
      await retrieveWithConsent(consentData.consent_token, agentAjwt.trim());
      showToast("success", "Agent login verified", "Agent-mediated Sauron flow complete. You can now shop and pay.");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      showToast("error", "Agent login failed", message);
    } finally {
      setLoggingIn(false);
    }
  };

  const submitPayment = async () => {
    if (!loggedIn) {
      showToast("error", "Login required", "Run user or agent login simulation before payment.");
      return;
    }
    if (!profile) {
      showToast("error", "Persona required", "No DB persona loaded for this session.");
      return;
    }

    const expectedName = `${profile.first_name} ${profile.last_name}`.trim().toLowerCase();
    if (fullName.trim().toLowerCase() !== expectedName || email.trim().toLowerCase() !== profile.email.toLowerCase()) {
      showToast("error", "Identity mismatch", "Checkout identity must match DB persona.");
      return;
    }

    const hasRestricted = cartItems.some((i) => i.ageRestricted);
    if (hasRestricted && isAdult !== true) {
      showToast("error", "Age restricted", "Persona not in 18+ eligibility ring. Purchase blocked.");
      return;
    }

    setPaying(true);
    try {
      await new Promise((r) => setTimeout(r, 1200));
      const oid = `ORD-${Date.now().toString().slice(-8)}`;
      setOrderId(oid);
      setStep("paid");
      showToast("success", "Payment complete", `Order ${oid} paid successfully.`);
    } finally {
      setPaying(false);
    }
  };

  if (loadingMerchant) {
    return <div className="max-w-6xl mx-auto px-6 py-12 text-sm text-neutral-500">Loading retail experience...</div>;
  }

  return (
    <div className="min-h-screen bg-neutral-50">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        <header className="bg-white border border-neutral-200 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-widest text-neutral-400">Sauron Client Experience</p>
            <h1 className="text-2xl font-bold text-neutral-900">Retail Checkout Demo</h1>
            <p className="text-sm text-neutral-500 mt-1">Merchant simulation with strict DB persona checks and proof verification.</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-neutral-400">Merchant</p>
            <p className="text-sm font-semibold text-neutral-800">{merchant?.name || "Not configured"}</p>
          </div>
        </header>

        <section className="bg-white border border-neutral-200 rounded-2xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Step 1: Simulate login</h2>
            <div className="inline-flex rounded-lg border border-neutral-300 overflow-hidden">
              <button
                onClick={() => {
                  setActorMode("user");
                  resetJourney();
                }}
                className={`px-3 py-1.5 text-xs font-semibold ${actorMode === "user" ? "bg-neutral-900 text-white" : "bg-white text-neutral-700"}`}
              >
                Sauron User
              </button>
              <button
                onClick={() => {
                  setActorMode("agent");
                  resetJourney();
                }}
                className={`px-3 py-1.5 text-xs font-semibold ${actorMode === "agent" ? "bg-neutral-900 text-white" : "bg-white text-neutral-700"}`}
              >
                Agent
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 space-y-3">
            <p className="text-sm text-neutral-600">
              {actorMode === "user"
                ? "Run login as normal Sauron user via extension window."
                : "Run delegated login with A-JWT agent token."}
            </p>

            {actorMode === "agent" && (
              <textarea
                value={agentAjwt}
                onChange={(e) => setAgentAjwt(e.target.value)}
                rows={3}
                placeholder="Paste agent A-JWT"
                className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-xs font-mono"
              />
            )}

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={actorMode === "user" ? loginAsUserWithPopup : loginAsAgent}
                disabled={loggingIn}
                className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold disabled:opacity-50"
              >
                {loggingIn ? "Running login..." : actorMode === "user" ? "Login with Sauron" : "Login as Agent"}
              </button>
              <button
                onClick={resetJourney}
                className="px-4 py-2 rounded-lg border border-neutral-300 text-sm font-semibold"
              >
                Reset journey
              </button>
            </div>

            <div className="text-xs text-neutral-500">
              {loggedIn
                ? `Login done. trust_verified=${identitySummary?.trust_verified ? "true" : "false"} | is_agent=${identitySummary?.is_agent ? "true" : "false"}`
                : "Not logged in yet."}
            </div>
            {profile && (
              <div className="text-xs text-neutral-500">
                Persona(DB): {profile.first_name} {profile.last_name} ({profile.email}) • DOB {profile.date_of_birth} • {isAdult ? "18+" : "under 18"}
              </div>
            )}
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2 bg-white border border-neutral-200 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Products</h2>
              <span className="text-xs px-2 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">Step 2: Choose articles</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {PRODUCTS.map((p) => (
                <div key={p.id} className="border border-neutral-200 rounded-xl p-4 flex flex-col gap-3">
                  <div className="h-28 rounded-lg bg-gradient-to-br from-neutral-100 to-neutral-200" />
                  <div>
                    <p className="font-semibold text-neutral-900">{p.name}</p>
                    <p className="text-xs text-neutral-500">{p.subtitle}</p>
                  </div>
                  <div className="flex items-center justify-between">
                    <p className="font-bold">EUR {p.price.toFixed(2)}</p>
                    {p.ageRestricted && (
                      <span className="text-[10px] px-2 py-1 rounded-full bg-amber-50 text-amber-700 border border-amber-200">18+</span>
                    )}
                  </div>
                  <button
                    onClick={() => addToCart(p)}
                    disabled={!loggedIn || (p.ageRestricted && isAdult !== true)}
                    className="mt-auto w-full py-2 rounded-lg bg-neutral-900 text-white text-sm font-medium hover:bg-neutral-700 disabled:opacity-50"
                  >
                    {p.ageRestricted && isAdult !== true ? "18+ blocked" : "Add to basket"}
                  </button>
                </div>
              ))}
            </div>
          </div>

          <aside className="space-y-4">
            <div className="bg-white border border-neutral-200 rounded-2xl p-4">
              <h3 className="font-semibold mb-2">Basket</h3>
              {cartItems.length === 0 ? (
                <p className="text-sm text-neutral-400">Your basket is empty.</p>
              ) : (
                <div className="space-y-3">
                  {cartItems.map((item) => (
                    <div key={item.id} className="flex items-center justify-between gap-2">
                      <div>
                        <p className="text-sm font-medium">{item.name}</p>
                        <p className="text-xs text-neutral-500">EUR {item.price.toFixed(2)} each</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button className="w-6 h-6 rounded border" onClick={() => changeQty(item.id, item.qty - 1)}>-</button>
                        <span className="text-sm w-5 text-center">{item.qty}</span>
                        <button className="w-6 h-6 rounded border" onClick={() => changeQty(item.id, item.qty + 1)}>+</button>
                      </div>
                    </div>
                  ))}
                  <div className="pt-2 border-t text-sm space-y-1">
                    <div className="flex justify-between"><span className="text-neutral-500">Subtotal</span><span>EUR {subtotal.toFixed(2)}</span></div>
                    <div className="flex justify-between"><span className="text-neutral-500">Shipping</span><span>EUR {shipping.toFixed(2)}</span></div>
                    <div className="flex justify-between font-bold text-base"><span>Total</span><span>EUR {total.toFixed(2)}</span></div>
                  </div>
                  <button
                    onClick={() => setStep("checkout")}
                    disabled={!loggedIn}
                    className="w-full py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-700"
                  >
                    Checkout
                  </button>
                </div>
              )}
            </div>
          </aside>
        </section>

        {step !== "cart" && (
          <section className="bg-white border border-neutral-200 rounded-2xl p-5 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold">Step 3: Checkout and payment</h2>
              <div className="flex gap-2 text-xs">
                <span className={`px-2 py-1 rounded-full border ${loggedIn ? "bg-green-50 text-green-700 border-green-200" : "bg-amber-50 text-amber-700 border-amber-200"}`}>
                  {loggedIn ? "Sauron login complete" : "Login required"}
                </span>
              </div>
            </div>

            {proofClaims && (
              <div className="border border-green-200 bg-green-50 rounded-xl p-4">
                <p className="text-sm font-semibold text-green-800">Sauron claims accepted at login</p>
                <pre className="text-xs text-green-900 mt-2 whitespace-pre-wrap break-all">{JSON.stringify(proofClaims, null, 2)}</pre>
              </div>
            )}

            {step === "checkout" && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <h3 className="font-semibold">Delivery</h3>
                  <input className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-sm" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Full name" readOnly={!!profile} />
                  <input className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-sm" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" readOnly={!!profile} />
                  <input className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-sm" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="Address" />
                  {profile && (
                    <p className="text-xs text-neutral-500">Name and email locked from DB persona ID.</p>
                  )}
                </div>

                <div className="space-y-3">
                  <h3 className="font-semibold">Payment</h3>
                  <input className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-sm" value={cardNumber} onChange={(e) => setCardNumber(e.target.value)} placeholder="Card number" />
                  <div className="grid grid-cols-2 gap-3">
                    <input className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-sm" value={expiry} onChange={(e) => setExpiry(e.target.value)} placeholder="MM/YY" />
                    <input className="w-full border border-neutral-300 rounded-lg px-3 py-2 text-sm" value={cvc} onChange={(e) => setCvc(e.target.value)} placeholder="CVC" />
                  </div>
                  <div className="text-xs text-neutral-500">Cards accepted: Visa, Mastercard, AmEx. 3DS simulated.</div>
                  <button
                    onClick={submitPayment}
                    disabled={paying || !loggedIn}
                    className="w-full py-2.5 rounded-lg bg-emerald-600 text-white font-semibold text-sm disabled:opacity-50"
                  >
                    {paying ? "Processing payment..." : `Pay EUR ${total.toFixed(2)}`}
                  </button>
                </div>
              </div>
            )}

            {step === "paid" && (
              <div className="border border-emerald-200 bg-emerald-50 rounded-xl p-5 space-y-2">
                <p className="text-emerald-800 font-semibold">Payment successful</p>
                <p className="text-sm text-emerald-700">Order {orderId} confirmed. Receipt sent to {email}.</p>
                <p className="text-xs text-emerald-700">Merchant billed: 1 Sauron credit for login flow ({identitySummary?.is_agent ? "agent" : "user"} path).</p>
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  );
}
