"use client";

/**
 * Sauron Consent Popup
 *
 * This page is opened as a popup by retail sites requesting user KYC data.
 * Flow:
 *   1. Site calls POST /kyc/request → gets request_id + consent_url
 *   2. Site opens window.open(consent_url)  ← this page
 *   3. User authenticates (email + password) and approves
 *   4. Sauron generates consent_token, this page posts it back via postMessage
 *   5. Popup closes. Site calls POST /kyc/retrieve with the consent_token.
 */

import React, { useEffect, useState, useCallback } from "react";
import { API } from "../context/ClientContext";

type Step = "loading" | "approve" | "submitting" | "granted" | "error";

async function readApiPayload(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object") return parsed as Record<string, unknown>;
  } catch {
    // Fallback for plain-text backend errors.
  }
  return { detail: text };
}

export default function ConsentPage() {
  const [step, setStep] = useState<Step>("loading");
  const [requestId, setRequestId] = useState("");
  const [siteName, setSiteName] = useState("");
  const [openerOrigin, setOpenerOrigin] = useState("*");
  const [requestedClaims, setRequestedClaims] = useState<string[]>([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  // Parse query params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const rid = params.get("request_id") || "";
    const site = params.get("site") || "";
    const origin = params.get("origin") || "*";
    setRequestId(rid);
    setSiteName(site);
    setOpenerOrigin(origin);

    // Try to parse claims from URL
    try {
      const claimsRaw = params.get("claims");
      if (claimsRaw) {
        setRequestedClaims(JSON.parse(decodeURIComponent(claimsRaw)));
      }
    } catch {
      // ignore parse errors
    }

    if (!rid || !site) {
      setErrorMsg("Missing consent request parameters.");
      setStep("error");
      return;
    }

    // Verify the request is still valid
    fetch(`${API}/kyc/consent_info/${encodeURIComponent(rid)}`)
      .then((r) => {
        if (!r.ok) throw new Error("Request not found or expired");
        return r.json();
      })
      .then((data) => {
        if (data.status === "granted") {
          setErrorMsg("This consent request has already been used.");
          setStep("error");
        } else {
          if (data.requested_claims?.length > 0) {
            setRequestedClaims(data.requested_claims);
          }
          setStep("approve");
        }
      })
      .catch((e) => {
        setErrorMsg(e.message || "Failed to load consent request.");
        setStep("error");
      });
  }, []);

  const handleApprove = useCallback(async () => {
    if (!email || !password) {
      setErrorMsg("Please enter your email and password.");
      return;
    }
    setStep("submitting");
    setErrorMsg("");

    try {
      const res = await fetch(`${API}/kyc/consent`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId, email, password }),
      });
      const data = await readApiPayload(res);
      if (!res.ok) {
        throw new Error(
          (typeof data.error === "string" && data.error) ||
          (typeof data.detail === "string" && data.detail) ||
          "Consent failed"
        );
      }

      setStep("granted");

      // Authenticate user session so the SDK can fetch credential + generate proof locally.
      let userSession: string | null = null;
      try {
        const authRes = await fetch(`${API}/user/auth`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        if (authRes.ok) {
          const authData = await authRes.json();
          userSession = authData.session || null;
          if (userSession) {
            // Warm credential cache now to minimize latency in opener app.
            await fetch(`${API}/user/credential`, {
              method: "GET",
              headers: { "x-sauron-session": userSession },
            }).catch(() => null);
          }
        }
      } catch {
        // Non-fatal. SDK can still proceed if it has another valid session.
      }

      // Post the consent_token back to the opener, then close
      if (window.opener) {
        window.opener.postMessage(
          {
            type: "sauron_consent",
            consent_token: typeof data.consent_token === "string" ? data.consent_token : "",
            user_session: userSession,
            request_id: requestId,
          },
          openerOrigin
        );
      }
      setTimeout(() => window.close(), 1500);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setErrorMsg(message);
      setStep("approve");
    }
  }, [email, password, requestId, openerOrigin]);

  const handleDeny = useCallback(() => {
    if (window.opener) {
      window.opener.postMessage(
        { type: "sauron_consent_denied", request_id: requestId },
        openerOrigin
      );
    }
    window.close();
  }, [requestId, openerOrigin]);

  const claimLabels: Record<string, string> = {
    age_over_threshold: "Age over threshold (ZKP)",
    age_threshold: "Requested age threshold value",
    credential_valid: "Credential validity proof (ZKP)",
    nationality_match: "Nationality match proof (ZKP)",
    merkle_inclusion: "Ledger inclusion proof (ZKP)",
  };

  const displayClaims = requestedClaims.length > 0
    ? requestedClaims
    : ["age_over_threshold", "age_threshold"];

  return (
    <div style={{
      minHeight: "100vh",
      background: "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "system-ui, -apple-system, sans-serif",
      color: "#f1f5f9",
    }}>
      <div style={{
        background: "#1e293b",
        border: "1px solid #334155",
        borderRadius: 16,
        padding: "32px 40px",
        width: 400,
        maxWidth: "90vw",
        boxShadow: "0 25px 50px rgba(0,0,0,0.5)",
      }}>
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 10,
            marginBottom: 8,
          }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: "50%",
              background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 18,
              fontWeight: "bold",
            }}>S</div>
            <span style={{ fontSize: 20, fontWeight: 700, letterSpacing: -0.5 }}>SauronID</span>
          </div>
        </div>

        {step === "loading" && (
          <p style={{ textAlign: "center", color: "#94a3b8" }}>Loading...</p>
        )}

        {step === "error" && (
          <>
            <h2 style={{ textAlign: "center", color: "#f87171", marginBottom: 12 }}>Error</h2>
            <p style={{ textAlign: "center", color: "#94a3b8", marginBottom: 24 }}>{errorMsg}</p>
            <button
              onClick={() => window.close()}
              style={btnStyle("#334155", "#475569")}
            >Close</button>
          </>
        )}

        {step === "granted" && (
          <>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>
                <span style={{ color: "#4ade80" }}>✓</span>
              </div>
              <h2 style={{ color: "#4ade80", marginBottom: 8 }}>Access granted</h2>
              <p style={{ color: "#94a3b8" }}>Returning to {siteName}...</p>
            </div>
          </>
        )}

        {(step === "approve" || step === "submitting") && (
          <>
            <h2 style={{ textAlign: "center", marginBottom: 4 }}>Sign in to continue</h2>
            <p style={{ textAlign: "center", color: "#94a3b8", marginBottom: 24, fontSize: 14 }}>
              <strong style={{ color: "#a78bfa" }}>{siteName}</strong> is requesting access to your identity
            </p>

            {/* Claims being requested */}
            <div style={{
              background: "#0f172a",
              borderRadius: 10,
              padding: "12px 16px",
              marginBottom: 24,
              border: "1px solid #334155",
            }}>
              <p style={{ fontSize: 12, color: "#64748b", marginBottom: 8, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>
                Data shared with {siteName}
              </p>
              {displayClaims.map((c) => (
                <div key={c} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
                  <span style={{ color: "#4ade80", fontSize: 12 }}>✓</span>
                  <span style={{ fontSize: 13, color: "#cbd5e1" }}>{claimLabels[c] || c}</span>
                </div>
              ))}
            </div>

            {/* Login form */}
            <div style={{ marginBottom: 16 }}>
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={step === "submitting"}
                style={inputStyle}
              />
            </div>
            <div style={{ marginBottom: 20 }}>
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleApprove()}
                disabled={step === "submitting"}
                style={inputStyle}
              />
            </div>

            {errorMsg && (
              <p style={{ color: "#f87171", fontSize: 13, marginBottom: 12, textAlign: "center" }}>
                {errorMsg}
              </p>
            )}

            <button
              onClick={handleApprove}
              disabled={step === "submitting"}
              style={btnStyle("#6366f1", "#4f46e5", step === "submitting")}
            >
              {step === "submitting" ? "Verifying..." : "Allow access"}
            </button>

            <button
              onClick={handleDeny}
              disabled={step === "submitting"}
              style={{ ...btnStyle("#334155", "#475569"), marginTop: 8 }}
            >
              Deny
            </button>

            <p style={{ textAlign: "center", fontSize: 11, color: "#475569", marginTop: 16 }}>
              Your data is anonymised with zero-knowledge proofs. {siteName} cannot track you across services.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

function btnStyle(bg: string, hover: string, disabled = false): React.CSSProperties {
  return {
    width: "100%",
    padding: "12px 0",
    background: disabled ? "#334155" : bg,
    color: disabled ? "#64748b" : "#fff",
    border: "none",
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
    transition: "background 0.15s",
    display: "block",
  };
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "10px 14px",
  background: "#0f172a",
  border: "1px solid #334155",
  borderRadius: 8,
  color: "#f1f5f9",
  fontSize: 14,
  outline: "none",
  boxSizing: "border-box",
};
