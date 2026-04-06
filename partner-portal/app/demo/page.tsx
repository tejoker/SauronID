"use client";

/**
 * SauronID Integration Demo
 * Shows partners exactly how to embed the button in 3 lines.
 */

import React, { useState, useEffect } from "react";

export default function DemoPage() {
  const [profile, setProfile] = useState<any>(null);
  const [tab, setTab] = useState<"demo" | "code">("demo");

  // Dynamically load the SDK after mount
  useEffect(() => {
    const script = document.createElement("script");
    script.src = "/sdk/sauron.js";
    script.async = true;
    document.body.appendChild(script);
    return () => { document.body.removeChild(script); };
  }, []);

  useEffect(() => {
    const handler = (e: any) => setProfile(e.detail);
    document.addEventListener("sauronid:success", handler);
    return () => document.removeEventListener("sauronid:success", handler);
  }, []);

  const integrationCode = `<!-- 1. Add the script -->
<script src="https://sauronid.example.com/sdk/sauron.js"></script>

<!-- 2. Place the button anywhere -->
<div
  data-sauron-site="YourSiteName"
  data-sauron-claims="first_name,last_name,nationality"
  data-sauron-api="http://localhost:3001">
</div>

<!-- 3. Listen for the result -->
<script>
  document.querySelector('[data-sauron-site]')
    .addEventListener('sauronid:success', function(e) {
      console.log('Verified user:', e.detail);
      // e.detail = { first_name, last_name, nationality, ... }
      // All fields are ZKP-attested — you never see raw documents.
    });
</script>`;

  const programmaticCode = `const sdk = new SauronID({
  siteName: "YourSiteName",
  apiUrl: "http://localhost:3001",
  claims: ["first_name", "nationality"],
  silentAuth: true,           // auto-login if device trusted (80% flow)
  onSuccess: (profile) => {
    // profile.first_name, profile.last_name, etc.
    loginUser(profile);
  },
  onError: (err) => showError(err.message),
});

sdk.render(document.getElementById("login-btn"));`;

  return (
    <div style={page.wrap}>
      <div style={page.inner}>
        {/* Hero */}
        <div style={page.hero}>
          <div style={page.heroLogo}>
            <div style={page.logoDot} />
            <span style={page.logoText}>SauronID</span>
          </div>
          <h1 style={page.h1}>The privacy-first identity button</h1>
          <p style={page.sub}>
            One script tag. Zero passwords. ZKP-attested claims. Your users keep their data — you get verified identity.
          </p>
          <div style={page.pillRow}>
            {["No raw data shared", "Bank-attested identity", "Zero-knowledge proofs", "80% frictionless re-auth", "Agent delegation"].map(p => (
              <span key={p} style={page.pill}>{p}</span>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div style={page.tabs}>
          <button style={{ ...page.tab, ...(tab === "demo" ? page.tabActive : {}) }} onClick={() => setTab("demo")}>Live demo</button>
          <button style={{ ...page.tab, ...(tab === "code" ? page.tabActive : {}) }} onClick={() => setTab("code")}>Integration guide</button>
        </div>

        {tab === "demo" && (
          <div style={page.section}>
            <div style={page.demoCard}>
              <h2 style={page.cardTitle}>Try it — sign in with SauronID</h2>
              <p style={page.cardSub}>This button is embedded via the SDK, exactly as a partner would do it.</p>

              {/* Auto-inited by SDK on script load */}
              <div
                data-sauron-site="DemoSite"
                data-sauron-claims="first_name,last_name,nationality"
                data-sauron-api="http://localhost:3001"
                data-sauron-text="Continue with SauronID"
                style={{ marginTop: 20, marginBottom: 20 }}
              />

              {profile && (
                <div style={page.result}>
                  <div style={page.resultTitle}>Verified claims received by site:</div>
                  <table style={page.table}>
                    <tbody>
                      {Object.entries(profile).filter(([, v]) => v).map(([k, v]) => (
                        <tr key={k}>
                          <td style={page.tdKey}>{k}</td>
                          <td style={page.tdVal}>{String(v)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p style={page.resultNote}>
                    No document scans. No passwords. The site received ZKP-attested attributes from the user&apos;s bank-verified credential.
                  </p>
                </div>
              )}
            </div>

            <div style={page.compareGrid}>
              <div style={page.compareCard}>
                <div style={page.compareTitle}>Without SauronID</div>
                {["User fills a registration form", "Email + password stored on your server", "You must handle GDPR compliance", "Data breaches = your liability", "No guarantee data is real"].map(i => (
                  <div key={i} style={page.compareItem}><span style={{ color: "#ef4444" }}>✗</span> {i}</div>
                ))}
              </div>
              <div style={{ ...page.compareCard, borderColor: "#a5b4fc" }}>
                <div style={{ ...page.compareTitle, color: "#4f46e5" }}>With SauronID</div>
                {["User clicks one button", "You receive verified attributes only", "GDPR: data stays with user", "Zero sensitive data on your servers", "Bank-attested — guaranteed real"].map(i => (
                  <div key={i} style={page.compareItem}><span style={{ color: "#22c55e" }}>✓</span> {i}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === "code" && (
          <div style={page.section}>
            <div style={page.demoCard}>
              <h2 style={page.cardTitle}>HTML snippet (simplest)</h2>
              <p style={page.cardSub}>Drop this into any page. No build step required.</p>
              <pre style={page.pre}><code>{integrationCode}</code></pre>
            </div>

            <div style={page.demoCard}>
              <h2 style={page.cardTitle}>Programmatic API</h2>
              <p style={page.cardSub}>Full control over rendering and callbacks.</p>
              <pre style={page.pre}><code>{programmaticCode}</code></pre>
            </div>

            <div style={page.demoCard}>
              <h2 style={page.cardTitle}>What you receive</h2>
              <p style={page.cardSub}>The <code>onSuccess</code> callback receives verified claims. Never raw documents.</p>
              <pre style={page.pre}><code>{`{
  "first_name":    "Alice",          // ZKP-attested via bank
  "last_name":     "Martin",
  "nationality":   "FR",
  "date_of_birth": "1990-03-15",    // only if you requested it
  "email":         "alice@..."      // only if user consented
}`}</code></pre>
              <div style={{ marginTop: 20 }}>
                <div style={page.compareTitle}>Available claims</div>
                {[
                  ["first_name", "First name (bank-verified)"],
                  ["last_name", "Last name (bank-verified)"],
                  ["nationality", "Nationality code (ISO 3166-1 alpha-2)"],
                  ["date_of_birth", "Date of birth (YYYY-MM-DD)"],
                  ["email", "Email address"],
                ].map(([k, v]) => (
                  <div key={k} style={page.compareItem}>
                    <code style={{ color: "#6366f1", fontFamily: "monospace" }}>{k}</code>
                    <span style={{ color: "#64748b", marginLeft: 8 }}>— {v}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={page.demoCard}>
              <h2 style={page.cardTitle}>Device trust (80% frictionless re-auth)</h2>
              <p style={page.cardSub}>
                After first consent, the SDK stores a device token in localStorage. On return visits,
                authentication is silent — no popup shown. Works out of the box when <code>silentAuth: true</code>.
              </p>
              <div style={page.flowSteps}>
                {[
                  ["First visit", "User clicks button → consent popup → ZKP proof → device token issued"],
                  ["Return visit", "SDK detects device token → silent check → profile returned instantly"],
                  ["New device", "No token found → popup shown → new device token issued"],
                ].map(([title, desc]) => (
                  <div key={title} style={page.flowStep}>
                    <div style={page.flowTitle}>{title}</div>
                    <div style={page.flowDesc}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const page: Record<string, React.CSSProperties> = {
  wrap: { minHeight: "100vh", background: "#f8fafc", fontFamily: "system-ui, -apple-system, sans-serif" },
  inner: { maxWidth: 860, margin: "0 auto", padding: "0 20px 60px" },
  hero: { textAlign: "center", padding: "60px 0 40px" },
  heroLogo: { display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 20 },
  logoDot: { width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,#6366f1,#8b5cf6)" },
  logoText: { fontSize: 22, fontWeight: 700, color: "#0f172a", letterSpacing: -0.5 },
  h1: { fontSize: 36, fontWeight: 800, color: "#0f172a", margin: "0 0 14px", lineHeight: 1.2 },
  sub: { fontSize: 16, color: "#64748b", maxWidth: 580, margin: "0 auto 24px", lineHeight: 1.7 },
  pillRow: { display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center" },
  pill: { padding: "4px 14px", background: "#ede9fe", color: "#5b21b6", borderRadius: 20, fontSize: 13, fontWeight: 500 },

  tabs: { display: "flex", borderBottom: "1px solid #e2e8f0", marginBottom: 28 },
  tab: { padding: "12px 20px", border: "none", background: "none", fontSize: 14, color: "#64748b", cursor: "pointer", borderBottom: "2px solid transparent", fontWeight: 500 },
  tabActive: { color: "#6366f1", borderBottom: "2px solid #6366f1" },

  section: { display: "flex", flexDirection: "column", gap: 24 },
  demoCard: { background: "#fff", border: "1px solid #e2e8f0", borderRadius: 16, padding: "28px 32px" },
  cardTitle: { fontSize: 18, fontWeight: 700, color: "#0f172a", margin: "0 0 6px" },
  cardSub: { fontSize: 14, color: "#64748b", margin: "0 0 16px" },

  result: { background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 12, padding: 20, marginTop: 8 },
  resultTitle: { fontSize: 14, fontWeight: 600, color: "#166534", marginBottom: 12 },
  table: { width: "100%", borderCollapse: "collapse" as const },
  tdKey: { padding: "4px 0", fontSize: 13, color: "#64748b", width: 140, fontFamily: "monospace" },
  tdVal: { padding: "4px 0", fontSize: 13, color: "#0f172a", fontWeight: 500 },
  resultNote: { fontSize: 12, color: "#166534", marginTop: 12, marginBottom: 0 },

  pre: { background: "#0f172a", color: "#e2e8f0", borderRadius: 10, padding: "20px 24px", overflowX: "auto", fontSize: 13, fontFamily: "monospace", lineHeight: 1.7, margin: 0 },

  compareGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 },
  compareCard: { background: "#fff", border: "1px solid #e2e8f0", borderRadius: 12, padding: "20px 24px" },
  compareTitle: { fontSize: 15, fontWeight: 700, color: "#0f172a", marginBottom: 14 },
  compareItem: { fontSize: 13, color: "#374151", padding: "5px 0", display: "flex", alignItems: "flex-start", gap: 8 },

  flowSteps: { display: "flex", flexDirection: "column", gap: 12, marginTop: 12 },
  flowStep: { background: "#f8fafc", borderRadius: 10, padding: "12px 16px" },
  flowTitle: { fontSize: 13, fontWeight: 700, color: "#0f172a", marginBottom: 4 },
  flowDesc: { fontSize: 13, color: "#64748b" },
};
