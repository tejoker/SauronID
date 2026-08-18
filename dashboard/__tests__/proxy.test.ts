// Tests for `proxy.ts` — the dashboard's single auth + tenant-isolation gate.
//
// This file exists because the thing it covers is the highest-authority code in
// the dashboard: everything behind it reaches the core with the god-mode admin
// key, and the proxy is what decides whether a request gets there and as which
// tenant. It had no direct test.
//
// Two properties are worth more than the rest and are asserted explicitly:
//
//   1. The session is verified on the EDGE runtime with Web Crypto, while
//      `lib/session.ts` signs it in the NODE runtime with node:crypto. Signing
//      here with the real `signSession` and verifying through the real proxy
//      pins those two implementations to the same bytes — a divergence would
//      lock every operator out (or, worse, accept a token the signer never
//      produced).
//   2. `x-sauron-admin-super` and `x-sauron-admin-tenants` are authority
//      headers written from the verified session. The proxy copies the incoming
//      headers before setting them, so a browser that sends its own must be
//      overwritten, not merged.

import { describe, it, expect, beforeAll } from "vitest";

const SECRET = "test-only-dashboard-session-secret";

// Both the signer and the proxy read this; set it before either is imported.
process.env.SAURON_DASHBOARD_SESSION_SECRET = SECRET;

let proxy: typeof import("../proxy").proxy;
let signSession: typeof import("../lib/session").signSession;
let NextRequest: typeof import("next/server").NextRequest;

beforeAll(async () => {
  ({ proxy } = await import("../proxy"));
  ({ signSession } = await import("../lib/session"));
  ({ NextRequest } = await import("next/server"));
});

const HOUR = 3600;
const now = () => Math.floor(Date.now() / 1000);

function token(over: Partial<import("../lib/session").Session> = {}): string {
  return signSession({
    op: "alice",
    tenants: ["acme"],
    super: false,
    exp: now() + HOUR,
    ...over,
  });
}

function req(
  path: string,
  opts: { session?: string; headers?: Record<string, string> } = {}
): InstanceType<typeof NextRequest> {
  const headers = new Headers(opts.headers ?? {});
  if (opts.session) headers.set("cookie", `sauron_session=${opts.session}`);
  return new NextRequest(`https://console.example.com${path}`, { headers });
}

describe("proxy — unauthenticated requests", () => {
  it("refuses an API call with 401 rather than reaching the core", async () => {
    const res = await proxy(req("/api/agents"));
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toMatchObject({ ok: false });
  });

  it("sends a page request to the login screen, preserving the destination", async () => {
    const res = await proxy(req("/activity"));
    expect(res.status).toBeGreaterThanOrEqual(300);
    expect(res.status).toBeLessThan(400);
    const location = new URL(res.headers.get("location")!);
    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("next")).toBe("/activity");
  });

  it("lets the login route and its API through without a session", async () => {
    for (const path of ["/login", "/api/auth/login"]) {
      const res = await proxy(req(path));
      expect(res.status, path).toBe(200);
    }
  });
});

describe("proxy — session integrity", () => {
  it("accepts a token produced by the node-runtime signer", async () => {
    const res = await proxy(req("/api/agents", { session: token() }));
    expect(res.status).toBe(200);
  });

  it("rejects a token whose payload was edited after signing", async () => {
    const [payload, mac] = token().split(".");
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString());
    decoded.super = true; // privilege escalation attempt
    const forged = `${Buffer.from(JSON.stringify(decoded)).toString("base64url")}.${mac}`;

    const res = await proxy(req("/api/agents", { session: forged }));
    expect(res.status).toBe(401);
  });

  it("rejects an expired session", async () => {
    const res = await proxy(
      req("/api/agents", { session: token({ exp: now() - 1 }) })
    );
    expect(res.status).toBe(401);
  });

  it("rejects a malformed token instead of throwing", async () => {
    for (const bad of ["", "no-dot", ".", "a.b.c"]) {
      const res = await proxy(req("/api/agents", { session: bad }));
      expect(res.status, JSON.stringify(bad)).toBe(401);
    }
  });
});

describe("proxy — tenant and authority binding", () => {
  it("derives the tenant from the session when the client asks for nothing", async () => {
    const res = await proxy(req("/api/agents", { session: token() }));
    expect(res.headers.get("x-middleware-override-headers")).toContain(
      "x-sauron-tenant-id"
    );
    expect(
      res.headers.get("x-middleware-request-x-sauron-tenant-id")
    ).toBe("acme");
  });

  it("refuses a tenant the operator is not authorized for", async () => {
    const res = await proxy(
      req("/api/agents", {
        session: token(),
        headers: { "x-sauron-tenant-id": "globex" },
      })
    );
    expect(res.status).toBe(403);
  });

  it("overwrites a browser-supplied super flag with the session's value", async () => {
    const res = await proxy(
      req("/api/keys/issue", {
        session: token(), // super: false
        headers: {
          "x-sauron-admin-super": "1",
          "x-sauron-admin-tenants": "acme,globex",
        },
      })
    );
    expect(res.headers.get("x-middleware-request-x-sauron-admin-super")).toBe("0");
    expect(res.headers.get("x-middleware-request-x-sauron-admin-tenants")).toBe(
      "acme"
    );
  });

  it("lets a super operator select any tenant", async () => {
    const res = await proxy(
      req("/api/agents", {
        session: token({ super: true, tenants: ["acme"] }),
        headers: { "x-sauron-tenant-id": "globex" },
      })
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("x-middleware-request-x-sauron-tenant-id")).toBe(
      "globex"
    );
    expect(res.headers.get("x-middleware-request-x-sauron-admin-super")).toBe("1");
  });
});
