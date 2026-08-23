/**
 * S3 redteam — tenant-jwt-claim-forgery.
 *
 * Threat model: docs/security/threat-model.md "Spoofing → admin JWT forgery".
 * The tenancy middleware reads the `tnt` claim from a Bearer JWT IFF
 * the operator has wired up `SAURON_ADMIN_JWT_HS256_SECRET`. Without
 * the correct secret, the decoded JWT validation MUST fail and the
 * request is treated as the default tenant (or rejected by admin
 * auth, depending on the route's auth middleware).
 *
 * Scenario:
 *   1. Mint a hand-rolled HS256 JWT with `{ "tnt": "acme_corp" }` and
 *      a wrong secret.
 *   2. Send it as a Bearer token to /v1/policy/list.
 *   3. Assert 401 (admin auth refuses the token) OR — if the route is
 *      reachable with default admin key, ensure the resolved tenant
 *      is NOT acme_corp.
 *
 * Mitigation in code:
 *   - core/src/tenancy/mod.rs::tenant_from_jwt — `decode(...).ok()?`
 *     returns None on signature mismatch, so the `tnt` claim is never
 *     trusted from an invalid JWT.
 *   - core/src/admin.rs::auth_middleware refuses unauthenticated calls.
 */

import {
    BASE_URL,
    ADMIN_KEY,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "../lib/_s12_lib";
import * as crypto from "crypto";

function b64url(buf: Buffer): string {
    return buf
        .toString("base64")
        .replace(/=+$/, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function mintForgedJwt(tenant: string, wrongSecret: string): string {
    const header = { alg: "HS256", typ: "JWT" };
    const payload = {
        tnt: tenant,
        sub: "forged",
        exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const h = b64url(Buffer.from(JSON.stringify(header)));
    const p = b64url(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${h}.${p}`;
    const sig = crypto
        .createHmac("sha256", wrongSecret)
        .update(signingInput)
        .digest();
    return `${signingInput}.${b64url(sig)}`;
}

async function main(): Promise<ScenarioResult> {
    const id = "T11";
    const name = "tenant-jwt-claim-forgery";
    if (!(await pingServer())) {
        return skipped(id, name, `server ${BASE_URL} unreachable`);
    }

    const forgedJwt = mintForgedJwt("acme_corp", "definitely-not-the-secret");

    // Case 1: ONLY the forged JWT (no static admin key).
    const r1 = await fetch(`${BASE_URL}/v1/policy/list`, {
        headers: { authorization: `Bearer ${forgedJwt}` },
    });
    const onlyJwtStatus = r1.status;

    // Case 2: forged JWT + valid static admin key (header). The static
    // admin key wins for auth, but the tenant from the JWT must NOT
    // resolve to acme_corp (signature check fails inside
    // tenant_from_jwt → falls through to header / default).
    let mixedStatus: number | null = null;
    let mixedBody = "";
    if (ADMIN_KEY) {
        const r2 = await fetch(`${BASE_URL}/v1/policy/list`, {
            headers: {
                authorization: `Bearer ${forgedJwt}`,
                "x-admin-key": ADMIN_KEY,
            },
        });
        mixedStatus = r2.status;
        mixedBody = (await r2.text()).slice(0, 200);
    }

    // Pass if forged-JWT-alone is rejected by admin auth (401/403).
    const pass = onlyJwtStatus === 401 || onlyJwtStatus === 403;

    return {
        id,
        name,
        pass,
        note:
            "Forged JWT (wrong HMAC) MUST not yield tenant access. Admin auth " +
            "refuses the token outright (401/403). Mitigation: tenancy/mod.rs::" +
            "tenant_from_jwt returns None on signature mismatch, falls back to default.",
        evidence: {
            forged_token_only_status: onlyJwtStatus,
            forged_with_admin_key_status: mixedStatus,
            forged_with_admin_key_body: mixedBody,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
