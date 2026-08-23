import { generateKeyPairSync } from "crypto";
import { CoreApi, randSuffix } from "../../core-api";

/** Agent registered with PoP material must not pass /agent/verify without challenge + JWS. */
export async function scenarioPopRequiredOnVerify(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-pop-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `pop_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Pop",
        last_name: "Redteam",
        date_of_birth: "1993-03-03",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();

    const { publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
    if (!jwk.x) throw new Error("failed to export Ed25519 JWK x");
    const popB64u = jwk.x;

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:pop-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pop-${sfx}`,
        ttl_secs: 3600,
        pop_public_key_b64u: popB64u,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const ajwt = reg.data.ajwt as string;
    if (!ajwt) throw new Error("missing ajwt");

    const v = await api.agentVerify({ ajwt });
    if (v.status !== 200) throw new Error(`/agent/verify HTTP ${v.status}`);
    if (v.data.valid === true) {
        throw new Error("verify without PoP must return valid=false when agent has pop_public_key_b64u");
    }
    const err = String(v.data.error ?? "");
    if (!err.toLowerCase().includes("pop")) {
        throw new Error(`expected PoP-related error, got: ${err || v.raw}`);
    }
}
