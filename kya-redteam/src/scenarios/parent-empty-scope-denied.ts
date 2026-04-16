import { CoreApi, randSuffix } from "../core-api";
import { twoRistrettoHexes } from "../ristretto";

/** Parent with no delegable scopes cannot delegate. */
export async function scenarioParentEmptyScopeDenied(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-empty-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `empty_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Empty",
        last_name: "Redteam",
        date_of_birth: "1988-08-08",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);

    const { pk1, pk2 } = twoRistrettoHexes();

    const parent = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:emptyp-${sfx}`,
        intent_json: "{}",
        public_key_hex: pk1,
        ttl_secs: 3600,
    });
    if (parent.status !== 200) throw new Error(`parent register ${parent.status}: ${parent.raw}`);
    const parentId = parent.data.agent_id as string;

    const child = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:emptyc-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age"] }),
        public_key_hex: pk2,
        ttl_secs: 3600,
        parent_agent_id: parentId,
    });
    if (child.status === 200) {
        throw new Error("child under parent with empty delegable scopes should fail");
    }
    const combined = child.raw.toLowerCase();
    if (!combined.includes("scope") && !combined.includes("delegat")) {
        throw new Error(`expected scope/delegation message, got: ${child.raw}`);
    }
}
