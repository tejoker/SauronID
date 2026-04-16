import { CoreApi, randSuffix } from "../core-api";
import { twoRistrettoHexes } from "../ristretto";

/** Child scopes must be subset of parent; out-of-scope delegation → 400. */
export async function scenarioDelegationScopeDenied(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-sub-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `sub_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Sub",
        last_name: "Redteam",
        date_of_birth: "1989-05-05",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);

    const { pk1, pk2 } = twoRistrettoHexes();

    const parent = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:parent-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age"] }),
        public_key_hex: pk1,
        ttl_secs: 3600,
    });
    if (parent.status !== 200) throw new Error(`parent register ${parent.status}: ${parent.raw}`);
    const parentId = parent.data.agent_id as string;
    if (!parentId) throw new Error("missing parent agent_id");

    const child = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:child-${sfx}`,
        intent_json: JSON.stringify({ scope: ["payment_initiation"] }),
        public_key_hex: pk2,
        ttl_secs: 3600,
        parent_agent_id: parentId,
    });
    if (child.status === 200) {
        throw new Error("child registration with out-of-scope intent should fail");
    }
    const err = (child.raw + (child.data as { error?: string }).error).toLowerCase();
    if (!err.includes("scope") && !err.includes("delegation") && !err.includes("subset")) {
        throw new Error(`expected scope/delegation error in body, got: ${child.raw}`);
    }
}
