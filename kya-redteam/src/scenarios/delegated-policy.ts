import { CoreApi, randSuffix } from "../core-api";

/** delegated_bank: payment_initiation and prove_age allowed per matrix. */
export async function scenarioDelegatedPolicy(api: CoreApi, bankSite: string, label: string): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-del-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 4);

    const email = `del_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    const { public_key_hex } = await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Del",
        last_name: "Redteam",
        date_of_birth: "1990-02-02",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:del-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age", "payment_initiation"] }),
        public_key_hex: public_key_hex.toLowerCase(),
        ttl_secs: 3600,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    if (reg.data.assurance_level !== "delegated_bank") {
        throw new Error(`expected delegated_bank, got ${reg.data.assurance_level}`);
    }
    const agentId = reg.data.agent_id as string;
    if (!agentId) throw new Error("missing agent_id");

    const pay = await api.policyAuthorize(agentId, "payment_initiation");
    if (!pay.allowed) throw new Error(`delegated_bank should allow payment_initiation: ${pay.reason}`);

    const age = await api.policyAuthorize(agentId, "prove_age");
    if (!age.allowed) throw new Error(`delegated_bank should allow prove_age: ${age.reason}`);
}
