import { CoreApi, randSuffix } from "../core-api";

/** Second /agent/kyc/consent with the same A-JWT must fail (server JTI store). */
export async function scenarioJtiReplay(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-zkp-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 5);

    const email = `jti_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    const { public_key_hex } = await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Jti",
        last_name: "Redteam",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:jti-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age"] }),
        public_key_hex: public_key_hex.toLowerCase(),
        ttl_secs: 3600,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const ajwt = reg.data.ajwt as string;
    if (!ajwt) throw new Error("missing ajwt");

    const req1 = await api.kycRequest(retail, ["age_over_threshold", "age_threshold"]);
    const c1 = await api.agentKycConsent({ ajwt, site_name: retail, request_id: req1 });
    if (c1.status !== 200) throw new Error(`first consent expected 200, got ${c1.status}: ${c1.raw}`);

    const req2 = await api.kycRequest(retail, ["age_over_threshold", "age_threshold"]);
    const c2 = await api.agentKycConsent({ ajwt, site_name: retail, request_id: req2 });
    if (c2.status === 200) {
        throw new Error("second consent with same A-JWT must not succeed (JTI replay)");
    }
}
