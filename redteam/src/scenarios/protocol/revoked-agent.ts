import { CoreApi, createPopKeyPair, randSuffix, signPopJws } from "../../core-api";

/** Revoked agent must return valid=false with a revocation error on /agent/verify. */
export async function scenarioRevokedAgent(api: CoreApi, bankSite: string, label: string): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    await api.ensureClient(bankSite, "BANK");

    const email = `revoke_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Revoke",
        last_name: "Redteam",
        date_of_birth: "1995-06-15",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();
    const pop = createPopKeyPair();

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:revoke-${sfx}`,
        intent_json: JSON.stringify({ scope: ["prove_age"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pop-${sfx}`,
        pop_public_key_b64u: pop.publicKeyB64u,
        ttl_secs: 3600,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const ajwt = reg.data.ajwt as string;
    const agentId = reg.data.agent_id as string;
    if (!ajwt || !agentId) throw new Error("missing ajwt or agent_id");

    // Verify before revocation: must be valid.
    const popChallenge = await api.agentPopChallenge(session, agentId);
    const before = await api.agentVerify({
        ajwt,
        pop_challenge_id: popChallenge.pop_challenge_id,
        pop_jws: signPopJws(popChallenge.challenge, pop.privateKey),
    });
    if (before.status !== 200) throw new Error(`/agent/verify pre-revoke HTTP ${before.status}`);
    if (before.data.valid !== true) {
        throw new Error(`agent must be valid before revocation: ${before.raw}`);
    }

    // Revoke.
    const rev = await api.revokeAgent(agentId, session);
    if (rev.status !== 200) throw new Error(`DELETE /agent/${agentId} ${rev.status}: ${rev.raw}`);
    if (rev.data.revoked !== true) throw new Error(`revoke response missing revoked=true: ${rev.raw}`);

    // Verify after revocation: must be invalid.
    const after = await api.agentVerify({ ajwt });
    if (after.status !== 200) throw new Error(`/agent/verify post-revoke HTTP ${after.status}`);
    if (after.data.valid === true) {
        throw new Error("revoked agent must not pass /agent/verify");
    }
    const errMsg = String(after.data.error ?? "").toLowerCase();
    if (!errMsg.includes("revok")) {
        throw new Error(`expected revocation error, got: ${after.data.error ?? after.raw}`);
    }
}
