-- Session revocation for the owner session.
--
-- The owner session is a stateless HMAC over `v2|tenant|key_image|expires_at`
-- with a one-hour lifetime. Because verification consulted no server state,
-- there was nothing to change in response to a leak: the token stayed valid for
-- its full hour no matter what the operator did. That matters more here than for
-- an ordinary web session, because this credential is what authorises
-- `POST /agent/register` and `POST /agent/{id}/checksum/update` — it mints agent
-- authority.
--
-- The epoch is folded into the signed payload, so incrementing it makes every
-- session previously issued for that owner fail verification on its next use.
--
-- Per-owner rather than per-session on purpose: the operational response to a
-- suspected leak is "cut this owner off", and a per-session table would need a
-- row per login to revoke a capability that expires within the hour anyway.

ALTER TABLE user_auth_credentials
    ADD COLUMN IF NOT EXISTS session_epoch BIGINT NOT NULL DEFAULT 0;
