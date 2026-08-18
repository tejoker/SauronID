-- Point each receipt at the owner-signed mandate that authorised it.
--
-- The mandate hash lives on the agent, but an agent can be re-registered later
-- under a wider grant. Without the hash on the receipt, an auditor holding a
-- receipt cannot tell which grant was in force when the action happened. Copied
-- at receipt time and committed by both the receipt signature (v4 domain) and
-- the chain hash, so it cannot be edited afterwards.
--
-- Empty for receipts written before this, and on the anonymous ring path, where
-- ring membership is the grant and there is no agent identity to resolve.
ALTER TABLE agent_action_receipts
    ADD COLUMN IF NOT EXISTS owner_mandate_hash TEXT NOT NULL DEFAULT '';
