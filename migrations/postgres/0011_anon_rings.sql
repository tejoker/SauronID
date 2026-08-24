-- Phase 2 of the anonymous ring-policy redesign.
-- See docs/architecture/anonymous-ring-policy.md.
--
-- A ring is a RULE; agents subscribe to many rings. Members are per-ring stealth
-- pseudonym points (core/src/ring_pseudonym.rs) — NEVER master keys — so a reader
-- of this table cannot link a member to an agent identity or correlate across rings.

CREATE TABLE IF NOT EXISTS rings (
    tenant_id   TEXT    NOT NULL DEFAULT 'default',
    ring_id     TEXT    NOT NULL,
    rule_json   TEXT    NOT NULL,
    version     BIGINT  NOT NULL DEFAULT 1,
    created_at  BIGINT  NOT NULL,
    updated_at  BIGINT  NOT NULL,
    PRIMARY KEY (tenant_id, ring_id)
);

CREATE TABLE IF NOT EXISTS ring_members (
    tenant_id        TEXT   NOT NULL DEFAULT 'default',
    ring_id          TEXT   NOT NULL,
    member_point_hex TEXT   NOT NULL,
    created_at       BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, ring_id, member_point_hex)
);

CREATE INDEX IF NOT EXISTS idx_ring_members_ring ON ring_members (tenant_id, ring_id);

-- Phase 3: receipts from the anonymous ring path carry ring_id + config_digest
-- instead of an agent identity (agent_id is '' for anon receipts). Both are also
-- committed by action_hash, so they are tamper-evident.
ALTER TABLE agent_action_receipts ADD COLUMN IF NOT EXISTS ring_id       TEXT;
ALTER TABLE agent_action_receipts ADD COLUMN IF NOT EXISTS config_digest TEXT;

-- Phase 4: multi-unit usage ledger keyed on the per-ring key image (pseudonym).
-- Tokens authoritative; usd derived from a per-model price map. Budgets in
-- RingRule.budgets are enforced per-pseudonym against usage_ledger.
CREATE TABLE IF NOT EXISTS usage_ledger (
    tenant_id     TEXT   NOT NULL DEFAULT 'default',
    ring_id       TEXT   NOT NULL,
    key_image_hex TEXT   NOT NULL,
    input_tokens  BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    usd           DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at    BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, ring_id, key_image_hex)
);

CREATE TABLE IF NOT EXISTS usage_log (
    log_id        TEXT   PRIMARY KEY NOT NULL,
    tenant_id     TEXT   NOT NULL DEFAULT 'default',
    ring_id       TEXT   NOT NULL,
    key_image_hex TEXT   NOT NULL,
    model_id      TEXT   NOT NULL,
    input_tokens  BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    usd           DOUBLE PRECISION NOT NULL DEFAULT 0,
    recorded_at   BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_usage_log_ring ON usage_log (tenant_id, ring_id, key_image_hex, recorded_at);
