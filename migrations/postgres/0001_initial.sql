-- SauronID Postgres schema, version 1.
--
-- Source of truth for the Postgres backend (sqlx + PgPool).
-- The legacy SQLite path (`core/src/db.rs::init_schema`) maintains the same
-- logical schema with SQLite-specific dialect; this file is the canonical
-- production target.
--
-- Apply via: sqlx migrate run --source migrations/postgres
--   or:      psql "$DATABASE_URL" -f migrations/postgres/0001_initial.sql
--
-- Dialect notes vs SQLite:
--   INTEGER PRIMARY KEY AUTOINCREMENT  →  BIGSERIAL PRIMARY KEY
--   INTEGER (epoch seconds)            →  BIGINT
--   TEXT                                →  TEXT (unchanged)
--   BLOB                                →  BYTEA
--   IFNULL(x, y)                        →  COALESCE(x, y)  (used in handlers)
--   INSERT OR IGNORE INTO ... VALUES …  →  INSERT INTO … VALUES … ON CONFLICT DO NOTHING
--   INSERT OR REPLACE INTO ... VALUES … →  INSERT INTO … VALUES … ON CONFLICT (key) DO UPDATE SET …
--   ?1, ?2 numbered params              →  $1, $2 (sqlx handles automatically with macros)

BEGIN;

-- Partner sites (banks + retail). No private-key column by design: partners
-- generate and retain their own ring key, and the server holds no custody.
-- Databases created before 0019 still have one; that migration drops it.
CREATE TABLE IF NOT EXISTS clients (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT     UNIQUE NOT NULL,
    public_key_hex  TEXT     NOT NULL,
    key_image_hex   TEXT     NOT NULL,
    tokens_b        BIGINT   NOT NULL DEFAULT 0,
    client_type     TEXT     NOT NULL CHECK (client_type IN ('FULL_KYC', 'ZKP_ONLY', 'BANK'))
);

-- Registered users
CREATE TABLE IF NOT EXISTS users (
    key_image_hex   TEXT PRIMARY KEY,
    public_key_hex  TEXT NOT NULL,
    first_name      TEXT NOT NULL DEFAULT '',
    last_name       TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL DEFAULT '',
    date_of_birth   TEXT NOT NULL DEFAULT '',
    nationality     TEXT NOT NULL DEFAULT ''
);

-- Optional mapping from bank customer IDs to user key images
CREATE TABLE IF NOT EXISTS bank_kyc_links (
    bank_customer_id TEXT PRIMARY KEY,
    user_key_image   TEXT NOT NULL,
    updated_at       BIGINT NOT NULL,
    metadata_json    TEXT NOT NULL DEFAULT '{}'
);

-- Bank attestation replay protection for webhook-based user registration
CREATE TABLE IF NOT EXISTS bank_attestation_nonces (
    provider_id TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    issued_at   BIGINT NOT NULL,
    PRIMARY KEY (provider_id, nonce)
);

-- BabyJubJub ZKP credentials (cached after issuer claim)
CREATE TABLE IF NOT EXISTS user_credentials (
    key_image_hex   TEXT PRIMARY KEY,
    credential_json TEXT NOT NULL,
    issued_at       BIGINT NOT NULL
);

-- ZKP pre-auth codes (stored at user registration, claimed on first credential fetch)
CREATE TABLE IF NOT EXISTS credential_codes (
    key_image_hex   TEXT    PRIMARY KEY,
    pre_auth_code   TEXT    NOT NULL,
    subject_did     TEXT    NOT NULL,
    issued_at       BIGINT  NOT NULL,
    claimed         INTEGER NOT NULL DEFAULT 0
);

-- User <-> client relationship
CREATE TABLE IF NOT EXISTS user_registrations (
    id                 BIGSERIAL PRIMARY KEY,
    client_name        TEXT    NOT NULL,
    user_key_image_hex TEXT    NOT NULL,
    source             TEXT    NOT NULL DEFAULT 'register',
    timestamp          BIGINT  NOT NULL,
    UNIQUE (client_name, user_key_image_hex, source)
);

-- Consent log (GDPR-auditable)
CREATE TABLE IF NOT EXISTS consent_log (
    id                    BIGSERIAL PRIMARY KEY,
    request_id            TEXT    UNIQUE NOT NULL,
    user_key_image        TEXT    NOT NULL DEFAULT '',
    site_name             TEXT    NOT NULL,
    requested_claims_json TEXT    NOT NULL DEFAULT '[]',
    granted_at            BIGINT  NOT NULL DEFAULT 0,
    consent_expires_at    BIGINT  NOT NULL DEFAULT 0,
    consent_token         TEXT    UNIQUE,
    token_used            INTEGER NOT NULL DEFAULT 0,
    revoked               INTEGER NOT NULL DEFAULT 0,
    issuing_agent_id      TEXT    DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_consent_log_token   ON consent_log (consent_token, token_used, revoked, consent_expires_at);
CREATE INDEX IF NOT EXISTS idx_consent_log_request ON consent_log (request_id, token_used, revoked);

-- AI agents delegated by human owners
CREATE TABLE IF NOT EXISTS agents (
    id                          BIGSERIAL PRIMARY KEY,
    agent_id                    TEXT    UNIQUE NOT NULL,
    human_key_image             TEXT    NOT NULL,
    agent_checksum              TEXT    NOT NULL,
    intent_json                 TEXT    NOT NULL DEFAULT '{}',
    assurance_level             TEXT    NOT NULL DEFAULT 'delegated_nonbank'
                                        CHECK (assurance_level IN ('delegated_bank', 'delegated_nonbank', 'autonomous_web3')),
    public_key_hex              TEXT    NOT NULL DEFAULT '',
    ring_key_image_hex          TEXT    NOT NULL DEFAULT '',
    parent_agent_id             TEXT    DEFAULT NULL,
    delegation_depth            INTEGER NOT NULL DEFAULT 0,
    pop_jkt                     TEXT    NOT NULL DEFAULT '',
    pop_public_key_b64u         TEXT    NOT NULL DEFAULT '',
    attestation_blob            TEXT,
    attestation_kind            TEXT    NOT NULL DEFAULT '',
    -- M1 of TPM2-bound PoP key roadmap (docs/planning/roadmap.md Plan 1):
    -- nullable hardware-attestation fields, populated when attestation_kind
    -- is 'tpm2_quote'. The verifier (M2) reads these to walk the EK chain
    -- and compare PCRs against the registered measurement.
    attestation_pubkey_b64u     TEXT,
    attestation_pcr_set         TEXT,
    attestation_ek_cert_chain_pem TEXT,
    issued_at                   BIGINT  NOT NULL,
    expires_at                  BIGINT  NOT NULL,
    revoked                     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_agents_human_active ON agents (human_key_image, revoked, expires_at);

-- Idempotent ALTERs for clusters running an earlier 0001_initial.sql snapshot.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS attestation_blob              TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS attestation_kind              TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS attestation_pubkey_b64u       TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS attestation_pcr_set           TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS attestation_ek_cert_chain_pem TEXT;

-- Agent VCs (self-sovereign KYA path)
CREATE TABLE IF NOT EXISTS agent_vcs (
    agent_id        TEXT    PRIMARY KEY,
    vc_json         TEXT    NOT NULL,
    vc_hash         TEXT    NOT NULL,
    issued_at       BIGINT  NOT NULL,
    expires_at      BIGINT  NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
);

-- Trusted device tokens (silent re-auth)
CREATE TABLE IF NOT EXISTS device_tokens (
    token_hash       TEXT    PRIMARY KEY,
    user_key_image   TEXT    NOT NULL,
    site_name        TEXT    NOT NULL,
    fingerprint_hash TEXT    NOT NULL,
    issued_at        BIGINT  NOT NULL,
    expires_at       BIGINT  NOT NULL,
    revoked          INTEGER NOT NULL DEFAULT 0
);

-- API usage billing (per-call metering)
CREATE TABLE IF NOT EXISTS api_usage (
    id          BIGSERIAL PRIMARY KEY,
    client_name TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    is_agent    INTEGER NOT NULL DEFAULT 0,
    timestamp   BIGINT  NOT NULL,
    meta        TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_api_usage_client_ts ON api_usage (client_name, timestamp);

-- Merkle commitment ledger
CREATE TABLE IF NOT EXISTS merkle_leaves (
    seq             BIGSERIAL PRIMARY KEY,
    commitment_hex  TEXT    NOT NULL UNIQUE,
    registered_at   BIGINT  NOT NULL
);

-- Anonymous request log
CREATE TABLE IF NOT EXISTS requests_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   BIGINT  NOT NULL,
    action_type TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'OK',
    detail      TEXT    NOT NULL DEFAULT ''
);

-- Pre-computed analytics
CREATE TABLE IF NOT EXISTS company_data (
    company_id  BIGINT NOT NULL,
    data_type   TEXT   NOT NULL CHECK (data_type IN ('stats', 'forecast', 'fraud_summary', 'fraud_recent')),
    data_json   TEXT   NOT NULL,
    PRIMARY KEY (company_id, data_type)
);

-- A-JWT JTI replay protection (server authoritative)
CREATE TABLE IF NOT EXISTS ajwt_used_jtis (
    jti     TEXT PRIMARY KEY NOT NULL,
    exp     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ajwt_used_jtis_exp ON ajwt_used_jtis (exp);

-- One-time PoP challenges
CREATE TABLE IF NOT EXISTS agent_pop_challenges (
    id          TEXT PRIMARY KEY NOT NULL,
    agent_id    TEXT NOT NULL,
    challenge   TEXT NOT NULL,
    exp         BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_pop_challenges_exp ON agent_pop_challenges (exp);

-- Server-computed agent checksum inputs (M3 port).
-- See core/src/db.rs init_schema for the SQLite mirror.
CREATE TABLE IF NOT EXISTS agent_checksum_inputs (
    agent_id          TEXT    PRIMARY KEY NOT NULL,
    agent_type        TEXT    NOT NULL,
    inputs_canonical  TEXT    NOT NULL,
    computed_checksum TEXT    NOT NULL,
    version           INTEGER NOT NULL DEFAULT 1,
    created_at        BIGINT  NOT NULL,
    updated_at        BIGINT  NOT NULL
);

-- Append-only audit trail for checksum rotations (M3 port).
-- NOTE: SQLite uses INTEGER PRIMARY KEY AUTOINCREMENT; Postgres uses
-- BIGSERIAL. Callers MUST NOT rely on gap-free monotonic ids on Postgres:
-- a BIGSERIAL sequence advances on rollback as well as commit.
CREATE TABLE IF NOT EXISTS agent_checksum_audit (
    id                BIGSERIAL PRIMARY KEY,
    agent_id          TEXT    NOT NULL,
    from_checksum     TEXT    NOT NULL,
    to_checksum       TEXT    NOT NULL,
    from_inputs_hash  TEXT    NOT NULL,
    to_inputs_hash    TEXT    NOT NULL,
    reason            TEXT    NOT NULL DEFAULT '',
    actor             TEXT    NOT NULL DEFAULT '',
    ts                BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_checksum_audit_agent ON agent_checksum_audit (agent_id, ts);

-- Per-call signature nonces (DPoP-style replay protection)
CREATE TABLE IF NOT EXISTS agent_call_nonces (
    agent_id    TEXT    NOT NULL,
    nonce       TEXT    NOT NULL,
    exp         BIGINT  NOT NULL,
    PRIMARY KEY (agent_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_agent_call_nonces_exp ON agent_call_nonces (exp);

-- Cryptographic action leash: ring-signed envelope nonces
CREATE TABLE IF NOT EXISTS agent_action_nonces (
    nonce       TEXT PRIMARY KEY NOT NULL,
    agent_id    TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    expires_at  BIGINT NOT NULL,
    used_at     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_action_nonces_exp ON agent_action_nonces (expires_at);

CREATE TABLE IF NOT EXISTS agent_action_receipts (
    receipt_id         TEXT PRIMARY KEY NOT NULL,
    action_hash        TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    ring_key_image_hex TEXT NOT NULL,
    policy_version     TEXT NOT NULL,
    ajwt_jti           TEXT NOT NULL,
    pop_jkt            TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL,
    signature          TEXT NOT NULL,
    created_at         BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_action_receipts_agent ON agent_action_receipts (agent_id, created_at);

-- Single-use payment authorisation envelopes
CREATE TABLE IF NOT EXISTS agent_payment_authorizations (
    auth_id        TEXT PRIMARY KEY NOT NULL,
    agent_id       TEXT NOT NULL,
    jti            TEXT NOT NULL UNIQUE,
    amount_minor   BIGINT NOT NULL,
    currency       TEXT NOT NULL,
    merchant_id    TEXT NOT NULL DEFAULT '',
    payment_ref    TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    consumed       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_agent       ON agent_payment_authorizations (agent_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_payment_auth_payment_ref ON agent_payment_authorizations (payment_ref);

-- Payment SMT leaves
CREATE TABLE IF NOT EXISTS payment_smt_leaves (
    key_hex     TEXT    PRIMARY KEY NOT NULL,
    value       INTEGER NOT NULL DEFAULT 0,
    updated_at  BIGINT  NOT NULL
);

-- Bitcoin anchoring receipts (mock or OpenTimestamps)
CREATE TABLE IF NOT EXISTS bitcoin_merkle_anchors (
    anchor_id          TEXT PRIMARY KEY NOT NULL,
    merkle_root_hex    TEXT NOT NULL,
    provider           TEXT NOT NULL,
    network            TEXT NOT NULL,
    op_return_hex      TEXT NOT NULL,
    txid               TEXT NOT NULL,
    broadcast          INTEGER NOT NULL DEFAULT 0,
    no_real_money      INTEGER NOT NULL DEFAULT 1,
    created_at         BIGINT NOT NULL,
    ots_receipt_blob   BYTEA,
    ots_calendar_url   TEXT NOT NULL DEFAULT '',
    ots_upgraded       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bitcoin_merkle_root ON bitcoin_merkle_anchors (merkle_root_hex);

-- Solana anchoring receipts (Memo Program transactions)
CREATE TABLE IF NOT EXISTS solana_merkle_anchors (
    anchor_id        TEXT PRIMARY KEY NOT NULL,
    merkle_root_hex  TEXT NOT NULL,
    network          TEXT NOT NULL,
    signature        TEXT NOT NULL UNIQUE,
    slot             BIGINT NOT NULL DEFAULT 0,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    created_at       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_solana_merkle_root ON solana_merkle_anchors (merkle_root_hex);
CREATE INDEX IF NOT EXISTS idx_solana_pending     ON solana_merkle_anchors (confirmed, created_at);

-- Sliding-window rate-limit counters
CREATE TABLE IF NOT EXISTS risk_rate_counters (
    bucket      TEXT    NOT NULL,
    window_id   BIGINT  NOT NULL,
    cnt         BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, window_id)
);
CREATE INDEX IF NOT EXISTS idx_risk_rate_counters_window ON risk_rate_counters (window_id);

-- Compliance screening overlays (sanctions / PEP / risk tier)
CREATE TABLE IF NOT EXISTS user_compliance_screening (
    key_image_hex   TEXT PRIMARY KEY NOT NULL,
    sanctions_tier  TEXT NOT NULL DEFAULT 'unknown',
    pep_flag        INTEGER NOT NULL DEFAULT 0,
    risk_tier       TEXT NOT NULL DEFAULT 'unknown',
    list_version    TEXT NOT NULL DEFAULT '',
    updated_at      BIGINT NOT NULL DEFAULT 0
);

-- Merkle batch anchors that timestamp agent_action_receipts on BTC/Solana.
-- tenant_id is added by 0004_multi_tenant.sql (same pattern as agents etc.).
CREATE TABLE IF NOT EXISTS agent_action_anchors (
    anchor_id        TEXT PRIMARY KEY NOT NULL,
    batch_root_hex   TEXT NOT NULL,
    n_actions        BIGINT NOT NULL,
    from_receipt_id  TEXT NOT NULL,
    to_receipt_id    TEXT NOT NULL,
    from_created_at  BIGINT NOT NULL,
    to_created_at    BIGINT NOT NULL,
    btc_anchor_id    TEXT NOT NULL DEFAULT '',
    sol_anchor_id    TEXT NOT NULL DEFAULT '',
    created_at       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_root  ON agent_action_anchors (batch_root_hex);
CREATE INDEX IF NOT EXISTS idx_agent_action_anchors_range ON agent_action_anchors (from_created_at, to_created_at);

-- Agent egress audit/enforcement log (see core/src/egress_gateway.rs).
-- tenant_id is added by 0004_multi_tenant.sql.
CREATE TABLE IF NOT EXISTS agent_egress_log (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      TEXT    NOT NULL,
    target_host   TEXT    NOT NULL,
    target_path   TEXT    NOT NULL DEFAULT '',
    method        TEXT    NOT NULL,
    body_hash_hex TEXT    NOT NULL DEFAULT '',
    status_code   INTEGER NOT NULL DEFAULT 0,
    ts            BIGINT  NOT NULL,
    allowed       INTEGER NOT NULL DEFAULT 1
);

-- Lightning/L402 invoices for agent-paid APIs. Intentionally NOT tenant-scoped
-- (see 0004_multi_tenant.sql header).
CREATE TABLE IF NOT EXISTS lightning_l402_invoices (
    invoice_id      TEXT    PRIMARY KEY NOT NULL,
    auth_id         TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    service         TEXT    NOT NULL,
    amount_msat     BIGINT  NOT NULL,
    payment_hash    TEXT    NOT NULL,
    macaroon        TEXT    NOT NULL UNIQUE,
    settled         INTEGER NOT NULL DEFAULT 0,
    created_at      BIGINT  NOT NULL,
    expires_at      BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lightning_l402_auth ON lightning_l402_invoices (auth_id);

COMMIT;
