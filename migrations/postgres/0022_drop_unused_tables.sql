-- Drop seven tables that were created on every boot and read by nothing.
--
-- Five were dead on both backends: no SELECT, INSERT, UPDATE or DELETE
-- anywhere in core/src referenced them, yet each was carried in the SQLite
-- init_schema AND here, with scripts/ops/check-schema-parity.sh enforcing that
-- the two copies stayed in step. Dead schema with a test keeping it alive.
--
-- Two more (consent_log, credential_codes) backed the end-user KYC consent and
-- credential routes, which are archived under
-- archive/removed-2026-08/kyc-consent/. SauronID constrains agents; it no
-- longer stores a human consent ledger.
--
-- Irreversible for existing data. A deployment that needs the consent history
-- should export it before applying this.
DROP TABLE IF EXISTS bank_attestation_nonces;
DROP TABLE IF EXISTS company_data;
DROP TABLE IF EXISTS device_tokens;
DROP TABLE IF EXISTS lightning_l402_invoices;
DROP TABLE IF EXISTS payment_smt_leaves;
DROP TABLE IF EXISTS consent_log;
DROP TABLE IF EXISTS credential_codes;
