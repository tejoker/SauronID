use rusqlite::Connection;

/// Opens persistent SQLite (path from DATABASE_PATH, default ./sauron.db).
pub fn open_db() -> Connection {
    let path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./sauron.db".to_string());
    let conn = Connection::open(&path).unwrap_or_else(|e| {
        panic!("cannot open SQLite at '{}': {}", path, e)
    });
    init_schema(&conn);
    println!("[DB] SQLite opened at '{}'.", path);
    conn
}

pub fn init_schema(conn: &Connection) {
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        -- Partner sites (banks + retail)
        CREATE TABLE IF NOT EXISTS clients (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    UNIQUE NOT NULL,
            public_key_hex  TEXT    NOT NULL,
            private_key_hex TEXT    NOT NULL,
            key_image_hex   TEXT    NOT NULL,
            client_type     TEXT    NOT NULL CHECK(client_type IN ('FULL_KYC', 'ZKP_ONLY', 'BANK'))
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

        -- BabyJubJub ZKP credentials (cached after issuer claim)
        CREATE TABLE IF NOT EXISTS user_credentials (
            key_image_hex   TEXT PRIMARY KEY,
            credential_json TEXT NOT NULL,
            issued_at       INTEGER NOT NULL
        );

        -- ZKP pre-auth codes (stored at user registration, claimed on first credential fetch)
        CREATE TABLE IF NOT EXISTS credential_codes (
            key_image_hex   TEXT    PRIMARY KEY,
            pre_auth_code   TEXT    NOT NULL,
            subject_did     TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            claimed         INTEGER NOT NULL DEFAULT 0
        );

        -- User <-> client relationship
        CREATE TABLE IF NOT EXISTS user_registrations (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name        TEXT    NOT NULL,
            user_key_image_hex TEXT    NOT NULL,
            source             TEXT    NOT NULL DEFAULT 'register',
            timestamp          INTEGER NOT NULL,
            UNIQUE(client_name, user_key_image_hex, source)
        );

        -- Consent log (GDPR-auditable)
        CREATE TABLE IF NOT EXISTS consent_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id       TEXT    UNIQUE NOT NULL,
            user_key_image   TEXT    NOT NULL DEFAULT '',
            site_name        TEXT    NOT NULL,
            granted_at       INTEGER NOT NULL DEFAULT 0,
            consent_token    TEXT    UNIQUE,
            token_used       INTEGER NOT NULL DEFAULT 0,
            revoked          INTEGER NOT NULL DEFAULT 0,
            issuing_agent_id TEXT    DEFAULT NULL
        );

        -- AI agents delegated by human owners
        CREATE TABLE IF NOT EXISTS agents (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id         TEXT    UNIQUE NOT NULL,
            human_key_image  TEXT    NOT NULL,
            agent_checksum   TEXT    NOT NULL,
            intent_json      TEXT    NOT NULL DEFAULT '{}',
            public_key_hex   TEXT    NOT NULL DEFAULT '',
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked          INTEGER NOT NULL DEFAULT 0
        );

        -- Agent VCs (self-sovereign KYA path)
        CREATE TABLE IF NOT EXISTS agent_vcs (
            agent_id        TEXT    PRIMARY KEY,
            vc_json         TEXT    NOT NULL,
            vc_hash         TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0
        );

        -- Trusted device tokens (silent re-auth)
        CREATE TABLE IF NOT EXISTS device_tokens (
            token_hash       TEXT    PRIMARY KEY,
            user_key_image   TEXT    NOT NULL,
            site_name        TEXT    NOT NULL,
            fingerprint_hash TEXT    NOT NULL,
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked          INTEGER NOT NULL DEFAULT 0
        );

        -- API usage billing (per-call metering)
        -- action: 'kyc_human' | 'kyc_agent' | 'zkp_login' | 'agent_register' | 'agent_vc_issue'
        CREATE TABLE IF NOT EXISTS api_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            is_agent    INTEGER NOT NULL DEFAULT 0,
            timestamp   INTEGER NOT NULL,
            meta        TEXT    NOT NULL DEFAULT '{}'
        );

        -- Merkle commitment ledger
        CREATE TABLE IF NOT EXISTS merkle_leaves (
            seq             INTEGER PRIMARY KEY AUTOINCREMENT,
            commitment_hex  TEXT    NOT NULL UNIQUE,
            registered_at   INTEGER NOT NULL
        );

        -- Anonymous request log
        CREATE TABLE IF NOT EXISTS requests_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            action_type TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'OK',
            detail      TEXT    NOT NULL DEFAULT ''
        );

        -- Pre-computed analytics
        CREATE TABLE IF NOT EXISTS company_data (
            company_id  INTEGER NOT NULL,
            data_type   TEXT    NOT NULL CHECK(data_type IN ('stats', 'forecast', 'fraud_summary', 'fraud_recent')),
            data_json   TEXT    NOT NULL,
            PRIMARY KEY (company_id, data_type)
        );
    ").expect("DB schema init failed");
}
