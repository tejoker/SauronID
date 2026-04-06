use rusqlite::Connection;

/// Ouvre une base SQLite persistante (chemin depuis DATABASE_PATH, défaut ./sauron.db).
pub fn open_db() -> Connection {
    let path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./sauron.db".to_string());
    let conn = Connection::open(&path).unwrap_or_else(|e| {
        panic!("cannot open SQLite at '{}': {}", path, e)
    });
    init_schema(&conn);
    println!("[DB] SQLite opened at '{}'.", path);
    conn
}

/// Crée toutes les tables si elles n'existent pas encore (idempotent).
pub fn init_schema(conn: &Connection) {
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        -- Sites partenaires (banks + retail sites)
        CREATE TABLE IF NOT EXISTS clients (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    UNIQUE NOT NULL,
            public_key_hex  TEXT    NOT NULL,
            private_key_hex TEXT    NOT NULL,
            key_image_hex   TEXT    NOT NULL,
            client_type     TEXT    NOT NULL CHECK(client_type IN ('FULL_KYC', 'ZKP_ONLY', 'BANK')),
            tokens_a        INTEGER NOT NULL DEFAULT 0,
            tokens_b        INTEGER NOT NULL DEFAULT 0
        );

        -- Utilisateurs enregistrés sur le réseau Sauron
        CREATE TABLE IF NOT EXISTS users (
            key_image_hex   TEXT PRIMARY KEY,
            public_key_hex  TEXT NOT NULL,
            first_name      TEXT NOT NULL DEFAULT '',
            last_name       TEXT NOT NULL DEFAULT '',
            email           TEXT NOT NULL DEFAULT '',
            date_of_birth   TEXT NOT NULL DEFAULT '',
            nationality     TEXT NOT NULL DEFAULT ''
        );

        -- Credentials ZKP signés par l'issuer BabyJubJub pour chaque utilisateur.
        -- Stockés côté serveur pour être récupérés par le client (consent popup).
        CREATE TABLE IF NOT EXISTS user_credentials (
            key_image_hex   TEXT PRIMARY KEY,
            credential_json TEXT NOT NULL,
            issued_at       INTEGER NOT NULL
        );

        -- Relation Client <-> User
        CREATE TABLE IF NOT EXISTS user_registrations (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name        TEXT    NOT NULL,
            user_key_image_hex TEXT    NOT NULL,
            source             TEXT    NOT NULL DEFAULT 'register',
            timestamp          INTEGER NOT NULL,
            UNIQUE(client_name, user_key_image_hex, source)
        );

        -- Consentements utilisateur (RGPD-auditable).
        CREATE TABLE IF NOT EXISTS consent_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id      TEXT    UNIQUE NOT NULL,
            user_key_image  TEXT    NOT NULL,
            site_name       TEXT    NOT NULL,
            granted_at      INTEGER NOT NULL,
            consent_token   TEXT    UNIQUE,
            token_used      INTEGER NOT NULL DEFAULT 0,
            revoked         INTEGER NOT NULL DEFAULT 0,
            -- non-null when consent was granted by an agent (not the human directly)
            issuing_agent_id TEXT   DEFAULT NULL
        );

        -- Agents IA délégués par des utilisateurs humains.
        CREATE TABLE IF NOT EXISTS agents (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id         TEXT    UNIQUE NOT NULL,
            human_key_image  TEXT    NOT NULL,
            agent_checksum   TEXT    NOT NULL,
            intent_json      TEXT    NOT NULL DEFAULT '{}',
            public_key_hex   TEXT    NOT NULL,
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked          INTEGER NOT NULL DEFAULT 0
        );

        -- Tokens B dépensés (anti-double-dépense)
        CREATE TABLE IF NOT EXISTS tokens_b_spent (
            hash TEXT PRIMARY KEY
        );

        -- Tokens A brûlés (legacy, conservé pour compatibilité)
        CREATE TABLE IF NOT EXISTS tokens_a_burned (
            hash TEXT PRIMARY KEY
        );

        -- Historique anonymisé des requêtes
        CREATE TABLE IF NOT EXISTS requests_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            action_type TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'OK',
            detail      TEXT    NOT NULL DEFAULT ''
        );

        -- Données analytics pré-calculées
        CREATE TABLE IF NOT EXISTS company_data (
            company_id  INTEGER NOT NULL,
            data_type   TEXT    NOT NULL CHECK(data_type IN ('stats', 'forecast', 'fraud_summary', 'fraud_recent')),
            data_json   TEXT    NOT NULL,
            PRIMARY KEY (company_id, data_type)
        );

        -- Commitment Ledger (Merkle Tree)
        CREATE TABLE IF NOT EXISTS merkle_leaves (
            seq             INTEGER PRIMARY KEY AUTOINCREMENT,
            commitment_hex  TEXT    NOT NULL UNIQUE,
            registered_at   INTEGER NOT NULL
        );

        -- ZKP pre-auth codes (issuer credential claims)
        CREATE TABLE IF NOT EXISTS credential_codes (
            key_image_hex   TEXT    PRIMARY KEY,
            pre_auth_code   TEXT    NOT NULL,
            subject_did     TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            claimed         INTEGER NOT NULL DEFAULT 0
        );

        -- Self-sovereign agent VCs (KYA independent path)
        CREATE TABLE IF NOT EXISTS agent_vcs (
            agent_id        TEXT    PRIMARY KEY,
            vc_json         TEXT    NOT NULL,
            liveness_passed INTEGER NOT NULL DEFAULT 0,
            vc_hash         TEXT    NOT NULL,
            issued_at       INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0
        );

        -- Trusted device tokens (silent re-auth)
        CREATE TABLE IF NOT EXISTS device_tokens (
            token_hash      TEXT    PRIMARY KEY,
            user_key_image  TEXT    NOT NULL,
            site_name       TEXT    NOT NULL,
            fingerprint_hash TEXT   NOT NULL,
            issued_at       INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0
        );
    ").expect("DB schema init failed");
}
