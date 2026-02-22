use rusqlite::Connection;

/// Ouvre une base SQLite **en mémoire** (vierge à chaque démarrage) et initialise le schéma.
pub fn open_db() -> Connection {
    let conn = Connection::open_in_memory().expect("cannot open in-memory SQLite");
    init_schema(&conn);
    println!("[DB] In-memory SQLite initialized.");
    conn
}

/// Crée toutes les tables au premier démarrage.
pub fn init_schema(conn: &Connection) {
    conn.execute_batch("
        PRAGMA journal_mode = WAL;

        -- Sites partenaires (Issuers KYC + Receivers ZKP)
        -- Les clés privées sont stockées exceptionnellement pour le hackathon
        -- afin d'être servies au frontend via /dev/clients.
        CREATE TABLE IF NOT EXISTS clients (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    UNIQUE NOT NULL,
            public_key_hex  TEXT    NOT NULL,
            private_key_hex TEXT    NOT NULL,
            key_image_hex   TEXT    NOT NULL,
            client_type     TEXT    NOT NULL CHECK(client_type IN ('FULL_KYC', 'ZKP_ONLY')),
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

        -- Relation Client ↔ User (qui a onboardé qui, qui a récupéré le KYC de qui)
        CREATE TABLE IF NOT EXISTS user_registrations (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name        TEXT    NOT NULL,
            user_key_image_hex TEXT    NOT NULL,
            source             TEXT    NOT NULL DEFAULT 'register',
            timestamp          INTEGER NOT NULL,
            UNIQUE(client_name, user_key_image_hex, source)
        );

        -- Tokens A brûlés lors des échanges (Flux 2) — anti-double-dépense
        CREATE TABLE IF NOT EXISTS tokens_a_burned (
            hash TEXT PRIMARY KEY
        );

        -- Tokens B dépensés lors des récupérations KYC/ZKP (Flux 3) — anti-double-dépense
        CREATE TABLE IF NOT EXISTS tokens_b_spent (
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

        -- Données analytics pré-calculées (stats, forecast, fraud)
        -- Stockées comme blobs JSON par company_id + data_type.
        CREATE TABLE IF NOT EXISTS company_data (
            company_id  INTEGER NOT NULL,
            data_type   TEXT    NOT NULL CHECK(data_type IN ('stats', 'forecast', 'fraud_summary', 'fraud_recent')),
            data_json   TEXT    NOT NULL,
            PRIMARY KEY (company_id, data_type)
        );

        -- Commitment Ledger (Merkle Tree — Préparation Solana).
        -- Chaque ligne représente une feuille de l'arbre de Merkle :
        -- le commitment est le SHA256 d'un secret généré par le client KYC.
        -- Cet ordre chronologique permet de reconstruire l'arbre en mémoire
        -- au redémarrage du serveur avec une fidélité bit-à-bit.
        CREATE TABLE IF NOT EXISTS merkle_leaves (
            seq             INTEGER PRIMARY KEY AUTOINCREMENT,
            commitment_hex  TEXT    NOT NULL UNIQUE,
            registered_at   INTEGER NOT NULL
        );
    ").expect("DB schema init failed");
}
