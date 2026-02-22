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
            client_type     TEXT    NOT NULL CHECK(client_type IN ('FULL_KYC', 'ZKP_ONLY'))
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
    ").expect("DB schema init failed");
}
