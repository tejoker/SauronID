//! Partner-site (client) creation.

use axum::{extract::State, http::StatusCode, response::Json};
use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::error::AppError;
use crate::identity::Identity;
use crate::sites::ClientType;
use crate::sql_params;
use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

// ─────────────────────────────────────────────────────
//  POST /admin/clients — créer un nouveau site partenaire
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddClientRequest {
    pub name: String,
    pub client_type: ClientType,
    /// Production partners generate and retain their own ring key. The server
    /// receives only the public key and key image; it never stores custody.
    #[serde(default)]
    pub public_key_hex: Option<String>,
    #[serde(default)]
    pub key_image_hex: Option<String>,
}

#[derive(Serialize)]
pub struct AddClientResponse {
    pub name: String,
    pub public_key_hex: String,
    pub key_image_hex: String,
    pub client_type: String,
    /// Development-only one-time secret when the server generated the key.
    /// Never persisted, and forbidden by default in production.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex_once: Option<String>,
}

pub async fn add_client(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<axum::Extension<crate::tenancy::TenantId>>,
    Json(payload): Json<AddClientRequest>,
) -> Result<Json<AddClientResponse>, AppError> {
    let tenant_id = tenant.map(|axum::Extension(t)| t).unwrap_or_default().0;
    let require_external = crate::runtime_mode::require_or_default(
        "SAURON_REQUIRE_EXTERNAL_CLIENT_KEYS",
        /* dev_default */ false,
        /* prod_default */ true,
    );
    let (pub_hex, ki_hex, private_key_hex_once) = match (
        &payload.public_key_hex,
        &payload.key_image_hex,
    ) {
        (Some(pub_hex), Some(ki_hex)) => {
            use curve25519_dalek::ristretto::CompressedRistretto;
            use curve25519_dalek::traits::Identity as _;
            for (label, encoded) in [("public_key_hex", pub_hex), ("key_image_hex", ki_hex)] {
                let bytes = hex::decode(encoded)
                    .map_err(|_| (StatusCode::BAD_REQUEST, format!("{label} must be hex")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| (StatusCode::BAD_REQUEST, format!("{label} must be 32 bytes")))?;
                let point = CompressedRistretto(arr).decompress().ok_or((
                    StatusCode::BAD_REQUEST,
                    format!("{label} is not a valid Ristretto point"),
                ))?;
                if point == curve25519_dalek::RistrettoPoint::identity() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("{label} must not be the identity point"),
                    )
                        .into());
                }
            }
            (pub_hex.clone(), ki_hex.clone(), None)
        }
        (None, None) if !require_external => {
            let identity = Identity::random();
            (
                identity.public_hex(),
                identity.key_image_hex(),
                Some(identity.secret_hex()),
            )
        }
        (None, None) => {
            return Err((
                    StatusCode::BAD_REQUEST,
                    "production requires externally generated public_key_hex and key_image_hex; private partner keys must never enter SauronID custody".into(),
                ).into());
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "public_key_hex and key_image_hex must be supplied together".into(),
            )
                .into());
        }
    };
    let type_str = payload.client_type.as_db_str();

    // Persistance en DB.
    {
        let st = state.read_or_recover();
        let mut db = st.db.lock().unwrap();
        // Both rows or neither: a client without its tenant binding is
        // unreachable and would block the name from being re-registered.
        db.any_conn()
            .transaction(|tx| {
                tx.execute(
                    "INSERT INTO clients (name, public_key_hex, key_image_hex, client_type)
             VALUES (?1, ?2, ?3, ?4)",
                    sql_params![&payload.name, &pub_hex, &ki_hex, type_str],
                )?;
                tx.execute(
                    "INSERT INTO client_tenant_bindings (client_name, tenant_id) VALUES (?1, ?2)",
                    sql_params![&payload.name, &tenant_id],
                )?;
                Ok(())
            })
            .map_err(|e| {
                // A duplicate client name is a 409; losing the write lock is a
                // 503 the caller should retry; anything else is a 500. Each
                // backend spells the violation differently.
                let msg = e.to_lowercase();
                if msg.contains("unique") || msg.contains("duplicate key") {
                    (
                        StatusCode::CONFLICT,
                        format!("Client already exists or DB error: {e}"),
                    )
                } else if crate::error::is_db_contention(&e) {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("database busy, retry shortly: {e}"),
                    )
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, e)
                }
            })?;
    }

    // Ajouter la clé publique au groupe client en mémoire (pour vérifier les ring sigs Flux 1).
    {
        let mut st = state.write_or_recover();
        // pub_hex is server-generated via Identity::random() so decoding is
        // expected to succeed, but we defensively avoid panic on any future
        // refactor that pipes user-influenced hex through this path.
        let pub_bytes = hex::decode(&pub_hex).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("hex decode: {e}"),
            )
        })?;
        if let Some(pt) = CompressedRistretto::from_slice(&pub_bytes)
            .ok()
            .and_then(|c| c.decompress())
        {
            st.client_group.add_member(pt);
        }
        tracing::info!(
            target: "sauron::admin",
            client = %payload.name,
            client_type = %type_str,
            client_group_size = st.client_group.members.len(),
            "new client added"
        );
    }

    Ok(Json(AddClientResponse {
        name: payload.name,
        public_key_hex: pub_hex,
        key_image_hex: ki_hex,
        client_type: type_str.to_string(),
        private_key_hex_once,
    }))
}
