use axum::{extract::{State, Json}, http::StatusCode};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use crate::state::{ServerState, sign_token};

// ─────────────────────────────────────────────────────
//  POST /client/add_tokens
//  Émet N Token B signés par le serveur.
//  Le frontend (site partenaire) gère sa propre balance en local.
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddTokensRequest {
    pub site_name: String,
    pub amount: u32,
}

#[derive(Serialize)]
pub struct AddTokensResponse {
    pub site: String,
    pub issued: u32,
    /// Tokens B signés prêts à l'emploi : "blind_value:sig"
    pub tokens: Vec<String>,
}

pub async fn add_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AddTokensRequest>,
) -> Result<Json<AddTokensResponse>, StatusCode> {
    if payload.amount == 0 || payload.amount > 10_000 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token_secret = {
        let st = state.read().unwrap();
        st.token_secret.clone()
    };

    // Génére des Token B signés sans stocker de balance en DB.
    let tokens: Vec<String> = (0..payload.amount)
        .map(|i| {
            use std::time::{SystemTime, UNIX_EPOCH};
            use sha2::{Sha256, Digest};
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let mut h = Sha256::new();
            h.update(&token_secret);
            h.update(b"BLIND_B:");
            h.update(payload.site_name.as_bytes());
            h.update(b":");
            h.update(&ts.as_nanos().to_le_bytes());
            h.update(&i.to_le_bytes());
            let blind_value = hex::encode(&h.finalize()[..16]);
            let sig = sign_token(&token_secret, "TOKEN_B", &blind_value);
            format!("{blind_value}:{sig}")
        })
        .collect();

    {
        let mut st = state.write().unwrap();
        st.total_tokens_b_issued += payload.amount as usize;
        st.log("ADD_TOKENS", "OK", &format!("site={} amount={}", payload.site_name, payload.amount));
    }

    println!("[BILLING] POST /client/add_tokens | '{}' +{} Token B", payload.site_name, payload.amount);

    Ok(Json(AddTokensResponse {
        site: payload.site_name,
        issued: payload.amount,
        tokens,
    }))
}
