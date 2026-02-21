use axum::{extract::{State, Json}, http::StatusCode};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use crate::state::ServerState;

// ─────────────────────────────────────────────────────
//  Route : POST /client/add_tokens
// ─────────────────────────────────────────────────────

/// Simule l'achat de Token B avec fiat par un site partenaire.
/// Dans une production réelle, ce serait remplacé par un paiement Stripe/Solana.
#[derive(Deserialize)]
pub struct AddTokensRequest {
    pub site_name: String,
    pub amount: u32,
}

#[derive(Serialize)]
pub struct AddTokensResponse {
    pub site: String,
    pub added: u32,
    pub purchased_tokens: i64,
}

pub async fn add_tokens(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AddTokensRequest>,
) -> Result<Json<AddTokensResponse>, StatusCode> {
    if payload.amount == 0 || payload.amount > 10_000 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut st = state.write().unwrap();
    let account = st.client_accounts.entry(payload.site_name.clone()).or_default();
    account.purchased_tokens += payload.amount as i64;
    let balance = account.purchased_tokens;

    println!(
        "[BILLING] POST /client/add_tokens | '{}' +{} tokens | purchased_total={}",
        payload.site_name, payload.amount, balance
    );

    Ok(Json(AddTokensResponse {
        site: payload.site_name,
        added: payload.amount,
        purchased_tokens: balance,
    }))
}

// ─────────────────────────────────────────────────────
//  Tests unitaires
// ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::state::ClientAccount;

    #[test]
    fn test_purchased_balance() {
        let mut acc = ClientAccount::default();
        assert_eq!(acc.purchased_balance(), 0);

        acc.purchased_tokens += 10;
        assert_eq!(acc.purchased_balance(), 10);

        acc.purchased_tokens += 5;
        assert_eq!(acc.purchased_balance(), 15);
    }

    #[test]
    fn test_kyc_provided_tracking() {
        let mut acc = ClientAccount::default();
        assert_eq!(acc.kyc_provided, 0);

        acc.kyc_provided += 3;
        assert_eq!(acc.kyc_provided, 3);
    }

    #[test]
    fn test_default_values() {
        let acc = ClientAccount::default();
        assert_eq!(acc.purchased_tokens, 0);
        assert_eq!(acc.kyc_provided, 0);
        assert_eq!(acc.purchased_balance(), 0);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut acc = ClientAccount::default();

        // Site achète 10 tokens B directement
        acc.purchased_tokens += 10;
        assert_eq!(acc.purchased_balance(), 10);

        // Site a injecté 7 KYC (Flux 1) — tracking côté admin
        acc.kyc_provided += 7;
        assert_eq!(acc.kyc_provided, 7);

        // Les tokens B issus de l'échange sont gérés indépendamment (Flux 2)
        // Le compte purchased_tokens reste à 10
        assert_eq!(acc.purchased_balance(), 10);
    }
}
