//! Envelope, proof and receipt shapes for the agent-action path.

use super::*;
// Production paths in this file go through `AnyConn`, so `params!` is only used
// by the tests below, which build SQLite fixtures directly.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ring;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionEnvelope {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    pub nonce: String,
    pub expires_at: i64,
    pub policy_hash: String,
    pub ajwt_jti: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentActionProof {
    pub envelope: AgentActionEnvelope,
    #[serde(alias = "agent_ring_signature")]
    pub ring_signature: ring::RingSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub tenant_id: String,
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub ring_key_image_hex: String,
    pub policy_version: String,
    pub ajwt_jti: String,
    pub pop_jkt: String,
    pub timestamp: i64,
    pub status: String,
    pub signature: String,
    /// Dense, monotonic position in this tenant's receipt chain. 0 marks a
    /// legacy receipt written before chaining existed.
    #[serde(default)]
    pub seq: i64,
    /// [`receipt_chain_hash`] of the receipt at `seq - 1`. Empty at seq 1 (chain
    /// genesis) and on legacy receipts.
    #[serde(default)]
    pub prev_hash: String,
    /// Hash of the owner-signed mandate that authorised this action, copied from
    /// the agent record at receipt time.
    ///
    /// An agent can be re-registered under a wider mandate later; without this,
    /// an auditor holding a receipt cannot tell WHICH grant was in force when
    /// the action happened. Empty when the agent registered before owner
    /// mandates, or on the anonymous ring path where there is no agent identity
    /// to resolve one from.
    #[serde(default)]
    pub owner_mandate_hash: String,
}

#[derive(Clone, Debug)]
pub struct AgentActionValidation {
    pub action_hash: String,
    pub ring_key_image_hex: String,
    pub receipt: ActionReceipt,
}

pub struct ValidateAgentActionOptions<'a> {
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
    pub human_key_image: &'a str,
    pub ajwt_jti: &'a str,
    pub intent: Option<&'a Value>,
    pub expected_action: &'a str,
    pub expected_resource: Option<&'a str>,
    pub expected_merchant_id: Option<&'a str>,
    pub expected_amount_minor: Option<i64>,
    pub expected_currency: Option<&'a str>,
    pub pop_jkt: Option<&'a str>,
    pub status: &'a str,
}

#[derive(Deserialize)]
pub struct AgentActionChallengeBody {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    pub ajwt_jti: String,
    #[serde(default = "default_challenge_ttl_secs")]
    pub ttl_secs: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentActionChallengeResponse {
    pub envelope: AgentActionEnvelope,
    pub canonical: String,
    pub action_hash: String,
    pub agent_ring_public_keys_hex: Vec<String>,
    pub signer_index: usize,
    pub signing_public_key_hex: String,
}

#[derive(Deserialize)]
pub struct ReceiptVerifyBody {
    pub receipt: ActionReceipt,
}
