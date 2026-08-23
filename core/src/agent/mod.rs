// ─────────────────────────────────────────────────────────────────────────────
//  A-JWT Agentic Layer
//
//  An A-JWT (Agentic JSON Web Token) allows an AI agent to call the Sauron API
//  on behalf of a human user.  The token proves:
//    - Which human authorised the agent  (sub = human key_image_hex)
//    - What the agent is allowed to do   (intent JSON)
//    - The agent hasn't been tampered    (agent_checksum = SHA-256 of agent config)
//
//  Token format (EdDSA/Ed25519, base64url-encoded JSON parts):
//    header.payload.signature   (dot-separated, all base64url-no-padding)
//
//  Signing keys are derived per-agent from server secret + agent identity
//  material, so each agent has a distinct effective signing key.
// ─────────────────────────────────────────────────────────────────────────────

mod ajwt;
mod call_sig;
mod handlers;
mod types;

pub use ajwt::*;
pub use call_sig::*;
pub use handlers::*;
pub use types::*;

#[cfg(test)]
mod call_sig_default_deny_tests;
#[cfg(test)]
mod owner_mandate_tests;
#[cfg(test)]
mod tenant_session_tests;
