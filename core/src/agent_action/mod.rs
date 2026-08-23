//! The agent-action path: envelope, canonical hashing, receipts, validation,
//! the anonymous ring variant, and the HTTP handlers.

use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

mod anon;
mod canonical;
mod handlers;
mod receipts;
mod types;
mod validate;

pub use anon::*;
pub use canonical::*;
pub use handlers::*;
pub use receipts::*;
pub use types::*;
pub use validate::*;

#[cfg(test)]
mod tests;
