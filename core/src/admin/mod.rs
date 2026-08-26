//! Admin surface. One file per concern; `auth.rs` gates all of them.

mod agents;
mod anchors;
mod auth;
mod clients;
mod health;
mod keys;
mod queries;
mod status;

pub use agents::*;
pub use anchors::*;
pub use auth::*;
pub use clients::*;
pub use health::*;
pub use keys::*;
pub use queries::*;
pub use status::*;

#[cfg(test)]
mod owner_session_revocation_tests;
#[cfg(test)]
mod tests;
