//! In-path agent egress gateway.
//! See `docs/design/agent-egress-gateway.md`.
//!
//! `POST /agent/egress/proxy` is the mandatory outbound path: the agent hands
//! SauronID the request it wants to make, SauronID verifies the bound identity
//! (via the per-call-sig middleware on the route), checks the target host
//! against the agent's `intent_json.egress_allowlist`, vets the resolved IP
//! (SSRF / metadata-endpoint / private-range block), forwards it over a pinned
//! connection with filtered headers and a capped response, and records the call
//! to the anchored `agent_egress_log`. Turns the previously *voluntary* egress
//! reporting (`/agent/egress/log`) into *enforced* egress — provided the
//! deployment blocks direct network egress so the agent must route through here.
//!
//! Ops caveat (unchanged): this gateway constrains egress that flows THROUGH it.
//! It cannot stop an agent that has direct network access — deployments MUST
//! egress-firewall the agent's network so the proxy is the only outbound path.
//!
//! Gated by `SAURON_EGRESS_GATEWAY` (off → 503). Phase 1 does NOT terminate TLS,
//! so it enforces at the host + resolved-IP level only — no payload inspection
//! beyond opt-in PII redaction of the request body.

use crate::any_db::{AnyConn, AnyRowGet};
use crate::error::AppError;
use crate::sql_params;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::ServerState;
use crate::sync_recover::RwLockRecover;

mod capability;
mod config;
mod guards;
mod matching;
mod proxy;

pub use capability::*;
pub use config::*;
pub use guards::*;
// Nothing in matching.rs is public API; the gateway handlers are.
pub(crate) use matching::*;
pub use proxy::*;

#[cfg(test)]
mod tests;
