// Calibrated clippy allows — style/complexity/doc-formatting heuristics only,
// NOT correctness/perf/security. The release gate still runs
// `clippy --all-targets -- -D warnings`, so real defects still fail CI; these
// four are noise on a codebase with legitimately multi-arg security fns and
// hand-written doc tables.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

pub mod admin;
pub mod agent;
pub mod agent_action;
pub mod agent_action_anchor;
pub mod agent_checksum;
pub mod aggregation;
pub mod ajwt_support;
pub mod any_db;
pub mod attestation;
pub mod audit;
/// Back-compat alias: the legacy `attestation_cbor` flat-file module lives at
/// `attestation::cbor` since the Sprint 6 module-layout refactor. Existing
/// integration tests import `sauron_core::attestation_cbor::*` — this
/// re-export preserves that path without forcing every test to update its
/// `use` lines.
pub mod bitcoin_anchor;
pub mod crypto_protocol;
pub mod db;
pub mod dpop;
pub mod egress_gateway;
pub mod error;
pub mod identity;
pub mod merkle;
pub mod middleware;
pub mod oprf;
pub mod policy;
pub mod repository;
pub mod ring;
pub mod ring_pseudonym;
pub mod rings;
pub mod risk;
pub mod routes;
pub mod runtime_mode;
pub mod secret_provider;
pub mod sites;
pub mod solana_anchor;
pub mod sql_translate;
pub mod state;
pub mod sync_recover;
pub mod tenancy;
pub mod transparent_proof;
pub mod usage;
pub mod user_session;
