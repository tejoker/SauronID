//! Policy DSL: declarative agent-binding configuration. See docs/architecture/policy-dsl.md for the schema.
//!
//! Layout:
//! - `assurance`  — KYA assurance-level matrix (legacy, ported from `policy.rs`).
//! - `ast`        — Sprint 1: AST types for the YAML/JSON DSL.
//! - `types`      — Sprint 1: shared newtypes, enums, errors, validators.
//! - `parser`     — Sprint 1: YAML/JSON parser + semantic validation.
//! - `invariants` — Sprint 2: runtime invariant library (budget/scope/rate/…).
//! - `compiler`   — Sprint 2: parsed policy → executable check list.
//! - `evaluator`  — Sprint 2: run compiled checks against an action.
//! - `store`      — Sprint 2: in-memory cache + SQL persistence.
//! - `handlers`   — Sprint 2: HTTP routes (`/v1/policy/*`).
//!
//! Convenience re-exports keep `core::policy::parse` callable without
//! `core::policy::parser::parse`.

pub mod assurance;
pub mod ast;
pub mod binding_handlers;
pub mod compiler;
pub mod evaluator;
pub mod expressions;
pub mod handlers;
pub mod invariants;
pub mod parser;
pub mod store;
pub mod types;

pub use assurance::*;
pub use ast::*;
pub use compiler::{compile, hash_policy, CompileError, CompiledPolicy};
pub use evaluator::{evaluate, evaluate_with_trace};
pub use invariants::{Action, EvaluationContext, RuntimeCheck, Verdict};
pub use parser::{parse, parse_json, parse_yaml, validate, SUPPORTED_VERSION};
pub use store::{PolicyStore, PolicySummary, StoreError};
pub use types::{
    validate_hhmm, validate_iana_tz, Allowlist, Budget, DataClassification, PolicyParseError,
};
