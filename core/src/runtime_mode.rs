//! Process-wide runtime mode (development vs production-like). Kept dependency-free so
//! compliance, risk, and DB layers can consult it without import cycles with `state`.

pub fn runtime_environment() -> String {
    std::env::var("ENV")
        .or_else(|_| std::env::var("SAURON_ENV"))
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase()
}

pub fn is_development_runtime() -> bool {
    matches!(
        runtime_environment().as_str(),
        "development" | "dev" | "local"
    )
}
