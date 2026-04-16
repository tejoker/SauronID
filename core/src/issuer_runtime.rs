//! Shared HTTP client + **per-issuer-host** fail-closed circuit breakers for ZKP issuer
//! `verify-proof`. Proof rejection (**HTTP 200** + `verified: false`) does **not** open the circuit.
//! Use [`IssuerRuntime::verify_proof_failover`] with multiple base URLs for redundancy.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug)]
pub struct IssuerCircuitConfig {
    /// 0 disables opening the circuit (still uses timeouts).
    pub failure_threshold: u32,
    pub open_secs: i64,
}

impl IssuerCircuitConfig {
    pub fn from_env() -> Self {
        let failure_threshold = std::env::var("SAURON_ISSUER_CIRCUIT_FAILURE_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5u32);
        let open_secs = std::env::var("SAURON_ISSUER_CIRCUIT_OPEN_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30_i64)
            .clamp(5, 3600);
        Self {
            failure_threshold: failure_threshold.min(1000),
            open_secs,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IssuerCircuitState {
    pub consecutive_trip_events: u32,
    pub open_until_epoch: i64,
}

pub struct IssuerRuntime {
    pub client: reqwest::Client,
    pub circuit_cfg: IssuerCircuitConfig,
    /// One circuit gate per normalized issuer base URL (e.g. `http://issuer-a:4000`).
    gates: Mutex<HashMap<String, IssuerCircuitState>>,
}

#[derive(Clone, Debug)]
pub enum IssuerVerifyError {
    CircuitOpen,
    Transport(String),
    Upstream(u16),
    JsonParse,
}

fn normalize_issuer_base(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

impl IssuerRuntime {
    pub fn from_env() -> Result<Self, String> {
        let connect_ms: u64 = std::env::var("SAURON_HTTP_CONNECT_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000)
            .clamp(100, 60_000);
        let timeout_ms: u64 = std::env::var("SAURON_HTTP_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15000)
            .clamp(500, 120_000);
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(connect_ms))
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| format!("http client build: {e}"))?;
        Ok(Self {
            client,
            circuit_cfg: IssuerCircuitConfig::from_env(),
            gates: Mutex::new(HashMap::new()),
        })
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Snapshot of all issuer endpoints that have interacted with this process (plus configured URLs).
    pub fn circuit_snapshots_json(&self, configured_bases: &[String]) -> serde_json::Value {
        let now = Self::now();
        let map = self.gates.lock().unwrap();
        let mut keys: Vec<String> = map.keys().cloned().collect();
        for k in configured_bases {
            let n = normalize_issuer_base(k);
            if !n.is_empty() && !keys.contains(&n) {
                keys.push(n);
            }
        }
        keys.sort();
        keys.dedup();
        let endpoints: Vec<serde_json::Value> = keys
            .into_iter()
            .map(|base| {
                let g = map.get(&base).copied().unwrap_or_default();
                serde_json::json!({
                    "issuer_base": base,
                    "issuer_circuit_open": self.circuit_cfg.failure_threshold > 0 && now < g.open_until_epoch,
                    "open_until_epoch": g.open_until_epoch,
                    "consecutive_trip_events": g.consecutive_trip_events,
                    "failure_threshold": self.circuit_cfg.failure_threshold,
                })
            })
            .collect();
        serde_json::json!({ "endpoints": endpoints })
    }

    fn record_trip_event(&self, base: &str) {
        if self.circuit_cfg.failure_threshold == 0 {
            return;
        }
        let now = Self::now();
        let k = normalize_issuer_base(base);
        let mut map = self.gates.lock().unwrap();
        let g = map.entry(k).or_default();
        g.consecutive_trip_events = g.consecutive_trip_events.saturating_add(1);
        if g.consecutive_trip_events >= self.circuit_cfg.failure_threshold {
            g.open_until_epoch = now + self.circuit_cfg.open_secs;
            g.consecutive_trip_events = 0;
        }
    }

    fn reset_trips(&self, base: &str) {
        let k = normalize_issuer_base(base);
        let mut map = self.gates.lock().unwrap();
        if let Some(g) = map.get_mut(&k) {
            g.consecutive_trip_events = 0;
        }
    }

    /// POST `{issuer_url}/verify-proof`. Returns cryptographic verification outcome on HTTP 200.
    pub async fn verify_proof_json(&self, issuer_url: &str, body: &Value) -> Result<bool, IssuerVerifyError> {
        let base = normalize_issuer_base(issuer_url);
        if base.is_empty() {
            return Err(IssuerVerifyError::Transport("empty issuer URL".into()));
        }

        let now = Self::now();
        {
            let map = self.gates.lock().unwrap();
            let g = map.get(&base).copied().unwrap_or_default();
            if self.circuit_cfg.failure_threshold > 0 && now < g.open_until_epoch {
                return Err(IssuerVerifyError::CircuitOpen);
            }
        }

        let url = format!("{}/verify-proof", base);
        let resp = match self.client.post(url).json(body).send().await {
            Ok(r) => r,
            Err(e) => {
                self.record_trip_event(&base);
                return Err(IssuerVerifyError::Transport(e.to_string()));
            }
        };

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            let val: Value = resp.json().await.map_err(|_| IssuerVerifyError::JsonParse)?;
            let ok = val
                .get("verified")
                .or_else(|| val.get("valid"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            self.reset_trips(&base);
            return Ok(ok);
        }

        if status == 429 || status >= 500 {
            self.record_trip_event(&base);
        }

        Err(IssuerVerifyError::Upstream(status))
    }

    /// Try each issuer base URL in order until a definitive cryptographic outcome (`Ok(true|false)`),
    /// or transport-style errors are exhausted. Used for redundant ZKP verifiers.
    pub async fn verify_proof_failover(&self, issuer_bases: &[String], body: &Value) -> Result<bool, IssuerVerifyError> {
        let bases: Vec<String> = issuer_bases
            .iter()
            .map(|s| normalize_issuer_base(s))
            .filter(|s| !s.is_empty())
            .collect();
        if bases.is_empty() {
            return Err(IssuerVerifyError::Transport(
                "no issuer URLs configured (set SAURON_ISSUER_URLS or SAURON_ISSUER_URL)".into(),
            ));
        }

        let mut last_err: Option<IssuerVerifyError> = None;
        for base in &bases {
            match self.verify_proof_json(base, body).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let retry = match &e {
                        IssuerVerifyError::CircuitOpen
                        | IssuerVerifyError::Transport(_)
                        | IssuerVerifyError::JsonParse => true,
                        IssuerVerifyError::Upstream(status) => *status == 429 || *status >= 500,
                    };
                    if !retry {
                        return Err(e);
                    }
                    last_err = Some(e.clone());
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            IssuerVerifyError::Transport("all issuer verify-proof attempts failed".into())
        }))
    }
}
