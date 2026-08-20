//! Gaussian mechanism: adds N(0, σ²) noise calibrated to (ε, δ)-DP.
//!
//! Source: Dwork & Roth, *The Algorithmic Foundations of Differential
//! Privacy*, 2014, Theorem A.1 / eq. (3.8):
//! σ ≥ sensitivity · √(2 · ln(1.25 / δ)) / ε.
//!
//! # Operating envelope
//!
//! The Dwork-Roth bound is proven for `ε ∈ (0, 1]` only. For `ε > 1`, the
//! (ε, δ)-DP guarantee does **not** follow from this σ; callers must use
//! the analytic Gaussian mechanism (Balle & Wang, ICML 2018) or a
//! different calibration. This module **rejects** `ε > 1` in
//! [`GaussianMechanism::new`] to enforce the documented envelope.
//!
//! Use the RDP path ([`crate::dp::composition::RdpAccountant::add_gaussian`])
//! for compositions that need a larger effective ε — RDP composes over
//! the per-step (α, σ²/Δ²) pair, not over (ε, δ).

use rand::RngCore;

use super::DpError;

/// Upper bound on `ε` accepted by [`GaussianMechanism::new`]. The
/// Dwork-Roth eq. 3.8 calibration is only proven for `ε ≤ 1`; tighter
/// calibrations (Balle-Wang 2018 analytic Gaussian) are required for
/// `ε > 1`.
pub const MAX_GAUSSIAN_EPSILON: f64 = 1.0;

/// `(ε, δ)`-DP additive-noise mechanism for numeric queries.
///
/// Calibrated to `L2` sensitivity.
#[derive(Debug, Clone, Copy)]
pub struct GaussianMechanism {
    pub epsilon: f64,
    pub delta: f64,
    pub sensitivity: f64,
}

impl GaussianMechanism {
    pub fn new(epsilon: f64, delta: f64, sensitivity: f64) -> Result<Self, DpError> {
        if !epsilon.is_finite() || !delta.is_finite() || !sensitivity.is_finite() {
            return Err(DpError::NonFinite);
        }
        if epsilon <= 0.0 {
            return Err(DpError::InvalidEpsilon(epsilon));
        }
        // Dwork-Roth eq. 3.8 σ-calibration is only valid for ε ≤ 1.
        // Cryptographic-review finding F-1: reject larger ε so a caller cannot
        // silently degrade the (ε, δ)-DP guarantee. Use RdpAccountant or
        // implement the analytic Gaussian (Balle-Wang 2018) for ε > 1.
        if epsilon > MAX_GAUSSIAN_EPSILON {
            return Err(DpError::InvalidEpsilon(epsilon));
        }
        if delta <= 0.0 || delta >= 1.0 {
            return Err(DpError::InvalidDelta(delta));
        }
        if sensitivity < 0.0 {
            return Err(DpError::InvalidSensitivity(sensitivity));
        }
        Ok(Self {
            epsilon,
            delta,
            sensitivity,
        })
    }

    /// Standard deviation σ = sensitivity · √(2 · ln(1.25 / δ)) / ε.
    /// (Dwork-Roth 2014 eq. 3.8.)
    pub fn sigma(&self) -> f64 {
        self.sensitivity * (2.0 * (1.25 / self.delta).ln()).sqrt() / self.epsilon
    }

    /// Add N(0, σ²) noise to `value`.
    ///
    /// Sampling via Box–Muller transform from two uniform samples.
    ///
    /// # RNG requirement
    ///
    /// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
    /// The (ε, δ)-DP guarantee assumes the adversary cannot predict the
    /// noise draw. Seeded `StdRng` is acceptable for tests only.
    pub fn add_noise<R: RngCore>(&self, value: f64, rng: &mut R) -> f64 {
        let sigma = self.sigma();
        let (z0, _z1) = box_muller(rng);
        value + sigma * z0
    }
}

/// Box–Muller: returns two independent standard normal samples.
fn box_muller<R: RngCore>(rng: &mut R) -> (f64, f64) {
    let u1 = uniform_strict(rng);
    let u2 = uniform_strict(rng);
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;
    (r * theta.cos(), r * theta.sin())
}

fn uniform_strict<R: RngCore>(rng: &mut R) -> f64 {
    let bits = rng.next_u64();
    let u = (bits >> 11) as f64 / ((1u64 << 53) as f64);
    if u <= 0.0 {
        f64::MIN_POSITIVE
    } else {
        u
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn rejects_invalid_params() {
        assert!(GaussianMechanism::new(0.0, 1e-5, 1.0).is_err());
        assert!(GaussianMechanism::new(1.0, 0.0, 1.0).is_err());
        assert!(GaussianMechanism::new(1.0, 1.0, 1.0).is_err());
        assert!(GaussianMechanism::new(1.0, 1e-5, -1.0).is_err());
        assert!(GaussianMechanism::new(f64::NAN, 1e-5, 1.0).is_err());
    }

    #[test]
    fn rejects_epsilon_above_one() {
        // Dwork-Roth eq. 3.8 σ calibration is only valid for ε ≤ 1.
        // F-1 hardening: constructor must reject larger ε.
        assert!(
            GaussianMechanism::new(1.0, 1e-5, 1.0).is_ok(),
            "ε = 1 boundary inclusive"
        );
        assert!(GaussianMechanism::new(1.0001, 1e-5, 1.0).is_err());
        assert!(GaussianMechanism::new(2.0, 1e-5, 1.0).is_err());
        assert!(GaussianMechanism::new(10.0, 1e-5, 1.0).is_err());
        match GaussianMechanism::new(2.0, 1e-5, 1.0).unwrap_err() {
            super::DpError::InvalidEpsilon(v) => assert!((v - 2.0).abs() < 1e-12),
            other => panic!("expected InvalidEpsilon, got {other:?}"),
        }
    }

    #[test]
    fn sigma_formula() {
        let m = GaussianMechanism::new(1.0, 1e-5, 1.0).unwrap();
        // σ = 1 · sqrt(2 · ln(125000)) / 1 ≈ 4.84
        let s = m.sigma();
        assert!((s - 4.84).abs() < 0.05, "sigma={}", s);
    }

    #[test]
    fn mean_near_zero() {
        let m = GaussianMechanism::new(1.0, 1e-5, 1.0).unwrap();
        let mut rng = StdRng::seed_from_u64(99);
        let n = 50_000;
        let sum: f64 = (0..n).map(|_| m.add_noise(0.0, &mut rng)).sum();
        let mean = sum / n as f64;
        // 3 σ_mean = 3σ/sqrt(N)
        let tol = 3.0 * m.sigma() / (n as f64).sqrt();
        assert!(mean.abs() < tol, "mean={} tol={}", mean, tol);
    }

    #[test]
    fn variance_matches_sigma_squared() {
        let m = GaussianMechanism::new(0.5, 1e-6, 1.0).unwrap();
        let mut rng = StdRng::seed_from_u64(11);
        let n = 50_000;
        let samples: Vec<f64> = (0..n).map(|_| m.add_noise(0.0, &mut rng)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let expected = m.sigma().powi(2);
        let rel_err = (var - expected).abs() / expected;
        assert!(
            rel_err < 0.05,
            "var={} expected={} rel_err={}",
            var,
            expected,
            rel_err
        );
    }

    #[test]
    fn deterministic_with_seeded_rng() {
        let m = GaussianMechanism::new(1.0, 1e-5, 1.0).unwrap();
        let mut a = StdRng::seed_from_u64(7);
        let mut b = StdRng::seed_from_u64(7);
        for _ in 0..50 {
            assert_eq!(m.add_noise(0.0, &mut a), m.add_noise(0.0, &mut b));
        }
    }
}
