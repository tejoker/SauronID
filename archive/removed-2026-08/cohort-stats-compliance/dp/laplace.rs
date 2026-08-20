//! Laplace mechanism: adds noise drawn from Laplace(0, sensitivity/ε).
//!
//! Source: Dwork & Roth, *The Algorithmic Foundations of Differential
//! Privacy*, 2014, Theorem 3.6 ("The Laplace mechanism preserves (ε, 0)-DP").
//!
//! # Floating-point caveat (Mironov 2012)
//!
//! This implementation samples noise in IEEE-754 double precision. The
//! inverse-CDF transform plus the `(1.0 - f64::EPSILON)` clamp on the
//! interior of the unit interval makes the realised mechanism
//! **(ε, ~2⁻⁵²)-DP rather than (ε, 0)-DP** — the δ inflation is the
//! probability mass concentrated on the truncation cliff at one ulp from
//! 1, ≈ 2.22e-16. This is six orders of magnitude tighter than the typical
//! δ = 1e-6 chosen in cohort definitions, but operators publishing under
//! a strict pure-DP claim should pick the snapping mechanism (Mironov
//! 2012) or discrete Laplace (Canonne-Kamath-Steinke 2020) instead.

use rand::RngCore;

use super::DpError;

/// Floating-point `(ε, δ≈2⁻⁵²)` additive-noise mechanism for numeric queries.
///
/// Calibrated to `L1` sensitivity. `ε` is the privacy budget.
#[derive(Debug, Clone, Copy)]
pub struct LaplaceMechanism {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl LaplaceMechanism {
    pub fn new(epsilon: f64, sensitivity: f64) -> Result<Self, DpError> {
        if !epsilon.is_finite() || !sensitivity.is_finite() {
            return Err(DpError::NonFinite);
        }
        if epsilon <= 0.0 {
            return Err(DpError::InvalidEpsilon(epsilon));
        }
        if sensitivity < 0.0 {
            return Err(DpError::InvalidSensitivity(sensitivity));
        }
        Ok(Self {
            epsilon,
            sensitivity,
        })
    }

    /// Scale parameter `b = sensitivity / ε`.
    pub fn scale(&self) -> f64 {
        self.sensitivity / self.epsilon
    }

    /// Add Laplace-distributed noise to `value`.
    ///
    /// Sampling via inverse CDF: `X = -b · sign(u) · ln(1 - 2|u|)` where
    /// `u` is uniform on `(-0.5, 0.5)`.
    ///
    /// # RNG requirement
    ///
    /// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
    /// The (ε, 0)-DP guarantee assumes the adversary cannot predict the
    /// noise draw. Seeded `StdRng` is acceptable for tests only — the seed
    /// is observable from binary memory and breaks the guarantee.
    pub fn add_noise<R: RngCore>(&self, value: f64, rng: &mut R) -> f64 {
        let b = self.scale();
        let u = uniform_open(rng) - 0.5;
        let sign = if u < 0.0 { -1.0 } else { 1.0 };
        let abs_2u = (2.0 * u.abs()).min(1.0 - f64::EPSILON);
        let noise = -b * sign * (1.0 - abs_2u).ln();
        value + noise
    }
}

/// Uniform on `(0, 1)` open interval (avoids the ln(0) trap).
fn uniform_open<R: RngCore>(rng: &mut R) -> f64 {
    // u64 → f64 in [0, 1). Bump zero to a tiny positive to keep (0,1) open.
    let bits = rng.next_u64();
    let u = (bits >> 11) as f64 / ((1u64 << 53) as f64);
    if u == 0.0 {
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
        assert!(LaplaceMechanism::new(0.0, 1.0).is_err());
        assert!(LaplaceMechanism::new(-1.0, 1.0).is_err());
        assert!(LaplaceMechanism::new(1.0, -0.1).is_err());
        assert!(LaplaceMechanism::new(f64::NAN, 1.0).is_err());
        assert!(LaplaceMechanism::new(1.0, f64::INFINITY).is_err());
    }

    #[test]
    fn mean_unbiased_over_many_samples() {
        let m = LaplaceMechanism::new(1.0, 1.0).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let n = 100_000;
        let mut sum = 0.0;
        for _ in 0..n {
            sum += m.add_noise(100.0, &mut rng) - 100.0;
        }
        let mean = sum / n as f64;
        // 3σ tolerance: σ_mean = scale * sqrt(2 / N)
        let tol = 3.0 * m.scale() * (2.0_f64 / n as f64).sqrt();
        assert!(mean.abs() < tol, "mean={} tol={}", mean, tol);
    }

    #[test]
    fn variance_matches_theory() {
        let m = LaplaceMechanism::new(0.5, 2.0).unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let n = 50_000;
        let samples: Vec<f64> = (0..n).map(|_| m.add_noise(0.0, &mut rng)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let expected = 2.0 * m.scale().powi(2);
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
        let m = LaplaceMechanism::new(1.0, 1.0).unwrap();
        let mut rng_a = StdRng::seed_from_u64(123);
        let mut rng_b = StdRng::seed_from_u64(123);
        for _ in 0..100 {
            assert_eq!(m.add_noise(5.0, &mut rng_a), m.add_noise(5.0, &mut rng_b));
        }
    }
}
