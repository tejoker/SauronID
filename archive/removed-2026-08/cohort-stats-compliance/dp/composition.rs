//! Composition theorems and Rényi-DP accountant.
//!
//! Sources:
//! - Dwork & Roth, *The Algorithmic Foundations of Differential Privacy*,
//!   2014, Theorem 3.16 (basic composition), Theorem 3.20 (advanced
//!   composition).
//! - Mironov, *Rényi Differential Privacy*, CSF 2017.

use super::DpError;

/// Basic composition: `(Σ ε_i, Σ δ_i)`. Source: Dwork-Roth 2014, Thm 3.16.
pub fn basic_composition(charges: &[(f64, f64)]) -> (f64, f64) {
    let eps: f64 = charges.iter().map(|(e, _)| *e).sum();
    let delta: f64 = charges.iter().map(|(_, d)| *d).sum();
    (eps, delta)
}

/// Advanced composition: k-fold (ε,δ)-DP composes to
/// `(ε √(2k ln(1/δ')) + kε(e^ε − 1), kδ + δ')`. Requires homogeneous ε.
/// Source: Dwork-Roth 2014, Thm 3.20.
pub fn advanced_composition(
    charges: &[(f64, f64)],
    delta_prime: f64,
) -> Result<(f64, f64), DpError> {
    if charges.is_empty() {
        return Ok((0.0, 0.0));
    }
    if delta_prime <= 0.0 || delta_prime >= 1.0 {
        return Err(DpError::Composition(format!(
            "delta_prime must be in (0,1), got {}",
            delta_prime
        )));
    }
    let eps0 = charges[0].0;
    if !charges.iter().all(|(e, _)| (e - eps0).abs() < 1e-12) {
        return Err(DpError::Composition(
            "advanced composition requires homogeneous epsilon".into(),
        ));
    }
    let k = charges.len() as f64;
    let delta_sum: f64 = charges.iter().map(|(_, d)| *d).sum();
    let term1 = eps0 * (2.0 * k * (1.0 / delta_prime).ln()).sqrt();
    let term2 = k * eps0 * (eps0.exp() - 1.0);
    Ok((term1 + term2, delta_sum + delta_prime))
}

/// Rényi-DP accountant. Tracks per-order α-RDP and converts to (ε, δ)
/// on demand. Tighter than basic/advanced for compositions of Gaussians.
/// Source: Mironov 2017.
#[derive(Debug, Clone)]
pub struct RdpAccountant {
    orders: Vec<f64>,
    rdp_at_order: Vec<f64>,
}

impl Default for RdpAccountant {
    fn default() -> Self {
        Self::new()
    }
}

impl RdpAccountant {
    pub fn new() -> Self {
        let orders: Vec<f64> = vec![
            1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0, 20.0, 24.0,
            28.0, 32.0, 48.0, 64.0,
        ];
        let rdp_at_order = vec![0.0; orders.len()];
        Self {
            orders,
            rdp_at_order,
        }
    }

    /// α-RDP of Gaussian mechanism with σ and L2 sensitivity:
    /// `RDP_α = α · sensitivity² / (2 σ²)`. Source: Mironov 2017, Prop 7.
    pub fn add_gaussian(&mut self, sigma: f64, sensitivity: f64) {
        let s2 = sensitivity.powi(2);
        for (a, r) in self.orders.iter().zip(self.rdp_at_order.iter_mut()) {
            *r += *a * s2 / (2.0 * sigma.powi(2));
        }
    }

    /// Convert accumulated α-RDP into the tightest `(ε, δ)`-DP bound for
    /// given `δ`. Source: Mironov 2017, Prop 3:
    /// `ε(α) = RDP_α + ln(1/δ) / (α − 1)`. Returns the minimum over orders.
    pub fn convert_to_eps_delta(&self, delta: f64) -> f64 {
        if delta <= 0.0 || delta >= 1.0 {
            return f64::INFINITY;
        }
        let ln_inv_delta = (1.0 / delta).ln();
        self.orders
            .iter()
            .zip(self.rdp_at_order.iter())
            .map(|(a, r)| r + ln_inv_delta / (a - 1.0))
            .fold(f64::INFINITY, f64::min)
    }

    pub fn orders(&self) -> &[f64] {
        &self.orders
    }
    pub fn rdp_values(&self) -> &[f64] {
        &self.rdp_at_order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_sums_correctly() {
        let cs = vec![(1.0, 1e-6), (0.5, 2e-6), (0.25, 3e-6)];
        let (e, d) = basic_composition(&cs);
        assert!((e - 1.75).abs() < 1e-12);
        assert!((d - 6e-6).abs() < 1e-18);
    }

    #[test]
    fn advanced_rejects_bad_delta_prime() {
        let cs = vec![(0.1, 1e-6); 10];
        assert!(advanced_composition(&cs, 0.0).is_err());
        assert!(advanced_composition(&cs, 1.0).is_err());
    }

    #[test]
    fn advanced_rejects_heterogeneous() {
        let cs = vec![(0.1, 1e-6), (0.2, 1e-6)];
        assert!(advanced_composition(&cs, 1e-6).is_err());
    }

    #[test]
    fn advanced_tighter_than_basic_for_small_eps() {
        // k=20 charges of ε=0.1 with δ'=0.01:
        // basic ε = 2.0; advanced ε ≈ 0.1·√(2·20·ln(100)) + 20·0.1·(e^0.1 − 1)
        //                          ≈ 0.1·13.56 + 0.21 = 1.57 (tighter).
        // For very small δ' (1e-6), advanced is LOOSER at this k/ε — needs
        // either smaller ε or larger k. Documented in privacy-model.md.
        let cs = vec![(0.1, 1e-7); 20];
        let (basic_eps, _) = basic_composition(&cs);
        let (adv_eps, _) = advanced_composition(&cs, 0.01).unwrap();
        assert!(
            adv_eps < basic_eps,
            "adv {} not tighter than basic {}",
            adv_eps,
            basic_eps
        );
    }

    #[test]
    fn rdp_finite_for_100_gaussians() {
        let mut acc = RdpAccountant::new();
        for _ in 0..100 {
            acc.add_gaussian(10.0, 1.0);
        }
        let eps = acc.convert_to_eps_delta(1e-5);
        assert!(eps.is_finite() && eps > 0.0, "eps={}", eps);
        assert!(eps < 10.0, "eps={} too loose", eps);
    }

    #[test]
    fn rdp_empty_returns_pure_delta_term() {
        let acc = RdpAccountant::new();
        let eps = acc.convert_to_eps_delta(1e-5);
        // With zero RDP, eps = ln(1/δ) / (α-1); minimum over orders.
        // Largest α (64) → eps = ln(1e5)/63 ≈ 0.183.
        assert!(eps > 0.0 && eps < 1.0, "eps={}", eps);
    }
}
