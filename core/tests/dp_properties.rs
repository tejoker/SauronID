//! Property tests for DP invariants. Hand-rolled (no proptest dep).
//! Each property is checked over a small number of seeded iterations.

use rand::rngs::StdRng;
use rand::SeedableRng;
use sauron_core::dp::{
    advanced_composition, basic_composition, cohort_membership_count, suppress_small_cohorts,
    BudgetDecision, DpBudgetLedger, EpsilonBudget, GaussianMechanism, LaplaceMechanism,
    RdpAccountant,
};

#[test]
fn prop_laplace_unbiased() {
    // For 10 random (eps, sensitivity) configs, mean of 20k samples is
    // within 3σ_mean of the true value.
    for seed in 0..10u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let eps = 0.1 + (seed as f64) * 0.2;
        let sens = 1.0 + (seed as f64) * 0.5;
        let m = LaplaceMechanism::new(eps, sens).unwrap();
        let n = 20_000;
        let sum: f64 = (0..n).map(|_| m.add_noise(50.0, &mut rng) - 50.0).sum();
        let mean = sum / n as f64;
        let sigma_mean = m.scale() * (2.0 / n as f64).sqrt();
        let tol = 4.0 * sigma_mean;
        assert!(mean.abs() < tol, "seed={} mean={} tol={}", seed, mean, tol);
    }
}

#[test]
fn prop_gaussian_variance() {
    for seed in 0..10u64 {
        let mut rng = StdRng::seed_from_u64(seed + 100);
        // The classic Gaussian mechanism's σ bound is only valid for ε ≤ 1
        // (MAX_GAUSSIAN_EPSILON); ε > 1 needs the analytic Gaussian
        // (Balle-Wang 2018), not yet implemented. Sweep 0.50..0.95 to stay
        // inside the supported domain — the old 0.5 + 0.1·seed reached 1.4 and
        // was rejected at construction.
        let eps = 0.5 + (seed as f64) * 0.05;
        let m = GaussianMechanism::new(eps, 1e-5, 1.0).unwrap();
        let n = 20_000;
        let samples: Vec<f64> = (0..n).map(|_| m.add_noise(0.0, &mut rng)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let expected = m.sigma().powi(2);
        let rel = (var - expected).abs() / expected;
        assert!(
            rel < 0.1,
            "seed={} var={} expected={} rel={}",
            seed,
            var,
            expected,
            rel
        );
    }
}

#[test]
fn prop_basic_composition_monotone() {
    let mut acc: Vec<(f64, f64)> = vec![];
    let mut prev = (0.0, 0.0);
    for i in 1..=20 {
        acc.push((0.05 * i as f64, 1e-7));
        let (e, d) = basic_composition(&acc);
        assert!(e >= prev.0 && d >= prev.1, "non-monotone at i={}", i);
        prev = (e, d);
    }
}

#[test]
fn prop_advanced_tighter_than_basic_for_large_k() {
    // Advanced composition (Dwork-Roth Thm 3.20) only beats basic when
    //   k(1 − ε)² / 2 > ln(1/δ')
    // For ε = 0.1, δ' = 0.01: ln(1/δ') = 4.6, so k > 11.4 suffices.
    for k in 15..=40 {
        let cs: Vec<(f64, f64)> = vec![(0.1, 1e-7); k];
        let (basic_eps, _) = basic_composition(&cs);
        let (adv_eps, _) = advanced_composition(&cs, 0.01).unwrap();
        assert!(
            adv_eps < basic_eps,
            "k={} basic={} advanced={}",
            k,
            basic_eps,
            adv_eps
        );
    }
}

#[test]
fn prop_rdp_finite_100_gaussians() {
    let mut acc = RdpAccountant::new();
    for _ in 0..100 {
        acc.add_gaussian(10.0, 1.0);
    }
    let eps = acc.convert_to_eps_delta(1e-5);
    assert!(eps.is_finite());
    // For σ=10, sens=1, k=100, δ=1e-5: minimum is around α≈5.5, eps≈5.3.
    assert!(eps > 0.0 && eps < 10.0, "eps={} out of expected band", eps);
}

#[test]
fn prop_k_anon_idempotent() {
    for cohort in 0..30usize {
        let rows: Vec<i32> = (0..cohort as i32).collect();
        let first = suppress_small_cohorts(rows.clone(), cohort, 10);
        let second = suppress_small_cohorts(first.clone(), cohort, 10);
        assert_eq!(first, second, "cohort={}", cohort);
    }
}

#[test]
fn prop_membership_count_matches_threshold() {
    let sizes: Vec<usize> = (0..50).collect();
    let mask = cohort_membership_count(&sizes, 10);
    for (i, &b) in mask.iter().enumerate() {
        assert_eq!(b, sizes[i] >= 10);
    }
}

// ─── S8 ext: ε ledger property tests ──────────────────────────────────────
//
// Hand-rolled property tests over the persistent ledger. Each property
// drives a fresh on-disk SQLite ledger and verifies a cumulative
// invariant across many synthetic publications.

fn temp_ledger(label: &str) -> DpBudgetLedger {
    use sauron_core::db::open_db_at;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("sauron-dpprop-{pid}-{nanos}-{label}.db"));
    let _ = std::fs::remove_file(&path);
    DpBudgetLedger::new(std::sync::Arc::new(open_db_at(path.to_str().unwrap(), 2)))
}

#[test]
fn prop_ledger_total_eps_never_exceeds_cap() {
    // For 8 random (cap, charge) combos, run N publications until denied.
    // Sum of all approved ε MUST be ≤ cap.
    for seed in 0..8u64 {
        let ledger = temp_ledger(&format!("cap_{seed}"));
        let cap = 1.0 + (seed as f64) * 0.5;
        let charge = 0.1 + (seed as f64) * 0.05;
        ledger.ensure_cycle("coh_p", "m", 0, cap, 1e-5).unwrap();
        let mut total = 0.0f64;
        for _ in 0..100 {
            let dec = ledger.can_publish("coh_p", "m", 0, charge, 1e-9).unwrap();
            match dec {
                BudgetDecision::Approved { .. } => {
                    ledger
                        .record_publication("coh_p", "m", 0, charge, 1e-9, 4.0)
                        .unwrap();
                    total += charge;
                }
                BudgetDecision::Denied { .. } => break,
            }
        }
        assert!(
            total <= cap + 1e-9,
            "seed={seed} total={total} exceeds cap={cap}"
        );
        // And we must have run at least one publication.
        assert!(total > 0.0, "seed={seed} ran no publications");
    }
}

#[test]
fn prop_ledger_no_metric_exceeds_its_individual_cap() {
    // Multiple metrics on the same cohort/cycle: each metric's spend
    // MUST be bounded by its own cap, regardless of how the others fare.
    let ledger = temp_ledger("per_metric");
    let metrics = ["m_a", "m_b", "m_c"];
    let caps = [1.0_f64, 2.0, 0.5];
    for (m, c) in metrics.iter().zip(caps.iter()) {
        ledger.ensure_cycle("coh_p", m, 0, *c, 1e-5).unwrap();
    }
    // Bash each metric until its budget runs out.
    let charge = 0.1f64;
    for (m, c) in metrics.iter().zip(caps.iter()) {
        let mut total = 0.0f64;
        for _ in 0..200 {
            match ledger.can_publish("coh_p", m, 0, charge, 1e-9).unwrap() {
                BudgetDecision::Approved { .. } => {
                    ledger
                        .record_publication("coh_p", m, 0, charge, 1e-9, 4.0)
                        .unwrap();
                    total += charge;
                }
                BudgetDecision::Denied { .. } => break,
            }
        }
        assert!(total <= *c + 1e-9, "metric={m} total={total} cap={c}");
    }
    // Cross-check via get_ledger.
    let rows = ledger.get_ledger("coh_p").unwrap();
    for r in &rows {
        let cap = match r.metric_id.as_str() {
            "m_a" => caps[0],
            "m_b" => caps[1],
            "m_c" => caps[2],
            _ => panic!("unexpected metric_id {}", r.metric_id),
        };
        assert!(
            r.epsilon_spent <= cap + 1e-9,
            "metric={} spent={} cap={}",
            r.metric_id,
            r.epsilon_spent,
            cap
        );
    }
}

#[test]
fn prop_budget_balance() {
    // 15 charges of 0.05·i summed = 0.05·(1+...+15) = 6.0 < budget 10.0.
    let mut b = EpsilonBudget::new(10.0, 1e-3).unwrap();
    let mut sum_e = 0.0;
    let mut sum_d = 0.0;
    for i in 1..=15 {
        let e = 0.05 * i as f64;
        let d = 1e-6;
        b.charge(e, d, &format!("q{}", i), i as i64).unwrap();
        sum_e += e;
        sum_d += d;
    }
    let log_e: f64 = b.audit_log().iter().map(|en| en.epsilon).sum();
    let log_d: f64 = b.audit_log().iter().map(|en| en.delta).sum();
    assert!((log_e - sum_e).abs() < 1e-9);
    assert!((log_d - sum_d).abs() < 1e-15);
}
