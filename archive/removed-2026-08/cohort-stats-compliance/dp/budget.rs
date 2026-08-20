//! ε-budget accountant. Tracks how much privacy budget has been spent and
//! refuses charges that would exceed the configured envelope.

use super::DpError;

/// One audit-log entry for a charge against the budget.
#[derive(Debug, Clone, PartialEq)]
pub struct EpsilonChargeEntry {
    pub query: String,
    pub epsilon: f64,
    pub delta: f64,
    pub timestamp_epoch: i64,
}

/// Append-only ε/δ ledger.
#[derive(Debug, Clone)]
pub struct EpsilonBudget {
    total_epsilon: f64,
    total_delta: f64,
    spent_epsilon: f64,
    spent_delta: f64,
    log: Vec<EpsilonChargeEntry>,
}

impl EpsilonBudget {
    pub fn new(total_epsilon: f64, total_delta: f64) -> Result<Self, DpError> {
        if !total_epsilon.is_finite() || !total_delta.is_finite() {
            return Err(DpError::NonFinite);
        }
        if total_epsilon <= 0.0 {
            return Err(DpError::InvalidEpsilon(total_epsilon));
        }
        if !(0.0..1.0).contains(&total_delta) {
            return Err(DpError::InvalidDelta(total_delta));
        }
        Ok(Self {
            total_epsilon,
            total_delta,
            spent_epsilon: 0.0,
            spent_delta: 0.0,
            log: Vec::new(),
        })
    }

    pub fn total_epsilon(&self) -> f64 {
        self.total_epsilon
    }
    pub fn total_delta(&self) -> f64 {
        self.total_delta
    }

    /// Charge `(epsilon, delta)` for `query`. Uses basic composition (sum).
    /// Rejects if the new total would exceed the budget.
    pub fn charge(
        &mut self,
        epsilon: f64,
        delta: f64,
        query: &str,
        now: i64,
    ) -> Result<(), DpError> {
        if !epsilon.is_finite() || !delta.is_finite() {
            return Err(DpError::NonFinite);
        }
        if epsilon < 0.0 {
            return Err(DpError::InvalidEpsilon(epsilon));
        }
        if delta < 0.0 {
            return Err(DpError::InvalidDelta(delta));
        }
        let new_eps = self.spent_epsilon + epsilon;
        let new_delta = self.spent_delta + delta;
        if new_eps > self.total_epsilon {
            return Err(DpError::BudgetExhausted {
                needed_epsilon: epsilon,
                available_epsilon: self.total_epsilon - self.spent_epsilon,
            });
        }
        if new_delta > self.total_delta {
            return Err(DpError::Composition(format!(
                "delta exhausted: needed {}, available {}",
                delta,
                self.total_delta - self.spent_delta
            )));
        }
        self.spent_epsilon = new_eps;
        self.spent_delta = new_delta;
        self.log.push(EpsilonChargeEntry {
            query: query.to_string(),
            epsilon,
            delta,
            timestamp_epoch: now,
        });
        Ok(())
    }

    /// `(remaining_epsilon, remaining_delta)`.
    pub fn remaining(&self) -> (f64, f64) {
        (
            self.total_epsilon - self.spent_epsilon,
            self.total_delta - self.spent_delta,
        )
    }

    pub fn is_exhausted(&self) -> bool {
        let (e, d) = self.remaining();
        e <= 0.0 || d <= 0.0
    }

    pub fn audit_log(&self) -> &[EpsilonChargeEntry] {
        &self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_init() {
        assert!(EpsilonBudget::new(0.0, 1e-5).is_err());
        assert!(EpsilonBudget::new(1.0, 1.0).is_err());
        assert!(EpsilonBudget::new(1.0, -0.1).is_err());
        assert!(EpsilonBudget::new(f64::NAN, 1e-5).is_err());
    }

    #[test]
    fn charge_within_budget() {
        let mut b = EpsilonBudget::new(1.0, 1e-5).unwrap();
        assert!(b.charge(0.3, 1e-6, "q1", 100).is_ok());
        assert!(b.charge(0.4, 1e-6, "q2", 200).is_ok());
        let (e, d) = b.remaining();
        assert!((e - 0.3).abs() < 1e-9);
        assert!((d - (1e-5 - 2e-6)).abs() < 1e-12);
        assert_eq!(b.audit_log().len(), 2);
    }

    #[test]
    fn exhausts_epsilon() {
        let mut b = EpsilonBudget::new(1.0, 1e-5).unwrap();
        b.charge(0.7, 1e-6, "q1", 1).unwrap();
        let err = b.charge(0.5, 1e-6, "q2", 2).unwrap_err();
        match err {
            DpError::BudgetExhausted {
                needed_epsilon,
                available_epsilon,
            } => {
                assert!((needed_epsilon - 0.5).abs() < 1e-9);
                assert!((available_epsilon - 0.3).abs() < 1e-9);
            }
            _ => panic!("wrong error: {:?}", err),
        }
    }

    #[test]
    fn audit_log_preserves_order() {
        let mut b = EpsilonBudget::new(10.0, 1e-3).unwrap();
        for i in 0..5 {
            b.charge(0.1, 1e-5, &format!("q{}", i), i as i64 * 10)
                .unwrap();
        }
        let log = b.audit_log();
        for (i, e) in log.iter().enumerate() {
            assert_eq!(e.query, format!("q{}", i));
            assert_eq!(e.timestamp_epoch, i as i64 * 10);
        }
    }

    #[test]
    fn is_exhausted_when_eps_zero() {
        let mut b = EpsilonBudget::new(1.0, 1e-3).unwrap();
        b.charge(1.0, 1e-6, "q1", 0).unwrap();
        assert!(b.is_exhausted());
    }
}
