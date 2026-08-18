//! k-anonymity: suppress small cohorts before publication.
//!
//! Used as a release gate: if a cohort has fewer than `k` members, publishing
//! its aggregate would risk re-identification of individual contributors.

/// Default k for cross-customer cohort publication.
pub const DEFAULT_K_THRESHOLD: usize = 10;

/// Returns `rows` unchanged if `cohort_size >= k_threshold`, otherwise empty.
///
/// Caller passes the actual cohort size (which may differ from `rows.len()`
/// — e.g., when `rows` is a paginated slice of the cohort).
pub fn suppress_small_cohorts<T: Clone>(
    rows: Vec<T>,
    cohort_size: usize,
    k_threshold: usize,
) -> Vec<T> {
    if cohort_size < k_threshold {
        Vec::new()
    } else {
        rows
    }
}

/// For each group size, returns `true` iff `size >= k`.
pub fn cohort_membership_count(group_sizes: &[usize], k: usize) -> Vec<bool> {
    group_sizes.iter().map(|n| *n >= k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_when_at_or_above_threshold() {
        let rows = vec![1, 2, 3];
        let out = suppress_small_cohorts(rows.clone(), 10, 10);
        assert_eq!(out, rows);
        let out2 = suppress_small_cohorts(rows.clone(), 15, 10);
        assert_eq!(out2, rows);
    }

    #[test]
    fn suppresses_below_threshold() {
        let rows = vec![1, 2, 3];
        let out = suppress_small_cohorts(rows, 9, 10);
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_zero_cohort() {
        let out: Vec<i32> = suppress_small_cohorts(vec![], 0, 10);
        assert!(out.is_empty());
    }

    #[test]
    fn membership_count_correct() {
        let sizes = vec![5, 10, 15, 1, 100];
        let mask = cohort_membership_count(&sizes, 10);
        assert_eq!(mask, vec![false, true, true, false, true]);
    }

    #[test]
    fn default_threshold_is_ten() {
        assert_eq!(DEFAULT_K_THRESHOLD, 10);
    }
}
