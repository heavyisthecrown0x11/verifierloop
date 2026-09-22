//! Period bookkeeping. A period boundary is an EXEC-COUNT threshold, not a timer.
//!
//! `exec_count` is cumulative total fuzzing execs (the counter N). A period runs
//! from `exec_start` until it has accrued `exec_threshold` execs. Wall-clock time
//! appears only as `harvest_unix`, a LABEL stamped at harvest — never a stopping
//! criterion.

/// Tracks one period's progress by cumulative exec count N.
#[derive(Debug, Clone)]
pub struct Period {
    /// Monotonic period id (0, 1, 2, ...).
    pub id: u64,
    /// Cumulative exec count N at which this period began.
    pub exec_start: u64,
    /// Current cumulative exec count N.
    pub exec_count: u64,
    /// Execs this period must accrue past `exec_start` before its boundary.
    pub exec_threshold: u64,
    /// Harvest timestamp as Unix epoch seconds — a LABEL only, set at harvest.
    /// Never a stopping/decision criterion.
    pub harvest_unix: Option<u64>,
}

impl Period {
    /// Start a new period at cumulative count `exec_start`.
    pub fn new(id: u64, exec_start: u64, exec_threshold: u64) -> Self {
        Self {
            id,
            exec_start,
            exec_count: exec_start,
            exec_threshold,
            harvest_unix: None,
        }
    }

    /// Execs accrued within this period so far.
    pub fn execs_this_period(&self) -> u64 {
        self.exec_count.saturating_sub(self.exec_start)
    }

    /// Has this period reached its exec-count boundary? (N-based, not time.)
    pub fn is_complete(&self) -> bool {
        self.execs_this_period() >= self.exec_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_is_exec_count_not_time() {
        let mut p = Period::new(1, 100, 50);
        assert_eq!(p.execs_this_period(), 0);
        p.exec_count = 120;
        assert!(!p.is_complete(), "only 20 execs into a 50-exec period");
        p.exec_count = 150;
        assert!(p.is_complete(), "reached +50 exec boundary");
        assert_eq!(p.execs_this_period(), 50);
    }

    #[test]
    fn zero_threshold_completes_immediately() {
        let p = Period::new(0, 0, 0);
        assert!(p.is_complete());
    }
}
