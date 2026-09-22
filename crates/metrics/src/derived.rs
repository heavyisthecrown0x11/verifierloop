//! DERIVED metrics — schema fixed now, values fill as the loop grows.
//!
//! Computed from CORE across a period. Never a decision criterion on its own.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DerivedMetrics {
    /// Secondary efficiency observation: new coverage / new state per exec.
    /// REPORT-ONLY — never a stopping/steering criterion. `None` until computable.
    pub efficiency_per_exec: Option<f64>,
    /// Number of CORE records in the period (a simple running aggregate).
    pub record_count: u64,
    // TODO(derived): richer period aggregates (rates, histograms, trend of states).
}
