//! The "did the loop expect this?" flag — a dedicated field to MEASURE
//! confirmation bias, kept separate from raw core observation.

use serde::{Deserialize, Serialize};

/// Whether the loop predicted the observed outcome before seeing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    /// The loop made no prediction (default).
    #[default]
    NoPrediction,
    /// The observation matched the loop's prediction.
    Expected,
    /// The observation contradicted the loop's prediction.
    Unexpected,
}

/// The confirmation-bias probe, kept separate from core observation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExpectationFlag {
    /// Expected / Unexpected / NoPrediction.
    pub expected: Expectation,
    /// What the loop predicted (if anything), for later bias analysis.
    pub predicted: Option<String>,
}
