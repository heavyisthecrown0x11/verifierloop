//! COUNTERFACTUAL layer — EXTRA / opt-in. Sits ON TOP of core, NEVER mutates it.
//!
//! Kept deliberately OUTSIDE core so the diff engine reads raw observation, not
//! the loop's own generated alternatives. MUST NOT feed back into fuzzer input
//! selection (see the confirmation-bias guardrail in the orchestrator).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CounterfactualLayer {
    /// Whether this layer was produced for the observation (opt-in; default OFF).
    pub enabled: bool,
    /// Loop-generated alternatives / predicted outcomes (opaque text for now).
    pub alternatives: Vec<String>,
    // TODO(cf): finalize the alternative representation when the layer is built.
}
