//! Metric schemas for the eBPF verifier hunting loop.
//!
//! The four groups and their relationship (see the top-level README):
//!   1. [`core`]           — CORE: fixed, pure operational observation, always on,
//!                           INDEPENDENT of the counterfactual layer.
//!   2. [`derived`]        — DERIVED: schema fixed now, values fill as the loop grows.
//!   3. [`counterfactual`] — COUNTERFACTUAL: opt-in, sits ON TOP of core, never mutates it.
//!   4. [`expectation`]    — the "did the loop expect this?" flag (confirmation-bias probe).
//!
//! CORE is finalized (full + register-state evolution); the other three carry
//! concrete-but-minimal shapes with TODOs for later enrichment. All groups
//! (de)serialize via serde and mirror `python/.../schemas/`.

pub mod core;
pub mod counterfactual;
pub mod derived;
pub mod expectation;
