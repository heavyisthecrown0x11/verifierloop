//! verifierloop orchestrator library.
//!
//! The binary (`main.rs`) is a thin entry point; the loop control flow lives here
//! so it can be unit-tested and driven by examples with a mock fuzzer.
//!
//! Modules:
//!   * [`period`]       — the period model (boundary = exec count N, not time).
//!   * [`driver`]       — the `FuzzDriver` abstraction + a `MockDriver` for tests.
//!   * [`loop_runtime`] — the period loop; hosts the confirmation-bias guardrail.

pub mod driver;
pub mod loop_runtime;
pub mod period;
