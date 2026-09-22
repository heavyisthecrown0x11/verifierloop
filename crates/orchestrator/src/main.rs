//! `verifierloop` orchestrator — binary entry point.
//!
//! Thin wrapper: all loop logic lives in the `orchestrator` library
//! (`loop_runtime`, `period`, `driver`).

fn main() {
    orchestrator::loop_runtime::run();
}
