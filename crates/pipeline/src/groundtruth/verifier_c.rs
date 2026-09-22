//! Ground-truth source 1 — `verifier.c` state-transition logic.
//! Reference model for accept/reject decisions + register-state evolution.

use std::path::Path;

/// Parsed reference view of verifier.c decision / state-transition logic.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct VerifierCModel {
    // TODO(gt-verifier-c): finalize.
}

/// Load from a bpf-next checkout's `kernel/bpf/verifier.c`. STUB.
/// TODO(gt-verifier-c): extract accept/reject + reg-state transition reference.
pub fn load(_verifier_c: &Path) -> VerifierCModel {
    todo!("scaffold: build verifier.c reference model")
}
