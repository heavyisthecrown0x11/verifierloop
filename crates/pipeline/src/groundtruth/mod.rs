//! Ground-truth adapters for the documented-vs-observed diff engine.
//!
//! The loop's "ground truth" is NOT a formal model. It is documentation + patch
//! diffs + classic logical analysis, drawn from four concrete external sources:
//!   1. `verifier_c`   — verifier.c state-transition logic (accept/reject + reg state)
//!   2. `verifier_rst` — Documentation/bpf/verifier.rst (documented behavior)
//!   3. `helper_proto` — helper bpf_func_proto / arg_type contracts
//!   4. `patch_diff`   — version patch diffs (git log between kernel versions)
//!
//! ...plus the intrinsic **logical invariants** (tnum well-formedness, bound
//! ordering, JIT/interpreter equivalence) that the `diff` stage checks directly —
//! the "classic logical analysis" pillar, which needs no external file.
//!
//! # Injectable oracle
//!
//! [`GroundTruth`] is a trait so the `diff` logic is testable now with a reference
//! oracle, and the real disk-backed loaders slot in later. The one source-backed
//! query available today is [`GroundTruth::helper_arg_type`] (source 3): the other
//! three sources need a bpf-next checkout and their loaders are TODO.

pub mod helper_proto;
pub mod patch_diff;
pub mod verifier_c;
pub mod verifier_rst;

use helper_proto::HelperProtoModel;
use patch_diff::PatchDiffModel;
use verifier_rst::{DocumentedOutcome, VerifierRstModel};

/// The ground-truth oracle the `diff` stage consults for **source-backed** checks.
///
/// Intrinsic logical invariants (tnum/bounds/jit-interp) are computed by `diff`
/// directly and do NOT go through this trait. This trait answers questions that
/// require an external source; each returns `Option` so "source not loaded" is
/// distinct from "no divergence".
///
/// Today only [`Self::helper_arg_type`] (source 3) is answerable. Queries for
/// verifier.c decisions (source 1), documented rules (source 2), and cross-version
/// deltas (source 4) will be added here as their loaders come online.
pub trait GroundTruth {
    /// Documented `arg_type` for helper argument `(helper, arg_index)`, or `None`
    /// if this oracle has no contract loaded for it (real proto loader TODO).
    fn helper_arg_type(&self, helper: &str, arg_index: u8) -> Option<String>;

    /// Expected verifier reg-type FAMILY for a helper arg (source 3, real path) —
    /// what the diff stage compares an OBSERVED arg reg-type against. Default
    /// `None`; impls carrying a `bpf_func_proto` slice override it.
    fn helper_arg_regtype(&self, _helper: &str, _arg_index: u8) -> Option<String> {
        None
    }

    /// Source 2 — what `Documentation/bpf/verifier.rst` says the verifier does with
    /// the documented program labelled `case_id`. `None` = no documented claim (or
    /// the claim's anchor drifted), which the diff stage reads as silence.
    fn documented_outcome(&self, _case_id: &str) -> Option<DocumentedOutcome> {
        None
    }

    /// Source 2 — the exact error string the documentation prints for `case_id`,
    /// when it prints one. Weighed DIFFERENTLY from the decision: a mismatch here
    /// is evidence for a reviewer, never a divergence verdict, because message
    /// text drifts between kernel versions far faster than behaviour does.
    fn documented_expected_error(&self, _case_id: &str) -> Option<String> {
        None
    }

    /// Source 4 — git-derived evidence about how far the documentation has fallen
    /// behind the verifier code. Not a check: it QUALIFIES a source-2 finding so the
    /// "real regression or stale prose?" question arrives with facts attached.
    /// `None` = no history available, which must read as silence.
    fn doc_staleness_evidence(&self) -> Option<String> {
        None
    }
}

/// The empty oracle: knows nothing, corroborates nothing. Used when only the
/// intrinsic logical-invariant checks should run (no external sources loaded).
///
/// Analogous to `normalize::UnimplementedParser`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoGroundTruth;

impl GroundTruth for NoGroundTruth {
    fn helper_arg_type(&self, _helper: &str, _arg_index: u8) -> Option<String> {
        None
    }
}

/// An in-memory oracle: real for whatever it has been populated with, `None`
/// elsewhere. The reference oracle for tests/examples and the shape the real
/// aggregated ground truth (once the disk loaders exist) will fill in.
#[derive(Debug, Default, Clone)]
pub struct StaticGroundTruth {
    /// Source 3 — helper arg_type contracts.
    pub helper_proto: HelperProtoModel,
    /// Source 2 — documented behaviour (anchor-verified cases).
    pub verifier_rst: VerifierRstModel,
    /// Source 4 — git-derived doc-vs-code staleness evidence.
    pub patch_diff: PatchDiffModel,
    // TODO(groundtruth): VerifierCModel, VerifierRstModel, PatchDiffModel — added
    // here (and exposed via new trait methods) as their loaders land.
}

impl StaticGroundTruth {
    /// Build from a helper-proto table (the one source usable without a tree).
    pub fn with_helper_proto(helper_proto: HelperProtoModel) -> Self {
        Self {
            helper_proto,
            ..Default::default()
        }
    }

    /// Attach documented-behaviour cases (source 2).
    pub fn with_verifier_rst(mut self, verifier_rst: VerifierRstModel) -> Self {
        self.verifier_rst = verifier_rst;
        self
    }

    /// Attach git-derived staleness evidence (source 4).
    pub fn with_patch_diff(mut self, patch_diff: PatchDiffModel) -> Self {
        self.patch_diff = patch_diff;
        self
    }
}

impl GroundTruth for StaticGroundTruth {
    fn helper_arg_type(&self, helper: &str, arg_index: u8) -> Option<String> {
        self.helper_proto
            .arg_type(helper, arg_index)
            .map(str::to_string)
    }

    fn helper_arg_regtype(&self, helper: &str, arg_index: u8) -> Option<String> {
        self.helper_proto
            .arg_regtype(helper, arg_index)
            .map(str::to_string)
    }

    fn documented_outcome(&self, case_id: &str) -> Option<DocumentedOutcome> {
        self.verifier_rst.outcome(case_id)
    }

    fn documented_expected_error(&self, case_id: &str) -> Option<String> {
        self.verifier_rst.expected_error(case_id).map(str::to_string)
    }

    fn doc_staleness_evidence(&self) -> Option<String> {
        self.patch_diff.staleness_note()
    }
}

/// Load and aggregate all four external ground-truth sources from a bpf-next
/// checkout. STUB.
/// TODO(groundtruth): load verifier.c + verifier.rst + helper protos + patch diffs
/// into a [`StaticGroundTruth`]. Needs the kernel tree.
pub fn load(_kernel_src: &std::path::Path) -> StaticGroundTruth {
    todo!("scaffold: load the four ground-truth sources from a bpf-next tree")
}
