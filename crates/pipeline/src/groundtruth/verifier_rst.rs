//! Ground-truth source 2 — `Documentation/bpf/verifier.rst` (documented behavior).
//!
//! The document is prose, so there is no honest way to *derive* rules from it
//! mechanically. What it DOES contain is a set of explicit behavioural claims of
//! the form "this program is rejected / is a correct program", each next to an
//! example program. Those are executable: run the documented program, compare the
//! observed verifier decision against the documented one. A difference is a real
//! documented-vs-observed divergence — the bug class intrinsic invariants and
//! helper contracts cannot see.
//!
//! TWO VEINS. The prose examples (`verifier.rst` up to ~line 60) claim only
//! accept/reject. The "Understanding eBPF verifier messages" section
//! (lines 353-560) is stronger: 11 invalid programs printed in `BPF_*` macro form —
//! the same macros `harness/diffharness.c` uses — each with its exact expected
//! error string. All 11 must be REJECTED, so they test the verifier's soundness.
//!
//! PROVENANCE DISCIPLINE. Each case below carries the document's own sentence
//! verbatim plus its line number. [`load`] re-reads the file and CHECKS that the
//! quote is still present: if the documentation changes, the case is reported as
//! STALE instead of being silently trusted. So the expectation's origin is
//! verifiable, and drift is loud. (The pseudo-asm -> real insn translation lives in
//! `harness/diffharness.c` next to each case id; that translation is a reviewable
//! judgement, the same shape as `helper_proto::SINGLE_FAMILY_ARG_TYPES`.)
//!
//! THREE WEIGHTS, NOT ONE. The document is version-drifted relative to the tree
//! (see OI-6), so its two kinds of claim cannot carry the same weight:
//!   * **decision** (`expected=reject`, `observed=accept`) — a DIVERGENCE. The
//!     kernel and its own documentation disagree about whether a program is safe.
//!   * **error text** — EVIDENCE, never a verdict. Message strings get reworded
//!     constantly; a mismatch is a note for the reviewer, not a claim of a bug.
//!     This is the same "give evidence, don't rule" discipline `patch_diff` uses.
//!   * **superseded** — the kernel source states a precondition the document
//!     omits, so the documented claim does not apply to our load path at all.
//!     Asserting it anyway would manufacture a permanent false divergence. A case
//!     may only be silenced this way by a VERIFIED source citation (see
//!     [`SourcePrecondition`]); if that citation ever disappears from the tree the
//!     case comes back to life by itself.

use std::collections::BTreeMap;
use std::path::Path;

/// What the documentation says the verifier does with a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentedOutcome {
    /// The document calls it a correct/valid program.
    Accept,
    /// The document says it is rejected.
    Reject,
}

/// A precondition the KERNEL SOURCE states and the documentation does not.
///
/// This is the only mechanism that may silence a documented claim, and it is
/// deliberately expensive to use: it needs a file, a line, and the verbatim code
/// text, and [`load`] checks that text is still in the tree. Silencing therefore
/// requires positive, re-checkable evidence — and reverses itself automatically if
/// the kernel drops the precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePrecondition {
    /// Path inside the kernel tree, e.g. `kernel/bpf/verifier.c`.
    pub file: &'static str,
    /// Line the code was read at (for triage; the anchor is what is checked).
    pub line: u32,
    /// The verbatim source line the precondition rests on.
    pub anchor: &'static str,
    /// Why this makes the documented claim inapplicable to our load path.
    pub why: &'static str,
}

/// One documented behavioural claim, anchored to the sentence that makes it.
#[derive(Debug, Clone)]
pub struct DocumentedCase {
    /// Stable id; the harness emits a program with this exact label.
    pub id: &'static str,
    /// Line in `Documentation/bpf/verifier.rst` the claim is made on (for triage).
    pub doc_line: u32,
    /// The document's own words, verbatim — the anchor `load` verifies.
    pub quote: &'static str,
    /// What the document says happens.
    pub outcome: DocumentedOutcome,
    /// The exact error string the document prints for this program, when it prints
    /// one. Anchor-checked like `quote`. A mismatch against the observed reject
    /// reason is EVIDENCE, not a divergence.
    pub expected_error: Option<&'static str>,
    /// A verified source-code precondition that makes the documented claim
    /// inapplicable on our load path. `None` for every case that is simply checked.
    pub superseded_by: Option<SourcePrecondition>,
}

/// The documented cases this loader knows how to check.
///
/// Deliberately small and literal: every entry is a sentence the document states
/// outright, not an inference from it. Adding a case means finding another explicit
/// claim, not interpreting prose.
pub const DOCUMENTED_CASES: &[DocumentedCase] = &[
    // --- vein 1: the prose examples ---------------------------------------
    DocumentedCase {
        id: "doc_unreadable_reg",
        doc_line: 30,
        quote: "will be rejected, since R2 is unreadable at the start of the program",
        outcome: DocumentedOutcome::Reject,
        // The message section prints this same program's error at line 375.
        expected_error: Some("R2 !read_ok"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_callee_saved_r6",
        doc_line: 45,
        quote: "is a correct program",
        outcome: DocumentedOutcome::Accept,
        expected_error: None,
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_bad_ptr_xadd",
        doc_line: 56,
        quote: "will be rejected, since R1 doesn't have a valid pointer type",
        outcome: DocumentedOutcome::Reject,
        expected_error: None, // the prose vein prints no error text for this one
        superseded_by: None,
    },
    // --- vein 2: "Understanding eBPF verifier messages" (lines 353-560) ----
    // All 11 are programs the document calls INVALID, so every outcome is Reject.
    DocumentedCase {
        id: "doc_msg_unreachable_insn",
        doc_line: 356,
        quote: "Program with unreachable instructions",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("unreachable insn 1"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_uninit_r0_exit",
        doc_line: 377,
        quote: "Program that doesn't initialize R0 before exiting",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("R0 !read_ok"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_stack_oob",
        doc_line: 388,
        quote: "Program that accesses stack out of bounds",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("invalid stack off=8 size=8"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_uninit_stack_arg",
        doc_line: 398,
        quote: "Program that doesn't initialize stack before passing its address into function",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("invalid indirect read from stack off -8+0 size 8"),
        // MEASURED 2026-09-01: this program is ACCEPTED by the current tree. The
        // cause is in the source, not in the verifier being wrong: a privileged
        // load may read uninitialized stack slots, and the harness loads as root.
        // The document states its claim unconditionally, so it is the document that
        // is incomplete here. Anchored so that removing the relaxation revives the
        // case automatically.
        superseded_by: Some(SourcePrecondition {
            file: "kernel/bpf/verifier.c",
            line: 21141,
            anchor: "env->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token);",
            why: "the documented rejection is unprivileged-only: bpf_allow_uninit_stack() \
                  is bpf_token_capable(token, CAP_PERFMON), so a privileged load — which \
                  is how this harness loads — may read an uninitialized stack slot and \
                  the documented error cannot occur",
        }),
    },
    DocumentedCase {
        id: "doc_msg_invalid_map_fd",
        doc_line: 414,
        quote: "Program that uses invalid map_fd=0 while calling to map_lookup_elem() function",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("fd 0 is not pointing to valid bpf_map"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_unchecked_map_value",
        doc_line: 432,
        quote: "Program that doesn't check return value of map_lookup_elem() before accessing \
                map element",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("R0 invalid mem access 'map_value_or_null'"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_misaligned_value",
        doc_line: 453,
        quote: "accesses the memory with incorrect alignment",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("misaligned access off 4 size 8"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_branch_imm_deref",
        doc_line: 477,
        quote: "accesses memory with correct alignment in one side of 'if' branch, but fails \
                to do so in the other side of 'if' branch",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("R0 invalid mem access 'imm'"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_unreleased_ref_null",
        doc_line: 508,
        quote: "Program that performs a socket lookup then sets the pointer to NULL without \
                checking it",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("Unreleased reference id=1, alloc_insn=7"),
        superseded_by: None,
    },
    DocumentedCase {
        id: "doc_msg_unreleased_ref_nocheck",
        doc_line: 536,
        quote: "Program that performs a socket lookup but does not NULL-check the returned \
                value",
        outcome: DocumentedOutcome::Reject,
        expected_error: Some("Unreleased reference id=1, alloc_insn=7"),
        superseded_by: None,
    },
];

/// A case whose documented claim is usable this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedCase {
    outcome: DocumentedOutcome,
    /// `None` when the document prints no error text, OR when the text it printed
    /// has since drifted out of the document (recorded in `drifted_error_text`).
    expected_error: Option<&'static str>,
}

/// Documented behaviour loaded from the tree, with drift accounted for.
#[derive(Debug, Default, Clone)]
pub struct VerifierRstModel {
    /// Cases whose anchoring quote was found in the document (usable).
    verified: BTreeMap<String, VerifiedCase>,
    /// Cases whose quote was NOT found — the document moved on. Reported, never
    /// silently used: a stale expectation is worse than no expectation.
    stale: Vec<String>,
    /// Cases silenced by a VERIFIED source precondition the document omits, with
    /// the reason. Reported so the silencing is visible, never invisible.
    superseded: Vec<(String, &'static str)>,
    /// Cases still usable for their decision, but whose documented ERROR TEXT is no
    /// longer in the document. The decision check survives (that is the high-value
    /// half); the message expectation is dropped, loudly rather than silently.
    drifted_error_text: Vec<String>,
}

impl VerifierRstModel {
    /// The documented outcome for `case_id`, if its anchor was verified.
    pub fn outcome(&self, case_id: &str) -> Option<DocumentedOutcome> {
        self.verified.get(case_id).map(|c| c.outcome)
    }

    /// The exact error string the document prints for `case_id`, if any survived.
    pub fn expected_error(&self, case_id: &str) -> Option<&'static str> {
        self.verified.get(case_id).and_then(|c| c.expected_error)
    }

    /// Number of usable (anchor-verified) cases.
    pub fn len(&self) -> usize {
        self.verified.len()
    }

    /// Whether nothing usable was loaded.
    pub fn is_empty(&self) -> bool {
        self.verified.is_empty()
    }

    /// Case ids whose documented sentence is no longer in the file (drift).
    pub fn stale(&self) -> &[String] {
        &self.stale
    }

    /// Cases silenced by a verified source precondition, with the reason.
    pub fn superseded(&self) -> &[(String, &'static str)] {
        &self.superseded
    }

    /// Cases whose documented error text drifted out of the document.
    pub fn drifted_error_text(&self) -> &[String] {
        &self.drifted_error_text
    }
}

/// Load documented behaviour from a bpf-next checkout.
///
/// `kernel_src` is the tree root; the file read is
/// `Documentation/bpf/verifier.rst`, plus every source file a case's
/// [`SourcePrecondition`] cites. Each case is admitted ONLY if its verbatim quote
/// is still present in the document; it is silenced only if its precondition
/// anchor is still present in the source.
pub fn load(kernel_src: &Path) -> std::io::Result<VerifierRstModel> {
    let doc = std::fs::read_to_string(kernel_src.join("Documentation/bpf/verifier.rst"))?;
    // A precondition file that cannot be read leaves the case LIVE: silencing needs
    // positive evidence, so a missing source must never silence anything.
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for case in DOCUMENTED_CASES {
        if let Some(pre) = case.superseded_by {
            if !sources.contains_key(pre.file) {
                if let Ok(text) = std::fs::read_to_string(kernel_src.join(pre.file)) {
                    sources.insert(pre.file.to_string(), text);
                }
            }
        }
    }
    Ok(from_sources(&doc, &sources))
}

/// Build the model from the document's text alone (exposed for testing).
///
/// With no kernel sources, nothing can be superseded — the fail-loud default.
pub fn from_text(text: &str) -> VerifierRstModel {
    from_sources(text, &BTreeMap::new())
}

/// Build the model from the document plus the kernel sources preconditions cite.
pub fn from_sources(doc: &str, kernel_sources: &BTreeMap<String, String>) -> VerifierRstModel {
    // Join wrapped lines: the document hard-wraps prose, so a quoted sentence may
    // span two lines. Compare against a whitespace-normalised single line.
    let flat = flatten(doc);
    let mut model = VerifierRstModel::default();
    for case in DOCUMENTED_CASES {
        if !flat.contains(&flatten(case.quote)) {
            model.stale.push(case.id.to_string());
            continue;
        }
        if let Some(pre) = case.superseded_by {
            let still_there = kernel_sources
                .get(pre.file)
                .is_some_and(|src| flatten(src).contains(&flatten(pre.anchor)));
            if still_there {
                model.superseded.push((case.id.to_string(), pre.why));
                continue;
            }
        }
        // The error text is anchored separately: losing it must not cost us the
        // decision check, which is the half that can find a real bug.
        let expected_error = match case.expected_error {
            Some(err) if !flat.contains(&flatten(err)) => {
                model.drifted_error_text.push(case.id.to_string());
                None
            }
            other => other,
        };
        model.verified.insert(
            case.id.to_string(),
            VerifiedCase {
                outcome: case.outcome,
                expected_error,
            },
        );
    }
    model
}

/// Whitespace-normalised text, so the document's hard wrapping never hides a match.
fn flatten(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "\
If register was never written to, it's not readable::

  bpf_mov R0 = R2
  bpf_exit

will be rejected, since R2 is unreadable at the start of the program.

::

  bpf_mov R6 = 1
  bpf_call foo
  bpf_mov R0 = R6
  bpf_exit

is a correct program. If there was R1 instead of R6, it would have
been rejected.

For example::

 bpf_mov R1 = 1
 bpf_xadd *(u32 *)(R1 + 3) += R2
 bpf_exit

will be rejected, since R1 doesn't have a valid pointer type at the time of
execution of instruction bpf_xadd.

Understanding eBPF verifier messages
====================================

Program with unreachable instructions::

Error::

  unreachable insn 1

Program that reads uninitialized register::

Error::

  R2 !read_ok

Program that doesn't initialize R0 before exiting::

Error::

  R0 !read_ok

Program that accesses stack out of bounds::

Error::

  invalid stack off=8 size=8

Program that doesn't initialize stack before passing its address into function::

Error::

  invalid indirect read from stack off -8+0 size 8

Program that uses invalid map_fd=0 while calling to map_lookup_elem() function::

Error::

  fd 0 is not pointing to valid bpf_map

Program that doesn't check return value of map_lookup_elem() before accessing
map element::

Error::

  R0 invalid mem access 'map_value_or_null'

Program that correctly checks map_lookup_elem() returned value for NULL, but
accesses the memory with incorrect alignment::

Error::

  misaligned access off 4 size 8

Program that correctly checks map_lookup_elem() returned value for NULL and
accesses memory with correct alignment in one side of 'if' branch, but fails
to do so in the other side of 'if' branch::

Error::

  R0 invalid mem access 'imm'

Program that performs a socket lookup then sets the pointer to NULL without
checking it::

Error::

  Unreleased reference id=1, alloc_insn=7

Program that performs a socket lookup but does not NULL-check the returned
value::

Error::

  Unreleased reference id=1, alloc_insn=7
";

    fn sources_with_uninit_stack_relaxation() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "kernel/bpf/verifier.c".to_string(),
            "\tenv->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token);\n"
                .to_string(),
        );
        m
    }

    #[test]
    fn admits_cases_whose_quote_is_present() {
        let m = from_text(DOC);
        assert_eq!(m.len(), DOCUMENTED_CASES.len(), "every documented claim anchors");
        assert!(m.stale().is_empty());
        assert!(m.drifted_error_text().is_empty());
        assert_eq!(m.outcome("doc_unreadable_reg"), Some(DocumentedOutcome::Reject));
        assert_eq!(m.outcome("doc_callee_saved_r6"), Some(DocumentedOutcome::Accept));
        assert_eq!(m.outcome("doc_bad_ptr_xadd"), Some(DocumentedOutcome::Reject));
    }

    #[test]
    fn message_vein_carries_exact_error_text() {
        let m = from_text(DOC);
        assert_eq!(m.expected_error("doc_msg_unreachable_insn"), Some("unreachable insn 1"));
        assert_eq!(
            m.expected_error("doc_msg_branch_imm_deref"),
            Some("R0 invalid mem access 'imm'")
        );
        // Every message-vein case is a REJECT claim: that is what makes them
        // soundness tests rather than documentation trivia.
        for case in DOCUMENTED_CASES.iter().filter(|c| c.id.starts_with("doc_msg_")) {
            assert_eq!(case.outcome, DocumentedOutcome::Reject, "{}", case.id);
            assert!(case.expected_error.is_some(), "{}", case.id);
        }
    }

    #[test]
    fn quotes_match_across_the_documents_hard_wrapping() {
        // The xadd claim is wrapped mid-sentence in the real file; normalisation
        // must still find it.
        assert!(DOC.contains("will be rejected, since R1 doesn't have a valid pointer type at the time of\nexecution"));
        assert_eq!(from_text(DOC).outcome("doc_bad_ptr_xadd"), Some(DocumentedOutcome::Reject));
    }

    #[test]
    fn drift_is_reported_not_silently_trusted() {
        // Documentation reworded: the anchor disappears -> the case must go STALE,
        // never keep asserting an expectation the document no longer makes.
        let reworded = DOC.replace(
            "will be rejected, since R2 is unreadable at the start of the program",
            "is refused because R2 holds no value yet",
        );
        let m = from_text(&reworded);
        assert_eq!(m.outcome("doc_unreadable_reg"), None, "stale case must not be usable");
        assert!(m.stale().contains(&"doc_unreadable_reg".to_string()));
        assert_eq!(m.len(), DOCUMENTED_CASES.len() - 1, "the others still anchor");
    }

    #[test]
    fn error_text_drift_costs_the_message_not_the_decision() {
        // Only the printed error string is reworded. The decision claim is
        // untouched, so the soundness check must survive — but the lost message
        // expectation has to be reported, not dropped quietly.
        let reworded = DOC.replace("unreachable insn 1", "unreachable instruction at 1");
        let m = from_text(&reworded);
        assert_eq!(
            m.outcome("doc_msg_unreachable_insn"),
            Some(DocumentedOutcome::Reject),
            "decision check must survive message drift"
        );
        assert_eq!(m.expected_error("doc_msg_unreachable_insn"), None);
        assert!(m.drifted_error_text().contains(&"doc_msg_unreachable_insn".to_string()));
    }

    #[test]
    fn a_verified_source_precondition_supersedes_a_documented_claim() {
        // The tree still carries the uninit-stack relaxation -> the documented
        // claim does not apply to a privileged load, so the case must be silenced
        // AND the silencing must be visible with its reason.
        let m = from_sources(DOC, &sources_with_uninit_stack_relaxation());
        assert_eq!(m.outcome("doc_msg_uninit_stack_arg"), None);
        let (id, why) = &m.superseded()[0];
        assert_eq!(id, "doc_msg_uninit_stack_arg");
        assert!(why.contains("CAP_PERFMON"));
        assert_eq!(m.len(), DOCUMENTED_CASES.len() - 1);
    }

    #[test]
    fn silencing_needs_positive_evidence_and_reverses_itself() {
        // No sources at all: nothing may be silenced.
        assert_eq!(
            from_text(DOC).outcome("doc_msg_uninit_stack_arg"),
            Some(DocumentedOutcome::Reject),
            "a case must never be silenced without the citation being checked"
        );
        // The kernel drops the relaxation: the citation stops anchoring and the
        // case comes back to life on its own.
        let mut without = BTreeMap::new();
        without.insert(
            "kernel/bpf/verifier.c".to_string(),
            "\tenv->allow_ptr_leaks = bpf_allow_ptr_leaks(env->prog->aux->token);\n".to_string(),
        );
        let m = from_sources(DOC, &without);
        assert_eq!(
            m.outcome("doc_msg_uninit_stack_arg"),
            Some(DocumentedOutcome::Reject),
            "removing the precondition must revive the documented claim"
        );
        assert!(m.superseded().is_empty());
    }
}
