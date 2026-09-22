//! Ground-truth source 2 (documented behaviour) — calibration on the real path.
//!
//! The same two-sided proof the other detector legs got: the check must stay SILENT
//! when the kernel agrees with its documentation, and must FIRE when they disagree.
//! Plus the provenance question this source raises specifically: the expectation
//! must come from the document (anchor-verified), so a drifted quote disables the
//! case instead of asserting a claim the document no longer makes.

use contract::PeriodPaths;
use pipeline::groundtruth::verifier_rst::{self, DocumentedOutcome};
use pipeline::groundtruth::{GroundTruth, NoGroundTruth, StaticGroundTruth};
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize};

/// A real harness block for a documented case, in the native format.
fn block(label: &str, decision: &str) -> String {
    format!(
        "===PROG {label} type=socket_filter ===\n\
         RESULT decision={decision} fd=3 errno=0 load_ns=1\n\
         ---LOG---\n\
         0: R1=ctx() R10=fp0\n\
         0: (b7) r0 = 0                        ; R0=0\n\
         1: (95) exit\n\
         processed 2 insns (limit 1000000) total_states 0 peak_states 0\n\
         ---END---\n"
    )
}

/// The document as shipped in the tree (its own words are the expectation).
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

is a correct program.

For example::

 bpf_mov R1 = 1
 bpf_xadd *(u32 *)(R1 + 3) += R2
 bpf_exit

will be rejected, since R1 doesn't have a valid pointer type at the time of
execution of instruction bpf_xadd.
";

/// A harness block whose verifier log actually carries a reject reason line.
fn block_rejected_with(label: &str, reason: &str) -> String {
    format!(
        "===PROG {label} type=socket_filter ===\n\
         RESULT decision=reject fd=-1 errno=13 load_ns=1\n\
         ---LOG---\n\
         0: R1=ctx() R10=fp0\n\
         0: (7a) *(u64 *)(r10 +8) = 0\n\
         {reason}\n\
         processed 1 insns (limit 1000000) total_states 0 peak_states 0\n\
         ---END---\n"
    )
}

/// The "Understanding eBPF verifier messages" vein: a claim plus the exact error
/// text the document prints for it.
const DOC_MSG: &str = "\
Program that accesses stack out of bounds::

Error::

  invalid stack off=8 size=8
";

fn gt_with_message_vein() -> StaticGroundTruth {
    StaticGroundTruth::default()
        .with_verifier_rst(verifier_rst::from_text(&format!("{DOC}{DOC_MSG}")))
}

fn drift_notes(out: &diff::DiffFindings) -> Vec<&diff::EvidenceNote> {
    out.notes
        .iter()
        .filter(|n| n.kind == "documented_message_drift")
        .collect()
}

fn run(native: &str, gt: &dyn GroundTruth, tag: &str) -> diff::DiffFindings {
    let dir = std::env::temp_dir().join(format!("vl-doc-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, native).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, gt).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn gt_with_doc() -> StaticGroundTruth {
    StaticGroundTruth::default().with_verifier_rst(verifier_rst::from_text(DOC))
}

fn doc_findings(out: &diff::DiffFindings) -> Vec<&diff::DivergenceFinding> {
    out.findings
        .iter()
        .filter(|f| f.kind == "documented_behavior_mismatch")
        .collect()
}

#[test]
fn silent_when_the_kernel_agrees_with_its_documentation() {
    // The document says this program is rejected; the kernel rejected it.
    let out = run(&block("doc_unreadable_reg", "reject"), &gt_with_doc(), "agree");
    assert!(doc_findings(&out).is_empty(), "false positive: {:?}", out.findings);
    assert_eq!(out.summary.documented_cases_checked, 1, "the case WAS compared");
}

#[test]
fn fires_when_the_kernel_contradicts_its_documentation() {
    // Same program, but the verifier ACCEPTED what the document says is rejected —
    // the documented-vs-observed divergence this source exists to catch.
    let out = run(&block("doc_unreadable_reg", "accept"), &gt_with_doc(), "disagree");
    let f = doc_findings(&out);
    assert_eq!(f.len(), 1, "the mismatch must be reported: {:?}", out.findings);
    assert_eq!(f[0].expected, "reject");
    assert_eq!(f[0].observed, "accept");
    assert_eq!(
        f[0].source,
        diff::GroundTruthSource::Documentation,
        "attributed to the documentation, not to an intrinsic invariant"
    );
}

#[test]
fn the_expectation_comes_from_the_document_not_the_checker() {
    // With no ground truth loaded, the very same contradiction produces nothing:
    // the claim lives in the document, not in the diff stage.
    let out = run(&block("doc_unreadable_reg", "accept"), &NoGroundTruth, "nogt");
    assert!(doc_findings(&out).is_empty());
    assert_eq!(out.summary.documented_cases_checked, 0, "nothing to compare against");
}

#[test]
fn a_drifted_quote_disables_the_case_instead_of_asserting_a_stale_claim() {
    // The documentation is reworded, so the anchor no longer matches. The case must
    // go quiet — asserting an expectation the document no longer makes would be
    // fabricating ground truth.
    let reworded = DOC.replace(
        "will be rejected, since R2 is unreadable at the start of the program",
        "is refused because R2 holds no value yet",
    );
    let model = verifier_rst::from_text(&reworded);
    assert!(model.stale().contains(&"doc_unreadable_reg".to_string()));

    let gt = StaticGroundTruth::default().with_verifier_rst(model);
    let out = run(&block("doc_unreadable_reg", "accept"), &gt, "stale");
    assert!(
        doc_findings(&out).is_empty(),
        "a stale case must not assert anything: {:?}",
        out.findings
    );
    assert_eq!(out.summary.documented_cases_checked, 0);
}

#[test]
fn unrelated_programs_are_untouched_by_this_source() {
    // A syzkaller replay block has no documented claim; the leg must ignore it.
    let out = run(&block("b4f4197b8455#0", "accept"), &gt_with_doc(), "unrelated");
    assert!(doc_findings(&out).is_empty());
    assert_eq!(out.summary.documented_cases_checked, 0);
}

#[test]
fn all_three_documented_cases_are_checkable_and_agree_when_correct() {
    let native = format!(
        "{}{}{}",
        block("doc_unreadable_reg", "reject"),
        block("doc_callee_saved_r6", "accept"),
        block("doc_bad_ptr_xadd", "reject"),
    );
    let out = run(&native, &gt_with_doc(), "all");
    assert_eq!(out.summary.documented_cases_checked, 3, "all three compared");
    assert!(doc_findings(&out).is_empty(), "{:?}", out.findings);
    assert_eq!(
        verifier_rst::from_text(DOC).outcome("doc_callee_saved_r6"),
        Some(DocumentedOutcome::Accept)
    );
}

// ---------------------------------------------------------------------------
// Source 4 (patch-diff) qualifying source 2 — devlog 0023.
// ---------------------------------------------------------------------------

use pipeline::groundtruth::patch_diff::{CommitInfo, PatchDiffModel};

fn stale_evidence() -> PatchDiffModel {
    PatchDiffModel {
        doc_last: Some(CommitInfo {
            sha: "107e16979905".into(),
            date: "2025-09-18".into(),
            subject: "doc".into(),
        }),
        code_last: Some(CommitInfo {
            sha: "a2e98481a639".into(),
            date: "2026-08-18".into(),
            subject: "code".into(),
        }),
        code_commits_since_doc: 351,
    }
}

#[test]
fn a_documented_divergence_carries_doc_vs_code_staleness_evidence() {
    // Citation anchoring proves the sentence still EXISTS, not that it is still
    // TRUE. So when the leg fires, the finding must already carry the evidence a
    // human needs to ask "regression, or stale prose?".
    let gt = gt_with_doc().with_patch_diff(stale_evidence());
    let out = run(&block("doc_unreadable_reg", "accept"), &gt, "evidence");
    let f = doc_findings(&out);
    assert_eq!(f.len(), 1);
    assert!(
        f[0].detail.contains("351 verifier.c commits since"),
        "the finding must carry git evidence: {}",
        f[0].detail
    );
    assert!(f[0].detail.contains("2025-09-18") && f[0].detail.contains("2026-08-18"));
}

#[test]
fn without_git_history_the_finding_still_stands_but_claims_nothing_extra() {
    // Missing evidence degrades to silence, never to an invented qualifier.
    let out = run(&block("doc_unreadable_reg", "accept"), &gt_with_doc(), "noevidence");
    let f = doc_findings(&out);
    assert_eq!(f.len(), 1, "the divergence itself does not depend on source 4");
    assert!(!f[0].detail.contains("commits since"), "no fabricated evidence");
}

// ---------------------------------------------------------------------------
// The message vein (verifier.rst:353-560) — devlog 0024.
//
// The decision claim and the error-text claim are deliberately NOT weighed the
// same. The document is 351 verifier.c commits behind, so its message strings
// drift constantly while its safety claims do not.
// ---------------------------------------------------------------------------

#[test]
fn an_exact_error_message_match_stays_completely_silent() {
    let out = run(
        &block_rejected_with("doc_msg_stack_oob", "invalid stack off=8 size=8"),
        &gt_with_message_vein(),
        "msg-exact",
    );
    assert!(doc_findings(&out).is_empty(), "{:?}", out.findings);
    assert!(drift_notes(&out).is_empty(), "{:?}", out.notes);
    assert_eq!(out.summary.documented_cases_checked, 1, "the case WAS compared");
}

#[test]
fn a_reworded_error_message_is_evidence_not_a_divergence() {
    // The kernel rejected the program exactly as documented; only the wording of
    // the message changed. That is documentation drift, and reporting it as a
    // divergence would make every period look dirty for no safety reason.
    let out = run(
        &block_rejected_with("doc_msg_stack_oob", "invalid write to stack R10 off=8 size=8"),
        &gt_with_message_vein(),
        "msg-drift",
    );
    assert!(
        doc_findings(&out).is_empty(),
        "message wording must never produce a verdict: {:?}",
        out.findings
    );
    assert_eq!(out.summary.finding_count, 0, "a clean period must still read clean");

    let n = drift_notes(&out);
    assert_eq!(n.len(), 1, "but the drift must be visible: {:?}", out.notes);
    assert_eq!(n[0].expected, "invalid stack off=8 size=8");
    assert_eq!(n[0].observed, "invalid write to stack R10 off=8 size=8");
    assert_eq!(n[0].source, diff::GroundTruthSource::Documentation);
    assert_eq!(out.summary.note_count, 1, "counted apart from findings");
    assert!(n[0].detail.contains("NOT a verifier divergence"));
}

#[test]
fn a_wrong_decision_outranks_a_matching_message() {
    // The loud half: the document says reject, the verifier accepted. This is the
    // soundness signal the message vein exists for, and it is a finding, not a note.
    let out = run(&block("doc_msg_stack_oob", "accept"), &gt_with_message_vein(), "msg-accept");
    let f = doc_findings(&out);
    assert_eq!(f.len(), 1, "{:?}", out.findings);
    assert_eq!((f[0].expected.as_str(), f[0].observed.as_str()), ("reject", "accept"));
    assert!(drift_notes(&out).is_empty(), "an accepted program has no reject text to drift");
}

#[test]
fn a_case_superseded_by_the_kernel_source_is_not_checked_at_all() {
    // MEASURED on the tree: a privileged load may read uninitialized stack, so the
    // documented rejection cannot happen on our load path. Asserting it anyway
    // would manufacture a permanent false divergence — but the silencing itself
    // must be visible, and must rest on a citation that is re-checked every load.
    let doc = format!(
        "{DOC}Program that doesn't initialize stack before passing its address into function::

Error::

  invalid indirect read from stack off -8+0 size 8
"
    );
    let mut sources = std::collections::BTreeMap::new();
    sources.insert(
        "kernel/bpf/verifier.c".to_string(),
        "\tenv->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token);\n".to_string(),
    );

    let live = verifier_rst::from_text(&doc);
    assert_eq!(
        live.outcome("doc_msg_uninit_stack_arg"),
        Some(DocumentedOutcome::Reject),
        "without the citation checked, the claim stands"
    );

    let model = verifier_rst::from_sources(&doc, &sources);
    assert!(model.superseded().iter().any(|(id, _)| id == "doc_msg_uninit_stack_arg"));
    let gt = StaticGroundTruth::default().with_verifier_rst(model);
    // The kernel ACCEPTS this program. With the precondition verified, that must
    // not be reported as a divergence.
    let out = run(&block("doc_msg_uninit_stack_arg", "accept"), &gt, "superseded");
    assert!(doc_findings(&out).is_empty(), "{:?}", out.findings);
    assert_eq!(out.summary.documented_cases_checked, 0, "not compared, and counted as such");
}
