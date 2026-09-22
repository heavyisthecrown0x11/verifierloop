//! Multi-branch family (OI-9 next increment: multi-branch / multi-merge flow).
//!
//! `--gen` and `--gen-rr` each have ONE compare and ONE merge point. This family has
//! TWO sequential branches and TWO merge points, and the second branch narrows a
//! register whose abstract state is itself the JOIN of the first branch's two paths.
//! A bounds/tnum desync introduced at merge 1 gets a second chance to surface (or be
//! masked) at branch 2 / merge 2 — a surface the single-diamond families don't reach.
//! Measured 2026-09-03 and pinned here.
//!
//! Result: 242 programs, all accepted, tnum-vs-bounds denominator = 2050, 0
//! divergences, 0 parser blind-spots. reg32_checked = 0 (multi-branch is
//! same-width per program, like reg-reg — the 32<->64 axis is the mixed family's job).

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const MB: &str = include_str!("fixtures/volume/gen-multibranch-242.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-mb-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("capture.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("capture", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (norm, out)
}

#[test]
fn the_multibranch_corpus_exercises_the_intrinsic_leg_across_two_merges() {
    let (norm, out) = run_diff(MB, "denom");
    assert_eq!(norm.records.len(), 242, "the full enumerated multi-branch family");
    assert!(
        out.summary.tnum_bounds_checked > 1900,
        "multi-branch must exercise the tnum-vs-bounds check across two merges; got {}",
        out.summary.tnum_bounds_checked
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn multi_branch_is_same_width_so_scores_zero_on_the_32_to_64_axis() {
    // Each program is purely w32 or w64; it does not force the two width views apart.
    // Pinned: non-zero here means the family or parser changed — re-measure.
    let (_, out) = run_diff(MB, "axis");
    assert_eq!(out.summary.reg32_checked, 0);
}

#[test]
fn the_multibranch_corpus_is_fully_parsed() {
    let (norm, _) = run_diff(MB, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the multi-branch corpus");
    let non_console_notes = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console_notes, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_accepted_and_uniquely_labelled() {
    assert_eq!(MB.matches("decision=accept").count(), 242, "all accepted");
    assert_eq!(MB.matches("decision=reject").count(), 0, "none rejected");
    let (norm, _) = run_diff(MB, "labels");
    let labels: Vec<&str> = norm.records.iter()
        .filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 242, "every record carries its label");
    assert!(labels.contains(&"genmb#w64.and.jeq#000"));
    assert!(labels.contains(&"genmb#w32.mod.jset#241"));
    let mut sorted = labels.clone();
    sorted.sort_unstable(); sorted.dedup();
    assert_eq!(sorted.len(), 242, "no two programs share a label");
}
