//! Pointer-arithmetic family (OI-9 next increment: pointer arithmetic).
//!
//! Every prior family (--gen / --gen-rr / --gen-mb / --gen-mix) combines only
//! SCALARS. This one takes a real PTR_TO_MAP_VALUE (bpf_map_lookup_elem on a 64-byte
//! ARRAY value), adds a shaped+narrowed scalar offset, and STORES through the
//! adjusted pointer -- aiming the verifier's pointer-bounds decision
//! (adjust_ptr_min_max_vals / check_mem_access). A logic bug here is a wrongly
//! ACCEPTED out-of-bounds WRITE (higher severity than an OOB read), which is why
//! this leg is the highest-EV surface so far. Measured 2026-09-03 and pinned here.
//!
//! Result: 242 programs, a MIX of 34 accepted / 208 rejected (this family is NOT
//! all-accepted by construction -- acceptance IS the decision under test), 199 EACCES
//! (safety reject) + 9 EINVAL (the diagnostics.c reporter's signed-compare path).
//! tnum_bounds_checked = 1191 (on both the scalar offset AND the pointer's own
//! var_off), 0 divergences, and -- notably for a first run -- 0 parser blind-spots:
//! the parser handled map_value pointer state and the diagnostics reject logs cleanly.
//! reg32_checked = 0 (same-width per program).

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const PTR: &str = include_str!("fixtures/volume/gen-ptr-242.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-ptr-{}-{}", std::process::id(), tag));
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
fn pointer_arith_exercises_the_intrinsic_leg_on_scalars_and_pointer_offsets() {
    let (norm, out) = run_diff(PTR, "denom");
    assert_eq!(norm.records.len(), 242, "the full enumerated pointer-arith family");
    assert!(
        out.summary.tnum_bounds_checked > 1000,
        "pointer-arith must exercise tnum-vs-bounds (incl. the pointer's var_off); got {}",
        out.summary.tnum_bounds_checked
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn pointer_arith_is_a_genuine_accept_reject_decision_surface() {
    // The point of this family: acceptance depends on whether the verifier can prove
    // the offset stays within value_size. Pinned so a change in pointer-bounds
    // behaviour (a kernel regression, or a generator change) forces a re-measure.
    assert_eq!(PTR.matches("decision=accept").count(), 34, "accepted (offset provably in-bounds)");
    assert_eq!(PTR.matches("decision=reject").count(), 208, "rejected (offset not provably in-bounds)");
    // Same-width per program: does not touch the 32<->64 axis.
    let (_, out) = run_diff(PTR, "axis");
    assert_eq!(out.summary.reg32_checked, 0);
}

#[test]
fn pointer_arith_opens_no_parser_blind_spot() {
    // map_value pointer state (`R0=map_value(ks=4,vs=64,...var_off=...)`), pointer
    // arithmetic (`r0 += r1`), and the diagnostics.c reject reports are shapes the
    // scalar families never printed. First run: they must not open a blind spot.
    let (norm, _) = run_diff(PTR, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the pointer-arith corpus");
    let non_console_notes = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console_notes, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(PTR, "labels");
    let labels: Vec<&str> = norm.records.iter()
        .filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 242, "every record carries its label");
    assert!(labels.contains(&"genptr#w64.and.jeq#000"));
    assert!(labels.contains(&"genptr#w32.mod.jset#241"));
    let mut sorted = labels.clone();
    sorted.sort_unstable(); sorted.dedup();
    assert_eq!(sorted.len(), 242, "no two programs share a label");
}
