//! Register-to-register family (OI-9 next increment: register-register operands).
//!
//! The classic `--gen` family combines a ranged register with a CONSTANT (BPF_K).
//! This family combines two INDEPENDENT ranged unknowns with BPF_X — a different
//! verifier path (scalar_min_max_* over two non-const scalars, plus a reg-reg branch
//! that back-propagates the narrowing onto BOTH registers). Measured 2026-09-01 and
//! pinned here.
//!
//! Result: 242 programs, all accepted, tnum-vs-bounds denominator = 2453 (the
//! LARGEST of any family so far — single-width 1497, mixed >1500), 0 divergences,
//! 0 parser blind-spots. `reg32_checked = 0`: reg-reg is a DIFFERENT axis from the
//! 32<->64 reconciliation (that is the mixed family's job), pinned so a change forces
//! a re-measure. The one lower-confidence record is an OI-10 console-interleave
//! repair (a kernel printk spliced into the shared serial capture and mended), not a
//! parse blind-spot.

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const REGREG: &str = include_str!("fixtures/volume/gen-regreg-242.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-rr-{}-{}", std::process::id(), tag));
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
fn the_regreg_corpus_gives_the_intrinsic_leg_its_largest_denominator() {
    let (norm, out) = run_diff(REGREG, "denom");
    assert_eq!(norm.records.len(), 242, "the full enumerated reg-reg family");
    assert!(
        out.summary.tnum_bounds_checked > 2000,
        "reg-reg must exercise the tnum-vs-bounds check heavily; got {}",
        out.summary.tnum_bounds_checked
    );
    // 0 out of >2000, on the reg-reg path the imm family never touched.
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn reg_reg_is_a_different_axis_from_the_32_to_64_region() {
    // reg-reg combines two same-width unknowns; it does not force the two width views
    // apart, so it scores zero on the 32<->64 denominator (the mixed family's job).
    // Pinned: if this becomes non-zero the family or the parser changed — re-measure.
    let (_, out) = run_diff(REGREG, "axis");
    assert_eq!(out.summary.reg32_checked, 0);
}

#[test]
fn the_regreg_corpus_is_fully_parsed() {
    // reg-reg alu (`r0 &= r6`) and reg-reg compares (`if r0 == r6 goto`) are state
    // shapes the imm family never printed; they must not open a parser blind spot.
    let (norm, _) = run_diff(REGREG, "parse");
    let unrecognized = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the reg-reg corpus");
    // The only lower-confidence records permitted are OI-10 console-interleave
    // repairs (a printk spliced into the shared serial capture), never a genuine
    // parse-confidence concern.
    let non_console_notes = norm
        .records
        .iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console_notes, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_accepted_and_uniquely_labelled() {
    // Every reg-reg recipe is a valid program (div/mod and shift by a register
    // included — the verifier accepts a possibly-zero divisor and a variable shift).
    assert_eq!(REGREG.matches("decision=accept").count(), 242, "all accepted");
    assert_eq!(REGREG.matches("decision=reject").count(), 0, "none rejected");

    let (norm, _) = run_diff(REGREG, "labels");
    let labels: Vec<&str> = norm
        .records
        .iter()
        .filter_map(|r| r.source_label.as_deref())
        .collect();
    assert_eq!(labels.len(), 242, "every record carries its label");
    assert!(labels.contains(&"genrr#w64.and.jeq#000"));
    assert!(labels.contains(&"genrr#w32.mod.jset#241"));
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 242, "no two programs share a label");
}
