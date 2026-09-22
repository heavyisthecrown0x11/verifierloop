//! Targeted generation (devlog 0025) — does an aimed corpus actually buy the
//! detector anything a random one does not?
//!
//! The reviewer's diagnosis was that bug hunting is `oracle x input`, and that this
//! project had grown the oracle while the input stayed at ~241 executions on TCG.
//! The claim these tests pin is stronger and more specific than "more programs":
//! the committed syzkaller volume gives the intrinsic tnum-vs-bounds check
//! **literally nothing to check**, so that leg's "0 divergences" was 0 out of 0 —
//! an absence of evidence. The targeted corpus makes it 0 out of ~1500.
//!
//! Both halves are pinned. If a future parser change ever makes the syzkaller
//! corpus report checkable observations, or makes the targeted one stop reporting
//! them, that is a regression in the measurement itself and must fail loudly.

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;
use metrics::core::{RegState, Tnum};

/// The full enumerated family, captured in the bpf-next VM.
const TARGETED: &str = include_str!("fixtures/volume/gen-targeted-242.log");
/// The larger of the two syzkaller volume captures, for the contrast.
const SYZ: &str = include_str!("fixtures/volume/syz-replay-184.log");
/// The mixed-width family (devlog 0026), aimed at the 32<->64 reconciliation.
const MIXED: &str = include_str!("fixtures/volume/gen-mixed-396.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-gen-{}-{}", std::process::id(), tag));
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
fn the_targeted_corpus_gives_the_intrinsic_leg_a_real_denominator() {
    let (norm, out) = run_diff(TARGETED, "targeted");
    assert_eq!(norm.records.len(), 242, "the full enumerated family");
    assert!(
        out.summary.tnum_bounds_checked > 1000,
        "the aimed corpus must actually exercise the tnum-vs-bounds check; got {}",
        out.summary.tnum_bounds_checked
    );
    // And with that denominator, "0 findings" finally means something.
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_syzkaller_volume_reaches_nothing_of_the_intrinsic_check() {
    // 0025's measurement, MEASURED THREE TIMES, and the guard below fired in BOTH
    // directions — which is the whole reason it is written as an exact equality.
    //
    // 0025: zero. syzkaller's programs are syscall sequences whose scalars are either
    //   fully known or fully unknown, never PARTIALLY known, so the intersection check —
    //   gated on `mask != 0` — gets nothing.
    // 0065: 357. Adding const_tnum_range_mismatch appeared to open a second half:
    //   `mask == 0` with stated bounds is exactly the fully-known scalar this corpus is
    //   full of, so the revision read as "syzkaller reaches one half after all".
    // 0076: zero again, and 0025 was right. A constant scalar prints as a BARE NUMBER —
    //   `print_reg_state` does `verbose_snum(value); return;` — so the parser derives
    //   umin, umax, smin and smax from that one token and comparing them with the tnum
    //   compares the value with itself. All 357 were tautologies. The check now requires
    //   a bound that was actually PRINTED, and this corpus prints none.
    //
    // The lesson is not about syzkaller. It is that a denominator can be inflated by
    // comparisons that cannot fail, and that "0 out of 357" read exactly like evidence.
    let (norm, out) = run_diff(SYZ, "syz");
    assert_eq!(norm.records.len(), 151);
    assert_eq!(
        out.summary.tnum_bounds_checked, 0,
        "if this changes the corpus or the parser changed — re-measure before trusting \
         any 'clean' period from it"
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_targeted_corpus_is_fully_parsed() {
    // A corpus that buys checks is worthless if the parser cannot read it. The five
    // new state shapes (32-bit compares, arsh, div/mod, branch merges) must not open
    // a blind spot — the 0018 lesson.
    let (norm, _) = run_diff(TARGETED, "parse");
    let unrecognized = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the targeted corpus");
    assert!(
        norm.records.iter().all(|r| r.parse_notes.is_empty()),
        "no lower-confidence records"
    );
}

#[test]
fn every_program_in_the_family_is_labelled_with_its_own_recipe() {
    // Reproducibility without a seed or a corpus file: the label names the exact
    // program, so a finding can be rebuilt from the report alone.
    let (norm, _) = run_diff(TARGETED, "labels");
    let labels: Vec<&str> = norm
        .records
        .iter()
        .filter_map(|r| r.source_label.as_deref())
        .collect();
    assert_eq!(labels.len(), 242, "every record carries its label");
    assert!(labels.contains(&"gen#w64.and.jeq#000"));
    assert!(labels.contains(&"gen#w32.mod.jset#241"));
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 242, "no two programs share a label");
}

// ---------------------------------------------------------------------------
// The denominator predicate itself — it decides what counts as evidence, so its
// exclusions are the part most worth testing.
// ---------------------------------------------------------------------------

fn reg(reg_type: &str, value: u64, mask: u64, umin: u64, umax: u64) -> RegState {
    RegState {
        reg: 0,
        reg_type: reg_type.to_string(),
        tnum: Tnum { value, mask },
        umin,
        umax,
        smin: 0,
        smax: 0,
        ..Default::default()
    }
}

#[test]
fn a_constant_is_not_a_check_it_is_a_tautology() {
    // `R0=13` gives the parser ONE token from which it derives both the tnum and the
    // bounds. Comparing them compares 13 with 13; it cannot fail whatever the
    // verifier does, so counting it would manufacture a denominator out of nothing.
    assert!(!diff::tnum_bounds_checkable(&reg("scalar", 13, 0, 13, 13)));
}

#[test]
fn a_fully_unknown_scalar_cannot_contradict_anything() {
    // Spans the whole domain, so it intersects every bound range by construction.
    assert!(!diff::tnum_bounds_checkable(&reg("scalar", 0, u64::MAX, 0, u64::MAX)));
    // Even narrowed bounds cannot help while the tnum says "anything".
    assert!(!diff::tnum_bounds_checkable(&reg("scalar", 0, u64::MAX, 10, 20)));
}

#[test]
fn placeholder_pointer_registers_do_not_count() {
    // The parser stores zeros for ctx/fp/map_ptr; those are filler, not observations.
    assert!(!diff::tnum_bounds_checkable(&reg("ctx", 0, 0, 0, 0)));
    assert!(!diff::tnum_bounds_checkable(&reg("fp", 0, 0, 0, 0)));
}

#[test]
fn a_partially_known_scalar_with_real_bounds_is_the_thing_that_counts() {
    // Both trackers were printed by the verifier independently — this is the only
    // shape where they can be caught disagreeing.
    assert!(diff::tnum_bounds_checkable(&reg("scalar", 0, 0xff, 0, 255)));
    assert!(diff::tnum_bounds_checkable(&reg("scalar", 0x100, 0xff, 256, 511)));
}

// ---------------------------------------------------------------------------
// The mixed-width family (devlog 0026) — OI-9's blind spot, closed and pinned.
// ---------------------------------------------------------------------------

#[test]
fn single_width_programs_cannot_reach_the_32_to_64_region_at_all() {
    // OI-9's claim, as a number. The 0025 family printed a 32-bit view on over a
    // thousand registers, and not ONE of them said anything the 64-bit view did not:
    // when the two agree the verifier collapses them into a single token
    // (`umax=umax32=255`), and a value cannot be caught disagreeing with itself.
    // No amount of MORE single-width programs changes this — it is structural.
    let (_, out) = run_diff(TARGETED, "sw32");
    assert_eq!(
        out.summary.reg32_checked, 0,
        "the single-width family must score zero on the 32<->64 denominator"
    );
}

#[test]
fn mixing_widths_inside_one_program_does_reach_it() {
    let (norm, out) = run_diff(MIXED, "mixed");
    assert_eq!(norm.records.len(), 396, "four enumerated sub-families");
    assert!(
        out.summary.reg32_checked > 100,
        "mixed-width programs must actually force the two views apart; got {}",
        out.summary.reg32_checked
    );
    // The 64-bit leg keeps working too — this corpus is a superset in signal, not a
    // trade.
    assert!(out.summary.tnum_bounds_checked > 1500, "{}", out.summary.tnum_bounds_checked);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_mixed_corpus_is_fully_parsed() {
    // movsx, 32-bit compares and upper-half shifts print state shapes the parser had
    // never seen before 0026 — including the hex-printed negative s32 that produced
    // ten bogus findings on the first run.
    let (norm, _) = run_diff(MIXED, "mixparse");
    let unrecognized = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the mixed corpus");
}

#[test]
fn all_four_sub_families_are_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(MIXED, "mixlabels");
    let labels: Vec<&str> = norm
        .records
        .iter()
        .filter_map(|r| r.source_label.as_deref())
        .collect();
    for prefix in ["mix#64-32.", "mix#32-64.", "mix#movsx", "mix#hi."] {
        assert!(
            labels.iter().any(|l| l.starts_with(prefix)),
            "sub-family {prefix} missing"
        );
    }
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 396, "no two programs share a label");
}
