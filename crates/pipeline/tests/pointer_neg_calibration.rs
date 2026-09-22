//! Negative-offset map-value family (T1-2) — the smin lower-bound path.
//!
//! --gen-ptr adds a POSITIVE bounded scalar to a map_value pointer, so the deciding
//! check is the UPPER bound (umax + size <= value_size). T1-2 drives the OTHER edge:
//! an offset whose signed minimum can go NEGATIVE, which would write BELOW the start
//! of the map value. The kernel guards it with a distinct check ("R%d min value is
//! negative, either use unsigned index or do a if (index >=0) check"); that smin path
//! is the historically bug-prone one — skipping it would ACCEPT an OOB-below write.
//!
//! The offset is pushed negative deterministically: `r1 &= 15` (-> [0,15]) then
//! `r1 -= C` (-> signed [-C, 15-C], smin = -C). Two forms:
//!   raw — no guard. If smin<0 the store MUST be rejected.
//!   grd — `if (r1 s< 0) goto skip_store`; the verifier must re-derive smin>=0 on the
//!         store path and ACCEPT (proving it is not merely over-rejecting everything).
//! Grid: form{raw,grd} x C(10 values) x reach{(off,W)} (6) = 120 programs, value_size=64.
//! Captured in the bpf-next VM (kernel 5e289c5a), 2026-09-03.
//!
//! Result: 60 accept / 60 reject. raw=4/60 (every accept is C==0, i.e. NO negative-capable
//! store is accepted), grd=56/60 (the guard rescues). The decision is a pure function of
//! the store-path offset range vs [0, value_size]; all 120 match the predicate below with
//! 0 exceptions. The "R0 min value is negative" message is present and fires exactly where
//! the effective min (smin+off) is negative. tnum_bounds_checked = 438, reg32_checked = 0,
//! 0 divergences, 0 parser blind-spots. Verdict: the smin lower-bound check is enforced —
//! no OOB-below accept on this kernel.

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const NEG: &str = include_str!("fixtures/volume/gen-ptrneg-120.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-ptrneg-{}-{}", std::process::id(), tag));
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

/// Decode `genptrneg#<form>.C<c>.o<off>.w<W>#<idx>` -> (form, C, off, W).
fn decode(label: &str) -> (String, i64, i64, i64) {
    let body = label.trim_start_matches("genptrneg#");
    let body = &body[..body.find('#').unwrap()];
    let mut it = body.split('.');
    let form = it.next().unwrap().to_string();
    let c = it.next().unwrap().trim_start_matches('C').parse().unwrap();
    let off = it.next().unwrap().trim_start_matches('o').parse().unwrap();
    let w = it.next().unwrap().trim_start_matches('w').parse().unwrap();
    (form, c, off, w)
}

fn program_decisions() -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for block in NEG.split("===PROG ").skip(1) {
        let label = block.split_whitespace().next().unwrap().to_string();
        let accepted = block
            .lines()
            .find(|l| l.starts_with("RESULT "))
            .map(|l| l.contains("decision=accept"))
            .unwrap();
        out.push((label, accepted));
    }
    out
}

/// The verified decision model. value_size=64, mask=15 so the non-negative span is [0,15].
/// A grd program with C>=16 has an all-negative window -> the guard makes the store DEAD,
/// so it accepts vacuously. Otherwise the store is live over r1 in [r1min, 15-C], and it is
/// accepted iff the lower bound is non-negative AND the reach fits: r1min>=0 && 15-C+off+W<=64.
fn predict_accept(form: &str, c: i64, off: i64, w: i64) -> bool {
    if form == "grd" && c >= 16 {
        return true; // dead store
    }
    let r1min = if form == "grd" { 0 } else { -c };
    let r1max = 15 - c;
    r1min >= 0 && (r1max + off + w) <= 64
}

#[test]
fn negative_offset_denominator_and_zero_divergence() {
    let (norm, out) = run_diff(NEG, "denom");
    assert_eq!(norm.records.len(), 120, "the full enumerated negative-offset family");
    eprintln!(
        "T1-2 tnum_bounds_checked = {}, reg32_checked = {}, finding_count = {}",
        out.summary.tnum_bounds_checked, out.summary.reg32_checked, out.summary.finding_count
    );
    assert!(
        out.summary.tnum_bounds_checked > 200,
        "must exercise tnum-vs-bounds on the shaped offset and pointer var_off; got {}",
        out.summary.tnum_bounds_checked
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn decision_is_a_pure_function_of_the_store_path_offset_range() {
    assert_eq!(NEG.matches("decision=accept").count(), 60, "accepted");
    assert_eq!(NEG.matches("decision=reject").count(), 60, "rejected");
    for (label, accepted) in program_decisions() {
        let (form, c, off, w) = decode(&label);
        let expect = predict_accept(&form, c, off, w);
        assert_eq!(
            accepted, expect,
            "{label}: predicted accept={expect} but verifier said {accepted}"
        );
    }
}

#[test]
fn no_negative_capable_store_is_accepted_and_the_guard_rescues() {
    // The core soundness statement of T1-2.
    let mut raw_acc = 0;
    let mut grd_acc = 0;
    for (label, accepted) in program_decisions() {
        let (form, c, _, _) = decode(&label);
        if !accepted { continue; }
        if form == "raw" {
            raw_acc += 1;
            // Every accepted raw program has a provably non-negative offset (C==0).
            assert_eq!(c, 0, "{label}: a raw program with a negative-capable offset was ACCEPTED");
        } else {
            grd_acc += 1;
        }
    }
    assert_eq!(raw_acc, 4, "raw accepts (only the C==0, in-bounds cases)");
    assert_eq!(grd_acc, 56, "grd accepts (the signed guard re-derives smin>=0)");
    // The smin lower-bound check is actually exercised and enforced, not vacuously absent.
    assert!(
        NEG.contains("min value is negative"),
        "the negative-min lower-bound path must be reached and reported"
    );
}

#[test]
fn negative_offset_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(NEG, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the negative-offset corpus");
    let non_console_notes = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console_notes, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(NEG, "labels");
    let labels: Vec<&str> = norm.records.iter()
        .filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 120, "every record carries its label");
    assert!(labels.contains(&"genptrneg#raw.C0.o0.w1#000"));
    assert!(labels.contains(&"genptrneg#grd.C64.o48.w4#119"));
    let mut sorted = labels.clone();
    sorted.sort_unstable(); sorted.dedup();
    assert_eq!(sorted.len(), 120, "no two programs share a label");
}
