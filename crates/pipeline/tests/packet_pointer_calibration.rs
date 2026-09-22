//! Packet-pointer family (OI-9 next increment: PTR_TO_PACKET bounds).
//!
//! The pointer-arith family used a PTR_TO_MAP_VALUE, whose bound the verifier KNOWS
//! (value_size). A packet pointer is the other kind: the verifier does not know where
//! the packet ends, so the PROGRAM must prove the bound with its own
//! `if (data + N > data_end)` compare and the verifier statically records that proof
//! as a per-pointer `range` (find_good_pkt_pointers). Nothing is runtime -- the
//! harness only loads, and the decision is a pure function of the instruction stream,
//! so the deterministic enumeration and denominator carry over. Loaded as SCHED_CLS
//! (socket_filter forbids direct packet access). Measured 2026-09-03, pinned here.
//!
//! Result: 242 programs, 49 accepted / 193 rejected (184 EACCES + 9 EINVAL --
//! the same nine signed-compare indices as the map-value family, i.e. a property of
//! the scalar shaping, not the pointer type). tnum_bounds_checked = 1254 (scalar
//! offset AND the pkt pointer's own var_off), 0 divergences, 0 parser blind-spots;
//! the one parse note is an OI-10 console-interleave repair. The range mechanism is
//! visible in the log: `r=0` before the compare, `r=16` after it. Rejections are the
//! MAX_PACKET_OFF guard ("outside of the object of size 0" when umax >> 0xffff).

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const PKT: &str = include_str!("fixtures/volume/gen-pkt-242.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-pkt-{}-{}", std::process::id(), tag));
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
fn packet_pointer_exercises_the_intrinsic_leg_on_scalars_and_pkt_offsets() {
    let (norm, out) = run_diff(PKT, "denom");
    assert_eq!(norm.records.len(), 242, "the full enumerated packet-pointer family");
    assert!(
        out.summary.tnum_bounds_checked > 1200,
        "packet-pointer must exercise tnum-vs-bounds (incl. the pkt var_off); got {}",
        out.summary.tnum_bounds_checked
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn packet_pointer_is_a_genuine_accept_reject_surface_on_the_range_guard() {
    // Acceptance ~ whether the shaping bounds the offset umax within MAX_PACKET_OFF so
    // a range can be recorded. Pinned so a change in packet-bounds behaviour (kernel
    // regression or generator change) forces a re-measure.
    assert_eq!(PKT.matches("decision=accept").count(), 49, "accepted (range recordable)");
    assert_eq!(PKT.matches("decision=reject").count(), 193, "rejected (no range / OOB)");
    let (_, out) = run_diff(PKT, "axis");
    assert_eq!(out.summary.reg32_checked, 0, "same-width per program");
}

#[test]
fn the_static_range_mechanism_is_captured_in_the_log() {
    // The whole design rests on the bound being proven STATICALLY by the program's own
    // compare, not on any runtime data_end. Pin the evidence: the data_end type and a
    // range that goes from 0 to a proven value across the compare.
    assert!(PKT.contains("R3=pkt_end()"), "data_end must be typed pkt_end");
    assert!(PKT.contains("r=0,"), "packet ptr starts with no proven range");
    assert!(PKT.contains("r=16,"), "the `if r5 > r3` compare must record a range");
    // And the reject side is the MAX_PACKET_OFF guard, not something else.
    assert!(PKT.contains("outside of the object of size 0"), "range-guard rejection text");
}

#[test]
fn packet_pointer_opens_no_parser_blind_spot() {
    // `pkt(id=..,r=..,var_off=..)`, `pkt_end()`, and SCHED_CLS were never printed by
    // the scalar or map-value families. First run: they must not open a blind spot.
    let (norm, _) = run_diff(PKT, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the packet-pointer corpus");
    let non_console_notes = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console_notes, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(PKT, "labels");
    let labels: Vec<&str> = norm.records.iter()
        .filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 242, "every record carries its label");
    assert!(labels.contains(&"genpkt#w64.and.jeq#000"));
    assert!(labels.contains(&"genpkt#w32.mod.jset#241"));
    let mut sorted = labels.clone();
    sorted.sort_unstable(); sorted.dedup();
    assert_eq!(sorted.len(), 242, "no two programs share a label");
}
