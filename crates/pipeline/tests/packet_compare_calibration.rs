//! Packet data_end compare-operator sweep (T1-3) — the range_right_open edge.
//!
//! The --gen-pkt family held the program's own bounds check fixed at `>` (BPF_JGT),
//! the canonical idiom. This sweep varies ONLY that range-setting compare and pins the
//! offset shaping to a small known scalar, so the accept/reject decision is a pure
//! function of the range machinery in `find_good_pkt_pointers`. Two orthogonal axes:
//!
//!   * closed vs right-open — {gt,lt} prove `r5 <= data_end`, {ge,le} prove `r5 < data_end`.
//!   * operand-order symmetry — gt (`r5 > end`) and lt (`end < r5`) are the SAME OOB
//!     condition written two ways; ge and le likewise. The verifier must not care.
//!
//! Grid: form(gt,ge,lt,le) x headroom M(1..5) x store-offset off(0..3) x width W(1,2,4)
//! = 240 programs, SCHED_CLS. Captured in the bpf-next VM (kernel 5e289c5a), 2026-09-03.
//!
//! Result: 128 accept / 112 reject. Per form: gt=27, ge=37, lt=27, le=37.
//!   - SYMMETRY holds exactly: gt==lt and ge==le. find_good_pkt_pointers is operand-order
//!     symmetric.
//!   - The closed and right-open boundaries differ by EXACTLY ONE BYTE: every one of the
//!     240 decisions matches `accept iff off+W <= M` (closed) / `<= M+1` (right-open).
//!     No off-by-one, no drift — the verifier proves precisely what the program checked.
//!   - tnum_bounds_checked = 720, reg32_checked = 0, 0 divergences, 0 parser blind-spots.

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const SWEEP: &str = include_str!("fixtures/volume/gen-pktcmp-240.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-pktcmp-{}-{}", std::process::id(), tag));
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

/// Decode a `genpc#<form>.M<m>.o<off>.w<W>#<idx>` label into (form, M, off, W).
fn decode(label: &str) -> (String, i64, i64, i64) {
    let body = label.trim_start_matches("genpc#");
    let body = &body[..body.find('#').unwrap()];
    let mut it = body.split('.');
    let form = it.next().unwrap().to_string();
    let m = it.next().unwrap().trim_start_matches('M').parse().unwrap();
    let off = it.next().unwrap().trim_start_matches('o').parse().unwrap();
    let w = it.next().unwrap().trim_start_matches('w').parse().unwrap();
    (form, m, off, w)
}

/// (label, accepted) for every program block in the raw capture.
fn program_decisions() -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for block in SWEEP.split("===PROG ").skip(1) {
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

#[test]
fn sweep_denominator_and_zero_divergence() {
    let (norm, out) = run_diff(SWEEP, "denom");
    assert_eq!(norm.records.len(), 240, "the full enumerated compare-op sweep");
    eprintln!(
        "T1-3 tnum_bounds_checked = {}, reg32_checked = {}, finding_count = {}",
        out.summary.tnum_bounds_checked, out.summary.reg32_checked, out.summary.finding_count
    );
    // Lower than the alu-x-cmp families (2453/2050/...): this sweep PINS the offset
    // shaping to a single `&= 7`, trading scalar variety for a clean isolation of the
    // range machinery. Measured 720; loose floor so a re-measure only fails on collapse.
    assert!(
        out.summary.tnum_bounds_checked > 700,
        "the sweep must exercise tnum-vs-bounds on the bounded offset and pkt var_off; got {}",
        out.summary.tnum_bounds_checked
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn accept_reject_split_and_per_form_symmetry() {
    // Pinned so any change in packet-bounds behaviour (kernel regression or generator
    // change) forces a re-measure.
    assert_eq!(SWEEP.matches("decision=accept").count(), 128, "accepted");
    assert_eq!(SWEEP.matches("decision=reject").count(), 112, "rejected");

    let mut acc = std::collections::BTreeMap::new();
    for (label, accepted) in program_decisions() {
        let (form, _, _, _) = decode(&label);
        let e = acc.entry(form).or_insert((0, 0));
        e.1 += 1;
        if accepted { e.0 += 1; }
    }
    assert_eq!(acc["gt"], (27, 60));
    assert_eq!(acc["ge"], (37, 60));
    assert_eq!(acc["lt"], (27, 60));
    assert_eq!(acc["le"], (37, 60));
    // Operand-order symmetry: the same OOB condition written two ways must decide alike.
    assert_eq!(acc["gt"].0, acc["lt"].0, "gt vs lt: operand-order symmetry (closed)");
    assert_eq!(acc["ge"].0, acc["le"].0, "ge vs le: operand-order symmetry (right-open)");
}

#[test]
fn closed_and_open_boundaries_differ_by_exactly_one_byte() {
    // The whole point of T1-3. Closed forms prove `r5 <= end` -> recorded range = M;
    // right-open forms prove `r5 < end` -> range = M+1. A store reaching byte off+W is
    // accepted iff off+W <= range. Every one of the 240 decisions must match this, with
    // the closed/open boundary shifted by exactly one byte and NOT a hair more.
    for (label, accepted) in program_decisions() {
        let (form, m, off, w) = decode(&label);
        let reach = off + w;
        let range = if form == "gt" || form == "lt" { m } else { m + 1 };
        let expect = reach <= range;
        assert_eq!(
            accepted, expect,
            "{label}: reach(off+W)={reach} vs range={range} (form {form}, M={m}) \
             expected accept={expect} but verifier said {accepted}"
        );
    }
}

#[test]
fn sweep_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(SWEEP, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the compare-op sweep");
    let non_console_notes = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console_notes, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(SWEEP, "labels");
    let labels: Vec<&str> = norm.records.iter()
        .filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 240, "every record carries its label");
    assert!(labels.contains(&"genpc#gt.M1.o0.w1#000"));
    assert!(labels.contains(&"genpc#le.M5.o3.w4#239"));
    let mut sorted = labels.clone();
    sorted.sort_unstable(); sorted.dedup();
    assert_eq!(sorted.len(), 240, "no two programs share a label");
}
