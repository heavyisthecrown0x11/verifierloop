//! T2-2 — multi-byte store-WIDTH memory-safety oracle (--gen-rtw2), the width
//! extension of the runtime memory-safety oracle (--gen-rtw, 0037).
//!
//! The off-by-one a real verifier bug would hit lives in the in-bounds check
//! `off + size <= value_size`, so the axis under test here is the store WIDTH, not
//! just the base offset. Each program stores `size` sentinel bytes (0xFF) through a
//! map-value pointer; the harness zeroes the target map BEFORE EVERY run (the sole
//! 0xFF source is this store, so a stale sentinel can never be miscounted), runs the
//! program via BPF_PROG_TEST_RUN over a 12-value input sweep, reads the map back, and
//! records where the sentinel run started (`store_off`) AND how long it was
//! (`store_len`) against the intended width (`store_size`). An accepted store is
//! CLAIMED in-bounds, so on a sound kernel every one of its `size` bytes must land
//! inside the value: `store_len == store_size`. A truncated run (`store_len <
//! store_size`) is a PARTIAL OOB write — some bytes crossed the value end even though
//! the base did not — and `store_off=none` is a total OOB write. Neither needs any
//! bound parsing; it is the direct memory-safety property.
//!
//! Shapes: (a) and.wN — attacker offset r6 &= MASK, store size N at map_out+r6
//! (accept iff MASK + N <= 64); (b) bndc.wN — a CONST offset baked into the ST insn:
//! off = 64-N ends exactly at the value end (ACCEPT), off = 65-N runs one byte past
//! it (REJECT) — the exact off-by-one control. Captured in the bpf-next VM (kernel
//! 5e289c5a), 2026-09-04.
//!
//! Result: 20 programs, 13 accept / 7 reject. 13 accepts x 12 inputs =
//! runtime_writes_checked=156, finding_count=0: every accepted store landed ENTIRELY
//! inside the value. The 7 rejects are the width overflows (and 0x3f with N>=2, and
//! every bndc off=65-N) — the verifier's static `off+size<=value_size` bound holds.
//! Non-vacuity is shown two ways: a planted absent write (store_off=none) AND a
//! planted truncated run (store_len<store_size) each fire runtime_oob_write.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const RTW2: &str = include_str!("fixtures/volume/gen-rtw2-20.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-rtw2-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (norm, out)
}

/// Rebuild the fixture with one program's RUNTIME line (for a given input) replaced
/// by `new_tail` (everything after `RUNTIME input=<hex> `) — used to plant a store
/// escape the real kernel never produced.
fn with_mutated_sample(label: &str, input_hex: &str, new_tail: &str) -> String {
    let mut out = String::new();
    for block in RTW2.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        if blabel == label {
            for line in block.lines() {
                if line.starts_with(&format!("RUNTIME input={input_hex} ")) {
                    out.push_str(&format!("RUNTIME input={input_hex} {new_tail}"));
                } else {
                    out.push_str(line);
                }
                out.push('\n');
            }
        } else {
            out.push_str(block);
        }
    }
    out
}

#[test]
fn every_accepted_store_landed_fully_in_bounds() {
    // The numbers the family lives by: runtime_writes_checked > 0 (accepted stores
    // were executed and their full landing checked) and finding_count == 0 (no store
    // — not even one byte of a multi-byte store — escaped the value).
    let (norm, out) = run_diff(RTW2, "base");
    eprintln!(
        "RTW2 records={} writes_checked={} finding_count={}",
        norm.records.len(), out.summary.runtime_writes_checked, out.summary.finding_count
    );
    assert_eq!(norm.records.len(), 20);
    assert_eq!(RTW2.matches("decision=accept").count(), 13, "13 in-bounds programs accept");
    assert_eq!(RTW2.matches("decision=reject").count(), 7, "7 width-overflow programs reject");
    assert_eq!(out.summary.runtime_writes_checked, 156, "13 accepts x 12 inputs = 156 store samples");
    assert_eq!(out.summary.finding_count, 0, "a store escaped the map value: {:?}", out.findings);
    assert_eq!(RTW2.matches("store_off=none").count(), 0, "no absent store on a sound kernel");
    // Every accepted sample wrote its full width — the property the pipeline enforces.
    for rec in &norm.records {
        for smp in &rec.core.runtime_samples {
            if let (Some(l), Some(s)) = (smp.store_len, smp.store_size) {
                assert_eq!(l, s, "a sound accepted store must write its full width");
            }
        }
    }
}

#[test]
fn the_oracle_has_teeth_a_planted_absent_write_fires() {
    // Non-vacuity #1 (inherited from --gen-rtw): a totally absent sentinel
    // (store_off=none) must fire an OOB-write finding.
    let mutated = with_mutated_sample("genrtw2#and.w1#000", "0x00000000", "store_off=none store_len=0 store_size=1");
    let (_, out) = run_diff(&mutated, "teeth-absent");
    let viols: Vec<_> = out.findings.iter().filter(|f| f.kind == "runtime_oob_write").collect();
    assert_eq!(viols.len(), 1, "the planted absent write must fire exactly once: {:?}", out.findings);
    assert_eq!(out.summary.finding_count, 1);
    assert_eq!(out.summary.runtime_writes_checked, 156, "an OOB sample is still a checked sample");
}

#[test]
fn the_oracle_has_teeth_a_planted_truncated_run_fires() {
    // Non-vacuity #2 (the T2-2-specific property single-byte --gen-rtw could not
    // express): a store whose BASE is in-bounds but whose run is SHORT (store_len <
    // store_size) is a PARTIAL OOB write and must fire. Plant a 5-of-8 run on the
    // tightest accept boundary, bndc.w8#018 (base off=56, full width ends at 64).
    let mutated = with_mutated_sample("genrtw2#bndc.w8#018", "0x00000000", "store_off=56 store_len=5 store_size=8");
    let (_, out) = run_diff(&mutated, "teeth-trunc");
    let viols: Vec<_> = out.findings.iter().filter(|f| f.kind == "runtime_oob_write").collect();
    assert_eq!(viols.len(), 1, "the planted truncated run must fire exactly once: {:?}", out.findings);
    assert_eq!(out.summary.finding_count, 1);
    // The finding names the partial escape, not an absence.
    assert!(viols[0].observed.contains("run 5 of 8"), "finding must describe the short run: {}", viols[0].observed);
    assert_eq!(out.summary.runtime_writes_checked, 156, "a truncated sample is still a checked sample");
}

#[test]
fn the_boundary_accept_writes_the_full_width() {
    // bndc.w8#018 is the tightest ACCEPT: an 8-byte store based at off=56 ends
    // exactly at the value end (56+8=64). On a sound kernel its whole run lands
    // inside, so every sample must show store_off=56, store_len=8, store_size=8.
    let (norm, _) = run_diff(RTW2, "boundary");
    let rec = norm.records.iter()
        .find(|r| r.source_label.as_deref() == Some("genrtw2#bndc.w8#018"))
        .expect("bndc.w8#018 present");
    assert!(!rec.core.runtime_samples.is_empty(), "the boundary accept must have run");
    for smp in &rec.core.runtime_samples {
        assert_eq!(smp.store_off, Some(56), "8-byte store based at the exact end");
        assert_eq!(smp.store_len, Some(8), "the full 8-byte run landed inside");
        assert_eq!(smp.store_size, Some(8));
    }
}

#[test]
fn the_reject_control_draws_the_off_by_one() {
    // The width overflows must be rejected at load time (the verifier's static
    // `off+size<=value_size` check), so they never run and are never checked. This
    // is what makes the accepts a genuine decision surface, not a walkover.
    let (norm, _) = run_diff(RTW2, "reject");
    let mut rejects = 0;
    for rec in &norm.records {
        if matches!(rec.core.verifier_decision, metrics::core::VerifierDecision::Reject { .. }) {
            rejects += 1;
            let label = rec.source_label.as_deref().unwrap_or("");
            assert!(rec.core.runtime_samples.is_empty(), "{label}: a rejected program must not run");
        }
    }
    assert_eq!(rejects, 7, "7 width-overflow programs reject");

    // The exact off-by-one: for each width N, the bndc pair (off=64-N accept,
    // off=65-N reject) must split accept/reject. Labels are emitted in that order.
    fn decision_of<'a>(norm: &'a normalize::NormalizedMetrics, label: &str) -> &'a metrics::core::VerifierDecision {
        &norm.records.iter().find(|r| r.source_label.as_deref() == Some(label)).unwrap().core.verifier_decision
    }
    for (accept_label, reject_label) in [
        ("genrtw2#bndc.w1#012", "genrtw2#bndc.w1#013"),
        ("genrtw2#bndc.w2#014", "genrtw2#bndc.w2#015"),
        ("genrtw2#bndc.w4#016", "genrtw2#bndc.w4#017"),
        ("genrtw2#bndc.w8#018", "genrtw2#bndc.w8#019"),
    ] {
        assert!(matches!(decision_of(&norm, accept_label), metrics::core::VerifierDecision::Accept { .. }),
                "{accept_label}: store ending exactly at the value end must accept");
        assert!(matches!(decision_of(&norm, reject_label), metrics::core::VerifierDecision::Reject { .. }),
                "{reject_label}: store ending one byte past the value end must reject");
    }
}

#[test]
fn runtime_write2_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(RTW2, "parse");
    let unrecognized = norm.unparsed.iter().filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the runtime-write2 corpus");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(RTW2, "labels");
    let labels: Vec<&str> = norm.records.iter().filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 20);
    assert!(labels.contains(&"genrtw2#and.w1#000"));
    assert!(labels.contains(&"genrtw2#and.w8#003"));
    assert!(labels.contains(&"genrtw2#bndc.w8#019"));
    let mut s = labels.clone(); s.sort_unstable(); s.dedup();
    assert_eq!(s.len(), 20, "no two programs share a label");
}
