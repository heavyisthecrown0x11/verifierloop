//! Runtime memory-safety oracle for map-value STORES (--gen-rtw) — the v2 extension
//! of the runtime ground-truth oracle (0036) to the actual memory-safety property.
//!
//! Each program reads a fully attacker-controlled 32-bit input, shapes it into an
//! offset the verifier proves in-bounds, and STORES a sentinel byte through a
//! map-value pointer at that offset. The harness zeroes the target map, runs the
//! program via BPF_PROG_TEST_RUN over a 12-value input sweep, reads the map back,
//! and records where the sentinel landed (`store_off`) — or `none` if it was ABSENT
//! (the store escaped the readable value into kernel memory). An accepted store is
//! CLAIMED in-bounds, so on a sound kernel the sentinel must always land inside the
//! value: `store_off=none` would be an OOB write the verifier accepted. This needs
//! NO bound parsing — it is the direct memory-safety check, the surface where real
//! exploitable verifier bugs live. Shapes: and / andadd (in-bounds, ACCEPT,
//! runtime-checked) + over (over-wide mask, the verifier must REJECT — a control).
//! Captured in the bpf-next VM (kernel 5e289c5a), 2026-09-04.
//!
//! Result: 9 programs, 7 accept / 2 reject. The 2 rejects are the over-wide masks
//! (off up to 127 > value_size-1) — the verifier's static bound holds. 7 accepts x
//! 12 inputs = runtime_writes_checked=84, finding_count=0: every accepted store
//! landed inside the map value. The oracle is shown non-vacuous by a planted-escape
//! test (a `store_off=none` sample DOES fire runtime_oob_write).

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const RTW: &str = include_str!("fixtures/volume/gen-rtw-9.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-rtw-{}-{}", std::process::id(), tag));
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

/// Rebuild the fixture with one program's store_off (for a given input) replaced —
/// used to plant an OOB write the real kernel never produced.
fn with_mutated_sample(label: &str, input_hex: &str, new_store_off: &str) -> String {
    let mut out = String::new();
    for block in RTW.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        if blabel == label {
            for line in block.lines() {
                if line.starts_with(&format!("RUNTIME input={input_hex} ")) {
                    out.push_str(&format!("RUNTIME input={input_hex} store_off={new_store_off}"));
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
fn every_accepted_store_landed_in_bounds() {
    // The numbers the family lives by: runtime_writes_checked > 0 (accepted stores
    // were actually executed and their landing checked) and finding_count == 0 (no
    // store escaped the map value).
    let (norm, out) = run_diff(RTW, "base");
    eprintln!(
        "RTW records={} writes_checked={} finding_count={}",
        norm.records.len(), out.summary.runtime_writes_checked, out.summary.finding_count
    );
    assert_eq!(norm.records.len(), 9);
    assert_eq!(RTW.matches("decision=accept").count(), 7, "7 in-bounds programs accept");
    assert_eq!(RTW.matches("decision=reject").count(), 2, "2 over-wide programs reject (control)");
    assert_eq!(out.summary.runtime_writes_checked, 84, "7 accepts x 12 inputs = 84 store samples");
    assert_eq!(out.summary.finding_count, 0, "a store escaped the map value: {:?}", out.findings);
    // No sample was ever absent on this kernel.
    assert_eq!(RTW.matches("store_off=none").count(), 0, "no OOB store on a sound kernel");
}

#[test]
fn the_oracle_has_teeth_a_planted_oob_write_fires() {
    // Non-vacuity: if an accepted store's sentinel is ABSENT (store_off=none), the
    // oracle MUST fire an OOB-write finding. Plant one in genrtw#and#003.
    let mutated = with_mutated_sample("genrtw#and#003", "0x00000000", "none");
    let (_, out) = run_diff(&mutated, "teeth");
    let viols: Vec<_> = out.findings.iter()
        .filter(|f| f.kind == "runtime_oob_write").collect();
    assert_eq!(viols.len(), 1, "the planted OOB write must fire exactly once: {:?}", out.findings);
    assert_eq!(out.summary.finding_count, 1);
    // The denominator is unchanged — an OOB sample is still a checked sample.
    assert_eq!(out.summary.runtime_writes_checked, 84);
}

#[test]
fn the_reject_control_draws_the_static_bound() {
    // The over-wide masks (off up to 127) must be rejected at load time — the
    // verifier's static in-bounds check — so they never run and are never checked.
    let (norm, _) = run_diff(RTW, "reject");
    for rec in &norm.records {
        let label = rec.source_label.as_deref().unwrap_or("");
        if label.contains("#over#") {
            assert!(
                matches!(rec.core.verifier_decision,
                         metrics::core::VerifierDecision::Reject { .. }),
                "{label}: an over-wide store offset must be rejected"
            );
            assert!(rec.core.runtime_samples.is_empty(), "{label}: a rejected program must not run");
        }
    }
}

#[test]
fn runtime_write_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(RTW, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the runtime-write corpus");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(RTW, "labels");
    let labels: Vec<&str> = norm.records.iter().filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 9);
    assert!(labels.contains(&"genrtw#and#000"));
    assert!(labels.contains(&"genrtw#over#008"));
    let mut s = labels.clone(); s.sort_unstable(); s.dedup();
    assert_eq!(s.len(), 9, "no two programs share a label");
}
