//! T3 — packet-write runtime memory-safety oracle (--gen-pktw), the PACKET analog of
//! the map-value store oracle (--gen-rtw 0037 / --gen-rtw2 0038).
//!
//! The fixture is a REAL VM capture (`scripts/run-pktw.sh`, self-built bpf-next
//! 5e289c5a under KVM, 2026-09-04). The counts were DERIVED from the range predicate
//! `off + W <= M` (M = PKTW_M = 32) BEFORE the run and the capture then MATCHED them
//! exactly — 8 accept / 4 reject, the accept boundary at off = M-W for every width
//! (w1 o31 accept / o32 reject, w2 o30/o31, w4 o28/o29, w8 o24/o25). Had the boundary
//! come out anywhere else, that discrepancy would itself have been the finding to
//! investigate, not a test to silently "fix" — see [[store-location-desync-is-the-hunt]].
//!
//! The store goes through a PTR_TO_PACKET whose bound the verifier does NOT know
//! statically — the PROGRAM proves it with its own `data + M > data_end` compare and the
//! verifier tracks the resulting `range` (find_good_pkt_pointers). The runtime packet is
//! sized to EXACTLY M, so data_end lands at byte M; the compare `data+M > data_end` is
//! false (M <= M) and the accepted store executes. On a sound kernel every accepted store
//! has off + W <= M, so all W sentinel bytes land in [0, M) and are copied back in
//! data_out (store_len == store_size). A verifier that accepted off + W = M + 1 (a range
//! off-by-one) would put the store's last byte AT data_end — in skb tailroom, which
//! test_run never copies back — so the run is truncated (store_len < store_size) or
//! absent: exactly the runtime_oob_write the SHARED diff predicate (check_runtime_write_
//! safety) already fires on. The parser, predicate, and metrics are reused UNCHANGED from
//! --gen-rtw2; only the bytes' provenance differs (packet read-back vs map read-back).
//!
//! Shape (SCHED_CLS, closed `>` idiom): `r2=data; r3=data_end; r5=r2; r5+=32;
//! if (r5 > r3) skip; *(uW*)(r2 + off) = -1`. Three arms per width W in {1,2,4,8}: an
//! interior accept at off 0, a boundary accept at off = M-W (ends exactly at byte M-1),
//! and the off-by-one at off = M-W+1 (last byte would be AT data_end -> REJECT).
//!
//! Measured: 12 programs, 8 accept / 4 reject, runtime_writes_checked = 8 (each accept
//! runs once, input = packet size 0x20), finding_count = 0 — every accepted packet store
//! wrote its FULL width inside [0, M), the tightest being w8 at off 24 (run of 8 ending
//! exactly at byte 32 = data_end). Non-vacuity: a planted absent write (store_off=none)
//! AND a planted truncated run (store_len<store_size), both injected into THIS real
//! capture, each fire runtime_oob_write exactly once.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const PKTW: &str = include_str!("fixtures/volume/gen-pktw-12.log");
const PKT_SIZE_HEX: &str = "0x00000020"; // runtime packet size = PKTW_M = 32

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-pktw-{}-{}", std::process::id(), tag));
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

/// Rebuild the fixture with one program's RUNTIME line (for a given input) replaced by
/// `new_tail` — used to plant a packet store escape the real kernel never produced.
fn with_mutated_sample(label: &str, input_hex: &str, new_tail: &str) -> String {
    let mut out = String::new();
    for block in PKTW.split("===PROG ").skip(1) {
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
fn every_accepted_packet_store_landed_fully_in_bounds() {
    let (norm, out) = run_diff(PKTW, "base");
    eprintln!(
        "PKTW records={} writes_checked={} finding_count={}",
        norm.records.len(), out.summary.runtime_writes_checked, out.summary.finding_count
    );
    assert_eq!(norm.records.len(), 12);
    assert_eq!(PKTW.matches("decision=accept").count(), 8, "8 in-range programs accept");
    assert_eq!(PKTW.matches("decision=reject").count(), 4, "4 off-by-one programs reject");
    assert_eq!(out.summary.runtime_writes_checked, 8, "8 accepts x 1 run = 8 store samples");
    assert_eq!(out.summary.finding_count, 0, "a packet store escaped the packet: {:?}", out.findings);
    assert_eq!(PKTW.matches("store_off=none").count(), 0, "no absent store on a sound kernel");
    for rec in &norm.records {
        for smp in &rec.core.runtime_samples {
            if let (Some(l), Some(s)) = (smp.store_len, smp.store_size) {
                assert_eq!(l, s, "a sound accepted packet store must write its full width");
            }
        }
    }
}

#[test]
fn the_oracle_has_teeth_a_planted_absent_write_fires() {
    // A totally absent sentinel (store escaped past data_end into tailroom) must fire.
    let mutated = with_mutated_sample(
        "genpktw#w1.o0#000", PKT_SIZE_HEX, "store_off=none store_len=0 store_size=1");
    let (_, out) = run_diff(&mutated, "teeth-absent");
    let viols: Vec<_> = out.findings.iter().filter(|f| f.kind == "runtime_oob_write").collect();
    assert_eq!(viols.len(), 1, "the planted absent write must fire exactly once: {:?}", out.findings);
    assert_eq!(out.summary.finding_count, 1);
    assert_eq!(out.summary.runtime_writes_checked, 8, "an OOB sample is still a checked sample");
}

#[test]
fn the_oracle_has_teeth_a_planted_truncated_run_fires() {
    // A store whose BASE is in-bounds but whose run is SHORT (last byte(s) crossed
    // data_end into tailroom) is a PARTIAL OOB packet write and must fire. Plant a
    // 5-of-8 run on the tightest accept boundary, w8.o24#010 (base off=24, full width
    // ends at byte 32 = data_end).
    let mutated = with_mutated_sample(
        "genpktw#w8.o24#010", PKT_SIZE_HEX, "store_off=24 store_len=5 store_size=8");
    let (_, out) = run_diff(&mutated, "teeth-trunc");
    let viols: Vec<_> = out.findings.iter().filter(|f| f.kind == "runtime_oob_write").collect();
    assert_eq!(viols.len(), 1, "the planted truncated run must fire exactly once: {:?}", out.findings);
    assert_eq!(out.summary.finding_count, 1);
    assert!(viols[0].observed.contains("run 5 of 8"), "finding must describe the short run: {}", viols[0].observed);
    assert_eq!(out.summary.runtime_writes_checked, 8, "a truncated sample is still a checked sample");
}

#[test]
fn the_boundary_accept_writes_the_full_width() {
    // w8.o24#010 is the tightest ACCEPT: an 8-byte packet store based at off=24 ends
    // exactly at byte M-1=31 (24+8=32=M). On a sound kernel its whole run lands inside,
    // so the sample must show store_off=24, store_len=8, store_size=8.
    let (norm, _) = run_diff(PKTW, "boundary");
    let rec = norm.records.iter()
        .find(|r| r.source_label.as_deref() == Some("genpktw#w8.o24#010"))
        .expect("w8.o24#010 present");
    assert!(!rec.core.runtime_samples.is_empty(), "the boundary accept must have run");
    for smp in &rec.core.runtime_samples {
        assert_eq!(smp.store_off, Some(24), "8-byte store based at M-W=24");
        assert_eq!(smp.store_len, Some(8), "the full 8-byte run landed inside");
        assert_eq!(smp.store_size, Some(8));
    }
}

#[test]
fn the_reject_control_draws_the_off_by_one() {
    // The one-past programs must be rejected at load time (the verifier's static range
    // check `off+W <= range`), so they never run and are never checked. This is what
    // makes the accepts a genuine decision surface, not a walkover.
    let (norm, _) = run_diff(PKTW, "reject");
    let mut rejects = 0;
    for rec in &norm.records {
        if matches!(rec.core.verifier_decision, metrics::core::VerifierDecision::Reject { .. }) {
            rejects += 1;
            let label = rec.source_label.as_deref().unwrap_or("");
            assert!(rec.core.runtime_samples.is_empty(), "{label}: a rejected program must not run");
        }
    }
    assert_eq!(rejects, 4, "4 off-by-one programs reject");

    // The exact off-by-one: for each width W, the boundary accept (off=M-W) and the
    // one-past reject (off=M-W+1) must split accept/reject.
    fn decision_of<'a>(norm: &'a normalize::NormalizedMetrics, label: &str) -> &'a metrics::core::VerifierDecision {
        &norm.records.iter().find(|r| r.source_label.as_deref() == Some(label)).unwrap().core.verifier_decision
    }
    for (accept_label, reject_label) in [
        ("genpktw#w1.o31#001", "genpktw#w1.o32#002"),
        ("genpktw#w2.o30#004", "genpktw#w2.o31#005"),
        ("genpktw#w4.o28#007", "genpktw#w4.o29#008"),
        ("genpktw#w8.o24#010", "genpktw#w8.o25#011"),
    ] {
        assert!(matches!(decision_of(&norm, accept_label), metrics::core::VerifierDecision::Accept { .. }),
                "{accept_label}: store ending exactly at data_end-1 must accept");
        assert!(matches!(decision_of(&norm, reject_label), metrics::core::VerifierDecision::Reject { .. }),
                "{reject_label}: store ending one byte past data_end must reject");
    }
}

#[test]
fn packet_write_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(PKTW, "parse");
    let unrecognized = norm.unparsed.iter().filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the packet-write corpus");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(PKTW, "labels");
    let labels: Vec<&str> = norm.records.iter().filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 12);
    assert!(labels.contains(&"genpktw#w1.o0#000"));
    assert!(labels.contains(&"genpktw#w8.o24#010"));
    assert!(labels.contains(&"genpktw#w8.o25#011"));
    let mut s = labels.clone(); s.sort_unstable(); s.dedup();
    assert_eq!(s.len(), 12, "no two programs share a label");
}
