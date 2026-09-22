//! 32<->64 x pointer-offset family (T1-1a) — the upper-unknown soundness probe.
//!
//! The setup was decided by measurement (the --probe-t1 three-claim probe): a 32-bit-
//! shaped offset zero-extends (views coincide, reg32=0, the 0025 trap); 32-bit ALU on a
//! pointer is prohibited (Option B); only the "hi" construction reaches the 32-tight/
//! 64-loose surface. Two arms, value_size=64:
//!   hi  — upper 32 unknown + a 32-bit compare narrowing ONLY the low half. Its 64-bit
//!         smin=S64_MIN, so adjust_ptr_min_max_vals (verifier.c:14665) MUST reject at the
//!         pointer add. reg32>0 proves the independent 32-view formed; any ACCEPT = bug.
//!   bnd — 32-bit AND zero-extends to a genuinely 64-bounded offset (reg32=0), accepted
//!         when it fits: the control that the verifier is not over-rejecting.
//! Grid: hi{cons(2) x cmp(5) x K(4)} = 40 + bnd{mask(3) x reach(4)} = 12 -> 52 programs,
//! ~3:1 hi:bnd. Captured in the bpf-next VM (kernel 5e289c5a), 2026-09-03.
//!
//! Result: 8 accept / 44 reject. hi = 0 accept / 40 reject (mutual exclusivity: reg32>0
//! <=> upper-unknown <=> reject; no hi program can be accepted on a sound verifier, and
//! none was). bnd = 8 accept / 4 reject (the 4 are correct upper-bound rejects). Every hi
//! reject is "unbounded min value" from adjust_ptr_min_max_vals. reg32_checked > 0 and it
//! comes ENTIRELY from the hi arm (bnd arm reg32=0), 0 divergences, 0 parser blind-spots.
//! Signature: reg32_checked>0 with 0 wrongly-accepted hi programs — NOT an accept/reject
//! balance. The discriminating "which view / sync" test is T1-1b (a new oracle arm).

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

const HI: &str = include_str!("fixtures/volume/gen-hi-52.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-hi-{}-{}", std::process::id(), tag));
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

/// Reassemble only the program blocks whose label contains `arm` ("#hi." or "#bnd.").
fn subset(arm: &str) -> String {
    let mut s = String::new();
    for block in HI.split("===PROG ").skip(1) {
        let label = block.split_whitespace().next().unwrap();
        if label.contains(arm) {
            s.push_str("===PROG ");
            s.push_str(block);
        }
    }
    s
}

fn program_decisions() -> Vec<(String, bool)> {
    HI.split("===PROG ").skip(1).map(|block| {
        let label = block.split_whitespace().next().unwrap().to_string();
        let acc = block.lines().find(|l| l.starts_with("RESULT "))
            .map(|l| l.contains("decision=accept")).unwrap();
        (label, acc)
    }).collect()
}

#[test]
fn the_gate_reg32_checked_comes_off_zero_and_only_from_the_hi_arm() {
    // The single number the family lives or dies by: reg32_checked > 0. And it must come
    // from the hi arm (the 32-tight/64-loose state), not the bounded arm (which zero-extends).
    let (_, all) = run_diff(HI, "all");
    let (_, hi) = run_diff(&subset("#hi."), "hi");
    let (_, bnd) = run_diff(&subset("#bnd."), "bnd");
    eprintln!(
        "T1-1a reg32_checked: all={} hi={} bnd={} | finding_count={}",
        all.summary.reg32_checked, hi.summary.reg32_checked, bnd.summary.reg32_checked,
        all.summary.finding_count
    );
    assert!(hi.summary.reg32_checked > 0, "the hi arm must lift reg32_checked off zero");
    assert_eq!(bnd.summary.reg32_checked, 0, "the bounded arm zero-extends -> reg32 must stay 0");
    assert_eq!(all.summary.finding_count, 0, "{:?}", all.findings);
}

#[test]
fn the_hi_arm_is_all_reject_and_never_accepts_an_upper_unknown_offset() {
    // The soundness statement. An accepted hi program would be an OOB-write accept.
    for (label, accepted) in program_decisions() {
        if label.contains("#hi.") {
            assert!(!accepted, "{label}: an upper-unknown offset was ACCEPTED for a pointer (bug)");
        }
    }
    assert_eq!(HI.matches("decision=accept").count(), 8, "only the bounded arm accepts");
    // The reject is the pointer-add sane-offset check, not something earlier.
    assert!(HI.contains("unbounded min value is not allowed"),
            "hi rejects must be the adjust_ptr_min_max_vals sane-offset check");
}

#[test]
fn the_bounded_control_accepts_when_the_64bounded_offset_fits() {
    // Not over-rejecting: a 32-bit AND zero-extends to [0,mask]; accept iff mask+off+W<=64.
    for (label, accepted) in program_decisions() {
        if !label.contains("#bnd.") { continue; }
        let body = label.trim_start_matches("genhi#bnd.");
        let body = &body[..body.find('#').unwrap()];
        let mut it = body.split('.');
        let mask: i64 = it.next().unwrap().trim_start_matches('m').parse().unwrap();
        let off: i64 = it.next().unwrap().trim_start_matches('o').parse().unwrap();
        let w: i64 = it.next().unwrap().trim_start_matches('w').parse().unwrap();
        let expect = mask + off + w <= 64;
        assert_eq!(accepted, expect, "{label}: mask+off+W={} vs 64", mask + off + w);
    }
}

#[test]
fn hi_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(HI, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the hi corpus");
    let non_console = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(HI, "labels");
    let labels: Vec<&str> = norm.records.iter().filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 52);
    assert!(labels.contains(&"genhi#hi.so.lt.K8#000"));
    assert!(labels.contains(&"genhi#bnd.m63.o48.w1#051"));
    let mut s = labels.clone(); s.sort_unstable(); s.dedup();
    assert_eq!(s.len(), 52, "no two programs share a label");
}
