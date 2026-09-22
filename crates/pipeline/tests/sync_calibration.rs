//! 32<->64 sync-fragile family (T1-1b) — the CVE-2020-8835 class regression guard.
//!
//! This is the DISCRIMINATING half of T1-1 (the soundness half is T1-1a, --gen-ptr-hi).
//! It drives the verifier into the exact register state CVE-2020-8835 corrupted: a
//! legitimately-64-bounded scalar narrowed through a sync-fragile 32<->64 sequence, so
//! the 32-bit view (u32 range) and the tnum's low 32 bits are maintained by independent
//! code and MUST stay consistent. The bug (buggy __reg_bound_offset32, fix f2d67fec0b43)
//! clamped the tnum low-32 to {0} while the u32 compares set [0x200,0x400] -> the two
//! views desync. That desync is EXACTLY invariant B (tnum32_bounds_inconsistent,
//! diff.rs): tnum low-32 span disjoint from [u32_min,u32_max].
//!
//! Two arms, value_size=64, all trivially safe programs (MOV r0,0; EXIT after the
//! narrowing) -- the surface is the register STATE the narrowing leaves, NOT the
//! accept/reject decision (every program accepts):
//!   cve   -- a full 64-bit unknown, narrowed by two jmp64 compares to a multi-2^32-block
//!            [LO,HI], then two jmp32 compares that set the low-32 view. SYNC_WIN[0] is the
//!            historical CVE window [0x200,0x400]. Because [LO,HI] spans several 2^32
//!            blocks, invariant C (reg32_reg64, single-block gated) is DISABLED here and
//!            invariant B is the sole live guard -- which is why the CVE was catchable only
//!            by the tnum-vs-u32 redundancy, not by the 64-bit endpoints.
//!   shift -- r1 = (unknown<<32)|unknown_low, then two jmp32 compares narrow the low half.
//! Grid: cve{pair(4) x win(4)} = 16 + shift{win(4) x pol(2)} = 8 -> 24 programs.
//! Captured in the bpf-next VM (kernel 5e289c5a), 2026-09-04.
//!
//! Result: 24 accept / 0 reject. reg32_checked = 56 (invariant B ran across the sync
//! states -> a CVE-2020-8835 regression WOULD fire), finding_count = 0 (B stayed silent
//! -> the 32<->64 views are consistent on this kernel: a working regression guard, no
//! false positives), 0 parser blind-spots. Signature: reg32_checked>0 AND finding_count=0
//! AND a non-empty multi-block subset (where C is off and B alone guards).

use contract::PeriodPaths;
use pipeline::diff::{self, reg32_checkable};
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const SYNC: &str = include_str!("fixtures/volume/gen-sync-24.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-sync-{}-{}", std::process::id(), tag));
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

/// Reassemble only the program blocks whose label contains `arm` ("#cve." or "#shift.").
fn subset(arm: &str) -> String {
    let mut s = String::new();
    for block in SYNC.split("===PROG ").skip(1) {
        let label = block.split_whitespace().next().unwrap();
        if label.contains(arm) {
            s.push_str("===PROG ");
            s.push_str(block);
        }
    }
    s
}

fn program_decisions() -> Vec<(String, bool)> {
    SYNC.split("===PROG ").skip(1).map(|block| {
        let label = block.split_whitespace().next().unwrap().to_string();
        let acc = block.lines().find(|l| l.starts_with("RESULT "))
            .map(|l| l.contains("decision=accept")).unwrap();
        (label, acc)
    }).collect()
}

#[test]
fn the_sync_machinery_runs_across_the_family_and_stays_silent() {
    // The two numbers T1-1b lives by: reg32_checked > 0 (invariant B examined the sync
    // states, so a CVE-2020-8835 regression would fire) and finding_count == 0 (B is
    // silent -> the 32<->64 views are consistent = a working guard, not a false positive).
    // It must come from BOTH arms, not one construction.
    let (_, all) = run_diff(SYNC, "all");
    let (_, cve) = run_diff(&subset("#cve."), "cve");
    let (_, shift) = run_diff(&subset("#shift."), "shift");
    eprintln!(
        "T1-1b reg32_checked: all={} cve={} shift={} | finding_count={}",
        all.summary.reg32_checked, cve.summary.reg32_checked,
        shift.summary.reg32_checked, all.summary.finding_count
    );
    assert_eq!(all.summary.reg32_checked, 56, "reg32_checked drifted from the pinned value");
    assert!(cve.summary.reg32_checked > 0, "the cve arm must exercise the sync machinery");
    assert!(shift.summary.reg32_checked > 0, "the shift arm must exercise the sync machinery");
    assert_eq!(
        cve.summary.reg32_checked + shift.summary.reg32_checked,
        all.summary.reg32_checked, "reg32_checked is additive over the arms"
    );
    assert_eq!(all.summary.finding_count, 0, "B must stay silent on a fixed kernel: {:?}", all.findings);
}

#[test]
fn invariant_b_is_the_sole_live_guard_in_the_multiblock_regime() {
    // The sharp T1-1b claim. Invariant C (reg32_reg64_inconsistent) is gated on a
    // single-2^32-block 64-bit range; the cve construction narrows to a MULTI-block
    // [LO,HI], so C is skipped there and invariant B (tnum-vs-u32) is the ONLY guard
    // still watching the 32-view -- exactly the redundancy CVE-2020-8835 needed. Prove a
    // non-empty set of checkable, multi-block scalar states actually occurs.
    let (norm, out) = run_diff(SYNC, "mb");
    let mut checkable = 0usize;
    let mut multiblock = 0usize;
    for rec in &norm.records {
        for snap in &rec.core.register_evolution {
            for reg in &snap.regs {
                if reg.reg_type != "scalar" || !reg32_checkable(reg) {
                    continue;
                }
                checkable += 1;
                if (reg.umin >> 32) != (reg.umax >> 32) {
                    multiblock += 1;
                }
            }
        }
    }
    eprintln!("T1-1b checkable-scalar-states={checkable} of-which-multiblock={multiblock}");
    assert!(checkable > 0, "the family must produce checkable 32-view states");
    assert!(multiblock > 0, "at least one checkable state must be multi-block (C off, B alone)");
    // And no B/C finding fired on any of them.
    assert!(
        !out.findings.iter().any(|f| f.kind.contains("tnum32") || f.kind.contains("reg32_reg64")),
        "a 32<->64 inconsistency fired -- possible CVE-2020-8835-class regression: {:?}",
        out.findings
    );
}

#[test]
fn the_cve_window_program_reaches_a_multiblock_32tight_state() {
    // Tie the guard to the historical window: gensync#cve.p0.w0 narrows to
    // [0x2000000000,0x4000000000] (multi-block) then w1 in [0x200,0x400] -- the exact
    // CVE-2020-8835 shape. It must reach a checkable, multi-block scalar state.
    let (norm, _) = run_diff(SYNC, "win");
    let rec = norm.records.iter()
        .find(|r| r.source_label.as_deref() == Some("gensync#cve.p0.w0#000"))
        .expect("the CVE-window program must be present");
    let hit = rec.core.register_evolution.iter().flat_map(|s| &s.regs).any(|reg| {
        reg.reg_type == "scalar" && reg32_checkable(reg) && (reg.umin >> 32) != (reg.umax >> 32)
    });
    assert!(hit, "the CVE-window program must reach a checkable multi-block 32-view state");
}

#[test]
fn every_program_accepts_because_the_surface_is_state_not_decision() {
    // Unlike the accept/reject calibration families, T1-1b's programs are all trivially
    // safe -- the constrained block is MOV r0,0; EXIT. The verifier should accept all 24;
    // the finding, if any, lives in the register state the narrowing leaves behind.
    for (label, accepted) in program_decisions() {
        assert!(accepted, "{label}: a trivially-safe sync program was rejected");
    }
    assert_eq!(SYNC.matches("decision=accept").count(), 24, "all 24 programs must accept");
}

#[test]
fn sync_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(SYNC, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the sync corpus");
    let non_console = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(SYNC, "labels");
    let labels: Vec<&str> = norm.records.iter().filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 24);
    assert!(labels.contains(&"gensync#cve.p0.w0#000"));
    assert!(labels.contains(&"gensync#shift.w3.pol1#023"));
    let mut s = labels.clone(); s.sort_unstable(); s.dedup();
    assert_eq!(s.len(), 24, "no two programs share a label");
}
