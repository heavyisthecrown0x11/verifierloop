//! BACK-EDGE / LOOP CONVERGENCE — the first program shape with a loop (devlog 0043,
//! `--gen-loop`).
//!
//! Every family before this one is a forward DAG, and that is the root cause of six legs
//! of zero findings (devlog 0042, [[why-zero-divergence-root-cause]]): the real bug list
//! lives in state pruning, precision and convergence, none of which is reachable without
//! a back-edge. The ORACLE here is 0042's, transferred UNCHANGED — same three loads,
//! same directional predicate, same `freq_states > base_states` denominator, same parser
//! and diff code. This leg is a pure INPUT increment, which is the point: aim the input,
//! do not grow the oracle.
//!
//! MECHANISM — `may_goto`, chosen over open-coded iterators and `bpf_loop` in OI-13.
//! One raw instruction (`BPF_JCOND` = 0xe0, `BPF_MAY_GOTO` = 0, and verifier.c:19075
//! requires `dst_reg == 0 && imm == 0`): no BTF, no kfunc, no subprog, no map. The jump
//! target is the loop EXIT and the fall-through continues into the body — confirmed
//! against the kernel's own `__cond_break` macro, which emits `.byte 0xe5` with the
//! offset pointing at `l_break`. On the fall-through the verifier bumps `may_goto_depth`
//! and calls `widen_imprecise_scalars()` against the previous entry at the same
//! instruction (verifier.c:16923) — a deliberate convergence over-approximation sitting
//! on top of precision marking and pruning.
//!
//! THE DECISION IS DERIVED. The state reaching the store is the JOIN over 0, 1, 2, ...
//! iterations — the ZERO-iteration path included, because the budget can be exhausted on
//! entry. With the store at +56 the program is acceptable iff that join keeps
//! `umax(r6) <= 7`. Two pairs make the family sharp:
//!   * `incmask` (`r6 += 1; r6 &= 7` -> [0,7], ACCEPT) vs `maskinc` (`r6 &= 7; r6 += 1`
//!     -> join [0,8], REJECT). The same two operations in the opposite ORDER, one byte
//!     apart. The verifier prints exactly `umin=1,umax=8,var_off=(0x0; 0xf)` for the
//!     rejecting one.
//!   * `mask.m7` (ACCEPT) vs `mask.m63` (REJECT). The same body; the only difference is
//!     that entering wide and breaking immediately leaves the wide range at the store.
//!
//! THE FIRST CAPTURE WAS VACUOUS AND SAID SO LOUDLY, which is why the vacuity guard
//! below is not optional. `ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - n - 1)`
//! leaves the side effect on `n` unsequenced against the offset expression, so the
//! back-edge was emitted as `goto pc-4` (landing on the ENTRY MASK) instead of `pc-3`
//! (the may_goto). Every iteration re-established the entry invariant, so all ten loop
//! bodies produced identical states and identical verdicts — ten clean accepts that
//! proved nothing. The tell was that the verdict was a pure function of `init_mask` with
//! `nop` and `inc` indistinguishable.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const LOOP: &str = include_str!("fixtures/volume/gen-loop-12.log");
const PROGRAMS: usize = 12;

/// The derived verdict per arm: accept iff the join over all iteration counts keeps
/// `umax(r6) <= 7`. Written out rather than computed so that a change in the family's
/// shape has to be re-derived by a human instead of silently re-fitting.
const EXPECTED: &[(&str, bool)] = &[
    ("genloop#nop.m7#000", true),      // body never touches r6: join is the entry [0,7]
    ("genloop#mask.m7#001", true),     // idempotent: [0,7] every iteration
    ("genloop#incmask.m7#002", true),  // +1 then mask: [0,7]
    ("genloop#maskinc.m7#003", false), // mask then +1: [1,8], join [0,8] -> 56+8+1 > 64
    ("genloop#shr.m7#004", true),      // shrinks: [0,3], [0,1], [0,0]
    ("genloop#xor3.m7#005", true),     // stays inside [0,7]
    ("genloop#cond.m7#006", true),     // branch re-establishes the invariant
    ("genloop#inc.m7#007", false),     // unbounded growth
    ("genloop#shl.m7#008", false),     // growth: {0,2,..,14} and on
    ("genloop#add8.m7#009", false),    // growth: [8,15] and on
    ("genloop#mask.m63#010", false),   // ZERO-iteration path leaves the entry [0,63]
    ("genloop#nop.m63#011", false),    // control: wide entry, nothing narrows it
];

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-loop-{}-{tag}", std::process::id()));
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

fn with_mutated_prune(label: &str, new_line: &str) -> String {
    let mut out = String::new();
    let mut hit = false;
    for block in LOOP.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        for line in block.lines() {
            if blabel == label && line.starts_with("PRUNE ") {
                out.push_str(new_line);
                hit = true;
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
    }
    assert!(hit, "planting target {label} not found — fixture changed?");
    out
}

fn prune_line_of(label: &str) -> String {
    for block in LOOP.split("===PROG ").skip(1) {
        if block.split_whitespace().next().unwrap() == label {
            for line in block.lines() {
                if line.starts_with("PRUNE ") {
                    return line.to_string();
                }
            }
        }
    }
    panic!("no PRUNE line for {label}");
}

/// THE VACUITY GUARD, and the most important test in this file. The first capture had a
/// broken back-edge that re-established the entry invariant every iteration, making the
/// verdict a pure function of `init_mask` and all ten loop bodies indistinguishable.
/// Pin that the BODY changes the verdict: among the arms that share an entry mask of 7
/// there must be both accepts and rejects.
#[test]
fn the_loop_body_actually_affects_the_verdict() {
    let (norm, _) = run_diff(LOOP, "vacuity");
    let mut accepts = 0;
    let mut rejects = 0;
    for rec in &norm.records {
        let label = rec.source_label.as_deref().unwrap_or("");
        if !label.contains(".m7#") {
            continue;
        }
        match rec.core.prune_probe.as_ref().unwrap().base_accept {
            true => accepts += 1,
            false => rejects += 1,
        }
    }
    assert!(
        accepts > 0 && rejects > 0,
        "every arm with the same entry mask reached the same verdict ({accepts} accept, \
         {rejects} reject) — the loop body is not reaching the deciding register, which \
         is what a mis-emitted back-edge looks like"
    );
}

#[test]
fn the_verdict_matches_the_derived_join_over_iteration_counts() {
    let (norm, _) = run_diff(LOOP, "derive");
    assert_eq!(norm.records.len(), PROGRAMS);
    for (label, expect) in EXPECTED {
        let rec = norm
            .records
            .iter()
            .find(|r| r.source_label.as_deref() == Some(*label))
            .unwrap_or_else(|| panic!("missing arm {label}"));
        assert_eq!(
            rec.core.prune_probe.as_ref().unwrap().base_accept,
            *expect,
            "{label}: the join over 0,1,2,... iterations decides this arm"
        );
    }
}

/// The sharp pair: the same two operations in the opposite order, one byte apart.
#[test]
fn operation_order_inside_the_loop_body_is_a_one_byte_boundary() {
    let (norm, _) = run_diff(LOOP, "pair");
    let verdict = |label: &str| {
        norm.records
            .iter()
            .find(|r| r.source_label.as_deref() == Some(label))
            .unwrap()
            .core
            .prune_probe
            .as_ref()
            .unwrap()
            .base_accept
    };
    assert!(verdict("genloop#incmask.m7#002"), "+1 then mask stays in [0,7]");
    assert!(!verdict("genloop#maskinc.m7#003"), "mask then +1 reaches 8, one byte over");
    assert!(verdict("genloop#mask.m7#001"), "narrow entry, idempotent body");
    assert!(
        !verdict("genloop#mask.m63#010"),
        "same body, wide entry: the zero-iteration path never runs it"
    );
}

/// The headline, with the oracle unchanged from 0042.
#[test]
fn the_verdict_does_not_depend_on_checkpoint_frequency() {
    let (_, out) = run_diff(LOOP, "base");
    eprintln!(
        "LOOP pairs_checked={} artifacts={} finding_count={}",
        out.summary.prune_pairs_checked, out.summary.prune_resource_artifacts,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.prune_pairs_checked as usize, PROGRAMS,
        "every back-edge program must be a USABLE differential"
    );
    assert_eq!(
        out.summary.finding_count, 0,
        "a loop program's verdict changed with checkpoint frequency: {:?}", out.findings
    );
    assert_eq!(out.summary.prune_resource_artifacts, 0);
}

#[test]
fn the_flag_engaged_on_every_loop_program() {
    let (norm, _) = run_diff(LOOP, "engaged");
    for rec in &norm.records {
        let p = rec.core.prune_probe.as_ref().unwrap();
        assert!(
            p.freq_states > p.base_states,
            "{}: base_states={} freq_states={} — the flag explored no extra states",
            rec.source_label.as_deref().unwrap_or("?"), p.base_states, p.freq_states
        );
    }
}

/// The teeth must fire on THIS leg's real capture, not only on the family they were
/// written against. A flagged accept over a default reject on a LOOP program means the
/// extra checkpoints let convergence prune away the path that produced the rejection.
#[test]
fn the_oracle_has_teeth_on_a_back_edge_program() {
    let base = prune_line_of("genloop#inc.m7#007");
    assert!(base.contains("base_verdict=reject"));
    let planted = base.replace("freq_verdict=reject", "freq_verdict=accept");
    let (_, out) = run_diff(&with_mutated_prune("genloop#inc.m7#007", &planted), "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "prune_soundness_desync").count(), 1,
        "an unbounded-growth loop accepted only under STATE_FREQ must fire: {:?}",
        out.findings
    );
}

#[test]
fn the_kernels_own_invariant_channel_stayed_silent_on_every_loop() {
    let (norm, _) = run_diff(LOOP, "inv");
    for rec in &norm.records {
        let p = rec.core.prune_probe.as_ref().unwrap();
        assert_ne!(
            p.inv_reason, "efault",
            "{}: reg_bounds_sanity_check fired under BPF_F_TEST_REG_INVARIANTS",
            rec.source_label.as_deref().unwrap_or("?")
        );
    }
}

#[test]
fn loop_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(LOOP, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
