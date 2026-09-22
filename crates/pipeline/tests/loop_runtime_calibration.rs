//! LOOP FIXPOINT vs RUNTIME — does the bound the verifier computed over an unbounded
//! number of iterations hold for the number the machine actually runs? (devlog 0044,
//! `--gen-loopr`).
//!
//! 0043 asked whether a back-edge program's VERDICT survives a change in checkpoint
//! frequency. This asks 0041's strictly stronger question on a loop: the verifier proves
//! a bound on the offset register at the store by computing a FIXPOINT, and the runtime
//! then picks one concrete iteration count out of millions. The store must land inside
//! the proven set for whichever count it happens to pick.
//!
//! IT ALSO CLOSES A HOLE IN 0043. That family emits a STORE line but never executes, so
//! `store_locations_checked` was 0 — by this project's own rule the claim was never
//! read, and zero findings there meant nothing about the location question.
//!
//! COST WAS MEASURED BEFORE IT WAS PAID (`--probe-loopr`, fixture probe-loopr-3.log).
//! On x86-64 `bpf_jit_supports_timed_may_goto()` is true, so the may_goto budget is
//! TIME-based and every run spends the full `NSEC_PER_SEC / 4`. Measured: 250.3 / 250.5
//! / 251.4 ms — the budget exactly. Being time-based is what makes the leg affordable:
//! KASAN/KCOV slowness lowers the iteration count inside the same 250ms rather than
//! extending the run, which is the OI-11 hazard this probe existed to rule out.
//!
//! NON-DETERMINISM IS DELIBERATE. The final offset depends on how many iterations fit in
//! the budget, so `incmask` lands somewhere different on every run. The oracle asks for
//! MEMBERSHIP in the proven set, never equality, so each run samples the fixpoint at a
//! fresh point. Nothing here may assert an exact `store_off` for such an arm.
//!
//! HONEST LIMIT. The budget is always spent, so the runtime never takes the
//! ZERO-iteration path. That path is real for the verifier — it is why `mask.m63` is
//! rejected in 0043 — but it is verifier-only evidence here, never runtime-confirmed.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use std::collections::BTreeSet;

const LOOPR: &str = include_str!("fixtures/volume/gen-loopr-7.log");
const PROBE: &str = include_str!("fixtures/volume/probe-loopr-3.log");
const PROGRAMS: usize = 7;
const ACCEPTED: usize = 6;
const SWEEP: usize = 8; // LOOPR_INPUTS: every residue of `input & 7`
const STORE_BASE: i64 = 56;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-loopr-{}-{tag}", std::process::id()));
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

fn with_mutated_sample(label: &str, input_hex: &str, new_tail: &str) -> String {
    let mut out = String::new();
    let mut hit = false;
    for block in LOOPR.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        for line in block.lines() {
            if blabel == label && line.starts_with(&format!("RUNTIME input={input_hex} ")) {
                out.push_str(&format!("RUNTIME input={input_hex} {new_tail}"));
                hit = true;
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
    }
    assert!(hit, "planting target {label}/{input_hex} not found — fixture changed?");
    out
}

fn landing_set(norm: &normalize::NormalizedMetrics, label: &str) -> BTreeSet<i64> {
    norm.records
        .iter()
        .find(|r| r.source_label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("missing arm {label}"))
        .core
        .runtime_samples
        .iter()
        .filter_map(|s| s.store_off)
        .filter(|o| *o >= 0)
        .collect()
}

/// The headline: every store landed inside the set the verifier's FIXPOINT proved,
/// and the denominator says the claim was actually read.
#[test]
fn every_loop_store_landed_inside_the_proven_fixpoint() {
    let (norm, out) = run_diff(LOOPR, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "LOOPR locations_checked={} writes_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.runtime_writes_checked,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.store_locations_checked as usize,
        ACCEPTED * SWEEP,
        "every run of every accepted loop program must be COMPARED against the proven \
         set; this counter being 0 is exactly the hole 0043 left"
    );
    assert_eq!(
        out.summary.finding_count, 0,
        "a loop store landed outside the verifier's fixpoint: {:?}", out.findings
    );
}

/// THE VACUITY GUARD. If the loop body never ran at runtime, the offset register would
/// still hold its entry value and every shape would land exactly where `nop` does. Pin
/// that at least one body demonstrably changed the landing set.
#[test]
fn the_loop_body_actually_ran_at_runtime() {
    let (norm, _) = run_diff(LOOPR, "vacuity");
    let nop = landing_set(&norm, "genloopr#nop#000");
    assert_eq!(
        nop.len(), SWEEP,
        "the untouched body must land on every residue of the entry mask: {nop:?}"
    );
    let shr = landing_set(&norm, "genloopr#shr#003");
    assert_eq!(
        shr, BTreeSet::from([STORE_BASE]),
        "a body that shifts the offset right collapses it to zero, so every input must \
         land on the store's own base offset — anything else means the body never ran"
    );
    assert_ne!(shr, nop, "the loop body must change where the store lands");
}

/// The proven window is narrow (8 of a 64-byte value), so a zero finding count is not
/// vacuous. Also pin that the runtime never escaped it.
#[test]
fn the_proven_window_is_narrow_and_the_runtime_stays_in_it() {
    let (norm, _) = run_diff(LOOPR, "window");
    for rec in &norm.records {
        let label = rec.source_label.as_deref().unwrap_or("");
        for smp in &rec.core.runtime_samples {
            let off = match smp.store_off {
                Some(o) if o >= 0 => o,
                _ => continue,
            };
            assert!(
                (STORE_BASE..STORE_BASE + 8).contains(&off),
                "{label}: landed at {off}, outside base+[0,7]"
            );
        }
    }
}

/// The verifier is allowed to be IMPRECISE, only never unsound. `cond` resets the offset
/// whenever it exceeds 3, so the runtime can only reach base+[0,3] even though the
/// verifier proves base+[0,7]. Pin that direction explicitly — a runtime set WIDER than
/// the proof is the finding; narrower is just conservatism.
#[test]
fn conservatism_is_allowed_but_only_in_the_safe_direction() {
    let (norm, _) = run_diff(LOOPR, "conservative");
    let cond = landing_set(&norm, "genloopr#cond#005");
    assert!(
        cond.iter().all(|o| (STORE_BASE..=STORE_BASE + 3).contains(o)),
        "the branch caps the reachable offset at 3: {cond:?}"
    );
    assert!(cond.len() > 1, "the arm must still vary, or it proves nothing");
}

/// TOOTH — 0041's location oracle must fire on THIS leg's real capture. An offset that is
/// still inside the map value but outside the loop's proven set is a desync, and the
/// memory-safety leg must stay silent, because that silence is the blind spot being
/// covered.
#[test]
fn the_oracle_has_teeth_on_a_loop_program() {
    let planted = with_mutated_sample(
        "genloopr#mask#001", "0x00000000", "store_off=40 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "a store outside the loop's proven set must fire exactly once: {:?}", out.findings
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "and the memory-safety leg must stay SILENT — offset 40 is still inside the value"
    );
}

/// The probe that sized this leg. Pinned so the cost claim stays checkable: the budget is
/// time-based and each run spends it in full.
#[test]
fn the_measured_budget_is_the_kernels_quarter_second() {
    let mut runs = 0;
    for line in PROBE.lines().filter(|l| l.starts_with("CHANNEL ")) {
        let ns: u64 = line
            .split_whitespace()
            .find_map(|t| t.strip_prefix("wall_ns="))
            .expect("probe must report wall time")
            .parse()
            .unwrap();
        assert!(
            (245_000_000..=270_000_000).contains(&ns),
            "a may_goto run should spend the full NSEC_PER_SEC/4 budget, got {ns} ns"
        );
        runs += 1;
    }
    assert_eq!(runs, 3, "the probe measured three shapes");
}

#[test]
fn loop_runtime_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(LOOPR, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
