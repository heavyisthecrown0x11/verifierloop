//! PRECISION AS THE PRUNING LEVER (devlog 0050, `--gen-prec`).
//!
//! `regsafe` (states.c:551) contains the single most powerful pruning rule in the
//! verifier:
//!
//!     if (!rold->precise && exact == NOT_EXACT)
//!             return true;
//!
//! An IMPRECISE old scalar matches ANY current scalar. Precision is therefore exactly
//! what STOPS a prune: if a register whose value decides memory safety is not marked
//! precise, two states differing only in that register are equated and the unsafe one is
//! pruned away. `mark_chain_precision` has to get that right, `precise.c` is on the
//! kernel's own danger list, and the backtracker logs its work
//! (`mark_precise: frame%d: regs=%s`, backtrack.c:280), so the mechanism is observable
//! rather than merely inferred from verdicts.
//!
//! THE AXIS is whether the differing register PARTICIPATES in the deciding access. The
//! first two arms differ in ONE operand of ONE instruction — which register the store
//! adds — so any difference between them is precision and nothing else:
//!   * `c8_16.s7` stores through r7, the register the two paths disagree about, so r7
//!     must be precise: the states are not equatable and both paths are explored.
//!   * `c8_16.s6` stores through a masked always-safe offset, so r7 is dead: it need not
//!     be precise, the short-circuit applies, and the second state is pruned.
//! Measured: the backtracker chases `regs=r7` 19 times in the first and never in the
//! second (it chases `regs=r6` there instead), and the first explores 3 states to the
//! second's 2. Note that the RAW count of mark_precise lines is higher in the s6 arm —
//! the backtracker works on other registers too — so the count is not the signal; WHICH
//! register is chased is.
//!
//! Store offset 40 makes the verdict a pure function of the constant: in bounds iff
//! `umax <= 23`, so 23 accepts and 24 rejects — an exact one-byte boundary proving the
//! decision tracks the VALUE, not the shape.
//!
//! TWO ORACLE BUGS THIS FAMILY EXPOSED, both in the store-location check, both found by
//! the a-b-c triage after a capture reported 24 findings:
//!   1. A pointer with a fixed non-zero offset is printed `imm=N`, NOT `off=N` — `imm=`
//!      is `var_off.value` when the var_off is constant (log.c:682-687), while `off=` is
//!      the separate `reg->off` field. Reading only `off=` made the constant 0, so every
//!      such store looked like it had escaped its own claim.
//!   2. An absent `umax` means U64_MAX by the log's convention, and `u64::MAX as i64` is
//!      -1, so using it as an interval endpoint produced an INVERTED window (`[40, 39]`)
//!      that rejected every landing site. The comparison now runs in u64 on the variable
//!      part, and an unstated upper bound constrains nothing.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const PREC: &str = include_str!("fixtures/volume/gen-prec-6.log");
const PROGRAMS: usize = 6;
const ACCEPTED: usize = 4;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-prec-{}-{tag}", std::process::id()));
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
    for block in PREC.split("===PROG ").skip(1) {
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

fn block_of(prefix: &str) -> &'static str {
    PREC.split("===PROG ")
        .find(|b| b.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing arm {prefix}"))
}

fn accepted(prefix: &str) -> bool {
    block_of(prefix)
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap()
        .contains("decision=accept")
}

fn base_states(prefix: &str) -> u64 {
    block_of(prefix)
        .lines()
        .find(|l| l.starts_with("PRUNE "))
        .unwrap()
        .split_whitespace()
        .find_map(|t| t.strip_prefix("base_states="))
        .unwrap()
        .parse()
        .unwrap()
}

/// Precision chased for a given register, counted from the backtracker's own log lines.
fn backtracked(prefix: &str, reg: &str) -> usize {
    block_of(prefix)
        .lines()
        .filter(|l| l.contains("mark_precise:") && l.contains(&format!("regs={reg} ")))
        .count()
}

/// THE LEVER, pinned two independent ways on a pair that differs in one operand.
#[test]
fn precision_is_what_blocks_the_prune() {
    assert!(
        backtracked("genprec#c8_16.s7#", "r7") > 0,
        "the store uses r7, so the backtracker must chase it precise"
    );
    assert_eq!(
        backtracked("genprec#c8_16.s6#", "r7"), 0,
        "with the store using r6 instead, r7 is dead and must never be chased — that is \
         the whole difference between these two programs"
    );
    assert!(
        backtracked("genprec#c8_16.s6#", "r6") > 0,
        "and r6 is chased there instead, so the arm is not simply doing less work"
    );
    assert!(
        base_states("genprec#c8_16.s7#") > base_states("genprec#c8_16.s6#"),
        "an imprecise r7 lets regsafe short-circuit and prune the second state, so the \
         dead-register arm must explore FEWER states: {} vs {}",
        base_states("genprec#c8_16.s7#"), base_states("genprec#c8_16.s6#")
    );
}

/// The verdict is a pure function of the constant, with an exact one-byte boundary.
#[test]
fn the_decision_tracks_the_value_with_a_one_byte_boundary() {
    assert!(accepted("genprec#c8_16.s7#"), "40 + 16 + 1 = 57");
    assert!(accepted("genprec#c8_23.s7#"), "40 + 23 + 1 = 64 exactly");
    assert!(!accepted("genprec#c8_24.s7#"), "40 + 24 + 1 = 65, one byte over");
    assert!(!accepted("genprec#c8_40.s7#"), "well over");
    assert!(accepted("genprec#c8_8.s7#"), "identical constants on both paths");
    assert!(accepted("genprec#c8_16.s6#"), "r7 unused, the store offset is masked");
}

/// REGRESSION GUARD for the `imm=` bug. A pointer with a fixed non-zero offset must reach
/// the pipeline with that offset in its tnum value, or its claim collapses to "exactly
/// the base" and every real landing site looks like an escape.
#[test]
fn a_fixed_pointer_offset_is_read_from_imm_not_lost() {
    let (norm, _) = run_diff(PREC, "imm");
    let rec = norm
        .records
        .iter()
        .find(|r| r.source_label.as_deref() == Some("genprec#c8_16.s7#000"))
        .unwrap();
    let site = rec.core.store_site.unwrap();
    let claims: Vec<_> = rec
        .core
        .register_evolution
        .iter()
        .filter(|s| s.insn_idx == site.insn_idx)
        .filter_map(|s| s.regs.iter().find(|r| r.reg == site.base_reg))
        .filter(|p| p.reg_type != "scalar")
        .collect();
    assert!(!claims.is_empty(), "the store pointer must have parsed claims");
    assert!(
        claims.iter().any(|p| p.tnum.mask == 0 && p.tnum.value == 8),
        "the fall-through path pins the pointer at +8 via `imm=8`: {claims:?}"
    );
    assert!(
        claims.iter().any(|p| p.tnum.mask == 0 && p.tnum.value == 16),
        "and the taken path at +16: {claims:?}"
    );
}

#[test]
fn no_oracle_fires_on_the_precision_family() {
    let (norm, out) = run_diff(PREC, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "PREC locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(out.summary.store_locations_checked as usize, ACCEPTED * SWEEP);
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// The claims here are single POINTS, so the check is at its sharpest — any other
/// landing site fires.
#[test]
fn the_oracle_has_teeth_on_a_point_claim() {
    let planted = with_mutated_sample(
        "genprec#c8_16.s7#000", "0x00000000", "store_off=52 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "52 is between the two point claims (48 and 56) and admitted by neither: {:?}",
        out.findings
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "and it is still inside the value, so memory safety stays silent"
    );
}

#[test]
fn precision_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(PREC, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
