//! SPILLED LINKS and DELTA ARITHMETIC (devlog 0049, `--gen-spill`).
//!
//! Two gaps left by 0046-0048, both visible in one line of `sync_linked_regs`
//! (verifier.c:16847):
//!
//!   reg = e->is_reg ? &vstate->frame[e->frameno]->regs[e->regno]
//!                   : &vstate->frame[e->frameno]->stack[e->spi].spilled_ptr;
//!
//! (1) A linked scalar's class spans STACK SLOTS, not just registers, and `stacksafe`
//!     has its own `check_ids` calls for spilled state. Every id family so far kept its
//!     scalars in registers.
//! (2) The ADD_CONST branch does real ARITHMETIC when two members of a class carry
//!     different deltas: `__mark_reg_known(&fake_reg, (s64)reg->delta -
//!     (s64)known_reg->delta)`. 0046 and 0047 only ever had ONE delta linked to a bare
//!     base, so the subtraction never had two non-trivial operands.
//!
//! Both answers are yes, and the paired design proves it rather than assuming it: for
//! each shape the one-path variant rejects while the both-path variant accepts, so the
//! rejection is about linkage and not about the shape.
//!
//! ACCEPTANCE ALONE WOULD NOT BE ENOUGH for the delta arm — a too-wide but still-safe
//! bound would also accept. The log gives the exact numbers, and the tests pin them:
//! `R6=scalar(id=1,...umax=7...)` alongside `R9=scalar(id=1+12,umin=12,umax=19,...)`.
//! The kernel even renders the compound id as `1+12`, base plus delta, and [12,19] is
//! exactly [0,7] + 12 — the subtraction produced the right range, not a widened one.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const SPILL: &str = include_str!("fixtures/volume/gen-spill-12.log");
const PROGRAMS: usize = 12;
const ACCEPTED: usize = 6;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-spill-{}-{tag}", std::process::id()));
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
    for block in SPILL.split("===PROG ").skip(1) {
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
    SPILL
        .split("===PROG ")
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

/// A linked scalar that lives in a STACK SLOT is still narrowed with its class. The
/// pairing is the proof: if spilled copies dropped out of the class, `spill.both` would
/// reject exactly like `spill.one`.
#[test]
fn a_spilled_copy_stays_in_the_linked_class() {
    assert!(!accepted("genspill#spill.no.s0#"), "baseline: the slot is never linked");
    assert!(!accepted("genspill#spill.one.s0#"), "linked on one path: one state is wide");
    assert!(
        accepted("genspill#spill.both.s0#"),
        "linked on both paths: narrowing the register must narrow the SPILLED copy, or \
         this rejects too and the rejection above says nothing about spilling"
    );
    assert!(accepted("genspill#spill.one.s6#"), "control: store through the narrowed reg");
}

/// The stack slot itself must carry the id and be narrowed by it — visible in the dump,
/// not inferred from the verdict.
#[test]
fn the_stack_slot_carries_the_id_and_is_narrowed_through_it() {
    let block = block_of("genspill#spill.both.s0#");
    let states: Vec<&str> = block
        .lines()
        .flat_map(|l| l.split_whitespace())
        .filter(|t| t.starts_with("fp-16=scalar(id="))
        .collect();
    assert!(!states.is_empty(), "the spilled slot must appear with an id");
    assert!(
        states.iter().any(|s| s.contains("umax=0xffffffff")),
        "before the check the slot is wide: {states:?}"
    );
    assert!(
        states.iter().any(|s| s.contains("umax=smax32=umax32=7")),
        "after the check the slot is narrowed through its id: {states:?}"
    );
}

/// The delta arithmetic, pinned by VALUE rather than by verdict. Two members of one class
/// at different offsets from the base exercise
/// `(s64)reg->delta - (s64)known_reg->delta`, and [12,19] is exactly [0,7] + 12 — a
/// widened-but-safe result would also have been accepted, so the numbers are the test.
#[test]
fn two_deltas_off_one_base_are_synced_to_exactly_the_right_ranges() {
    assert!(!accepted("genspill#delta.no.s9#"), "baseline");
    assert!(!accepted("genspill#delta.one.s9#"), "linked on one path only");
    assert!(accepted("genspill#delta.both.s9#"), "delta 12 narrows with the class");
    assert!(accepted("genspill#delta.both.s7#"), "so does delta 4, same class");

    let block = block_of("genspill#delta.both.s9#");
    let narrow = block
        .lines()
        .find(|l| l.contains("if r6 > 0x7") && l.contains("R9=scalar(id="))
        .expect("the narrowing check must appear with the delta register's state");
    assert!(
        narrow.contains("R6=scalar(id=") && narrow.contains("umax=smax32=umax32=7"),
        "the base must be narrowed to [0,7]: {narrow}"
    );
    assert!(
        narrow.contains("umin=smin32=umin32=12") && narrow.contains("umax=smax32=umax32=19"),
        "and the delta-12 member to exactly [12,19] — not merely to something safe: {narrow}"
    );
    assert!(
        narrow.contains("+12"),
        "the kernel renders the compound id as base+delta, which is what makes the \
         arithmetic auditable from the log: {narrow}"
    );
}

/// THE SHAPE A REAL BUG LIVED IN, added in 0062 after calibration pointed at it. Commit
/// 3878ae04e9fc ("bpf: Fix incorrect delta propagation between linked registers") fixed
/// sync_linked_regs propagating a 32-BIT delta as if it were 64-bit — "can lead to
/// accepting a program with OOB access". 0049 pinned the delta arithmetic by VALUE, but
/// only in the alu64 form, so this shape had never been generated at all.
///
/// The fix is in our tree, so the expected result is clean; what the arm buys is that the
/// class now has a detector. HONEST SCOPE: this covers the 32-bit delta LINK shape, not
/// the wraparound trigger the bug needed (a base near 2^32, where a 32-bit add wraps to a
/// small value while a 64-bit reading would carry into the upper word). That trigger is a
/// further refinement, not something this arm demonstrates.
#[test]
fn the_thirty_two_bit_delta_link_is_covered_and_agrees_with_the_sixty_four_bit_one() {
    assert!(!accepted("genspill#delta32.no.s9#"), "baseline");
    assert!(!accepted("genspill#delta32.one.s9#"), "linked on one path only");
    assert!(accepted("genspill#delta32.both.s9#"), "delta 12 narrows with the class");
    assert!(accepted("genspill#delta32.both.s7#"), "so does delta 4");

    let block = block_of("genspill#delta32.both.s9#");
    let narrow = block
        .lines()
        .find(|l| l.contains("if r6 > 0x7") && l.contains("R9=scalar(id="))
        .expect("the narrowing check must appear with the delta register's state");
    assert!(
        narrow.contains("umin=smin32=umin32=12") && narrow.contains("umax=smax32=umax32=19"),
        "the alu32 link must reach the same [12,19] the alu64 one does: {narrow}"
    );
    assert!(narrow.contains("+12"), "and carry the compound id: {narrow}");
}

#[test]
fn no_oracle_fires_on_the_spill_family() {
    let (norm, out) = run_diff(SPILL, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "SPILL locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(out.summary.store_locations_checked as usize, ACCEPTED * SWEEP);
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_oracle_has_teeth_on_the_spill_family() {
    let planted = with_mutated_sample(
        "genspill#delta.both.s9#006", "0x00000000", "store_off=20 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "a store outside the proven set must fire once: {:?}", out.findings
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "offset 20 is still inside the value"
    );
}

#[test]
fn spill_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(SPILL, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
