//! WHICH `exact_level` OUR SHAPES REACH (devlog 0051, `--gen-exact`).
//!
//! `regsafe` takes an `exact_level` and behaves very differently per level (states.c):
//!   EXACT        -> regs_exact(): memcmp + check_ids, the strictest comparison there is
//!   NOT_EXACT    -> the precision short-circuit applies: `!rold->precise` matches anything
//!   RANGE_WITHIN -> range/tnum logic runs, but the precision short-circuit does NOT
//! and they arrive from different call sites: the main pruning path picks
//! `loop ? RANGE_WITHIN : NOT_EXACT` where `loop = incomplete_read_marks(...)`
//! (states.c:1405), the iterator paths pass RANGE_WITHIN (:1333/:1358/:1364), and EXACT
//! is used at :1372 for ONE purpose only — infinite-loop detection, which prints
//! "infinite loop detected at insn %d". That message is the only way to confirm the
//! EXACT path from outside, and this family uses it as a marker.
//!
//! THE PREDICTION THIS LEG TESTED, AND GOT WRONG. The precision short-circuit is gated on
//! `exact == NOT_EXACT`, so 0050's result — a dead register lets the verifier prune a
//! state — should NOT hold wherever the comparison is RANGE_WITHIN. If a may_goto loop
//! selected RANGE_WITHIN, the same pair inside a loop would stop showing the gap.
//! MEASURED: it still shows it. `loop.s6` prunes to 2 states with the register never
//! backtracked, exactly like `flat.s6`, while `loop.s7` goes the other way and explores 6
//! states with 50 backtracks. So being inside a loop does not by itself select
//! RANGE_WITHIN — the gate really is `incomplete_read_marks`, not the presence of a
//! back-edge, which is why that was left as a measurement rather than asserted.
//!
//! TWO CONSTRUCTION BUGS, both diagnosed from the kernel's own error text rather than
//! guessed at:
//!   * an UNCONDITIONAL `goto head` back-edge makes everything after it unreachable, so
//!     check_cfg rejects the program before walking a single state ("Remove the
//!     unreachable instruction", processed 0 insns) and the EXACT path is never reached.
//!     The back-edge has to be conditional.
//!   * `may_goto` can break out on ENTRY, so a register first assigned inside the loop is
//!     uninitialised on the zero-iteration path ("Initialize R7 on every path before this
//!     instruction"). The same zero-iteration path that decides the verdicts in 0043.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const EX: &str = include_str!("fixtures/volume/gen-exact-5.log");
const PROGRAMS: usize = 5;
const ACCEPTED: usize = 4;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-exact-{}-{tag}", std::process::id()));
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
    for block in EX.split("===PROG ").skip(1) {
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
    EX.split("===PROG ")
        .find(|b| b.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing arm {prefix}"))
}

fn field(prefix: &str, line_start: &str, key: &str) -> u64 {
    block_of(prefix)
        .lines()
        .find(|l| l.starts_with(line_start))
        .unwrap()
        .split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap()
        .parse()
        .unwrap()
}

fn accepted(prefix: &str) -> bool {
    block_of(prefix)
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap()
        .contains("decision=accept")
}

/// The EXACT level is reachable from our shapes, and observable. The state count is the
/// guard that matters here: a CFG rejection also produces `decision=reject`, but with
/// ZERO states walked — which is what an unconditional back-edge gave, and it would make
/// the arm silently meaningless.
#[test]
fn the_exact_path_is_reached_and_says_so() {
    assert!(!accepted("genexact#inf.s6#"), "an infinite loop must be rejected");
    assert_eq!(
        field("genexact#inf.s6#", "EXACT ", "infinite_loop_detected="), 1,
        "the EXACT comparison at states.c:1372 is what prints this, and it is the only \
         way to confirm that level from outside"
    );
    assert!(
        field("genexact#inf.s6#", "PRUNE ", "base_states=") >= 1,
        "the verifier must have WALKED states to get there — a check_cfg rejection \
         reports zero states and never reaches the comparison at all"
    );
}

/// 0050's precision result, reproduced inside this capture so the loop arms have a
/// same-run baseline instead of a cross-capture one.
#[test]
fn the_flat_precision_gap_reproduces() {
    assert!(field("genexact#flat.s7#", "EXACT ", "r7_backtracked=") > 0);
    assert_eq!(field("genexact#flat.s6#", "EXACT ", "r7_backtracked="), 0);
    assert!(
        field("genexact#flat.s7#", "PRUNE ", "base_states=")
            > field("genexact#flat.s6#", "PRUNE ", "base_states="),
        "the dead-register arm prunes a state the precise one cannot"
    );
}

/// THE MEASUREMENT THAT CORRECTED THE PREDICTION. If a may_goto loop selected
/// RANGE_WITHIN, the precision short-circuit would be off there and the gap would close.
/// It does not: the looped pair shows the same qualitative gap, and wider.
#[test]
fn a_may_goto_loop_does_not_by_itself_disable_the_precision_short_circuit() {
    assert_eq!(
        field("genexact#loop.s6#", "EXACT ", "r7_backtracked="), 0,
        "the dead register is still never chased inside a loop"
    );
    assert!(
        field("genexact#loop.s7#", "EXACT ", "r7_backtracked=") > 0,
        "while the live one still is"
    );
    let s7 = field("genexact#loop.s7#", "PRUNE ", "base_states=");
    let s6 = field("genexact#loop.s6#", "PRUNE ", "base_states=");
    assert!(
        s7 > s6,
        "the gap must persist in the loop — if RANGE_WITHIN applied here, the dead \
         register could not buy a prune either: {s7} vs {s6}"
    );
    assert_eq!(
        s6, field("genexact#flat.s6#", "PRUNE ", "base_states="),
        "and the dead-register arm prunes to the SAME count in both contexts, which is \
         what says the comparison is NOT_EXACT in both"
    );
}

#[test]
fn no_oracle_fires_on_the_exact_family() {
    let (norm, out) = run_diff(EX, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "EXACT locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(out.summary.store_locations_checked as usize, ACCEPTED * SWEEP);
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_oracle_has_teeth_on_the_exact_family() {
    let planted = with_mutated_sample(
        "genexact#loop.s7#003", "0x00000000", "store_off=52 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "52 sits between the point claims at 48 and 56: {:?}", out.findings
    );
    assert_eq!(out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0);
}

#[test]
fn exact_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(EX, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
