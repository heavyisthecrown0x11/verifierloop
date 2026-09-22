//! TRYING TO REACH RANGE_WITHIN ON PURPOSE (devlog 0052, `--gen-rw`) — and finding the
//! LIMIT of what this instrument can observe.
//!
//! 0051 predicted the precision short-circuit would stop working inside a loop, since it
//! is gated on `exact == NOT_EXACT`; a may_goto loop turned out not to select
//! RANGE_WITHIN. This leg aimed at a call site that passes it unconditionally
//! (states.c:1333, the iterator's next-call instruction) by splitting BEFORE the loop so
//! the two states meet there rather than at an ordinary instruction in the body.
//!
//! MEASURED: the dead-register arm still merges. In the iterator context it carries
//! exactly HALF the active-iterator states of the precise arm (7 against 14) and still
//! never has the register backtracked — so precision still buys pruning there in effect.
//!
//! AND THE PREDICTION IS STILL NOT SETTLED, because the level of an individual prune is
//! NOT OBSERVABLE FROM OUTSIDE. Reading :1333 to the end shows why:
//!
//!     if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
//!             ...
//!             if (iter_state->iter.state == BPF_ITER_STATE_ACTIVE) {
//!                     loop = true;
//!                     goto hit;          /* <- this IS the prune path */
//!             }
//!
//! so RANGE_WITHIN can prune there, while the block is gated on `sl->state.branches` and
//! completed states fall through to the main comparison at :1405 with
//! `loop ? RANGE_WITHIN : NOT_EXACT`. Both can merge our pair, and the log never says
//! which one did. The 2x ratio proves a merge happened; it cannot attribute it.
//!
//! THE USEFUL RESULT IS THEREFORE A BOUND ON THE INSTRUMENT: EXACT is the only level with
//! an external marker (the "infinite loop detected" message, 0051). Predictions of the
//! form "context X selects level Y" are not testable this way, and that is recorded so
//! the attempt is not repeated. What remains measurable — and is measured here — is
//! whether a merge happened at all, and what it cost.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const RW: &str = include_str!("fixtures/volume/gen-rw-4.log");
const PROGRAMS: usize = 4;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-rw-{}-{tag}", std::process::id()));
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
    for block in RW.split("===PROG ").skip(1) {
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
    assert!(hit, "planting target {label}/{input_hex} not found");
    out
}

fn block_of(prefix: &str) -> &'static str {
    RW.split("===PROG ")
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

/// The iterator arms must actually be iterator programs, or the whole comparison is
/// between two straight-line programs wearing different names.
#[test]
fn the_iterator_arms_really_use_an_iterator() {
    assert_eq!(field("genrw#flat.s7#", "RW ", "iter_active="), 0);
    assert_eq!(field("genrw#flat.s6#", "RW ", "iter_active="), 0);
    assert!(field("genrw#iter.s7#", "RW ", "iter_active=") > 0);
    assert!(field("genrw#iter.s6#", "RW ", "iter_active=") > 0);
}

/// The flat baseline, carried in this capture so the comparison is within one run.
#[test]
fn the_flat_precision_gap_is_present_as_the_baseline() {
    assert!(field("genrw#flat.s7#", "RW ", "r7_backtracked=") > 0);
    assert_eq!(field("genrw#flat.s6#", "RW ", "r7_backtracked="), 0);
    assert!(
        field("genrw#flat.s7#", "PRUNE ", "base_states=")
            > field("genrw#flat.s6#", "PRUNE ", "base_states=")
    );
}

/// THE MEASUREMENT. In the iterator context the dead-register arm still merges, and the
/// cost is quantified exactly: half the active-iterator states, because the precise arm
/// carries both values of the register through every iterator state and the imprecise one
/// carries a single merged value.
#[test]
fn the_dead_register_still_merges_inside_an_iterator_and_halves_its_states() {
    assert_eq!(
        field("genrw#iter.s6#", "RW ", "r7_backtracked="), 0,
        "the dead register is still never chased"
    );
    assert!(field("genrw#iter.s7#", "RW ", "r7_backtracked=") > 0);
    let precise = field("genrw#iter.s7#", "RW ", "iter_active=");
    let merged = field("genrw#iter.s6#", "RW ", "iter_active=");
    assert_eq!(
        precise, merged * 2,
        "the precise arm carries BOTH register values through every iterator state and \
         the imprecise arm one, so the ratio is exactly 2: {precise} vs {merged}"
    );
    assert!(
        field("genrw#iter.s7#", "PRUNE ", "base_states=")
            > field("genrw#iter.s6#", "PRUNE ", "base_states="),
        "and the overall state count follows"
    );
}

/// The bound this leg establishes, written as a test so it is not quietly forgotten: a
/// merge is observable, its exact_level is not. Both :1333 (RANGE_WITHIN, `goto hit`) and
/// :1405 (NOT_EXACT) can perform it, and nothing in the log distinguishes them — only
/// EXACT has an external marker, and no arm here trips it.
#[test]
fn the_level_of_a_prune_is_not_observable_from_the_log() {
    for arm in ["genrw#flat.s7#", "genrw#flat.s6#", "genrw#iter.s7#", "genrw#iter.s6#"] {
        assert!(
            !block_of(arm).contains("infinite loop detected"),
            "{arm}: no arm here reaches the one level that announces itself"
        );
        assert!(
            !block_of(arm).contains("RANGE_WITHIN") && !block_of(arm).contains("NOT_EXACT"),
            "{arm}: the log never names the level a comparison used — which is exactly \
             why 'context X selects level Y' cannot be tested this way"
        );
    }
}

#[test]
fn no_oracle_fires_on_the_range_within_family() {
    let (norm, out) = run_diff(RW, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "RW locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(out.summary.store_locations_checked as usize, PROGRAMS * SWEEP);
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_oracle_has_teeth_on_the_range_within_family() {
    let planted = with_mutated_sample(
        "genrw#iter.s7#002", "0x00000000", "store_off=52 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "{:?}", out.findings
    );
    assert_eq!(out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0);
}

#[test]
fn range_within_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(RW, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
