//! COMPOSITION GENERATOR (devlog 0054, `--gen-comp`) — the second half of the fourth
//! pivot, and the first family whose shapes nobody named.
//!
//! Switching surface (0053) addressed one axis: mature code versus fresh. It did not
//! address the other. Every family before this one, that one included, produces shapes
//! whose bug class can be NAMED, so "clean" has only ever meant "clean on the shapes I
//! thought to write". This generator composes the pieces built across 0043-0053 at
//! random — link forms, spills, ALU shaping, branch narrowing, bounded loops, dynptr
//! slices — with the oracles held fixed.
//!
//! THE HARD PART IS VALIDITY, NOT THE ORACLE. A randomly concatenated program is almost
//! always rejected, and a rejected program never reaches the runtime oracles: a
//! denominator-zero trap one layer up from the ones 0041-0050 kept finding. The fix is to
//! treat a program as a walk over a typed CONTEXT rather than a byte string — every piece
//! declares what it REQUIRES of the live state and what it PROVIDES, and only pieces
//! whose requirements currently hold are ever offered.
//!
//! THE CONTEXT CARRIES MORE THAN REGISTER TYPES, and dynptr is why: its interface is the
//! richest of the pieces. It consumes a 16-byte STACK_DYNPTR slot pair the verifier tracks
//! by id, and yields a PTR_TO_MEM whose size is a constant the caller chose — plus an
//! OFFSET into the map value that the slice's base corresponds to, which is 0053's
//! coordinate translation generalised so the store's declared offset is always in the
//! coordinates the sentinel readback uses.
//!
//! THE VALIDITY RESULT IS THE HEADLINE, and it is what makes the zero interpretable:
//! nineteen of the forty-eight programs are rejected, and ALL NINETEEN are rejected on
//! BOUNDS — "Add or adjust a bounds check that proves offset + access_size stays within
//! the object". ZERO are rejected structurally: no uninitialised register, no unreachable
//! instruction, no invalid instruction. Every program the generator emits is
//! well-formed, and the only thing that decides its verdict is the semantic question the
//! oracle already asks.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use std::collections::BTreeSet;

const COMP: &str = include_str!("fixtures/volume/gen-comp-896.log");
const PROGRAMS: usize = 896;
const ACCEPTED: usize = 775;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-comp-{}-{tag}", std::process::id()));
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

fn recipes() -> Vec<String> {
    COMP.lines()
        .filter(|l| l.starts_with("COMP "))
        .filter_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("recipe=")))
        .map(str::to_string)
        .collect()
}

/// THE VALIDITY METRIC, and the reviewer's warning answered with a measurement. Raw accept
/// rate is the wrong number: a rejection is a legitimate verdict. The right question is
/// whether rejections are SEMANTIC (the store is genuinely out of bounds) or STRUCTURAL
/// (the generator emitted something malformed). Structural rejections would mean the walk
/// is producing garbage the oracle can never see.
/// Every distinct rejection reason in the corpus, as the verifier phrased it.
fn rejection_reasons() -> Vec<String> {
    let mut out = Vec::new();
    for block in COMP.split("===PROG ").skip(1) {
        if !block.contains("RESULT decision=reject") {
            continue;
        }
        let log = match block.split_once("---LOG---") {
            Some((_, l)) => l,
            None => continue,
        };
        if let Some(line) = log.lines().find(|l| {
            l.starts_with('R') && l.contains("unbounded memory access")
                || l.starts_with('R') && l.contains("min value is negative")
                || l.starts_with("invalid access to map value")
                || l.starts_with("math between")
                || l.starts_with("Initialize R")
                || l.contains("unreachable instruction")
                || l.contains("!read_ok")
                || l.starts_with("invalid bpf_ld")
                || l.contains("unknown opcode")
                || l.contains("jump out of range")
        }) {
            out.push(line.split(',').next().unwrap_or(line).trim().to_string());
        }
    }
    out
}

/// THE VALIDITY METRIC, and the reviewer's warning answered with a measurement. Raw accept
/// rate is the wrong number: a rejection is a legitimate verdict. The right question is
/// whether rejections are SEMANTIC (the store is genuinely out of bounds) or STRUCTURAL
/// (the generator emitted something malformed). Structural rejections would mean the walk
/// is producing garbage the oracle can never see.
///
/// This is written as an ALLOWLIST rather than a pattern for "structural", because the
/// first version used a loose `invalid ` match and counted "invalid access to map value"
/// — a BOUNDS error — as structural. A metric that cries wolf is worse than none. Any
/// rejection reason not on this list is unclassified and must be triaged before the
/// corpus is trusted.
#[test]
fn every_rejection_is_semantic_and_none_is_structural() {
    let semantic = [
        "unbounded memory access",             // the offset register has no proven bound
        "invalid access to map value",         // the constant offset is out of range
        "math between",                        // pointer arithmetic with an unbounded reg
        // NEW WITH `relink` (0069), and triaged before being allowed in. The delta link
        // makes the class BASE carry a negative signed lower bound — `rB = rA; rB += 4`
        // then a bound on rB gives rA `smin = -4` — so adding the base to the store
        // pointer can be refused for a reason none of the earlier pieces produced. It is a
        // BOUNDS question like the others, not malformedness: the verifier is asking for
        // proof the index cannot be negative.
        "min value is negative",
    ];
    let structural = ["Initialize R", "!read_ok", "unreachable", "unknown opcode",
                      "invalid bpf_ld", "jump out of range",
                      // A leaked ringbuf reservation would be the GENERATOR's fault, not a
                      // property under test: the piece must submit on every path, including
                      // the one where its slice comes back NULL.
                      "Unreleased reference", "reference"];
    let reasons = rejection_reasons();
    let rejects = COMP.matches("RESULT decision=reject").count();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for r in &reasons {
        seen.insert(r.clone());
    }
    eprintln!("COMP rejects={rejects} classified={} distinct={:?}", reasons.len(), seen);
    assert_eq!(
        reasons.len(), rejects,
        "every rejection must be classifiable — an unrecognised reason means a shape the \
         generator produces that nobody has looked at"
    );
    for r in &seen {
        assert!(
            semantic.iter().any(|p| r.contains(p)),
            "unclassified rejection reason, triage before trusting the corpus: {r}"
        );
        assert!(
            !structural.iter().any(|p| r.contains(p)),
            "a structural rejection means the typed walk emitted something malformed, and \
             a malformed program teaches the oracles nothing: {r}"
        );
    }
}

/// The sub-register axis has to be LIVE in the corpus, not merely present as a piece. The
/// first widened run scored reg32_checked = 0 while alu32 was its most-used piece: the
/// initial scalars came from 32-bit loads, which zero-extend, so the 32-bit view coincided
/// with the 64-bit one and there was nothing to check. One scalar is now loaded 64 bits
/// wide to give alu32 an upper-unknown operand.
#[test]
fn the_sub_register_view_is_actually_exercised() {
    let (_, out) = run_diff(COMP, "reg32");
    assert!(
        out.summary.reg32_checked > 0,
        "alu32 pieces must produce a distinct 32-bit view, or the axis is decorative"
    );
}

/// The denominator. This is the widest runtime denominator any leg has produced, and it
/// is what makes a zero finding count mean something here.
#[test]
fn the_corpus_reaches_the_oracles_in_bulk() {
    let (norm, out) = run_diff(COMP, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    assert_eq!(
        COMP.matches("RESULT decision=accept").count(), ACCEPTED,
        "the corpus is fixed by its seeds, so this count is reproducible"
    );
    eprintln!(
        "COMP locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert!(
        out.summary.store_locations_checked >= 3800,
        "the runtime oracles must actually be fed: got {}",
        out.summary.store_locations_checked
    );
    assert_eq!(
        out.summary.prune_pairs_checked as usize, PROGRAMS,
        "and every program is usable for the kernel-vs-kernel differential"
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// NOVELTY, which is the entire point: the corpus must contain compositions no
/// hand-written family produced. A generator that emitted one shape forty-eight times
/// would pass every other test here and prove nothing.
#[test]
fn the_corpus_contains_shapes_no_hand_written_family_produced() {
    let all = recipes();
    assert_eq!(all.len(), PROGRAMS, "every program declares its recipe");
    let distinct: BTreeSet<&String> = all.iter().collect();
    assert!(
        distinct.len() >= 80,
        "the walk must actually vary: only {} distinct recipes", distinct.len()
    );
    let kinds: BTreeSet<&str> = all
        .iter()
        .flat_map(|r| r.split(',').filter(|k| !k.is_empty()))
        .collect();
    assert!(
        kinds.len() >= 14,
        "every piece in the pool must actually be reachable from the walk: {kinds:?}"
    );
    let mixed = all
        .iter()
        .filter(|r| {
            let kinds: BTreeSet<&str> = r.split(',').filter(|k| !k.is_empty()).collect();
            kinds.contains("dynptr") && kinds.len() >= 3
        })
        .count();
    assert!(
        mixed > 0,
        "at least one program must combine a dynptr slice with two other piece kinds — \
         that is a shape no earlier family could emit at all"
    );
}

/// THE FOURTH HEALTH METRIC: combination diversity. "Every piece is reachable" is not
/// enough, because the bug classes this project is aimed at live in the INTERACTION of two
/// or more features — so what matters is how much of the piece-COMBINATION space the walk
/// realises, not how often each piece appears.
///
/// Measuring it changed the generator. A uniform walk saturated the adjacent PAIR space
/// immediately (every achievable pair, with the only two missing — dynptr after dynptr and
/// iter after iter — impossible by construction, since each is emitted at most once per
/// program), but reached just 35% of the achievable adjacent TRIPLES: 235 of 679. So the
/// frontier was one level above where the metric was first aimed. The walk now prefers a
/// piece that completes an unseen triple, then an unseen pair, then anything, with ties
/// broken by the seeded RNG so the corpus stays reproducible — and recipes start at three,
/// because a two-piece recipe contributes no triple at all. Triples went 35% -> 87%.
/// Pieces `comp_can` permits at most once per program, so a combination repeating one of
/// them is unreachable by construction and must not count against coverage.
const ONCE_ONLY: &[&str] = &["dynptr", "iter", "call", "dynskb", "ringbuf", "skref"];

fn achievable(kinds: &[&str], arity: usize) -> usize {
    let n = kinds.len();
    let total = n.pow(arity as u32);
    (0..total)
        .filter(|i| {
            let mut idx = *i;
            let mut combo = Vec::with_capacity(arity);
            for _ in 0..arity {
                combo.push(kinds[idx % n]);
                idx /= n;
            }
            ONCE_ONLY
                .iter()
                .all(|o| combo.iter().filter(|k| *k == o).count() <= 1)
        })
        .count()
}

#[test]
fn the_walk_covers_the_combination_space_not_just_the_pieces() {
    let owned: Vec<Vec<String>> = recipes()
        .iter()
        .map(|r| r.split(',').filter(|k| !k.is_empty()).map(str::to_string).collect())
        .collect();
    assert!(
        owned.iter().all(|r| r.len() >= 3),
        "a two-piece recipe contributes no triple, so the walk must not emit one"
    );
    let all: Vec<Vec<&str>> =
        owned.iter().map(|r| r.iter().map(String::as_str).collect()).collect();
    let kinds: Vec<&str> = {
        let set: BTreeSet<&str> = all.iter().flatten().copied().collect();
        set.into_iter().collect()
    };
    let pairs: BTreeSet<(&str, &str)> =
        all.iter().flat_map(|r| r.windows(2).map(|w| (w[0], w[1]))).collect();
    let triples: BTreeSet<(&str, &str, &str)> =
        all.iter().flat_map(|r| r.windows(3).map(|w| (w[0], w[1], w[2]))).collect();
    let ap = achievable(&kinds, 2);
    let at = achievable(&kinds, 3);
    eprintln!(
        "COMP pieces={} pairs={}/{} triples={}/{}",
        kinds.len(), pairs.len(), ap, triples.len(), at
    );
    // RELATIVE, not absolute. The achievable triple space grows as N^3 with the pool — 679
    // at nine pieces, 916 at ten — so a fixed threshold would fire a false alarm on every
    // addition even while the absolute number of realised triples RISES (592 -> 645 when
    // `call` joined). The corpus is expected to grow with the pool; what must hold is the
    // FRACTION of the reachable space the walk actually visits.
    assert_eq!(
        pairs.len(), ap,
        "every adjacent pair the requirements allow must be realised"
    );
    assert!(
        triples.len() * 100 >= at * 85,
        "the coverage-directed walk must reach most of the achievable triples, or the \
         corpus is exploring a corner of the combination space: {}/{}",
        triples.len(), at
    );
}

/// Determinism: a finding has to be replayable, so every program carries the seed that
/// produced it.
#[test]
fn every_program_carries_the_seed_that_produced_it() {
    let seeds: Vec<&str> = COMP
        .lines()
        .filter(|l| l.starts_with("COMP "))
        .filter_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("seed=")))
        .collect();
    assert_eq!(seeds.len(), PROGRAMS);
    assert_eq!(
        seeds.iter().collect::<BTreeSet<_>>().len(), PROGRAMS,
        "distinct seeds, so a single program can be replayed on its own"
    );
}

/// The teeth, on a randomly composed program rather than a designed one.
///
/// The planted site has to be provably OUTSIDE the claim, and a fixed value is not: an
/// earlier version planted 63 and it stopped firing as soon as the corpus happened to pick
/// a program whose proven window legitimately reached 63 (a narrowing bound of 15 puts the
/// store base at 48, so [48,63] admits it). The site is now derived from the program's own
/// declared store offset — one byte BELOW it — which `admits` rejects for any non-negative
/// pointer offset, because it requires the landing site to be at or above the base.
#[test]
fn the_oracle_has_teeth_on_a_composed_program() {
    let mut target: Option<(String, i64)> = None;
    for block in COMP.split("===PROG ").skip(1) {
        if !block.contains("RESULT decision=accept") {
            continue;
        }
        let declared: i64 = match block
            .lines()
            .find(|l| l.starts_with("STORE "))
            .and_then(|l| l.split_whitespace().find_map(|t| t.strip_prefix("off=")))
            .and_then(|v| v.parse().ok())
        {
            Some(v) => v,
            None => continue,
        };
        let stores = block
            .lines()
            .any(|l| l.starts_with("RUNTIME input=0x00000000 store_off=")
                && !l.contains("store_off=none"));
        if declared > 0 && stores {
            target = Some((block.split_whitespace().next().unwrap().to_string(), declared));
            break;
        }
    }
    let (label, declared) = target.expect("some accepted program stores at a positive offset");
    let planted = format!(
        "store_off={} store_len=1 store_size=1 executed=1", declared - 1);
    let mut text = String::new();
    let mut hit = false;
    for block in COMP.split("===PROG ").skip(1) {
        text.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        for line in block.lines() {
            if blabel == label && line.starts_with("RUNTIME input=0x00000000 ") && !hit {
                text.push_str(&format!("RUNTIME input=0x00000000 {planted}"));
                hit = true;
            } else {
                text.push_str(line);
            }
            text.push('\n');
        }
    }
    assert!(hit, "planting target {label} not found");
    let (_, out) = run_diff(&text, "teeth");
    assert!(
        out.findings.iter().any(|f| f.kind == "store_location_desync"),
        "a landing site below the store's own base must fire on a composed program too: \
         {label} declared off={declared}, planted {}: {:?}",
        declared - 1, out.findings
    );
}

#[test]
fn composition_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(COMP, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}

/// THE FOURTEENTH PIECE, `relink` (devlog 0069) — and the only one whose shape was named
/// by a real bug rather than by reading the verifier.
///
/// Calibration pair five (af9e89d8dd39, devlog 0068) returned two things. The first was a
/// boundary: an over-rejection is invisible to every consistency invariant we own. The
/// second is this — the INPUT SHAPE that produced it, which no family of ours generated:
///
///     rB = rA ; rB += 4          a delta-link
///     if rB > k1+4 goto exit     the SYNC that stamps the base on a buggy kernel
///     rC = rA                    the SECOND link, which re-mints the base's id there
///     if rB > k2+4 goto exit     a tighter bound that only reaches the base if it survived
///
/// The piece emits the whole sequence itself rather than hoping the walk places a narrow on
/// the right register — which register CP_NARROW picks is random, so as separate pieces the
/// shape would essentially never assemble.
///
/// It is DECISION-RELEVANT by construction: the epilogue's store offset is computed from
/// the second, tighter bound, so a verifier that lost the link keeps the looser one and
/// rejects the store. The shape therefore reaches the oracle through the ordinary verdict,
/// with no new channel needed.
#[test]
fn the_relink_shape_that_a_real_bug_named_is_actually_generated() {
    let all = recipes();
    let with_relink = all.iter().filter(|r| r.split(',').any(|k| k == "relink")).count();
    assert!(
        with_relink >= 50,
        "the shape calibration pair five named must be a real part of the corpus, not a \
         token appearance: {with_relink} of {}",
        all.len()
    );
    // And it must COMBINE, not just appear — a piece that only ever runs alone tests the
    // shape but not the composition the generator exists for.
    let combined = all
        .iter()
        .filter(|r| {
            let ks: BTreeSet<&str> = r.split(',').filter(|k| !k.is_empty()).collect();
            ks.contains("relink") && ks.len() >= 3
        })
        .count();
    assert!(combined >= 30, "relink must appear alongside other pieces: {combined}");

    // The sequence itself, read out of a capture: link, delta, sync, second link. The
    // compound id is the kernel's own rendering of the class, so its presence next to a
    // plain id is what proves the class was built at all.
    assert!(
        COMP.contains("id=1+4"),
        "a delta-linked class must actually be printed by the verifier"
    );
}

// ---------------------------------------------------------------------------
// THE PIECE'S OWN TEETH (devlog 0069): does `relink` actually discriminate on the bug
// whose shape it encodes?
//
// A piece that merely APPEARS in the corpus proves nothing. The whole 896-program corpus
// was run twice — once on bpf-next tip, once on a kernel built from `af9e89d8dd39~1` with
// the same config — and the verdicts matched by seed. Measured:
//
//     programs matched by seed        896     (recipes identical on both kernels, so the
//     verdict flips                     7      generator is kernel-independent and the
//       ... whose recipe has relink     7      comparison means what it says)
//       ... without relink              0
//     direction                    accept -> reject, all seven
//
// SPECIFICITY IS PERFECT AND SENSITIVITY IS LOW, and both numbers are honest. None of the
// 598 programs without the piece flipped: nothing else in the corpus is sensitive to this
// bug. Only 7 of 298 relink programs did, because the shape reaches the verdict only when
// relink is the LAST bound-establishing piece and the epilogue happens to build its store
// pointer from the class base. That is the nature of a random composition generator: the
// shape is present at a rate, not guaranteed.
//
// The two fixtures below are those seven programs from each kernel — the corpora
// themselves are 15-17 MB and are not committed twice.
// ---------------------------------------------------------------------------

const FLIP_FIXED: &str = include_str!("fixtures/calibration/relink-flips-fixed.log");
const FLIP_BUGGY: &str = include_str!("fixtures/calibration/relink-flips-buggy.log");

/// The mechanism, read out of the two logs at the same instruction — this is the
/// commit's own story reproduced by a program the GENERATOR wrote, not a transcribed
/// selftest.
///
///   fixed:  65: if r9 > 0x10  ; R6=scalar(id=8,...umax=12)   base narrowed through the class
///           66: r7 = r6       ; R6=scalar(id=8,...umax=12)   id STAYS 8
///           67: if r9 > 0xf   ; R6=scalar(id=8,...umax=11)   and tightens again
///           69: *(u8 *)(r8+52) with R8 umax=11  ->  52+11 = 63, the last valid byte
///
///   buggy:  66: r7 = r6       ; R6=scalar(id=9,...) R7=scalar(id=9,...)   id RE-MINTED
///           67: if r9 > 0xf   ; R6 not updated at all — the link is gone
///           69: the same store now reaches 52+12 = 64, one past a 64-byte value
#[test]
fn the_relink_piece_discriminates_on_the_kernel_that_had_the_bug() {
    let fixed_progs = FLIP_FIXED.matches("===PROG ").count();
    let buggy_progs = FLIP_BUGGY.matches("===PROG ").count();
    assert_eq!((fixed_progs, buggy_progs), (7, 7));

    // Every one of them accepts on the fixed kernel and rejects on the buggy one.
    assert_eq!(FLIP_FIXED.matches("RESULT decision=accept").count(), 7);
    assert_eq!(FLIP_BUGGY.matches("RESULT decision=reject").count(), 7);

    // Every one of them contains the piece.
    assert_eq!(FLIP_FIXED.matches("relink").count() >= 7, true);

    // And the rejection is the expected one: the store runs off the end of the map value
    // because the base kept the looser bound.
    assert!(
        FLIP_BUGGY.contains("invalid access to map value")
            || FLIP_BUGGY.contains("max value is outside of the allowed memory range"),
        "the buggy kernel must reject on BOUNDS, which is the consequence the broken link \
         produces — any other reason means this fixture is measuring something else"
    );

    // The id re-mint itself, which is the bug: the same `rX = base` instruction leaves the
    // base's id alone on one kernel and replaces it on the other.
    assert!(FLIP_FIXED.contains("66: (bf) r7 = r6                      ; R6=scalar(id=8,"));
    assert!(FLIP_BUGGY.contains("66: (bf) r7 = r6                      ; R6=scalar(id=9,"));
}
