//! COVERAGE-GUIDED CONTINUOUS FUZZING (devlog 0078) — the throughput leg.
//!
//! The strategic position: after seven calibration pairs the ORACLE stopped being the
//! bottleneck. Volume and aim became it, and the honest estimate of finding anything in
//! another batch-sized run was low single digits. This mode trades batch runs for a loop
//! that keeps and perturbs whatever reaches new verifier code.
//!
//! WHAT IS MUTATED IS THE GENOME, NOT THE BYTECODE. Byte-level mutation produces
//! mostly-malformed programs the verifier discards before any oracle sees them — the
//! denominator-zero trap one layer above the ones 0041-0050 kept finding, and the reason
//! 0054 built a typed walk in the first place. Perturbing genes keeps every mutant inside
//! the grammar.
//!
//! Coverage decides only what is KEPT; every program is still judged by the oracle whose
//! reference is not the verifier.

const SMOKE: &str = include_str!("fixtures/calibration/fuzz-smoke.log");

fn field(line: &str, key: &str) -> u64 {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in {line}"))
        .trim_end_matches(|c: char| !c.is_ascii_digit())
        .parse()
        .unwrap_or_else(|_| panic!("bad {key} in {line}"))
}

fn status_lines() -> Vec<&'static str> {
    SMOKE.lines().filter(|l| l.starts_with("STATUS ")).collect()
}

/// THE THROUGHPUT, which is the whole point of the leg.
///
/// Measured on a 240-second budget: ~456k programs loaded and ~3.6M return values compared
/// against the independent reference — roughly 1900 programs a second. The previous mode
/// managed 4096 programs a run.
#[test]
fn the_loop_runs_at_a_useful_rate() {
    let last = status_lines().last().copied().expect("status lines");
    let iters = field(last, "iters=");
    let elapsed = field(last, "elapsed=").max(1);
    let compared = field(last, "compared=");
    // The floor moves down when a gene buys something, and 0095's iterator gene bought the
    // kfunc surface: seen_pcs 5369 -> 6168, and the verification pass 30.3% -> 35.8%. Three
    // kfunc calls plus a real back-edge are not free, so the rate drops; the coverage and
    // depth assertions elsewhere are what stop this from becoming a licence to be slow.
    assert!(iters > 80_000, "only {iters} iterations");
    assert!(iters / elapsed > 500, "only {} programs/sec", iters / elapsed);
    assert!(compared > iters, "every accepted program must contribute several comparisons");
}

/// THE FEEDBACK ACTUALLY FEEDS BACK: coverage grows, and the corpus grows with it.
#[test]
fn coverage_and_corpus_both_grow() {
    let ss = status_lines();
    let first = ss.first().unwrap();
    let last = ss.last().unwrap();
    assert!(field(last, "seen_pcs=") > field(first, "seen_pcs="));
    assert!(field(last, "corpus=") > field(first, "corpus="));
    assert!(SMOKE.contains("CORPUS n=1 "), "the first keep must be recorded");
    // Monotone: the seen-set only grows and the corpus only grows.
    let mut pcs = 0;
    let mut corp = 0;
    for l in &ss {
        assert!(field(l, "seen_pcs=") >= pcs);
        assert!(field(l, "corpus=") >= corp);
        pcs = field(l, "seen_pcs=");
        corp = field(l, "corpus=");
    }
}

/// THE CEILING, AND WHAT MOVES IT (devlog 0079, 0080).
///
/// 0078's version asserted `reject == 0` and said that if it ever became non-zero the
/// grammar had gained a decision surface and the ceiling should be re-measured. It has now
/// been re-measured twice, and the pattern is the point:
///
///     grammar                       coverage   rejections
///     scalar only (0078)             4789        0%
///     + map-value store (0079)       4942       23%
///     + var-offset stack (0080)      5188       39%
///     + atomic RMW (0081)            5251       29%
///     + MOVSX, +2 oracles (0082)     5203       30%
///     + diamonds, counted loop(0084) 5406       29%
///
/// Each new KIND of memory adds roughly 150-250 PCs; more programs add none. The limit is
/// the number of distinct memory kinds the grammar can express, not the number of programs
/// it emits — which is why the next lift is packet pointers rather than a longer run.
///
/// The plateau is real rather than an artefact: `trunc=0` says no load ever filled the KCOV
/// buffer, so nothing was lost to truncation. Without that check "we plateaued" and "we
/// overflowed" would look identical.
///
/// NOTE the cost, recorded rather than hidden: rejections buy coverage and spend
/// throughput, because a rejected program never reaches the oracle. Comparisons fell from
/// 3.17M to 2.36M as rejections rose from 23% to 39%. There is a point past which more
/// decision surface stops paying, and this is the number that will show it.
#[test]
fn the_ceiling_is_set_by_memory_kinds_not_by_program_count() {
    let ss = status_lines();
    let last = ss.last().unwrap();
    let acc = field(last, "accept=");
    let rej = field(last, "reject=");
    assert!(rej > 0 && rej < acc, "two-sided decision surface: accept {acc}, reject {rej}");
    assert!(
        field(last, "seen_pcs=") > 5_150,
        "the ceiling should sit around the 5200-5250 the memory-kind additions reached"
    );
    // A load that fills the KCOV buffer loses coverage, and lost coverage looks exactly
    // like a plateau — so this is watched rather than assumed. Atomics lengthened the
    // longest programs enough for a single load to reach the cap; one in half a million
    // does not move the number, but a rising count would mean the ceiling is the BUFFER.
    assert!(
        field(last, "trunc=") * 100_000 < field(last, "iters="),
        "truncated loads are no longer negligible: {} of {}",
        field(last, "trunc="), field(last, "iters=")
    );
    // The corpus must keep growing too: a ceiling that rose without new keeps would mean
    // the coverage came from noise rather than from programs worth mutating.
    assert!(field(last, "corpus=") > 120, "corpus {}", field(last, "corpus="));
}

/// The run must refuse rather than degrade. Without KCOV this would still LOOK like
/// fuzzing while being a plain random walk.
#[test]
fn the_loop_refuses_to_run_without_feedback() {
    assert!(!SMOKE.contains("FUZZ abort"), "the smoke run aborted");
    assert!(SMOKE.contains("FUZZ start"), "no start line");
    assert!(SMOKE.contains("FUZZ done"), "the run did not finish cleanly");
}

/// THREE ORACLES, AND WHY NOT THE ONE THAT WAS SUGGESTED (devlog 0082).
///
/// Screening all 21 reconstructable historical verifier fixes against this fuzzer gave a
/// number worth keeping: **14 of 21 would have been found** — triggerable by the grammar
/// AND caught by an oracle. Of the seven that would not, three are triggerable TODAY and
/// still invisible, because they are cross-state pruning defects that no single-state check
/// can see by construction.
///
/// The screening's suggested cure was a kernel-VERSION verdict differential. That was
/// declined, and the reason is a result this project already owns: 0068 established that
/// two kernel versions are ALLOWED to disagree on a verdict, since precision changes every
/// release — so a version flip is evidence only when you already know which side is the bug.
/// It calibrates; it cannot hunt.
///
/// What IS sound is a differential against the SAME kernel under a flag that must not change
/// the answer. `BPF_F_TEST_STATE_FREQ` only intensifies checkpointing, so a verdict flip
/// means a prune decided something the unpruned walk did not — exactly the invisible class.
/// `BPF_F_TEST_REG_INVARIANTS` promotes the kernel's own bounds assertion to a hard fault.
/// The resource direction is excluded, because state-freq inflates the state count by
/// construction and a flagged rejection on a complexity limit is the instrument's own
/// artefact (0042).
#[test]
fn the_expensive_oracles_run_and_cost_little() {
    let last = status_lines().last().copied().unwrap();
    // Both counters must be PRESENT — a run whose extra oracles never executed would report
    // the same zero as a run where they executed and found nothing.
    assert!(last.contains("pruneflip="), "the pruning differential must be reported");
    assert!(last.contains("invfault="), "the invariant channel must be reported");
    assert_eq!(field(last, "pruneflip="), 0);
    assert_eq!(field(last, "invfault="), 0);

    // AND THE DENOMINATOR, which 0042 made non-negotiable and 0083 supplied here. A pair
    // counts only once BPF_F_TEST_STATE_FREQ demonstrably WIDENED the state space; two
    // verdicts from identical explorations prove nothing about pruning. Without this,
    // `pruneflip=0` would mean "0 out of 0" while reading exactly like "0 out of many" —
    // the 0025 trap, arriving in the newest instrument.
    // The threshold falls as programs get longer and slower to verify — 43k pairs at 8-gene
    // genomes, 17k at 6-20. Fewer pairs, but each one is a deeper exploration: the point of
    // 0085 was that a large count of trivial comparisons is worth less than a smaller count
    // of real ones.
    assert!(
        field(last, "prunepairs=") > 10_000,
        "the pruning differential must actually be evaluated, not merely reported: {}",
        field(last, "prunepairs=")
    );

    // THE LIVENESS GATE, on the highest-volume input this project has (0094). 0088 built the
    // oracle and 0089 calibrated it against a real bug, but until now it ran only on the
    // hand-built families: the widest denominator in the project was attached to the
    // narrowest input. Wired into the gated sample it produces more cells in three minutes
    // than the entire 896-program composition corpus does — so this floor is deliberately
    // far above what the corpus can reach, and would fail loudly if the hook were dropped.
    assert!(
        field(last, "livecells=") > 100_000,
        "the liveness gate must actually be evaluated on the fuzz corpus: {}",
        field(last, "livecells=")
    );
    assert!(field(last, "liverows=") > 10_000, "{}", field(last, "liverows="));
    assert_eq!(field(last, "livemiss="), 0, "a liveness-gate overreach is a finding");
    // HONEST SCOPE next to the zero. The fuzz grammar emits no kfuncs and no subprogram
    // calls, so `bpflive.h` models all of it; if a future grammar addition changes that, this
    // number moves and the denominator above must be read against it rather than alone.
    assert_eq!(
        field(last, "liveunsup="),
        0,
        "every fuzz program is inside the model today; if that changes, say so in the leg"
    );

    // THE KFUNC SURFACE (0095). [[coverage-fraction]] measured that kfunc/BTF calls held
    // 1318 of the verification pass's coverage points — 13% of it, four times the next
    // largest theme — and that the grammar had never emitted one. The iterator gene is the
    // way in, and the assertion is that it actually fires: a gene that is in the enum but
    // never emitted would leave every number below unchanged and look exactly like success.
    assert!(
        field(last, "iteremitted=") > 10_000,
        "the iterator gene must actually reach programs: {}",
        field(last, "iteremitted=")
    );
    // Coverage is the point of the gene, so it carries a floor of its own. 5369 PCs was the
    // number immediately before it; anything at or below that means the surface did not open.
    assert!(
        field(last, "seen_pcs=") > 5_800,
        "the kfunc surface must show up as coverage: {}",
        field(last, "seen_pcs=")
    );
    // The resource direction is excluded by construction rather than by luck: state-freq
    // inflates the state count, so a flagged rejection on a complexity limit is the
    // instrument's own artefact. Counted so its absence is a measurement, not an assumption.
    assert!(last.contains("pruneartifact="));

    // And they must be affordable. Ungated they cost 2.5x (511k iterations became 202k);
    // reserved for programs that reached new coverage, plus a one-in-eight sample, the loop
    // runs at 424k — a ~17% toll instead of 60%.
    let iters = field(last, "iters=");
    // The gated path does two log_level=1 loads (the state count lives only in the log),
    // and 0084's loops make some programs genuinely more expensive to VERIFY — deeper
    // exploration is the point, and it is not free. Recorded as a floor rather than a
    // target: 511k with no extra oracles, 202k ungated, 424k gated, 250k once the grammar
    // could loop, 140k once 0085 raised the genome to 6-20 genes. Every drop here bought
    // depth (avgstates 1 -> 3, maxstates 8 -> 46); the floor moves DOWN deliberately, and
    // it is the depth assertions above that stop this from becoming a licence to be slow.
    // ... and 100k once 0095 put three kfunc calls and a back-edge into 59% of programs,
    // which is what opened the largest unreached theme in the coverage map.
    assert!(iters > 80_000, "the gating did not recover throughput: {iters}");
}

/// A NON-ZERO DENOMINATOR IS NOT ENOUGH IF THE COMPARISONS ARE TRIVIAL (devlog 0084).
///
/// 0083 gave the pruning differential a denominator — 43,379 pairs where
/// BPF_F_TEST_STATE_FREQ demonstrably widened the state space — and reported zero flips.
/// Measuring how DEEP the search actually went turned that number over: `avgstates=1`. The
/// verifier was exploring essentially ONE state per program, so those were 43,379 trivial
/// comparisons. Pruning had nothing to decide.
///
/// It is the same lesson 0076 learned about constants — "a constant is not a check, it is a
/// tautology" — one level up: a one-state exploration is not a prune. A denominator counts
/// comparisons that RAN; this counts whether they could have said anything.
///
/// Two grammar additions supply the missing fuel. Diamonds make a branch RECONVERGE, so two
/// states meet inside the body rather than every branch running to the tail — the grammar
/// had been emitting ladders, and states_equal operates on meetings. A counted back-edge
/// then makes one instruction be reached repeatedly with different states; it is
/// deterministic, unlike `may_goto` whose time-based budget would break the closed-form
/// property the reference interpreter needs.
#[test]
fn the_search_is_deep_enough_for_pruning_to_mean_something() {
    let last = status_lines().last().copied().unwrap();
    assert!(last.contains("avgstates="), "the search depth must be reported at all");
    assert!(
        field(last, "avgstates=") >= 2,
        "at one state per program the pruning differential is counting comparisons that \
         cannot fail: avgstates={}",
        field(last, "avgstates=")
    );
    // The maximum matters too: an average of two with a maximum of two would mean every
    // program is the same shallow shape.
    let maxes = last
        .split_whitespace()
        .find_map(|t| t.strip_prefix("maxstates="))
        .expect("maxstates");
    let (base, freq) = maxes.split_once('/').expect("base/freq");
    let base: u64 = base.parse().unwrap();
    let freq: u64 = freq.parse().unwrap();
    assert!(base >= 8, "deepest base exploration only {base} states");
    assert!(freq > base * 2, "state-freq must widen the deep cases too: {base} -> {freq}");
}

/// THE SUBSUMPTION MODEL ON THE FUZZ LOOP (leg 0105).
///
/// 0088 built the pruning-decision reference, 0101-0103 calibrated it against three real
/// kernel bugs on three different arms — and through all of that it ran only on hand-built
/// families: 2,038 prune pairs per 896-program corpus run, evaluated offline from an 18 MB
/// capture. That is a calibration instrument, not a hunting one.
///
/// It could not simply be pointed at the fuzz loop: ~1.5 KB of prune-pair dump per program
/// at ~1900 programs/sec is ~10 GB of log per hour if the rows leave the VM. So the
/// comparison moved inside (`harness/bpfsubs.h`), exactly as the liveness gate did in 0094,
/// and only aggregates plus real disagreements come out.
///
/// Measured in 180 seconds: 24,901 pairs — twelve times the whole corpus, every three
/// minutes — of which 7,354 are non-trivial.
#[test]
fn subsumption_model_rides_the_fuzz_loop() {
    const SUBS: &str = include_str!("fixtures/calibration/fuzz-subs.log");
    let last = SUBS
        .lines()
        .rev()
        .find(|l| l.starts_with("FUZZ done"))
        .expect("a completed fuzz run");

    // ROWS FIRST, and this is the ambiguity that made the counter necessary: a stock kernel
    // carries no instrumentation and reports pairs=0, an instrumented kernel that pruned
    // nothing also reports pairs=0. Only `subsrows` separates them.
    assert!(
        field(last, "subsrows=") > 0,
        "no prune-pair rows seen at all — the run used a kernel without the instrumentation \
         patch, which is a different fact from a clean result: {last}"
    );
    assert!(
        field(last, "subspairs=") > 10_000,
        "the model must see fuzz-scale volume, not corpus-scale: {}",
        field(last, "subspairs=")
    );

    // THE DENOMINATOR, again. A pair whose every register short-circuited on precision
    // proves nothing; `subsnontrivial` counts the ones where range/tnum actually ran, and
    // it is the number a zero should be read against.
    assert!(
        field(last, "subsnontrivial=") > 1_000,
        "agreement on trivial pairs is not agreement: {}",
        field(last, "subsnontrivial=")
    );

    // A FORMAT THE IN-VM MODEL CANNOT READ MUST RAISE, NOT PASS. Zero here means every row
    // parsed; a non-zero would mean the loop was silently measuring less than it reported.
    assert_eq!(
        field(last, "subsunsup="),
        0,
        "the in-VM model refused rows it could not parse — the numbers above are then \
         reported against an incomplete denominator: {last}"
    );
    assert_eq!(field(last, "subsdisagree="), 0, "unexpected candidate: {last}");

    // THE SECOND CHECKPOINT POLICY (leg 0107). The model saw only the DEFAULT policy until
    // now, and 0103 measured what that hides: the heuristic declines a new state at a merge
    // until >=20 jumps or >=100 insns have passed, so the pair `--probe-wraparc2` needed did
    // not exist at all without TEST_STATE_FREQ. Every shape of that family was invisible.
    //
    // Measured over an hour: the forced policy yields 44% more pairs and 16% more
    // non-trivial ones (497,938 / 152,114 against 345,465 / 131,247), so the honest total
    // denominator rose from 197k to 283k on 13% FEWER programs. Buying distribution beat
    // buying hours — which is what 0106's saturation curve implied and this is its number.
    assert!(
        field(last, "subsfpairs=") > field(last, "subspairs="),
        "forcing checkpoints must yield MORE pairs than the default heuristic, or the second \
         load is paying throughput for nothing: {last}"
    );
    assert!(field(last, "subsfnontrivial=") > 1_000, "{last}");
    assert_eq!(
        field(last, "subsfunsup="),
        0,
        "the forced-policy rows must all parse too — a partial denominator on one policy \
         would make the two numbers incomparable: {last}"
    );
    assert_eq!(field(last, "subsfdisagree="), 0, "unexpected candidate (freq): {last}");
}
