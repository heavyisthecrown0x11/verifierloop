//! THE SUBSUMPTION MODEL'S OWN TEETH (devlog 0099/0100, reviewer bulgusu B1/B4).
//!
//! `scripts/subsume-check.py` is an independent implementation of `states_equal`'s scalar
//! arm — the project's first same-kernel reference for the PRUNING DECISION. Until this
//! file it was also the only oracle here with no test at all: `prunepair-sample.log` sat
//! in `tests/fixtures/volume/` next to 37 fixtures that are all `include_str!`-ed, and
//! nothing read it.
//!
//! That mattered, because the model shipped with a real transcription bug. The kernel does
//! the final comparison of `cnum_is_subset` in `ut` arithmetic, so the addition WRAPS
//! (`cnum_defs.h:244`); the model wrote the same line in Python, where it does not. The two
//! part company when `bigger.size == UT_MAX` and the rebased `smaller` wraps: kernel says
//! contained, model says not — a FALSE FINDING, and precisely on the wrapping arcs
//! `--probe-wraparc` is built to produce.
//!
//! THE RULE THIS FILE ENFORCES: a model's test must FAIL on the model's broken version.
//! A vector that passes on both sides is not a test of the bug, it is a vector that walks
//! past it. `SELFTEST_SUBSET`'s three wrap vectors fail on the unmasked model (measured:
//! `failed=3`, exit 1) and pass on the fixed one.
//!
//! The model is Python and this suite is Rust. It is invoked rather than ported ON PURPOSE:
//! a second implementation of the same predicate would be free to drift from the first, and
//! this project only benefits from independent implementations when the independence is
//! deliberate (`bpfref.h`, `bpflive.h`), never when it is an accident of language.
//!
//! If `python3` is missing the tests FAIL — they do not skip. A test that quietly skips is
//! the denominator-zero trap in another costume.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/pipeline must sit two levels under the repo root")
        .to_path_buf()
}

fn run_model(args: &[&str]) -> (String, bool) {
    let root = repo_root();
    let out = Command::new("python3")
        .arg(root.join("scripts/subsume-check.py"))
        .args(args)
        .current_dir(&root)
        .output()
        .expect("python3 must be available: the subsumption model is the only reference \
                 this project has for the pruning decision, so it is not optional");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.success(),
    )
}

fn field<'a>(text: &'a str, prefix: &str, key: &str) -> &'a str {
    let line = text
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{text}"));
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
        .unwrap_or_else(|| panic!("no field {key:?} on line {line:?}"))
}

/// The vectors, and the reason each one exists. Every vector is tied to a measured event.
#[test]
fn model_self_test_passes() {
    let (out, ok) = run_model(&["--self-test"]);
    assert!(
        ok,
        "the model's own vectors must pass; output was:\n{out}"
    );
    assert_eq!(
        field(&out, "SELFTEST", "failed="),
        "0",
        "vectors failed:\n{out}"
    );
    // Guard against the vectors quietly disappearing: a self-test that checks nothing
    // reports failed=0 just as loudly as one that checks everything.
    let vectors: usize = field(&out, "SELFTEST", "vectors=").parse().unwrap();
    assert!(
        vectors >= 20,
        "the vector set shrank to {vectors}; it pins B1 (wrap), the 2f2ec8e7730e base-id \
         cross-check, and the B3a liveness-gate GAP — losing one silently un-pins a limit"
    );
}

/// The orphan fixture, adopted. These numbers are a real capture from the 896-program
/// composition corpus, taken through `patches/prunepair-instrumentation.patch`.
#[test]
fn model_agrees_with_the_kernel_on_the_sample_capture() {
    let (out, ok) = run_model(&["crates/pipeline/tests/fixtures/volume/prunepair-sample.log"]);
    assert!(ok, "model run failed:\n{out}");

    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "50");
    assert_eq!(field(&out, "SUBSUME pairs=", "agree="), "50");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0");
    assert_eq!(field(&out, "SUBSUME pairs=", "unmodelled="), "0");
}

/// THE DENOMINATOR RULE, applied to this oracle (devlog 0066's guard, reviewer finding B3).
///
/// `agree=50` on its own is worth nothing: the precision short-circuit passes a register
/// without comparing it, so a pair can "agree" having computed nothing. The four terminal
/// categories must therefore partition the pairs, and the non-trivial half must be a
/// stated number rather than an implied one.
#[test]
fn denominator_partitions_the_pairs() {
    let (out, _) = run_model(&["crates/pipeline/tests/fixtures/volume/prunepair-sample.log"]);
    let pairs: usize = field(&out, "SUBSUME denominator", "pairs=").parse().unwrap();
    let trivial: usize = field(&out, "SUBSUME denominator", "trivial=").parse().unwrap();
    let nontrivial: usize = field(&out, "SUBSUME denominator", "nontrivial=").parse().unwrap();
    let breaks: usize = field(&out, "SUBSUME denominator", "breaks=").parse().unwrap();
    let unmodelled: usize = field(&out, "SUBSUME denominator", "unmodelled=").parse().unwrap();

    assert_eq!(
        field(&out, "SUBSUME denominator", "sums="),
        "ok",
        "the model must say so itself:\n{out}"
    );
    assert_eq!(
        trivial + nontrivial + breaks + unmodelled,
        pairs,
        "terminal categories do not partition the pairs:\n{out}"
    );
    assert_eq!(nontrivial, 31, "the sample's real denominator");
    assert!(
        trivial > 0,
        "a capture with no trivial pairs would mean the short-circuit never fired, which \
         contradicts every measurement since 0099 — suspect the parser, not the corpus"
    );
}

/// THE ARMS THE MODEL DOES NOT IMPLEMENT (reviewer finding B3). All three were measured
/// inert on the 896-program corpus, and none of them was written down. A silent
/// precondition is not a result; the first real disagreement has to eliminate these three
/// before it can be called a kernel finding, and that triage is only cheap if they are
/// counted.
#[test]
fn unimplemented_arms_are_counted_not_silent() {
    let (out, _) = run_model(&["crates/pipeline/tests/fixtures/volume/prunepair-sample.log"]);
    let line = out
        .lines()
        .find(|l| l.starts_with("SUBSUME unimplemented_arms"))
        .expect("the model must declare the arms it does not implement");

    for key in [
        "ptr_id_pairs=",                  // kernel seeds the idmap here, the model does not
        "dead_reg_cmps=",                 // comparisons the kernel never makes (liveness gate)
        "live_reg_cmps=",                 // its denominator
        "pairs_without_liveness_claim=",  // bpflive refused the program
        "pairs_without_tracked_reg=",     // claim exists, but the pair holds only r10
    ] {
        assert!(line.contains(key), "missing {key} in:\n{line}");
    }

    // refsafe() seeds the SAME idmap before any frame is walked, and the capture patch
    // prints neither refs[] nor active_lock_id — so this arm cannot be counted at all.
    // Saying that is the measurement.
    assert!(
        line.contains("refsafe_idmap_seed=not-observable-from-capture"),
        "the unobservable arm must still be named:\n{line}"
    );
}

// ---- PAIR THIRTEEN: `2f2ec8e7730e`, AND THE FIRST POSITIVE CALIBRATION OF THIS CHANNEL ----
//
// Every calibration before this one certified an oracle by making it fire on a planted
// violation, or measured a BOUNDARY where it could not fire at all. The pruning /
// cross-state channel had never had a positive: 0092 built `--probe-idbase` as the prune
// differential's first positive control and the differential reported NOTHING, because
// `BPF_F_TEST_STATE_FREQ` only makes pruning more aggressive and this bug is one the
// default checkpointing already takes (OI-15).
//
// The subsumption model sees it, and the reason it can is the distinction the channel
// verification drew: `2f2ec8e7730e` is a PREDICATE bug — sixteen lines wholly inside
// `check_scalar_ids`, corrupting no field the model reads — while `f54c7898ed1c`, the
// candidate this replaced, is a STATE bug (it corrupts `precise`, which the model reads
// from the capture and therefore inherits).
//
//     buggy `2f2ec8e7730e^`   unlinked: accept   linked: accept
//     fixed `2f2ec8e7730e`    unlinked: REJECT   linked: accept
//
// The pair the model objects to is the commit's own example, verbatim:
//
//     old   r2 id=1   r3 id=80000001 (delta=1)      base ids: 1 -> 1
//     cur   r2 id=1   r3 id=80000002 (delta=1)      base ids: 1 -> 2   <-- conflict
//
// The compound ids map cleanly (0x80000001 -> 0x80000002); only the BASE cross-check the
// fix added catches that `1` is already mapped to `1`. Without it the states compare equal
// and the verifier prunes a path it never proved.
//
// NOTE THE DENOMINATOR MOVES TOO, and that is confirmatory rather than incidental: the
// buggy capture carries TWO prune pairs, the fixed one carries ONE. On the fixed kernel
// `states_equal` returns false, so `hit:` is never reached and the prune event the model
// objected to does not exist. A calibration where the fixed side merely fell silent would
// be weaker than one where the event itself disappears.
//
// Captures: `--probe-idbase` on two kernels built from the same config, differing in the
// commit and in the era instrumentation patch (`patches/prunepair-instrumentation-minmax.patch`,
// which prints min/max because this revision predates cnum — see the era-floor typology).

const IDBASE_BUGGY: &str = include_str!("fixtures/volume/idbase-instr-buggy-2.log");
const IDBASE_FIXED: &str = include_str!("fixtures/volume/idbase-instr-fixed-1.log");

fn run_on_fixture(body: &str, tag: &str) -> String {
    // Unique per CALL, not per (pid, tag): these tests run in parallel inside one binary,
    // so two of them sharing a temp path race on write-then-delete. Found by running the
    // whole workspace — alone, this file passed.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("vl-subsume-{}-{n}-{tag}.log", std::process::id()));
    std::fs::write(&path, body).unwrap();
    let (out, ok) = run_model(&[path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "model run failed on {tag}:\n{out}");
    out
}

#[test]
fn pair_thirteen_fires_on_the_buggy_kernel() {
    let out = run_on_fixture(IDBASE_BUGGY, "buggy");

    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "1", "{out}");
    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "2", "{out}");

    // THE ARM IS THE CALIBRATION. A disagreement count alone does not close this: the
    // model has four known ways to disagree wrongly, and the whole point is that this one
    // lands on the predicate the commit repairs.
    let cand = out
        .lines()
        .find(|l| l.starts_with("SUBSUME candidate"))
        .expect("the buggy capture must name its candidate");
    assert!(
        cand.contains("arm=check_scalar_ids"),
        "the disagreement must be on the arm `2f2ec8e7730e` fixes, not another: {cand}"
    );

    // ...and the alternative explanations must be measured zero in the SAME output, so the
    // triage is read off the artifact rather than reconstructed later (reviewer B3).
    let arms = out
        .lines()
        .find(|l| l.starts_with("SUBSUME unimplemented_arms"))
        .unwrap();
    assert!(arms.contains("dead_reg_cmps=0"), "liveness gate not ruled out: {arms}");
    assert!(arms.contains("ptr_id_pairs=0"), "pointer-id idmap not ruled out: {arms}");
}

#[test]
fn pair_thirteen_is_silent_on_the_fixed_kernel() {
    let out = run_on_fixture(IDBASE_FIXED, "fixed");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0", "{out}");
    // The prune itself is gone, not merely tolerated.
    assert_eq!(
        field(&out, "SUBSUME pairs=", "pairs="),
        "1",
        "the fixed kernel must not reach `hit:` for the trigger at all:\n{out}"
    );
}

/// The era format is a second capture format, and a parser that silently failed to read it
/// would report `pairs=0 disagree=0` — indistinguishable from a clean kernel. This is the
/// 0065 lesson (a parser blind spot reads as a meaningless clean) applied in advance.
#[test]
fn era_captures_actually_parse() {
    for (body, tag, want_pairs) in [(IDBASE_BUGGY, "buggy", "2"), (IDBASE_FIXED, "fixed", "1")] {
        let out = run_on_fixture(body, tag);
        assert_eq!(field(&out, "SUBSUME pairs=", "unmodelled="), "0", "{out}");
        assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), want_pairs, "{out}");
        assert_ne!(
            field(&out, "SUBSUME nontrivial_pairs=", "scalar_comparisons="),
            "0",
            "a capture that parses but compares nothing is the denominator-zero trap:\n{out}"
        );
    }
}

// ---- PAIR FOURTEEN: `fd675184fc7a`, THE SECOND POSITIVE — AND ON A DIFFERENT ARM --------
//
// Pair thirteen calibrated `check_scalar_ids`. This one calibrates `range_within`, from a
// bug five years older, and it exists because the 0101 fan-out screened 40 historical
// state-quoting verifier fixes under the predicate/state typology and found exactly ONE the
// model could see. The screen's value was not the hit rate; it was that 23 of the 40 turned
// out to corrupt a field the model READS, which is a structural blindness, not a gap to
// close by trying harder.
//
// THE FIX IS FOUR ADDED COMPARISONS, nothing else:
//
//     +	       old->u32_min_value <= cur->u32_min_value &&
//     +	       old->u32_max_value >= cur->u32_max_value &&
//     +	       old->s32_min_value <= cur->s32_min_value &&
//     +	       old->s32_max_value >= cur->s32_max_value;
//
// so a jmp32-narrowed pair is judged on 64-bit bounds alone. The fields are written
// correctly; only the decision is wrong — which is exactly and only what this model can see.
//
// HAND-VERIFIED AGAINST THE COMMIT. The captured pair matches the bounds the maintainer
// quoted, field for field:
//
//     old r0  u64=0..ffffffffffffffff  s64=8000000000000000..7fffffffffffffff
//             u32=0..ffffffff          s32=80000000..3030
//     cur r0  u64=0..ffffffff7fffffff  s64=8000000000000000..7fffffff7fffffff
//             u32=3031..7fffffff       s32=3031..7fffffff
//
// old.s32_max (12336) >= cur.s32_max (2147483647) is false, so the eight-comparison form
// refuses. The four-comparison form sees only the 64-bit pairs, which hold, and prunes.
//
// THE VERDICT CHANNEL IS BLIND HERE, and that is the point: both kernels ACCEPT both arms.
// Upstream's reported consequence is a HANG (the unwalked branch is dead-code rewritten to
// `goto pc-1`), and a hang is observable by no oracle this project has — `run-harness-vm.sh`
// wraps the boot in `timeout … || true`, so it is indistinguishable from a slow round. The
// subsumption model is the only thing here that sees this bug at all.
//
// THE 2021 ERA IS A THIRD CAPTURE FORMAT (`patches/prunepair-instrumentation-2021.patch`):
// no exact_level, no cnum, no delta/BPF_ADD_CONST, and regsafe's scalar arm is a
// REG_LIVE_READ gate, a two-sided precision short-circuit, then range_within && tnum_in.
// The `live=` field is printed for the gate and doubles as the era marker — the row tells
// its consumer which regsafe it owes.

const JMP32_BUGGY: &str = include_str!("fixtures/volume/jmp32prune-instr-buggy-4.log");
const JMP32_FIXED: &str = include_str!("fixtures/volume/jmp32prune-instr-fixed-2.log");

#[test]
fn pair_fourteen_fires_on_the_buggy_kernel() {
    let out = run_on_fixture(JMP32_BUGGY, "j32buggy");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "2", "{out}");
    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "4", "{out}");

    // Both candidates must land on range_within — the arm the commit repairs. An equal
    // count on another arm would be a different bug, or ours.
    let cands: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("SUBSUME candidate"))
        .collect();
    assert_eq!(cands.len(), 2, "{out}");
    for c in &cands {
        assert!(c.contains("arm=range_within"), "wrong arm: {c}");
        assert!(c.contains("insn=7"), "wrong instruction: {c}");
    }

    // The era gate was applied, not guessed: this revision's regsafe opens with
    // `if (!(rold->live & REG_LIVE_READ)) return true;` and the capture prints `live=`.
    let arms = out
        .lines()
        .find(|l| l.starts_with("SUBSUME unimplemented_arms"))
        .unwrap();
    assert!(arms.contains("live_gated_regs=2"), "{arms}");
}

#[test]
fn pair_fourteen_is_silent_on_the_fixed_kernel() {
    let out = run_on_fixture(JMP32_FIXED, "j32fixed");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0", "{out}");
    // Same signature as pair thirteen: the objected-to prune does not merely become
    // tolerable, it stops happening. 4 pairs on the buggy kernel, 2 on the fixed one.
    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "2", "{out}");
    assert_ne!(
        field(&out, "SUBSUME nontrivial_pairs=", "scalar_comparisons="),
        "0",
        "a silent fixed side proves nothing if nothing was compared:\n{out}"
    );
}

/// SPECIFICITY. The two arms differ in ONE thing — whether the narrowing jumps are jmp32 or
/// jmp64 — and a 64-bit jump narrows the bounds the buggy `range_within` already compares.
/// So every disagreement must sit in the `jmp32` arm and none in `jmp64`. Without this the
/// count alone would not distinguish "the model found the bug" from "the model dislikes this
/// program shape".
#[test]
fn pair_fourteen_control_arm_is_clean() {
    let buggy_only_jmp64: String = JMP32_BUGGY
        .split("===PROG ")
        .filter(|blk| blk.starts_with("jmp32prune#fd675184fc7a#jmp64"))
        .map(|blk| format!("===PROG {blk}"))
        .collect();
    assert!(
        buggy_only_jmp64.contains("PRUNEPAIR"),
        "the control arm must itself produce a prune pair, or its silence is vacuous"
    );
    let out = run_on_fixture(&buggy_only_jmp64, "j32control");
    assert_eq!(
        field(&out, "SUBSUME pairs=", "disagree="),
        "0",
        "the control arm fired on the BUGGY kernel — the signal is not specific to the bug:\n{out}"
    );
}

// ---- PAIR SIXTEEN: `cd5b460ed1ec`, AND THE INPUT PROBLEM 0100 LEFT OPEN -----------------
//
// This one cost no kernel build. The buggy image already existed (0100 built
// `bzImage-instr-cn` at `cd5b460ed1ec~1`) and the oracle already implemented the predicate;
// what was missing for four legs was the INPUT. 0100 ended by naming the trigger's three
// conditions and failing to satisfy them together.
//
// CONDITION (c) IS WHY IT FAILED, and the failure was measured rather than guessed: 0100's
// arc crossed only the UT_MAX/0 boundary, so the s32 projection stayed [-16, 16] and the
// buggy min/max check refused correctly at `16 >= 272`. To blind min/max, every projection
// has to open to the full range, which needs an arc containing ST_MAX and ST_MIN too — i.e.
// covering more than half the space.
//
// A CONDITIONAL JUMP CANNOT BUILD THAT. Jumps narrow to contiguous intervals; "not in [a,b]"
// arrives as two separate states, never as one wrapping arc. The wrap must come from
// arithmetic, and then it is two instructions:
//
//     if w6 > 0x80000020 goto out      -- w6 in [0, 0x80000020], a span wider than 2^31
//     w6 += 0x7FFFFFF0                 -- rotate: cnum32{base=0x7FFFFFF0, size=0x80000020}
//
// which is the commit's own counterexample. Masking first — 0100's `&= 0x20; -= 0x10` — pins
// the low bits and then condition (a), tnum containment, fails before range_within is even
// consulted. The jump leaves them unknown, so (a) holds for free.
//
// MEASURED, and the captured pair is the commit's example verbatim:
//
//     old r6  r32 = {base=0x7ffffff0, size=0x80000020}   prec=1
//     cur r6  r32 = {base=0x100,      size=0x0}
//
// TEST_STATE_FREQ IS PART OF THE INPUT, NOT THE DETECTOR. Without it the default heuristic
// declines a checkpoint at the merge and both paths walk it independently — measured: 4
// pairs, `scalar_comparisons=0`, the only prune landing on r10 in the exit block. The flag
// creates the opportunity to ask; the decision under audit is still range_within's own, and
// the model — not a flag differential — is what reports it. That distinction is what OI-15
// is about.
//
// THE CONTROL is the same program with `if w6 > 0x20`, so the arc crosses only UT_MAX/0.
// There the buggy kernel's own min/max check refuses and the merge prune never happens —
// which is the specificity evidence: the prune appears only when the arc spans BOTH
// boundaries, i.e. exactly when min/max goes blind.
//
// `range_within` has not changed since `cd5b460ed1ec`, so tip is a valid fixed side here
// (the project's rule is that tip stands in only when nothing touched the code under test).

const WRAPARC2_BUGGY: &str = include_str!("fixtures/volume/wraparc2-instr-buggy-3.log");
const WRAPARC2_FIXED: &str = include_str!("fixtures/volume/wraparc2-instr-fixed-3.log");

#[test]
fn pair_sixteen_fires_on_the_buggy_kernel() {
    let out = run_on_fixture(WRAPARC2_BUGGY, "wa2buggy");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "1", "{out}");

    let cand = out
        .lines()
        .find(|l| l.starts_with("SUBSUME candidate"))
        .expect("the buggy capture must name its candidate");
    assert!(cand.contains("arm=range_within"), "wrong arm: {cand}");
    assert!(cand.contains("insn=17"), "the merge is insn 17: {cand}");

    // The comparison actually ran — a break with no scalar comparison would mean the model
    // refused on a type or id mismatch, which is a different claim entirely.
    assert_ne!(
        field(&out, "SUBSUME nontrivial_pairs=", "scalar_comparisons="),
        "0",
        "{out}"
    );
}

#[test]
fn pair_sixteen_is_silent_on_the_fixed_kernel() {
    let out = run_on_fixture(WRAPARC2_FIXED, "wa2fixed");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0", "{out}");
    // And again the event itself is gone rather than merely tolerated: with correct arc
    // containment the states are not equivalent, so the merge is never pruned and no scalar
    // is compared anywhere in the capture.
    assert_eq!(
        field(&out, "SUBSUME nontrivial_pairs=", "scalar_comparisons="),
        "0",
        "the fixed kernel must not prune the merge at all:\n{out}"
    );
}

/// THE ARC IS THE POINT, so pin its exact shape. If a future generator change quietly stops
/// producing a both-boundary arc, every assertion above still passes on a weaker input and
/// the calibration silently becomes vacuous — the same failure mode as a denominator that
/// goes to zero unnoticed.
#[test]
fn pair_sixteen_capture_carries_the_commits_own_arc() {
    assert!(
        WRAPARC2_BUGGY.contains("r32=7ffffff0+80000020"),
        "the buggy capture must contain cnum32{{base=0x7FFFFFF0, size=0x80000020}} — the \
         counterexample cd5b460ed1ec's message quotes"
    );
    assert!(
        WRAPARC2_BUGGY.contains("r32=100+0"),
        "and the second path's constant, which sits in that arc's gap"
    );
}

// ---- THE POINTER ARM (leg 0104) --------------------------------------------------------
//
// The 0101 fan-out named this gap: `states_equal`'s pointer arm was modelled by no oracle at
// all, and at least one historical bug lives there (`1ad2f5838d34`, 2017 — a wrong pruning
// decision inside `compare_ptrs_to_packet`). Until now the model PASSED every non-scalar
// register silently, which is the loose direction — it cannot manufacture a finding, but it
// also cannot see one, and worse, the ids on those registers never entered the idmap the
// scalar arm shares (reviewer finding B3c, measured at 273 exposed pairs).
//
// WHY THIS NEEDED A CAPTURE CHANGE. Every pointer arm in `regsafe` is built on a byte
// comparison, not a field comparison:
//
//     map_value family : memcmp(rold, rcur, offsetof(struct bpf_reg_state, var_off)) && ...
//     regs_exact       : memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) && ...
//
// and the bytes in between are a UNION whose members include kernel pointers (`map_ptr`,
// `btf`). A model that re-derived those fields would be guessing at a struct layout, and a
// guess is what this project refuses. So the patch prints the PREFIX itself and the model
// slices it — exact by construction, with `vo` marking where the shorter cut lands. `range`
// for the packet arms is read out of that same blob (the union's first member, bytes 8..12)
// rather than printed twice, so there is only one source of truth for it.
//
// MEASURED on the 896-program corpus, same capture as before plus the prefix:
//
//     before   other_type_regs=3818  ptr_cmps=0     (every pointer silently passed)
//     after    other_type_regs=0     ptr_cmps=3818  (every pointer through a modelled arm)
//     disagree 0 both ways · ptr_id_pairs 273 -> 0 · verdicts still 896/896 vs stock
//
// The two 3818s are the consistency check: the arms now run on exactly the registers that
// used to be skipped. And the fallback is retained on purpose — a capture without `pfx`
// still parses and still passes pointers, so every era variant and every fixture from legs
// 0101-0103 keeps working, with the skip COUNTED rather than silent.

const PTR_SAMPLE: &str = include_str!("fixtures/volume/prunepair-ptr-sample.log");

#[test]
fn pointer_arms_run_and_agree_on_a_real_capture() {
    let out = run_on_fixture(PTR_SAMPLE, "ptr");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0", "{out}");

    // THE DENOMINATOR. `disagree=0` from an arm that never executed is the zero this
    // project exists to refuse, so the arm's own count has to be positive and the skip
    // count has to be zero — the same pair of facts, stated from both sides.
    let n: usize = field(&out, "SUBSUME nontrivial_pairs=", "ptr_cmps=").parse().unwrap();
    assert!(n > 0, "the pointer arms must actually have run:\n{out}");
    assert_eq!(
        field(&out, "SUBSUME nontrivial_pairs=", "other_type_regs="),
        "0",
        "no pointer register may be skipped once the capture carries a prefix:\n{out}"
    );
}

/// The capture format is what makes the arm possible, so pin it: a prefix line per register
/// line. If the patch ever stops emitting it the arm silently reverts to passing everything
/// and `disagree=0` above still holds — vacuously.
#[test]
fn pointer_capture_carries_one_prefix_per_register() {
    let pfx = PTR_SAMPLE.lines().filter(|l| l.starts_with("PRUNEPAIR_PFX ")).count();
    let rows = PTR_SAMPLE.lines().filter(|l| l.starts_with("PRUNEPAIR insn=")).count();
    assert!(rows > 0, "fixture carries no prune pairs at all");
    assert_eq!(pfx, rows, "every register line needs its prefix line");
    assert!(
        PTR_SAMPLE.contains("PRUNEPAIR_PFX vo="),
        "the prefix must declare where offsetof(var_off) falls, or the short cut is a guess"
    );
}

/// The pre-prefix captures must keep working, with the skip COUNTED. This is what lets
/// pairs thirteen/fourteen/sixteen stay valid across the format change instead of being
/// re-run on a rebuilt kernel each time the capture grows a field.
#[test]
fn captures_without_a_prefix_fall_back_and_say_so() {
    let out = run_on_fixture(IDBASE_FIXED, "ptrfallback");
    assert_eq!(field(&out, "SUBSUME nontrivial_pairs=", "ptr_cmps="), "0", "{out}");
    assert_ne!(
        field(&out, "SUBSUME nontrivial_pairs=", "other_type_regs="),
        "0",
        "the fallback must COUNT what it skips:\n{out}"
    );
}

// ---- THE IN-VM MODEL, AND WHY ITS EQUIVALENCE IS A TEST (leg 0105) ----------------------
//
// `harness/bpfsubs.h` is a second implementation of the same predicate, in C, so the
// comparison can happen inside the VM. That is not a preference: 11,996 prune-pair rows per
// 896 programs is ~1.5 KB each, and at the fuzz loop's ~1900 programs/sec shipping them out
// is ~10 GB of log per hour, for a number. `bpflive.h` hit this exact wall in 0094.
//
// A SECOND IMPLEMENTATION IS A LIABILITY unless the two are pinned together. This project
// benefits from independent implementations only when the independence is DELIBERATE
// (`bpfref.h` against the JIT, `bpflive.h` against liveness.c); here it is forced by volume,
// which means the two must agree, and "must agree" has to be a test rather than a habit.
// The Python model stays the reference — it is the one calibrated against real kernel bugs
// (pairs thirteen, fourteen, sixteen) — and the C one is calibrated against it.
//
// Measured at the moment of writing, on the 896-program capture: both report
// pairs=2038 agree=2038 nontrivial=1017 scalar=1596 ptr=3818 shortcircuit=584, counter for
// counter. And on captures in an era format the C model cannot read, it REFUSES loudly
// (`unsup=11866` on the min/max capture, `unsup=24` on the 2021 one) instead of reporting
// the zero that would read as clean.

fn run_c_model(body: &str, tag: &str) -> String {
    let root = repo_root();
    let dir = std::env::temp_dir().join(format!("vl-subsdrv-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("subsdrv");
    let out = Command::new("cc")
        .args(["-O2", "-I"])
        .arg(root.join("harness"))
        .arg("-o")
        .arg(&bin)
        .arg(root.join("harness/subsdrv.c"))
        .output()
        .expect("cc must be available: the in-VM model is C, and an unbuildable second \
                 implementation cannot be shown equivalent to the reference one");
    assert!(
        out.status.success(),
        "bpfsubs.h failed to compile:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = dir.join("capture.log");
    std::fs::write(&log, body).unwrap();
    let run = Command::new(&bin).arg(&log).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    String::from_utf8_lossy(&run.stdout).into_owned()
}

/// THE EQUIVALENCE. Same capture, two implementations, every counter compared — not just
/// the verdict, because two models can agree on "clean" while disagreeing about how much
/// they looked at, and that difference is exactly what a denominator is for.
#[test]
fn the_c_model_matches_the_python_reference() {
    let py = run_on_fixture(PTR_SAMPLE, "equivpy");
    let c = run_c_model(PTR_SAMPLE, "equivc");

    for (pyline, pykey, ckey) in [
        ("SUBSUME pairs=", "pairs=", "pairs="),
        ("SUBSUME pairs=", "agree=", "agree="),
        ("SUBSUME pairs=", "disagree=", "disagree="),
        ("SUBSUME pairs=", "unmodelled=", "unmodelled="),
        ("SUBSUME nontrivial_pairs=", "nontrivial_pairs=", "nontrivial="),
        ("SUBSUME nontrivial_pairs=", "scalar_comparisons=", "scalar="),
        ("SUBSUME nontrivial_pairs=", "ptr_cmps=", "ptr="),
        ("SUBSUME nontrivial_pairs=", "shortcircuited_regs=", "sc="),
    ] {
        let a = field(&py, pyline, pykey);
        let b = field(&c, "pairs=", ckey);
        assert_eq!(a, b, "{pykey} differs: python={a} c={b}\npython:\n{py}\nc:\n{c}");
    }
}

/// A FORMAT THE C MODEL CANNOT READ MUST REFUSE, LOUDLY. The fuzz loop runs at tip, but the
/// era captures exist and will be re-run; a silent `pairs=0` from an unreadable capture is
/// the denominator-zero trap wearing the costume of a clean result.
#[test]
fn the_c_model_refuses_era_formats_instead_of_reporting_zero() {
    let c = run_c_model(IDBASE_BUGGY, "erarefuse");
    assert_eq!(field(&c, "pairs=", "pairs="), "0", "{c}");
    assert_ne!(
        field(&c, "pairs=", "unsup="),
        "0",
        "an unreadable capture must raise `unsupported`, not report a clean zero:\n{c}"
    );
    // ...and it must still say it SAW the rows, so "no instrumentation" stays
    // distinguishable from "instrumented and nothing pruned".
    assert_ne!(field(&c, "pairs=", "rows=").to_string(), "0", "{c}");
}
