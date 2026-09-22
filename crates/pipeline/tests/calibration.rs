//! CALIBRATION AGAINST A REAL VERIFIER BUG (devlog 0061).
//!
//! Every leg so far proved its oracle fires on a violation WE PLANTED. None ever proved
//! one fires on a bug the kernel actually had. Without that, eighteen legs of "clean" are
//! ambiguous: either bpf-next is sound on these surfaces, or our oracle has a blind spot.
//! This test removes the ambiguity for one bug class.
//!
//! THE BUG. Commit 3844d153a41a, "bpf: Fix insufficient bounds propagation from
//! adjust_scalar_min_max_vals" (2022-07-01), reported by Kuee K1r0a:
//!
//!   "a corner case where the tnum becomes constant after the call to
//!    __reg_bound_offset(), but the register's bounds are not, that is, its min bounds
//!    are still not equal to the register's max bounds. This in turn allows to LEAK
//!    POINTERS through turning a pointer register as is into an unknown scalar via
//!    adjust_ptr_min_max_vals()."
//!
//! It is a soundness bug, not an over-rejection, and its signature is precisely the
//! property this project has been checking for thirty legs. The two fixtures are the
//! kernel's OWN printed state, quoted verbatim from the commit's "Before:" and "After:"
//! logs — the differing line is the one the commit marks `<--- [*]`:
//!
//!   before:  9: (07) r3 += -32767  ; R3_w=scalar(imm=0,umax=1,var_off=(0x0; 0x0))
//!   after:   9: (07) r3 += -32767  ; R3_w=scalar(imm=0,umax=0,var_off=(0x0; 0x0))
//!
//! WHAT CALIBRATION FOUND, before any kernel was rebuilt — two blind spots, either of
//! which alone made the oracle unable to see this bug:
//!
//!   1. The parser did not accept the `R<n>_w=` register form that older kernels print,
//!      so NOTHING parsed and the denominator went silently to zero — `tnum_bounds_checked
//!      = 0` with `parser_unrecognized = 0`. The exact failure shape the denominator rule
//!      exists to catch, arriving from a new direction.
//!   2. The tnum-vs-bounds invariant only tested that the tnum's span INTERSECTS
//!      [umin, umax]. For the buggy state the span is [0,0] and the bounds are [0,1] —
//!      they intersect, so the check stayed silent even once the state parsed. The
//!      missing property is the stronger one the kernel checks itself under the same
//!      name: a CONSTANT tnum must PIN the bounds.
//!
//! Both are fixed, and this test keeps them fixed.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const BUGGY: &str = include_str!("fixtures/calibration/cve-3844d153a41a-buggy.log");
const FIXED: &str = include_str!("fixtures/calibration/cve-3844d153a41a-fixed.log");

/// The second pair, and a different KIND of calibration: captured by running the kernel
/// that had the bug, not quoted from a commit message. See the module note below.
const FR_BUGGY: &str = include_str!("fixtures/calibration/fakereg-92424801261d-buggy.log");
const FR_FIXED: &str = include_str!("fixtures/calibration/fakereg-92424801261d-fixed.log");

/// The third pair (devlog 0065): commit 049c4e13714e, on the pre-2022 LOG FORMAT.
const A32_BUGGY: &str = include_str!("fixtures/calibration/alu32-049c4e13714e-buggy.log");
const A32_FIXED: &str = include_str!("fixtures/calibration/alu32-049c4e13714e-fixed.log");

/// The fourth pair (devlog 0067): commit ae67b9fb8c4e. The buggy half is quoted from the
/// commit; the fixed half is a REAL capture from the current kernel (`--probe-sx`).
const SX_BUGGY: &str = include_str!("fixtures/calibration/sx-ae67b9fb8c4e-buggy.log");
const SX_FIXED: &str = include_str!("fixtures/calibration/sx-ae67b9fb8c4e-fixed.log");

/// The fifth pair (devlog 0068): commit af9e89d8dd39. BOTH halves are real captures, from
/// two kernels built from the same config — the first pair whose answer is a BOUNDARY.
const IL_BUGGY: &str = include_str!("fixtures/calibration/idlink-af9e89d8dd39-buggy.log");
const IL_FIXED: &str = include_str!("fixtures/calibration/idlink-af9e89d8dd39-fixed.log");

/// The sixth pair (devlog 0070): commit 811c363645b3, aimed at the RUNTIME channel — and
/// the measurement contradicted the prediction. Both halves are real captures.
const SP_BUGGY: &str = include_str!("fixtures/calibration/spill-811c363645b3-buggy.log");
const SP_FIXED: &str = include_str!("fixtures/calibration/spill-811c363645b3-fixed.log");

/// The seventh pair (devlog 0076): commit 3cf2b61eb067 — the SIGNED half of the property
/// pair one calibrated, which 0061 did not have.
const MV_BUGGY: &str = include_str!("fixtures/calibration/mov32-3cf2b61eb067-buggy.log");
const MV_FIXED: &str = include_str!("fixtures/calibration/mov32-3cf2b61eb067-fixed.log");

/// The EIGHTH pair (devlog 0087): commit 3878ae04e9fc — the first pair aimed at the
/// STORE-LOCATION channel, which 0041 named "the hunt" and which no real bug had ever
/// exercised. All three halves are real captures from `--probe-deltalink`.
///
/// `buggy` is 3878ae04e9fc~1 and `fixed` is 3878ae04e9fc itself, built from BYTE-IDENTICAL
/// .config files: the two kernels differ in the commit's four lines and nothing else. The
/// tip capture is kept separately because it is NOT a substitute for `fixed` — two further
/// fixes to the very same function (7a433e519364, bc308be380c1) landed after it, so a
/// silence at tip could belong to either of them.
const DL_BUGGY: &str = include_str!("fixtures/calibration/deltalink-3878ae04e9fc-buggy.log");
const DL_FIXED: &str = include_str!("fixtures/calibration/deltalink-3878ae04e9fc-fixed.log");
const DL_TIP: &str = include_str!("fixtures/calibration/deltalink-3878ae04e9fc-tip.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-cal-{}-{tag}", std::process::id()));
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

/// THE HEADLINE: the oracle catches a real verifier soundness bug, at the exact
/// instruction the fix commit marks.
#[test]
fn the_oracle_catches_the_real_bug() {
    let (_, out) = run_diff(BUGGY, "buggy");
    let hits: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind == "const_tnum_range_mismatch")
        .collect();
    assert_eq!(
        hits.len(), 1,
        "the state the buggy verifier printed must fire exactly once: {:?}", out.findings
    );
    assert!(
        hits[0].detail.contains("insn 9") && hits[0].detail.contains("r3"),
        "and at the instruction the commit marks with [*]: {}", hits[0].detail
    );
}

/// AND THE OTHER HALF: it does not fire on the fixed state. A check that fires on both
/// would prove nothing at all.
#[test]
fn the_oracle_stays_silent_on_the_fix() {
    let (_, out) = run_diff(FIXED, "fixed");
    assert_eq!(
        out.summary.finding_count, 0,
        "the corrected state is consistent and must not be reported: {:?}", out.findings
    );
}

/// The first blind spot, pinned: an older kernel's `R<n>_w=` form must parse, or the
/// denominator silently goes to zero and a calibration run reports a meaningless clean.
#[test]
fn the_older_register_form_parses_instead_of_silently_vanishing() {
    assert!(BUGGY.contains("R3_w="), "the fixture must use the older form");
    let (norm, out) = run_diff(BUGGY, "wform");
    assert!(
        out.summary.tnum_bounds_checked > 0,
        "a zero denominator here is the silent failure this test exists to prevent"
    );
    let states: usize = norm
        .records
        .iter()
        .flat_map(|r| r.core.register_evolution.iter())
        .map(|s| s.regs.len())
        .sum();
    assert!(states > 0, "no register state parsed at all");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}

/// The second blind spot, pinned as a property rather than a fixture: intersecting the
/// bounds is not enough, because the buggy tnum span [0,0] sits inside [0,1].
#[test]
fn intersecting_the_bounds_is_not_enough_to_catch_it() {
    use metrics::core::{RegState, Tnum};
    let buggy = RegState {
        reg: 3,
        reg_type: "scalar".to_string(),
        tnum: Tnum { value: 0, mask: 0 },
        umin: 0,
        umax: 1,
        ..Default::default()
    };
    // The old test: does the tnum span meet the bounds? It does — which is exactly why
    // the intersection check could never have caught this bug.
    let (lo, hi) = (buggy.tnum.value, buggy.tnum.value | buggy.tnum.mask);
    assert!(
        !(hi < buggy.umin || lo > buggy.umax),
        "the spans intersect, so a disjointness test stays silent on the real bug"
    );
    // The property that does catch it.
    assert!(
        buggy.umin != buggy.tnum.value || buggy.umax != buggy.tnum.value,
        "a constant tnum must pin both bounds"
    );
}

// ---------------------------------------------------------------------------------
// SECOND PAIR: 92424801261d, "bpf: Fix reg_set_min_max corruption of fake_reg" (2024-06)
//
// A different kind of calibration, and the reason it is worth the cost of a kernel build.
// The first pair could be read straight out of a commit message because the inconsistent
// state was printed as ordinary register state. This one cannot: the violating registers
// (true_reg2, false_reg1, false_reg2) live inside reg_set_min_max and are never printed
// that way — they appear only inside the kernel's own "REG INVARIANTS VIOLATION" message.
//
// So the detection channel is not a parsed state but a VERDICT: 0042's third load, where
// BPF_F_TEST_REG_INVARIANTS turns reg_bounds_sanity_check from warn-and-recover into a
// hard -EFAULT. Both fixtures are real captures — the same probe run against two kernels
// built from the same config, differing only in whether the fix is applied.
//
// HONEST SCOPE: this validates the REG_INVARIANTS channel end to end. It does NOT show
// that our parsed-state invariants would catch this bug — they cannot, because the
// corrupt registers are never printed as state. Two bugs, two channels; neither result
// transfers to the other.

fn accepted_and_inv(text: &str) -> (bool, String) {
    let line = text.lines().find(|l| l.starts_with("PRUNE ")).expect("a PRUNE line");
    let f = |k: &str| {
        line.split_whitespace()
            .find_map(|t| t.strip_prefix(k))
            .unwrap()
            .to_string()
    };
    (f("base_verdict=") == "accept", f("inv_reason="))
}

/// THE FIRING HALF, on the kernel that actually had the bug: the default load succeeds
/// while the REG_INVARIANTS load faults, and the pipeline turns that into a finding.
#[test]
fn the_instrument_catches_the_fake_reg_corruption_on_the_buggy_kernel() {
    let (base_ok, inv) = accepted_and_inv(FR_BUGGY);
    assert!(base_ok, "the buggy kernel accepts the program by default");
    assert_eq!(inv, "efault", "and faults under BPF_F_TEST_REG_INVARIANTS");
    assert!(
        FR_BUGGY.contains("REG INVARIANTS VIOLATION"),
        "the kernel says so itself, which is what makes this capture self-evidencing"
    );
    let (_, out) = run_diff(FR_BUGGY, "fr-buggy");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "reg_invariants_violation").count(), 1,
        "and the pipeline must report it exactly once: {:?}", out.findings
    );
}

/// THE SILENT HALF, on the fixed kernel: same probe, same config, only the fix differs.
#[test]
fn the_instrument_is_silent_on_the_fixed_kernel() {
    let (base_ok, inv) = accepted_and_inv(FR_FIXED);
    assert!(base_ok);
    assert_eq!(inv, "none", "no fault once the fix is in");
    assert!(!FR_FIXED.contains("REG INVARIANTS VIOLATION"));
    let (_, out) = run_diff(FR_FIXED, "fr-fixed");
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// The kernel's own diagnosis, pinned: the two properties it names are the two this
/// project checks under different names, which is why the channel is worth having.
#[test]
fn the_kernels_own_violation_names_our_two_invariants() {
    assert!(
        FR_BUGGY.contains("range bounds violation"),
        "an inverted unsigned range — our unsigned_bounds_inverted"
    );
    assert!(
        FR_BUGGY.contains("const tnum out of sync with range bounds"),
        "a constant tnum that does not pin its bounds — our const_tnum_range_mismatch, \
         the very property 0061 had to ADD"
    );
}

// ---------------------------------------------------------------------------
// PAIR THREE (devlog 0065) — commit 049c4e13714e, "bpf: Fix alu32 const subreg bound
// tracking on bitwise operations" (2021-05-10, reported by Manfred Paul).
//
// THE BUG. `scalar32_min_max_and/or/xor()` delegated the 32-bit bound update to
// `scalar_min_max_*()`, which only actually does it when BOTH 64-bit registers are
// known constants. So for a register whose LOW half is constant while the full 64-bit
// value is not, the 32-bit bounds were left stale — and the commit's own log shows them
// landing in an impossible state:
//
//   before:  ...,s32_min_value=1,s32_max_value=0,u32_min_value=1,u32_max_value=0)
//   after:   ...,s32_min_value=0,s32_max_value=0,u32_min_value=0,u32_max_value=0)
//
// `u32_min > u32_max` denotes the EMPTY set. Both `u32_bounds_inverted` and
// `s32_bounds_inverted` have been in this pipeline since 0026 and would have caught it
// on sight.
//
// WHAT CALIBRATION FOUND, and why it is a third distinct kind of blind spot:
//
//   * pair one (3844d153a41a) — the oracle was MISSING the property.
//   * pair two (92424801261d) — the state is never printed, so a different CHANNEL
//     (the verdict under BPF_F_TEST_REG_INVARIANTS) had to carry it.
//   * pair three — the property was there and correct all along. The oracle could not
//     read the LOG. A 2021 kernel spells SCALAR_VALUE `inv` (with a `P` suffix when
//     precise) and its bounds `umin_value=` / `u32_min_value=`; every such register fell
//     through to the pointer branch, took the reg_type "inv", lost its 32-bit view
//     entirely, and was then skipped by every scalar check.
//
//     Measured on this fixture with the fix disabled: `finding_count=0`,
//     `parser_unrecognized=0`, `tnum_bounds_checked=0`, `reg32_checked=0`. Not quite
//     silent — each record did carry a `parse_notes` entry reading "unrecognized
//     reg-type form: inv" — but nothing gates on a parse note, and the headline numbers
//     read as a clean pass. The tell was the DENOMINATORS collapsing to zero, which is
//     the 0025 rule doing its job for the fourth time.
//
// AND THE MISSING DENOMINATOR. The four ordering checks are ungated on purpose (an
// inverted range is a contradiction by itself and needs no second tracker), but that
// also meant NOTHING COUNTED THEM: 35 legs of "no inverted ranges" with no denominator
// at all, the exact ambiguity 0025 exists to remove. `bounds_order_checked` now counts
// every comparison that could have fired, and the answer turned out to be reassuring
// rather than embarrassing — see `the_ordering_checks_finally_have_a_denominator`.
//
// SCOPE. The fixtures are quoted from the commit message. That text is EXPANDED relative
// to what `print_verifier_state` at that revision actually emits: it glosses the signed
// bounds with a hex form the kernel never prints, and it shows fields the kernel's own
// omission rules would have suppressed. So each fixture carries a second program,
// `-omitted`, rendered under those rules — mechanically derived from the source, and
// labelled as derived, not quoted. It is the arm that matters: it shows the bug's
// signature survives the omissions, so the detection is not an artefact of the
// commit message's formatting.
// ---------------------------------------------------------------------------

/// THE HEADLINE for pair three: on the buggy state, three independent invariants fire.
#[test]
fn the_oracle_catches_the_stale_32_bit_bounds() {
    let (_, out) = run_diff(A32_BUGGY, "a32-buggy");
    for kind in [
        "u32_bounds_inverted",
        "s32_bounds_inverted",
        // The intersection check catches this one too — unlike pair one, where the
        // buggy span sat INSIDE the bounds and only the stronger const-pins-bounds
        // property could see it.
        "tnum32_bounds_inconsistent",
    ] {
        let hits: Vec<_> = out.findings.iter().filter(|f| f.kind == kind).collect();
        assert_eq!(
            hits.len(),
            2,
            "{kind} must fire on BOTH the quoted and the omission-rule arm: {:?}",
            out.findings
        );
    }
    assert!(
        out.findings.iter().all(|f| f.detail.contains("insn 10 r2")),
        "every finding must land on the register and instruction the commit marks: {:?}",
        out.findings
    );
}

/// THE SILENT HALF: the same states with the fix applied say nothing.
#[test]
fn the_oracle_stays_silent_on_the_alu32_fix() {
    let (norm, out) = run_diff(A32_FIXED, "a32-fixed");
    assert_eq!(norm.records.len(), 2);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
    // Silence is only evidence with a denominator behind it. An unparsed format produces
    // exactly this same zero, which is the trap pair one walked into.
    assert!(
        out.summary.reg32_checked >= 2 && out.summary.bounds_order_checked >= 4,
        "silent, but on what? reg32={} order={}",
        out.summary.reg32_checked,
        out.summary.bounds_order_checked
    );
}

/// The blind spot itself, as a test. A pre-2022 log must PARSE — not merely fail to
/// produce findings, which is what a format the parser cannot read looks like from the
/// outside.
#[test]
fn the_pre_2022_log_format_parses_instead_of_silently_vanishing() {
    for (tag, text) in [("a32-b", A32_BUGGY), ("a32-f", A32_FIXED)] {
        let (norm, out) = run_diff(text, tag);
        assert_eq!(
            norm.unparsed
                .iter()
                .filter(|u| u.kind == UnparsedKind::Unrecognized)
                .count(),
            0,
            "{tag}: unrecognized blocks"
        );
        assert!(
            norm.records.iter().all(|r| r.parse_notes.is_empty()),
            "{tag}: an `inv(...)` register must not be reported as an unknown family"
        );
        // The denominators are the real evidence: a format that does not parse scores
        // zero on every one of them while looking perfectly clean.
        // The tnum denominator here is 3, not more: 0076 stopped counting constant
        // scalars whose bounds the parser synthesized from the value itself, and this
        // era's `inv1337` / `inv4294967298` are exactly that. The number that matters for
        // THIS pair is reg32_checked, which is what the bug is about.
        assert!(
            out.summary.reg32_checked >= 2 && out.summary.tnum_bounds_checked >= 3,
            "{tag}: denominators too small to mean anything: reg32={} tnum={}",
            out.summary.reg32_checked,
            out.summary.tnum_bounds_checked
        );
    }
}

/// The omission-rule arm on its own: the signature survives what the kernel ACTUALLY
/// prints, not just what the commit message quotes.
#[test]
fn the_signature_survives_the_kernels_own_omission_rules() {
    // `print_verifier_state` at that revision prints s32_min_value only when it differs
    // from smin_value, u32_min_value only when it differs from umin_value, and so on. In
    // the buggy state all four differ, so all four are printed; in the fixed state the
    // two minima coincide with their 64-bit partners and are suppressed.
    assert!(A32_BUGGY.contains("umax_value=4294967296,var_off=(0x0; 0x100000000),s32_min_value=1,s32_max_value=0,u32_min_value=1,u32_max_value=0"));
    assert!(A32_FIXED.contains("umax_value=4294967296,var_off=(0x0; 0x100000000),s32_max_value=0,u32_max_value=0"));

    let (_, buggy) = run_diff(A32_BUGGY, "a32-omit-b");
    let (_, fixed) = run_diff(A32_FIXED, "a32-omit-f");
    let omitted_hits = buggy
        .findings
        .iter()
        .filter(|f| f.record_index == Some(1))
        .count();
    assert_eq!(
        omitted_hits, 3,
        "the derived arm must fire on its own: {:?}", buggy.findings
    );
    assert_eq!(fixed.findings.len(), 0, "{:?}", fixed.findings);
}

/// The denominator the ordering checks never had — and the answer it gives.
///
/// This is the half that makes the other tests worth anything. `0 inverted ranges` across
/// the whole project was uncountable until now; measured, it is 0 out of tens of
/// thousands on the current corpus, which is a real statement about bpf-next rather than
/// an absence of evidence.
#[test]
fn the_ordering_checks_finally_have_a_denominator() {
    const COMP: &str = include_str!("fixtures/volume/gen-comp-896.log");
    let (_, out) = run_diff(COMP, "a32-denom");
    assert!(
        out.summary.bounds_order_checked > 20_000,
        "the composition corpus must exercise the ordering checks heavily; got {}",
        out.summary.bounds_order_checked
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);

    // And the counter must EXCLUDE comparisons that cannot fail, or it is decoration:
    // the buggy pair scores more than the fixed one only because its bounds are printed,
    // never because a bound was absent and resolved to an extreme.
    let (_, buggy) = run_diff(A32_BUGGY, "a32-denom-b");
    assert!(
        buggy.summary.bounds_order_checked >= 6,
        "got {}",
        buggy.summary.bounds_order_checked
    );
}

// ---------------------------------------------------------------------------
// PAIR FOUR (devlog 0067) — commit ae67b9fb8c4e, "bpf: Fix truncation bug in
// coerce_reg_to_size_sx()" (2024-10-14, reported by Shung-Hsi Yu and Zac Ecob).
//
// THE BUG, and it is one line. After a sign-extending move the verifier wrote the new
// bounds with a CHAINED assignment:
//
//     reg->umin_value = reg->u32_min_value = s64_min;
//
// which is `u32_min_value = (u32)s64_min` FIRST and then `umin_value = u32_min_value` —
// the 64-bit bound set from the already-truncated 32-bit one. The fix only swaps the
// order. The same function then sets `var_off = tnum_range(s64_min, s64_max)` from the
// UNtruncated values, so the buggy state carries a tnum saying
// [0xfffffffffffffffe, 0xffffffffffffffff] beside unsigned bounds saying
// [0xfffffffe, 0xffffffff] — two DISJOINT sets.
//
// THE RESULT, and it is the first of its kind here: NO blind spot. The instrument needed
// no repair at all, and what catches it is this project's OLDEST invariant, the
// tnum-vs-bounds intersection that has been in the diff stage since the first leg. Three
// pairs found three different holes; the fourth found none, which is only worth
// something because the first three did.
//
// AND A GENUINELY COUNTERINTUITIVE ONE. This is a bug about 32-bit truncation, and the
// 32<->64 invariants (0026) are BLIND to it — `reg32_checked` is 0 on both halves. The
// reason is the bug itself: truncating the 64-bit bound to its low half makes the two
// views agree exactly, and `reg32_checkable` excludes registers whose 32-bit view says
// nothing the 64-bit one does not. The corruption erases the very disagreement that
// check needs. It is the 64-bit tnum, untouched by the truncation, that keeps the
// evidence. Pinned below, because "aim the 32-bit checks at 32-bit bugs" is exactly the
// wrong lesson to draw.
//
// PROVENANCE. The buggy half is quoted from the commit and needs no derivation — unlike
// pair three, this log IS in the format its kernel prints (2024-era log.c, the same one
// we capture against; the omitted `umax32=` is U32_MAX, suppressed by the normal rule).
// The fixed half is not quoted at all: `--probe-sx` reproduces the commit's own
// disassembly on the current kernel and the capture goes in verbatim, all three widths.
// ---------------------------------------------------------------------------

/// THE HEADLINE for pair four: the oldest invariant in the stage catches it, unaided.
#[test]
fn the_oldest_invariant_catches_the_sign_extension_truncation() {
    let (_, out) = run_diff(SX_BUGGY, "sx-buggy");
    let hits: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind == "tnum_bounds_inconsistent")
        .collect();
    assert_eq!(hits.len(), 1, "{:?}", out.findings);
    assert!(
        hits[0].detail.contains("insn 3 r0"),
        "on the instruction the commit marks: {}",
        hits[0].detail
    );
    // The disjointness itself, so a future change that merely renames the kind cannot
    // pass this test while measuring something else.
    assert!(
        hits[0].observed.contains("umin=4294967294 umax=4294967295"),
        "the truncated 64-bit bounds: {}",
        hits[0].observed
    );
    assert_eq!(out.summary.finding_count, 1, "{:?}", out.findings);
}

/// THE SILENT HALF — and this one is a real capture, not a derivation.
#[test]
fn the_current_kernel_is_silent_at_all_three_sign_extension_widths() {
    let (norm, out) = run_diff(SX_FIXED, "sx-fixed");
    assert_eq!(norm.records.len(), 3, "s8, s16 and s32 arms");
    assert_eq!(
        norm.unparsed
            .iter()
            .filter(|u| u.kind == UnparsedKind::Unrecognized)
            .count(),
        0
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
    // Silence with a denominator behind it, as always.
    assert!(
        out.summary.tnum_bounds_checked >= 6,
        "got {}",
        out.summary.tnum_bounds_checked
    );
    // And the fix's actual content, read off the capture: the 64-bit bound keeps its
    // full width while the 32-bit one is the truncation of it.
    assert!(
        SX_FIXED.contains("umin=0xfffffffffffffffe,umin32=0xfffffffe"),
        "the fixed kernel must print the untruncated 64-bit bound"
    );
}

/// The counterintuitive half, pinned: a 32-bit truncation bug that the 32-bit invariants
/// cannot see, because the truncation destroys the disagreement they look for.
#[test]
fn the_32_bit_invariants_are_blind_to_this_32_bit_bug() {
    let (_, buggy) = run_diff(SX_BUGGY, "sx-32b");
    let (_, fixed) = run_diff(SX_FIXED, "sx-32f");
    assert_eq!(
        (buggy.summary.reg32_checked, fixed.summary.reg32_checked),
        (0, 0),
        "reg32_checkable excludes a register whose 32-bit view says nothing new — and \
         after the truncation the two views agree exactly, which is the bug"
    );
    // So the finding cannot have come from there. It came from the 64-bit tnum.
    assert!(buggy
        .findings
        .iter()
        .all(|f| f.aspect != "bounds32"));
}

// ---------------------------------------------------------------------------
// PAIR FIVE (devlog 0068) — commit af9e89d8dd39, "bpf: Preserve id of register in
// sync_linked_regs()" (2026-01), and the first target this instrument CANNOT see.
//
// THE BUG. sync_linked_regs()'s delta branch called copy_register_state(reg, known_reg),
// which copies known_reg's id — including its BPF_ADD_CONST flag — and then restored only
// `off` and `subreg_def`. The comment above it already said "Must preserve off, id and
// add_const flag"; the code did not preserve the id. So after
//
//     r1 = r0        ; both get id=1
//     r1 += 4        ; r1 gets id=1+4
//     if r1 < 10 ... ; the sync propagates r1's bounds to r0 AND stamps ADD_CONST on r0
//
// the next `r2 = r0` hits assign_scalar_id_before_mov's ADD_CONST branch, which clears
// r0's id and mints a fresh one — silently breaking r0's link to r1. Bounds found for r1
// afterwards never reach r0.
//
// WHY IT IS OUTSIDE THIS INSTRUMENT, and why that is the finding. The resulting state is
// perfectly self-consistent: r0 simply keeps [6,255] where the truth is [10,255]. That is
// an over-APPROXIMATION, which is exactly what a sound verifier is allowed to produce, so
// the bug is an OVER-REJECTION, not an unsoundness. Every invariant this project owns is
// an internal-consistency check, and none of them can fire on a state that contradicts
// nothing. Measured below rather than argued: zero findings on the buggy capture, against
// real denominators (14 tnum-vs-bounds, 53 ordering, 2 prune pairs, 1 REG_INVARIANTS
// load). Silence with a denominator behind it is a result; silence without one would have
// been the 0025 trap again.
//
// THE CHANNEL THAT DOES SEE IT is the verdict, across kernel VERSIONS: the program is safe
// iff the verifier is precise enough to prove the branch at insn 7 always taken, so the
// buggy kernel rejects it with "div by zero" and the fixed one accepts.
//
// AND THE HONEST LIMIT ON THAT CHANNEL: a version differential is a calibration
// instrument, not a hunting oracle. Two kernel versions are ALLOWED to disagree on a
// verdict — precision changes with every release — so a flip is only evidence when you
// already know which side is the bug. That is the boundary this pair establishes, and it
// is the first pair to establish one instead of finding a hole.
//
// BOTH halves are real captures (`--probe-idlink`) from two kernels built from the same
// config, differing only in the fix.
// ---------------------------------------------------------------------------

fn decisions(text: &str, tag: &str) -> Vec<(String, String)> {
    let (norm, _) = run_diff(text, tag);
    norm.records
        .iter()
        .map(|r| {
            (
                r.source_label.clone().unwrap_or_default(),
                format!("{:?}", r.core.verifier_decision),
            )
        })
        .collect()
}

/// THE MEASUREMENT: the verdict flips on the trigger and NOT on the control.
///
/// The control differs by exactly one instruction — the second link, `r2 = r0` — which is
/// the only thing that re-mints r0's id. If it flipped too, the flip would be about
/// something else and the arm would prove nothing.
#[test]
fn the_verdict_flips_on_the_trigger_and_holds_on_the_control() {
    let buggy = decisions(IL_BUGGY, "il-buggy");
    let fixed = decisions(IL_FIXED, "il-fixed");
    assert_eq!(buggy.len(), 2);
    assert_eq!(fixed.len(), 2);

    assert!(buggy[0].0.ends_with("trigger") && buggy[0].1.contains("div by zero"));
    assert!(fixed[0].0.ends_with("trigger") && fixed[0].1 == "Accept");

    assert!(buggy[1].0.ends_with("control") && buggy[1].1 == "Accept");
    assert!(fixed[1].0.ends_with("control") && fixed[1].1 == "Accept");
}

/// THE BOUNDARY, and the point of the leg: every consistency invariant is silent on the
/// buggy capture — measured against real denominators, not asserted.
#[test]
fn no_consistency_invariant_can_see_an_over_approximation() {
    let (_, buggy) = run_diff(IL_BUGGY, "il-b-inv");
    assert_eq!(
        buggy.summary.finding_count, 0,
        "an over-approximation contradicts nothing: {:?}", buggy.findings
    );
    // The denominators that make that zero mean something. Without them this test would
    // be indistinguishable from a capture nothing looked at.
    assert!(buggy.summary.tnum_bounds_checked >= 10, "{}", buggy.summary.tnum_bounds_checked);
    assert!(buggy.summary.bounds_order_checked >= 40, "{}", buggy.summary.bounds_order_checked);
    assert!(buggy.summary.prune_pairs_checked >= 2, "{}", buggy.summary.prune_pairs_checked);

    // And the kernel's OWN checker is silent too, so the channel that caught pair two
    // cannot catch this one: the flagged load returns the ordinary verdict, not -EFAULT.
    assert!(
        IL_BUGGY.contains("inv_verdict=reject inv_errno=22 inv_reason=verdict"),
        "REG_INVARIANTS must mirror the plain rejection, not report a fault"
    );
    assert!(!IL_BUGGY.contains("REG INVARIANTS VIOLATION"));
}

/// The difference IS visible in the log — it is simply not a contradiction.
///
/// Worth pinning because it names what a detector for this class would need: not another
/// invariant, but a REFERENCE. `id=2` is self-consistent; it is only wrong relative to
/// what a better verifier does with the same program.
#[test]
fn the_broken_link_is_visible_as_a_difference_but_not_as_a_contradiction() {
    // The buggy kernel re-mints r0's id at the second link; the fixed one keeps it.
    assert!(IL_BUGGY.contains("5: (bf) r2 = r0                       ; R0=scalar(id=2,"));
    assert!(IL_FIXED.contains("5: (bf) r2 = r0                       ; R0=scalar(id=1,"));
    // And the consequence one instruction later: only the fixed kernel carries r1's new
    // bound across to r0, which is what makes the branch at 7 provable.
    assert!(IL_FIXED.contains("6: (a5) if r1 < 0xe goto pc+2         ; R0=scalar(id=1,smin=umin=smin32=umin32=10"));
    assert!(IL_BUGGY.contains("6: (a5) if r1 < 0xe goto pc+2         ; R1=scalar(id=1+4"));
    // Both states are internally consistent, which is why the pipeline reports nothing on
    // either — already asserted above, restated here as the reason this test exists.
    let (_, fixed) = run_diff(IL_FIXED, "il-f-diff");
    assert_eq!(fixed.summary.finding_count, 0, "{:?}", fixed.findings);
}

// ---------------------------------------------------------------------------
// PAIR SIX (devlog 0070) — commit 811c363645b3, "bpf: Fix check_stack_write_fixed_off() to
// correctly spill imm" (2023-11-01, Hao Sun). Aimed at the RUNTIME channel, which no pair
// had reached. THE PREDICTION WAS WRONG, and the correction is the result.
//
// THE BUG, one cast. `check_stack_write_fixed_off()` tracked a 64-bit `BPF_ST_MEM`'s
// immediate as `__mark_reg_known(&fake_reg, (u32)insn->imm)`. `insn->imm` is an s32, so the
// cast drops the sign: `-44` is tracked as `4294967252`.
//
//     buggy:  1: (7a) *(u64 *)(r2 -40) = -44   ; fp-40_w=4294967252
//             2: (79) r0 = *(u64 *)(r2 -40)    ; R0_w=4294967252
//     fixed:  1: (7a) *(u64 *)(r2 -40) = -44   ; fp-40=-44
//             2: (79) r0 = *(u64 *)(r2 -40)    ; R0=-44
//
// THE PREDICTION, made independently by me and by a screening pass, and WRONG in the same
// way: since `r0` looks like a large positive constant, `if r0 s< 0xa` looks false, the
// verifier proves the program returns 1 — while the value really is -44, so the branch is
// really taken and the program really returns 0. Verifier says 1, runtime says 0: a clean
// hit for the retval oracle.
//
// WHAT ACTUALLY HAPPENS. On the buggy kernel the observed return value is 1, matching the
// wrong proof exactly. Because the verifier resolved the branch STATICALLY, it never walked
// the other side, and `bpf_opt_hard_wire_dead_code_branches()` (kernel/bpf/fixups.c:564)
// then rewrites every conditional jump whose one side was never `seen` into a `JA` — so the
// branch is REMOVED from the program that actually runs.
//
//     THE RUNTIME ORACLE'S REFERENCE IS THE PROGRAM THE VERIFIER PRODUCED, NOT THE PROGRAM
//     THAT WAS SUBMITTED. Any bug whose effect is a wrong STATIC BRANCH RESOLUTION is
//     invisible to it by construction: the wrong belief is baked into the emitted code, and
//     the observation then agrees with the wrong proof.
//
// This is a second and sharper boundary than pair five's. Pair five could not be seen
// because the state was merely wider than the truth. This one cannot be seen because the
// instrument's own ground truth has been rewritten to agree with the error.
//
// It also invalidates a whole shape of reasoning about candidates: every historical fix
// whose consequence is described as "dead-code rewrite of reachable code" is in this class,
// however cleanly its commit message quotes the corrupted state.
//
// WHAT WOULD CATCH IT is a different REFERENCE. For a generated program the harness knows
// the intended result independently of the verifier — this one is closed-form: store -44,
// reload, -44 < 10, return 0. Comparing the observed retval against the GENERATOR's
// expectation rather than the verifier's claim turns this from invisible into a one-line
// check. That is the leg's forward-looking output.
// ---------------------------------------------------------------------------

/// THE MEASUREMENT that corrected the prediction: the buggy kernel returns 1, agreeing
/// with its own wrong proof. The control arm — a POSITIVE immediate, which survives the
/// cast unchanged — agrees on both kernels, so the difference is specifically the lost sign.
#[test]
fn the_runtime_follows_the_verifier_because_the_dead_branch_is_removed() {
    // The corrupted state, and its correct counterpart.
    assert!(SP_BUGGY.contains("*(u64 *)(r2 -40) = -44        ; R2_w=fp0 fp-40_w=4294967252"));
    assert!(SP_FIXED.contains("*(u64 *)(r2 -40) = -44        ; R2=fp0 fp-40=-44"));

    // The verifier proves 1 on the buggy kernel and 0 on the fixed one...
    assert!(SP_BUGGY.contains("4: (b7) r0 = 1"));
    assert!(SP_FIXED.contains("6: (b7) r0 = 0"));

    // ...and the OBSERVED return value follows the proof on each, rather than diverging
    // from it on either. This is the whole finding.
    let neg = |log: &str| -> String {
        let block = log.split("===PROG ").find(|b| b.starts_with("spill#811c363645b3#neg")).unwrap();
        block.lines().find(|l| l.starts_with("RUNTIME ")).unwrap().to_string()
    };
    assert!(neg(SP_BUGGY).contains("retval=0x00000001"), "{}", neg(SP_BUGGY));
    assert!(neg(SP_FIXED).contains("retval=0x00000000"), "{}", neg(SP_FIXED));

    // Control: a positive immediate is unaffected by the (u32) cast, so both kernels agree.
    let pos = |log: &str| -> String {
        let block = log.split("===PROG ").find(|b| b.starts_with("spill#811c363645b3#pos")).unwrap();
        block.lines().find(|l| l.starts_with("RUNTIME ")).unwrap().to_string()
    };
    assert!(pos(SP_BUGGY).contains("retval=0x00000001"));
    assert!(pos(SP_FIXED).contains("retval=0x00000001"));
}

/// THE BOUNDARY, with a denominator behind it: every VERIFIER-REFERENCED oracle ran on the
/// buggy capture and was satisfied. Silence here is not "nothing was looked at" — it is
/// those oracles evaluating the program and finding it consistent, because the program had
/// been rewritten to be so.
///
/// 0071 added an oracle whose reference is NOT the verifier, and it does fire here — so
/// this test pins the boundary precisely rather than by a total count: the class that
/// cannot see this bug, and the one that can, on the same capture.
#[test]
fn every_verifier_referenced_oracle_is_satisfied_by_the_buggy_program() {
    let (_, buggy) = run_diff(SP_BUGGY, "sp-buggy");

    // The retval check compared both arms against a proven bound and reported nothing.
    assert_eq!(
        buggy.summary.runtime_checked, 2,
        "a skipped comparison would make this test say nothing at all"
    );
    assert!(!buggy.findings.iter().any(|f| f.kind == "runtime_bound_violation"));

    // No parsed-state invariant fires either: `R0_w=4294967252` is a pinned constant whose
    // tnum and bounds agree. It is wrong, not inconsistent — and since 0076 it is not even
    // COUNTED, because a bare-number constant's bounds are synthesized by the parser from
    // the value itself and comparing them cannot fail. A denominator of zero here is a
    // SHARPER statement of the boundary than a number that could never have moved: the
    // parsed-state channel does not merely stay silent on this bug, it has nothing to say.
    assert_eq!(
        buggy.summary.tnum_bounds_checked, 0,
        "a constant scalar prints as a bare number, so there is no independent bound to \
         compare the tnum against"
    );
    assert!(
        buggy.findings.iter().all(|f| f.kind == "runtime_intent_violation"),
        "the ONLY thing that may fire here is the oracle whose reference is the generator: \
         {:?}",
        buggy.findings
    );

    let (_, fixed) = run_diff(SP_FIXED, "sp-fixed");
    assert_eq!(fixed.summary.finding_count, 0, "{:?}", fixed.findings);
}

// ---------------------------------------------------------------------------
// THE ORACLE PAIR SIX ASKED FOR (devlog 0071) — and it is the first one here whose
// reference is not the verifier.
//
// 0070's boundary was structural, not incidental: every oracle this project owns compares
// the verifier against itself, or compares a runtime observation against the verifier's own
// printed claim. When a bug makes the verifier confidently WRONG in a self-consistent way,
// and dead-code hard-wiring bakes that belief into the emitted program, the whole family is
// blind by construction.
//
// `EXPECT intended_retval=` breaks the circle. The harness states what the program must
// return, derived from the program text and nothing else — for this one: store -44, reload
// it, -44 is less than 10, return 0. `check_runtime_intent` compares the observed return
// value against that.
//
// THE RESULT, on the very capture 0070 showed was invisible:
//
//     buggy kernel   runtime_checked = 2  (the old oracle ran and was satisfied)
//                    runtime_intent_checked = 2, ONE finding: expected 0, observed 1
//     fixed kernel   runtime_intent_checked = 2, no findings
//
// Both denominators are non-zero on the same capture, which is the whole demonstration:
// this is not a case the old oracle failed to reach, it is one it reached and could not see.
// ---------------------------------------------------------------------------

/// THE HEADLINE: the generator-intent oracle catches what the verifier-referenced one
/// cannot, on the same program, on the same kernel, in the same run.
#[test]
fn the_generator_intent_oracle_sees_what_the_verifier_referenced_one_cannot() {
    let (_, buggy) = run_diff(SP_BUGGY, "sp-intent-b");

    let hits: Vec<_> = buggy
        .findings
        .iter()
        .filter(|f| f.kind == "runtime_intent_violation")
        .collect();
    assert_eq!(hits.len(), 1, "{:?}", buggy.findings);
    assert!(hits[0].expected.contains("retval == 0"), "{}", hits[0].expected);
    assert!(hits[0].observed.contains("retval=1"), "{}", hits[0].observed);

    // The old oracle RAN on this same capture and was satisfied — the two denominators
    // side by side are the point. A zero here would mean the comparison never happened,
    // which is a different and much weaker statement.
    assert_eq!(buggy.summary.runtime_checked, 2);
    assert_eq!(buggy.summary.runtime_intent_checked, 2);
    assert!(
        !buggy.findings.iter().any(|f| f.kind == "runtime_bound_violation"),
        "the verifier-referenced check must stay silent, or this test is measuring \
         something other than the gap it claims to measure"
    );
}

/// THE SILENT HALF: on the fixed kernel the program returns what its source says, and the
/// new oracle says nothing — with the same non-zero denominator.
#[test]
fn the_intent_oracle_is_silent_when_the_program_does_what_it_says() {
    let (_, fixed) = run_diff(SP_FIXED, "sp-intent-f");
    assert_eq!(fixed.summary.finding_count, 0, "{:?}", fixed.findings);
    assert_eq!(fixed.summary.runtime_intent_checked, 2);
}

/// The control arm carries its own expectation, and it is a DIFFERENT one — so the oracle
/// cannot be passing by accident on a constant.
#[test]
fn each_arm_states_its_own_expectation() {
    assert!(SP_BUGGY.contains("EXPECT intended_retval=0"), "the neg arm expects 0");
    assert!(SP_BUGGY.contains("EXPECT intended_retval=1"), "the pos arm expects 1");
    // And the pos arm — a positive immediate, unaffected by the (u32) cast — meets its
    // expectation on BOTH kernels, so the one violation above is specifically the lost sign.
    for log in [SP_BUGGY, SP_FIXED] {
        let pos = log
            .split("===PROG ")
            .find(|b| b.starts_with("spill#811c363645b3#pos"))
            .unwrap();
        assert!(pos.contains("EXPECT intended_retval=1"));
        assert!(pos.contains("retval=0x00000001"));
    }
}

/// The guard that keeps the intent oracle from firing on an ABSENCE.
///
/// Most families print `store_off=` and no `retval=` at all — the store location is their
/// signal. `RuntimeSample.retval` then holds a DEFAULT zero, indistinguishable from a
/// program that really returned 0. Comparing that against an expectation of 1 would fire on
/// every sample of every such family: the same "absence read as an observed zero" that
/// produced ten false OOB findings in 0041, arriving from a new direction and caught this
/// time before any capture was taken.
#[test]
fn a_sample_with_no_observed_retval_is_not_compared_against_the_expectation() {
    use pipeline::normalize::RecordParser;
    use pipeline::verifier_log::VerifierLogParser;

    // A store-only RUNTIME line, the shape most families emit.
    let block = "===PROG t type=socket_filter ===\n\
                 RESULT decision=accept fd=1 errno=0 load_ns=0\n\
                 EXPECT intended_retval=1\n\
                 RUNTIME input=0x00000000 store_off=7 store_len=1 store_size=1 executed=1\n\
                 ---LOG---\n\
                 0: (b7) r0 = 1                        ; R0_w=scalar(imm=1,umin=1,umax=1,var_off=(0x1; 0x0))\n\
                 ---END---\n";
    let out = VerifierLogParser.parse("t", block.as_bytes());
    let rec = out.records.first().expect("one record");
    let smp = rec.core.runtime_samples.first().expect("one sample");
    assert!(!smp.retval_observed, "no retval= token was printed");
    assert_eq!(smp.retval, 0, "the default, which must NOT be read as an observation");
    assert_eq!(rec.core.intended_retval, Some(1));
}

// ---------------------------------------------------------------------------
// PAIR SEVEN (devlog 0076) — commit 3cf2b61eb067, "bpf: Fix signed bounds propagation
// after mov32" (2021-12, reported by Kuee K1r0a — the same reporter as pair one).
//
// THE BUG. `zext_32_to_64()` on the mov32 path calls `__reg_assign_32_into_64()` without
// the `__update_reg_bounds` / `__reg_deduce_bounds` / `__reg_bound_offset` triplet that
// every other path runs, so no refinement from the tnum takes place. After `w0 = -1;
// w0 = w0` the register is still the constant 0xffffffff, its tnum and its UNSIGNED bounds
// still pinned to it — and its SIGNED pair pessimised to [0, 4294967295].
//
// The commit names the property in its own words: "they break assumptions about const
// scalars that smin_value == smax_value and umin_value == umax_value". Pair one calibrated
// the second clause. This is the first — and 0061 did not have it, so this fires only
// because the check gained its signed half here.
//
// THE SCOPE NOTE MATTERS MORE THAN THE PAIR, and it applies to pair one too: on a REAL
// capture from any kernel since 2017 this check cannot fire at all. `print_reg_state` does
// `verbose_snum(value); return;` for a constant scalar, so its bounds are never printed and
// the parser derives all four from that single number — a comparison of the value with
// itself. Both fixtures here are commit-message dumps, which is the only place the fields
// appear. Measured: the composition, intent and store-location corpora contain ZERO
// const-tnum states with a printed bound.
// ---------------------------------------------------------------------------

/// The signed half fires, and only on the buggy state.
#[test]
fn the_signed_half_of_const_pins_bounds_catches_the_mov32_bug() {
    let (_, buggy) = run_diff(MV_BUGGY, "mv-buggy");
    let hits: Vec<_> = buggy
        .findings
        .iter()
        .filter(|f| f.kind == "const_tnum_range_mismatch")
        .collect();
    assert_eq!(hits.len(), 1, "{:?}", buggy.findings);
    assert!(hits[0].expected.contains("smin == smax == value"), "{}", hits[0].expected);
    assert!(hits[0].observed.contains("smin=0 smax=4294967295"), "{}", hits[0].observed);

    let (_, fixed) = run_diff(MV_FIXED, "mv-fixed");
    assert_eq!(fixed.summary.finding_count, 0, "{:?}", fixed.findings);
    // Silence with a denominator: the fixed state is evaluated, not skipped.
    assert_eq!(fixed.summary.tnum_bounds_checked, 2);
}

/// THE MEASUREMENT THAT MATTERS MORE — and it corrects a claim this project made in 0065.
///
/// A constant scalar has printed as a BARE NUMBER since 2017 (`print_reg_state`:
/// `tnum_is_const` -> `verbose_snum`, return). The parser then derives umin, umax, smin and
/// smax from that one token, so the const-pins-bounds check compares the value with itself
/// — a tautology, exactly what `tnum_bounds_checkable` already excludes for the
/// intersection check. 0061 added the check without that exclusion, and its denominator
/// filled with comparisons that could not fail.
///
/// The correction runs backwards through the record: 0065 revised the syzkaller corpus from
/// "0 checkable observations" up to 357 and concluded it reached one half of the intrinsic
/// check after all. It does not. All 357 were tautologies, and 0025's original zero was
/// right. That revision is now undone in `targeted_generation.rs`.
#[test]
fn a_constant_scalars_bounds_are_synthesized_and_must_not_be_counted() {
    // Asserted on REAL captures rather than synthetic text, because the claim is about
    // what kernels actually print.
    const MODERN: &str = include_str!("fixtures/volume/gen-intent-64.log");
    let (modern, _) = run_diff(MODERN, "taut-modern");
    let const_states: Vec<_> = modern
        .records
        .iter()
        .flat_map(|r| r.core.register_evolution.iter())
        .flat_map(|s| s.regs.iter())
        .filter(|r| r.reg_type == "scalar" && r.tnum.mask == 0)
        .collect();
    assert!(!const_states.is_empty(), "the corpus must contain constants at all");
    assert!(
        const_states.iter().all(|r| !r.bounds_from_log),
        "a modern kernel prints a constant scalar as a bare number, so NONE of its bounds \
         can have been read from the log — if this fails the kernel changed and the \
         denominator correction needs re-measuring"
    );

    // The 2022-era pair-one fixture, where a bound really was printed independently.
    let (old, _) = run_diff(BUGGY, "taut-2022");
    assert!(
        old.records
            .iter()
            .flat_map(|r| r.core.register_evolution.iter())
            .flat_map(|s| s.regs.iter())
            .any(|r| r.reg_type == "scalar" && r.tnum.mask == 0 && r.bounds_from_log),
        "that era printed `scalar(imm=0,umax=1,var_off=(0x0; 0x0))` — an independent umax"
    );
}


// ===========================================================================================
// PAIR EIGHT — 3878ae04e9fc: the store-location channel, calibrated against a real bug
// ===========================================================================================
//
// `adjust_reg_min_max_vals()` stamped BPF_ADD_CONST for a 32-BIT add without recording the
// width, and `sync_linked_regs()` then replayed that delta in full 64-bit arithmetic. When
// the CPU zero-extends but a negative delta borrows below zero, the verifier's constant
// grows an upper word the real value can never have.
//
// WHY THIS PAIR BELONGS TO THIS CHANNEL AND NO OTHER. The resulting state is a pinned
// constant with tnum and bounds in agreement: internally consistent, so every consistency
// invariant is silent by construction. The verdict is ACCEPT on both kernels, so the verdict
// channel is silent too. The program returns 1 either way, so the intent oracle is silent.
// What is wrong is only the RELATION between the proof and reality — the verifier proves the
// store lands at map_value+8, the CPU puts it at map_value+0 — and check_store_location is
// the one oracle whose reference is the runtime landing site.
//
// The two arms differ in ONE thing: whether the 32-bit add wraps. 0062 added this bug's LINK
// shape to --gen-spill but explicitly not its wraparound trigger, and named that gap; the
// control arm is that missing ingredient isolated as a variable.

fn dl_labelled_findings(text: &str, tag: &str) -> Vec<(String, String)> {
    let (norm, out) = run_diff(text, tag);
    out.findings
        .iter()
        .map(|f| {
            let label = f
                .record_index
                .and_then(|i| norm.records.get(i as usize))
                .and_then(|r| r.source_label.clone())
                .unwrap_or_default();
            (label, f.kind.clone())
        })
        .collect()
}

/// THE HEADLINE: the store-location oracle fires on the kernel that had the bug, and is
/// silent on the kernel that fixed it — with the same denominator on both sides, so the
/// zero is a real zero and not a comparison that never ran.
#[test]
fn deltalink_the_store_location_oracle_fires_only_on_the_kernel_that_had_the_bug() {
    let (_, buggy) = run_diff(DL_BUGGY, "dl-b");
    let (_, fixed) = run_diff(DL_FIXED, "dl-f");
    let (_, tip) = run_diff(DL_TIP, "dl-t");

    assert_eq!(
        buggy.findings.iter().filter(|f| f.kind == "store_location_desync").count(),
        1,
        "{:?}",
        buggy.findings
    );
    assert_eq!(buggy.summary.finding_count, 1, "{:?}", buggy.findings);
    assert_eq!(fixed.summary.finding_count, 0, "{:?}", fixed.findings);
    assert_eq!(tip.summary.finding_count, 0, "{:?}", tip.findings);

    // The denominator behind all three numbers. Two accepted programs, one store sample
    // each: without this the fixed side's zero would be indistinguishable from a capture
    // the oracle never looked at.
    for (name, s) in [
        ("buggy", &buggy.summary),
        ("fixed", &fixed.summary),
        ("tip", &tip.summary),
    ] {
        assert_eq!(s.store_locations_checked, 2, "{name}");
    }
}

/// THE CONTROL: the finding belongs to the `wrap` arm and only to it. Both arms are the
/// same program with the same instructions; they differ in the base constant, and therefore
/// in whether the 32-bit add wraps. If the control fired too, the finding would be about
/// the shape rather than about the wraparound.
#[test]
fn deltalink_the_control_arm_isolates_the_wraparound() {
    let hits = dl_labelled_findings(DL_BUGGY, "dl-b-arm");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(
        hits[0].0.ends_with("wrap") && !hits[0].0.ends_with("nowrap"),
        "the finding must be the wrapping arm's: {hits:?}"
    );
    assert_eq!(hits[0].1, "store_location_desync");

    // And both arms really were accepted and really did store, on both kernels — otherwise
    // "the control is clean" would just mean the control never ran.
    for (text, tag) in [(DL_BUGGY, "dl-b-dec"), (DL_FIXED, "dl-f-dec")] {
        let d = decisions(text, tag);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(d.iter().all(|(_, v)| v == "Accept"), "{d:?}");
        assert_eq!(text.matches("executed=1").count(), 2, "both stores must execute");
        assert_eq!(text.matches("store_off=0 ").count(), 2, "both land at 0 at runtime");
    }
}

/// THE DIFFERENCE IS IN THE LOG, and it is a claim about the world rather than a
/// contradiction inside the state — which is precisely why only a runtime reference can
/// judge it. The buggy kernel prints an `off=8` for the store's base register; the fixed
/// one proves offset 0, the same place the CPU uses.
#[test]
fn deltalink_the_wrong_offset_is_printed_but_contradicts_nothing() {
    assert!(
        DL_BUGGY.contains("R7_w=map_value(ks=4,vs=64,off=8)"),
        "the buggy kernel must prove the store at +8"
    );
    assert!(
        !DL_FIXED.contains("off=8"),
        "the fixed kernel must not: the link is not created at all"
    );
    // No consistency invariant sees it, on either side — the state is self-consistent.
    let (_, buggy) = run_diff(DL_BUGGY, "dl-b-cons");
    assert!(
        !buggy.findings.iter().any(|f| f.kind.starts_with("tnum")
            || f.kind.ends_with("_inverted")
            || f.kind == "reg32_reg64_inconsistent"),
        "{:?}",
        buggy.findings
    );
}

/// THE BOUNDARY THIS PAIR ALSO DRAWS. Three other channels ran on the very same buggy
/// capture and stayed silent, each for a reason that is a property of the bug and not of
/// the capture. Counting them is what turns "the other oracles said nothing" from an
/// absence into a measurement.
#[test]
fn deltalink_the_other_channels_ran_and_were_silent() {
    let (_, buggy) = run_diff(DL_BUGGY, "dl-b-chan");

    // The intent oracle (0071) compared the generator's own claim against the observed
    // retval, twice — and agreed: the divergence is in WHERE the store went, never in what
    // the program returned.
    assert_eq!(buggy.summary.runtime_intent_checked, 2);
    assert!(!buggy.findings.iter().any(|f| f.kind == "runtime_intent_violation"));

    // BPF_F_TEST_REG_INVARIANTS loaded both programs and found nothing to fault: a pinned
    // constant with matching bounds is exactly what that checker calls well-formed.
    assert_eq!(buggy.summary.reg_invariants_checked, 2);
    assert!(!buggy.findings.iter().any(|f| f.kind == "reg_invariants_violation"));

    // The pruning differential ran on both programs and both kernels agreed with
    // themselves under BPF_F_TEST_STATE_FREQ.
    assert_eq!(buggy.summary.prune_pairs_checked, 2);
    assert!(!buggy.findings.iter().any(|f| f.kind.starts_with("prune_")));

    // And the memory-safety oracle saw a store that stayed INSIDE the value — which is the
    // whole point of the shape: an in-bounds store in the wrong place is the class every
    // bounds-only oracle misses.
    assert_eq!(buggy.summary.runtime_writes_checked, 2);
    assert!(!buggy.findings.iter().any(|f| f.kind == "runtime_oob_write"));
}

/// NO BLIND SPOTS: every block parsed, on all three kernels. A pair that silently failed to
/// parse would report a clean fixed side for the wrong reason — the trap 0065 fell into.
#[test]
fn deltalink_every_block_parses_on_all_three_kernels() {
    for (text, tag) in [(DL_BUGGY, "dl-b-p"), (DL_FIXED, "dl-f-p"), (DL_TIP, "dl-t-p")] {
        let (norm, _) = run_diff(text, tag);
        assert_eq!(norm.records.len(), 2, "{tag}");
        assert_eq!(
            norm.unparsed
                .iter()
                .filter(|u| u.kind == normalize::UnparsedKind::Unrecognized)
                .count(),
            0,
            "{tag}"
        );
    }
}

// ===========================================================================================
// PAIR ELEVEN — 2f2ec8e7730e: the pruning differential's BOUNDARY, measured
// ===========================================================================================
//
// `check_scalar_ids()` mapped the compound id `base|BPF_ADD_CONST` but never the base id, so
// two states whose LINK STRUCTURE differs compared equal: the commit's own words are "old has
// r2.id=A, r3.id=A|flag ... cur has r2.id=B, r3.id=C|flag (r3 derived from unrelated r4).
// Without the base check, idmap gets two independent entries A->B and A|flag->C|flag."
//
// THIS PAIR WAS BUILT AS A POSITIVE CONTROL AND CAME BACK A BOUNDARY. `check_prune_differential`
// had 43,379 pairs and had never fired (devlog 0083/0085), so its false-negative rate was
// unmeasured: "no unsound prunes in the corpus" and "the detector is dead" give the same
// number. This commit is the cleanest possible test of that, because its diff touches nothing
// but `check_scalar_ids()` — sixteen lines, no value-domain effect whatsoever.
//
// THE MEASUREMENT SETTLES IT, AND STRUCTURALLY. The differential ran with a real denominator
// (the flag widened the state space 2 -> 8 states) on a program the very next kernel rejects,
// and reported nothing. The reason is not the corpus and not a defect: `BPF_F_TEST_STATE_FREQ`
// only makes pruning MORE aggressive. Its soundness direction needs `freq ACCEPT && base
// REJECT` — the extra checkpoints introducing a prune that was not there. A bug where the
// DEFAULT checkpointing already takes the unsound prune produces the same accepting verdict on
// both sides of the flag, and is invisible to a flag differential BY CONSTRUCTION.
//
// So the 43,379 zeros are not evidence that the corpus is free of unsound prunes. They are
// evidence about a detector that can only see prunes the flag itself creates.
//
// All three halves are real captures. buggy = 2f2ec8e7730e~1, fixed = 2f2ec8e7730e, configs
// byte-identical.

const IB_BUGGY: &str = include_str!("fixtures/calibration/idbase-2f2ec8e7730e-buggy.log");
const IB_FIXED: &str = include_str!("fixtures/calibration/idbase-2f2ec8e7730e-fixed.log");
const IB_TIP: &str = include_str!("fixtures/calibration/idbase-2f2ec8e7730e-tip.log");

/// THE TRIGGER IS REAL: the buggy kernel accepts a program both later kernels reject, and the
/// control — the same program with the second path's r3 derived from the SAME base — is
/// accepted everywhere. Without this the boundary below would just be a program nothing
/// happened to.
#[test]
fn the_unsound_prune_is_real_and_the_control_isolates_it() {
    let b = decisions(IB_BUGGY, "ib-b");
    let f = decisions(IB_FIXED, "ib-f");
    let t = decisions(IB_TIP, "ib-t");
    for d in [&b, &f, &t] {
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(d[0].0.ends_with("unlinked") && d[1].0.ends_with("linked"), "{d:?}");
    }
    assert_eq!(b[0].1, "Accept", "the buggy kernel must accept the trigger");
    assert_ne!(f[0].1, "Accept", "the fix must reject it: {:?}", f[0]);
    assert_ne!(t[0].1, "Accept", "and tip still does: {:?}", t[0]);
    // The control carries no id conflict, so it is accepted on every kernel.
    for (name, d) in [("buggy", &b), ("fixed", &f), ("tip", &t)] {
        assert_eq!(d[1].1, "Accept", "{name}: the control must not move");
    }
}

/// THE BOUNDARY: the flag differential ran, with a denominator, and was silent — on the very
/// kernel that has the unsound prune.
#[test]
fn the_flag_differential_cannot_see_a_prune_the_baseline_already_takes() {
    let (_, buggy) = run_diff(IB_BUGGY, "ib-b-pd");
    assert_eq!(
        buggy.summary.prune_pairs_checked, 2,
        "the denominator must be real: the flag has to have widened the state space"
    );
    assert_eq!(buggy.summary.prune_resource_artifacts, 0);
    assert!(
        !buggy.findings.iter().any(|f| f.kind.starts_with("prune_")),
        "{:?}",
        buggy.findings
    );
    assert_eq!(buggy.summary.finding_count, 0, "{:?}", buggy.findings);

    // And the mechanism, straight out of the capture: both sides of the flag ACCEPT, because
    // the default checkpointing already takes the prune. `freq ACCEPT && base REJECT` — the
    // only direction the check reports — cannot arise here.
    assert!(IB_BUGGY.contains("base_verdict=accept"), "{IB_BUGGY:.0}");
    assert!(IB_BUGGY.contains("freq_verdict=accept"));
    assert!(
        IB_BUGGY.contains("base_states=2") && IB_BUGGY.contains("freq_states=8"),
        "the flag must demonstrably have changed the state space"
    );
}

// ===========================================================================================
// PAIR TWELVE — bc308be380c1: the verifier accepts, the kernel dies
// ===========================================================================================
//
// `sync_linked_regs()` propagated a delta between two registers linked to the same base but
// advanced with DIFFERENT ALU widths, then applied `zext_32_to_64()` because the 32-bit flag
// sat on `known_reg`. The commit spells out the consequence: "the CPU does NOT zero-extend
// it. The actual CPU value of r8 is 0xFFFFFFFE + 2 = 0x100000000, not 0. The verifier now
// underestimates r8's 64-bit bounds, which is a soundness violation."
//
// The arms differ in ONE instruction, the width of a single add: `r8 += 2` (alu64) against
// `w8 += 2` (alu32). In the control both links are 32-bit, the zext the verifier applies is
// CORRECT, and verifier and CPU agree on offset 0.
//
// WHAT THE MEASUREMENT SHOWED, and it is the strongest evidence this instrument has produced:
// on the buggy kernel the trigger is ACCEPTED, and running it faults inside the JITed program:
//
//     RESULT decision=accept
//     BUG: unable to handle page fault for address: ffff888105d1c528
//     Oops: 0002 [#1] SMP KASAN NOPTI            <- 0002: a WRITE fault
//     RIP: 0010:bpf_prog_08e3cb6c8754a5c4+0xaf   <- inside the program itself
//     bpf_test_run+0x468 / bpf_prog_test_run_skb+0xf97
//
// AND THE BOUNDARY THAT COMES WITH IT. The channel this pair was built for —
// `check_runtime_write_safety`, which reports a sentinel that never arrives — cannot report
// it, because the observation requires surviving the store and the store is fatal by
// construction. The divergence is 4 GB; nothing lands inside a 64-byte map value and nothing
// returns to print a RUNTIME line. For this class the detector is the CRASH, which is why
// `run-harness-vm.sh` now names an oops instead of losing the run as "markers not found".
//
// Three kinds of boundary have now been measured, and they are different: 0068 (the class is
// outside the instrument), 0092 (the detector's own flag cannot create the condition), and
// this one (the observation requires surviving an event that is fatal by construction).

const MW_FIXED: &str = include_str!("fixtures/calibration/mixwidth-bc308be380c1-fixed.log");
const MW_TIP: &str = include_str!("fixtures/calibration/mixwidth-bc308be380c1-tip.log");
const MW_CRASH: &str = include_str!("fixtures/calibration/mixwidth-bc308be380c1-buggy-crash.txt");

/// THE FIX IS WHAT REJECTS IT, and the control shows the rejection is about the add's width.
#[test]
fn the_mixed_width_link_is_rejected_once_the_propagation_is_skipped() {
    for (text, tag) in [(MW_FIXED, "mw-f"), (MW_TIP, "mw-t")] {
        let d = decisions(text, tag);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(d[0].0.ends_with("mixed") && d[1].0.ends_with("same"), "{d:?}");
        assert_ne!(d[0].1, "Accept", "{tag}: the mixed-width trigger must be rejected");
        assert_eq!(d[1].1, "Accept", "{tag}: the same-width control must not move");
    }
    // The control really runs and really stores, at the offset the verifier proved. Without
    // this the rejection above could be about the shape rather than the width.
    assert!(MW_FIXED.contains("input=0xfffffffe retval=0x00000001 store_off=0"));
    assert!(MW_FIXED.contains("executed=1"));
}

/// THE BUGGY KERNEL ACCEPTED IT AND THEN DIED. Pinned from the serial console, because the
/// harness never got to print a result: this is the one finding whose evidence is an oops.
#[test]
fn the_buggy_kernel_accepts_the_program_and_faults_running_it() {
    assert!(MW_CRASH.contains("RESULT decision=accept"), "the verifier accepted it");
    assert!(
        MW_CRASH.contains("BUG: unable to handle page fault"),
        "and the kernel faulted running it"
    );
    // `Oops: 0002` — bit 1 set is a WRITE fault, which is what an out-of-bounds store is.
    assert!(MW_CRASH.contains("Oops: 0002"), "a WRITE fault, not a read");
    // Inside the JITed program, reached through the test-run path: not incidental noise.
    assert!(MW_CRASH.contains("RIP: 0010:bpf_prog_"), "the fault is inside the program");
    assert!(MW_CRASH.contains("bpf_test_run+"), "reached through BPF_PROG_TEST_RUN");
}

// ===========================================================================================
// THE HUNT'S FIRST FINDING WAS OUR OWN LOG BUFFER (0097)
// ===========================================================================================
//
// The first million-program hunt after both levers were opened produced exactly one FINDING:
// `prune_verdict_flip base=accept freq=reject reason=verdict`. Triage said (c)-negative for
// the seventh time.
//
// `freq_errno=28` is ENOSPC, and kernel/bpf/log.c:295 returns it when the verifier LOG was
// truncated — `log->len_max > log->len_total`, a statement about the harness's buffer and not
// about the program. The state-freq load explored 202 states where the default explored 49,
// wrote four times the log_level=2 output, overflowed 256 KB, and came back rejected. The
// classifier looked only for "BPF program is too large" and "too many states", so it fell
// through to "verdict" and was reported as a pruning disagreement.
//
// THE DEEPER THE SEARCH, THE MORE OF THESE. 0095's iterator gene took maxstates from 17/61 to
// 73/238; every one of those deep explorations is a candidate. Reading ENOSPC as a verdict
// turns the instrument's own success at going deep into a stream of false findings.
//
// Fixed in three places: the reason is now `log_truncated`; the fuzz loop's flagged load asks
// for log_level=1, which is all `total_states` needs and removes the source rather than
// classifying it; and the check below treats it as the resource direction it is.

const PLT: &str = include_str!("fixtures/calibration/prune-log-truncated.log");

/// A truncated log is the RESOURCE direction, never a finding — and the capture that proves
/// it is the replayed genome from the hunt that reported it.
#[test]
fn a_truncated_verifier_log_is_not_a_pruning_disagreement() {
    assert!(
        PLT.contains("freq_errno=28") && PLT.contains("freq_reason=log_truncated"),
        "the fixture must carry the ENOSPC case it was captured for"
    );
    let (_, out) = run_diff(PLT, "plt");
    assert!(
        !out.findings.iter().any(|f| f.kind.starts_with("prune_")),
        "a log-buffer overflow must not be reported as a pruning result: {:?}",
        out.findings
    );
    // Counted as the artefact it is, and NOT folded into the denominator: a pair whose
    // flagged half never finished says nothing about pruning either way.
    assert_eq!(out.summary.prune_resource_artifacts, 1);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// AND THE GENOME REPLAYS. Until 0097 the devlog claimed every genome was replayable while
/// nothing could read one back; a report nobody can reproduce is not a finding. This fixture
/// is the output of `--fuzz-replay` on the reported genome, and it reproduces the original
/// state counts exactly.
#[test]
fn the_reported_genome_reproduces_the_state_counts_it_was_reported_with() {
    assert!(PLT.contains("base_states=49"), "the original base count");
    assert!(PLT.contains("freq_states=202"), "and the original flagged count");
    assert!(PLT.contains("REPLAY insns=79 genes=18"), "rebuilt from the printed genome");
}
