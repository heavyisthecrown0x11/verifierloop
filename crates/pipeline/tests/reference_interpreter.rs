//! THE REFERENCE INTERPRETER, CALIBRATED (devlog 0073).
//!
//! `harness/bpfref.h` is a second implementation of the eBPF ISA subset this harness emits.
//! It exists because of the boundary 0070 measured: every oracle in this project used the
//! kernel as its own reference, so when the verifier is confidently wrong — and
//! `bpf_opt_hard_wire_dead_code_branches()` bakes that belief into the emitted program —
//! the whole family is silent. An independent reference is the only way out.
//!
//! But "independent" cuts both ways: a second implementation that is simply WRONG turns
//! every program into a false finding. So before it is allowed to judge anything, it is
//! judged. The sixteen places a naive interpreter goes wrong — transcribed from
//! `kernel/bpf/core.c` and the ISA standardisation document — are emitted as programs and
//! run through BOTH bpfref and the real kernel, and every one must agree.
//!
//! The traps are chosen for how easy they are to get wrong, not how exotic they are:
//! 32-bit ALU zero-extension (including MOV and NEG), `MOV|K`'s sign-extension differing
//! between the two ALU classes, JMP32 comparing only the low half, `x/0 = 0` and
//! `x%0 = x` at runtime, `S64_MIN sdiv -1 = S64_MIN`, negation of the minimum wrapping,
//! a DW immediate store SIGN-extending its s32 (the very rule 811c363645b3 got wrong in
//! the verifier's parallel bookkeeping), MEMSX filling the upper half where a plain load
//! zero-extends, MOVSX stopping at 32 bits in the ALU class, the 32-bit MOD zeroing the
//! upper half on a zero divisor where ALU64 leaves it untouched, `off` being signed, and
//! LD_IMM64 consuming two slots.
//!
//! Each program is shaped so its distinguishing bits land in the LOW 32 bits, because
//! BPF_PROG_TEST_RUN's retval is a u32 — several of these traps are about the UPPER half,
//! and returning the value directly would compare the half that carries no information.

const TRAPS: &str = include_str!("fixtures/calibration/refinterp-traps.log");

fn lines() -> Vec<&'static str> {
    TRAPS.lines().filter(|l| l.starts_with("REFTRAP ")).collect()
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in {line}"))
}

/// THE HEADLINE: on every trap, the independent interpreter and the kernel agree.
#[test]
fn the_reference_interpreter_agrees_with_the_kernel_on_every_trap() {
    let ls = lines();
    assert!(ls.len() >= 16, "only {} traps captured", ls.len());
    for l in &ls {
        assert_eq!(
            field(l, "verdict="),
            "agree",
            "the reference interpreter must match the kernel here: {l}"
        );
    }
}

/// A trap that did not RUN measured nothing, and must never be mistaken for agreement.
///
/// This is not hypothetical: the first capture had one program declaring seven
/// instructions while emitting six, so the verifier rejected it at load. The run reported
/// `kernel=0x00000000` — the uninitialised default — next to a reference value of 7, which
/// read exactly like a semantic disagreement and was not one.
#[test]
fn every_trap_actually_loaded_and_executed() {
    for l in &lines() {
        assert_eq!(field(l, "load="), "accept", "trap rejected at load: {l}");
        assert_eq!(field(l, "ran="), "1", "trap never executed: {l}");
        assert_eq!(field(l, "ref_status="), "ok", "reference faulted: {l}");
    }
}

/// The traps must actually SPLIT — a suite where every program returns the same value
/// would pass while testing nothing.
#[test]
fn the_traps_cover_distinct_answers_and_the_upper_half() {
    use std::collections::BTreeSet;
    let vals: BTreeSet<&str> = lines().iter().map(|l| field(l, "ref=")).collect();
    assert!(vals.len() >= 6, "traps collapse onto too few answers: {vals:?}");

    // The pairs that differ ONLY in the rule under test are the ones that make the suite
    // meaningful, so they are named rather than left implicit.
    let val = |name: &str| -> String {
        let l = lines()
            .into_iter()
            .find(|l| field(l, "name=") == name)
            .unwrap_or_else(|| panic!("missing trap {name}"));
        field(l, "ref=").to_string()
    };
    assert_ne!(
        val("mov64_k_sign_extends"), val("mov32_k_zero_extends"),
        "`r1 = -1` and `w1 = -1` must not produce the same upper half"
    );
    assert_ne!(
        val("movsx32_then_zero_extends"), val("movsx64_fills_upper_half"),
        "a sign-extending mov must differ between the two ALU classes"
    );
    assert_ne!(
        val("udiv_by_runtime_zero_is_zero"), val("umod_by_runtime_zero_is_dst"),
        "x/0 and x%0 have different defined results"
    );
}
