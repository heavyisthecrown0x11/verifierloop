//! The 32<->64 subregister leg (devlog 0026) — calibrated on the REAL parser path.
//!
//! Same two-sided proof every other leg got: silent when the verifier's two views of
//! a scalar agree, loud when they cannot both be true. Every case below is a real
//! harness block parsed by the real parser, not a hand-built `RegState` — because
//! this leg's first run produced ten findings that were all a parser bug, and a test
//! that skips the parser would not have caught it.
//!
//! Soundness of the checks: each tracker independently OVER-approximates the same
//! non-empty set of reachable values, so any two must intersect. An empty
//! intersection is the verifier contradicting itself.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize;
use pipeline::verifier_log::VerifierLogParser;

/// A harness block whose single state line carries the register state under test.
fn block(reg_state: &str) -> String {
    format!(
        "===PROG probe type=socket_filter ===\n\
         RESULT decision=accept fd=3 errno=0 load_ns=1\n\
         ---LOG---\n\
         0: R1=ctx() R10=fp0\n\
         0: (b7) r0 = 1                        ; {reg_state}\n\
         1: (95) exit\n\
         processed 2 insns (limit 1000000) total_states 0 peak_states 0\n\
         ---END---\n"
    )
}

fn run(reg_state: &str, tag: &str) -> diff::DiffFindings {
    let dir = std::env::temp_dir().join(format!("vl-sub-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("capture.log");
    std::fs::write(&src, block(reg_state)).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("probe", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn kinds(out: &diff::DiffFindings) -> Vec<&str> {
    out.findings.iter().map(|f| f.kind.as_str()).collect()
}

#[test]
fn silent_when_the_two_views_are_consistent() {
    // 64-bit range spans two 2^32 blocks, so the 32-bit view IS independent
    // information (the leg actually runs) — and it agrees with the tnum.
    let out = run(
        "R0=scalar(umin=0,umax=0x1ffffffff,umin32=0,umax32=100,var_off=(0x0; 0x3f))",
        "agree",
    );
    assert_eq!(out.summary.reg32_checked, 1, "the leg must have RUN");
    assert!(kinds(&out).is_empty(), "false positive: {:?}", out.findings);
}

#[test]
fn fires_when_the_tnum_and_the_32_bit_range_cannot_both_hold() {
    // tnum says the low half is in [0x200, 0x20f]; the 32-bit range says [0, 100].
    // Both over-approximate the same set, so they must intersect. They do not.
    let out = run(
        "R0=scalar(umin=0,umax=0x1ffffffff,umin32=0,umax32=100,var_off=(0x200; 0xf))",
        "tnum32",
    );
    assert!(
        kinds(&out).contains(&"tnum32_bounds_inconsistent"),
        "{:?}",
        out.findings
    );
}

#[test]
fn fires_when_the_32_bit_and_64_bit_views_disagree() {
    // The 64-bit range is confined to one block, so every value's low half lies in
    // [256, 511]. The 32-bit view claims [1000, 2000]. One of the two is wrong.
    let out = run(
        "R0=scalar(umin=256,umax=511,umin32=1000,umax32=2000,var_off=(0x0; 0xffffffff))",
        "reg32v64",
    );
    assert!(
        kinds(&out).contains(&"reg32_reg64_inconsistent"),
        "{:?}",
        out.findings
    );
}

#[test]
fn fires_on_an_inverted_32_bit_range() {
    let out = run("R0=scalar(umin=0,umax=100,umin32=2000,umax32=100)", "inverted");
    assert!(kinds(&out).contains(&"u32_bounds_inverted"), "{:?}", out.findings);
}

#[test]
fn a_view_that_merely_restates_the_64_bit_one_is_not_a_check() {
    // The verifier prints the two views as ONE shared token whenever they agree
    // (`umax=umax32=255`). Counting that as a check would inflate the denominator
    // with a comparison of a value against itself — the same tautology the
    // tnum-vs-bounds denominator excludes for constants.
    let out = run(
        "R0=scalar(umin=0,umax=255,umin32=0,umax32=255,var_off=(0x0; 0xff))",
        "restates",
    );
    assert_eq!(out.summary.reg32_checked, 0, "must not count as a check");
    assert!(kinds(&out).is_empty());
}

#[test]
fn a_full_32_bit_range_says_nothing_and_is_not_counted() {
    // umin32/umax32 omitted entirely -> both at their extremes (log.c omits a bound
    // sitting at its extreme). A full range contradicts nothing.
    let out = run("R0=scalar(umin=0,umax=0x1ffffffff,var_off=(0x0; 0x1ffffffff))", "full32");
    assert_eq!(out.summary.reg32_checked, 0);
    assert!(kinds(&out).is_empty());
}

#[test]
fn a_hex_printed_negative_s32_is_not_an_inverted_range() {
    // THE REGRESSION for the bug this leg's first run produced. The kernel prints
    // signed 32-bit bounds in hex WITHOUT sign extension
    // (kernel/bpf/log.c:print_scalar_ranges), so `smin32=0x80000010` is -2147483632.
    // Read as a plain integer it is +2147483664 — larger than smax32, which looks
    // exactly like the verifier reporting an impossible range. Ten such "findings"
    // appeared on the first real capture; all ten were this.
    let out = run(
        "R0=scalar(smin=umin=256,smax=umax=0x1000000ff,smin32=0x80000010,var_off=(0x10; 0x1ffffffef))",
        "hexneg",
    );
    assert!(
        !kinds(&out).contains(&"s32_bounds_inverted"),
        "a hex-printed negative s32 must not read as an inverted range: {:?}",
        out.findings
    );
}
