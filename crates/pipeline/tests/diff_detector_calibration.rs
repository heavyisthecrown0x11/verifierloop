//! Detector-calibration test — proves the diff engine's intrinsic invariants
//! CATCH a real-format inconsistency on the REAL parser path, not just on
//! hand-built synthetic CoreMetrics.
//!
//! A detector that stays silent on clean data proves nothing on its own — silence
//! could mean "clean input" or "deaf detector". This test shows BOTH halves on the
//! real path (ingest → normalize(VerifierLogParser) → diff):
//!   * SILENT on a real, self-consistent verifier state (control), and
//!   * SHOUTS on a single deliberately-injected inconsistency (a malformed tnum,
//!     `var_off=(0x1; 0xff)` → `value & mask != 0`).
//!
//! The injection is a fault the real verifier would never emit; the point is to
//! prove the parser+diff DETECTION chain is calibrated before opening fuzz volume.
//! (If diff stayed silent here, a real verifier bug would slip through too.)

use contract::PeriodPaths;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize};

// A real harness native-format block (bpf-next `ranged_and`): read a ctx u32, mask
// to 0..255. The masked scalar's tnum is `var_off=(0x0; 0xff)` — well-formed.
const CLEAN: &str = "\
===PROG ranged_and type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
0: (61) r0 = *(u32 *)(r1 +0)          ; R0=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R1=ctx()
1: (57) r0 &= 255                     ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
2: (95) exit
processed 3 insns (limit 1000000) total_states 0 peak_states 0
---END---
";

/// Full real path for one native block: ingest → normalize(VerifierLogParser) → diff.
fn findings_kinds(native: &str, tag: &str) -> Vec<String> {
    let scratch = std::env::temp_dir().join(format!(
        "verifierloop-calib-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let src = scratch.join("diffharness.log");
    std::fs::write(&src, native).unwrap();

    let period = PeriodPaths::new(&scratch.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &StaticGroundTruth::default()).unwrap();

    let kinds = out.findings.iter().map(|f| f.kind.clone()).collect();
    let _ = std::fs::remove_dir_all(&scratch);
    kinds
}

#[test]
fn silent_on_clean_real_state() {
    // A real, self-consistent verifier observation must produce NO findings.
    let kinds = findings_kinds(CLEAN, "clean");
    assert!(
        kinds.is_empty(),
        "diff flagged a clean real state (false positive): {kinds:?}"
    );
}

#[test]
fn shouts_on_injected_inconsistency_via_real_parser() {
    // Inject ONE fault into the masked scalar's tnum: value bit set inside the
    // unknown mask (`0x0` → `0x1`), so `value & mask != 0` — a malformed tnum.
    // The target substring is unique to the masked line (the wider scalar ends in
    // `0xffffffff))`, so this does not touch it).
    let mutant = CLEAN.replace("var_off=(0x0; 0xff))", "var_off=(0x1; 0xff))");
    assert_ne!(mutant, CLEAN, "fault injection must change exactly the masked tnum");

    let kinds = findings_kinds(&mutant, "mutant");
    assert!(
        kinds.iter().any(|k| k == "tnum_malformed"),
        "diff did NOT catch the injected malformed tnum on the real path — \
         detector is deaf; found: {kinds:?}"
    );
}

/// Sanity: the control and mutant differ by exactly the injected fault, so the
/// only reason the outcomes differ is the detector reacting to that fault.
#[test]
fn control_and_mutant_differ_only_by_the_injection() {
    let mutant = CLEAN.replace("var_off=(0x0; 0xff))", "var_off=(0x1; 0xff))");
    // Exactly one character changed.
    let diffs = CLEAN
        .chars()
        .zip(mutant.chars())
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(diffs, 1, "injection must be a single-character fault");
}
