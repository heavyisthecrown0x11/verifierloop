//! THE AIMED CLOSED-FORM FAMILY (`--gen-intent`, devlog 0074) — the first corpus judged by
//! an oracle that never consults the verifier.
//!
//! WHY THIS SHAPE. Screening the tree's history for "an accepted program behaved
//! differently from what its instructions mean" found thirteen instances, six in the last
//! 34 months and four in a single month, two of whose commit messages use the phrase
//! "verifier-vs-runtime mismatch" outright. The most productive shape by a wide margin is
//! LINK-THEN-DIVERGE — mint a shared scalar id, tag one member with a constant delta, do
//! something that should but might not clear the link, narrow one member by a branch and
//! then USE the other — which is exactly what calibration pair five named and what the
//! `relink` composition piece was built from. The second is a 32-bit width or sign
//! mis-tracking consumed by a signed compare.
//!
//! CLOSED-FORM FOR THE HARNESS, UNKNOWN TO THE VERIFIER. Pure constants would leave the
//! range tracker nothing to get wrong, so the seed scalars come from a map the harness
//! wrote a moment earlier: opaque to the verifier, known to us. `bpfref.h` therefore
//! interprets from the BODY with those seeds preloaded, and the fixed prologue that does
//! the lookup is skipped rather than modelled.
//!
//! THE MEASUREMENT, full run: 4096 programs, all accepted, 32768 return values compared
//! against the independent interpreter, **zero disagreements**. This fixture is the first
//! 64 programs of that run; the numbers below are its share.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const CORPUS: &str = include_str!("fixtures/volume/gen-intent-64.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-int-{}-{tag}", std::process::id()));
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

/// Clean, with the denominator that makes it mean something.
#[test]
fn the_corpus_is_clean_against_an_independent_implementation_of_the_isa() {
    let (norm, out) = run_diff(CORPUS, "clean");
    assert_eq!(norm.records.len(), 64);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
    assert_eq!(
        out.summary.runtime_intent_checked, 512,
        "every program's whole input sweep must be compared — 64 programs x 8 inputs"
    );
    // And the third implementation: each program is loaded twice, once JITted and once
    // with net.core.bpf_jit_enable=0, so the kernel's OWN interpreter runs it too.
    assert_eq!(out.summary.jit_interp_checked, 64);
}

/// THREE INDEPENDENT IMPLEMENTATIONS, and they agree everywhere (0075).
///
/// The x86-64 JIT, the kernel's own interpreter, and bpfref.h. Two of the three pairings
/// were impossible before this leg: `CONFIG_BPF_JIT_ALWAYS_ON` compiles ___bpf_prog_run
/// out, so the lab kernel could only ever execute one way. A variant without that symbol
/// makes the second load meaningful.
///
/// Full run, 4096 programs x 8 inputs: 32768 comparisons in each pairing, zero
/// disagreements in all three.
#[test]
fn the_jit_and_the_kernels_own_interpreter_agree_with_each_other_and_with_us() {
    let jit: Vec<(&str, &str)> = CORPUS
        .lines()
        .filter(|l| l.starts_with("RUNTIME "))
        .filter_map(|l| {
            let i = l.split_whitespace().find_map(|t| t.strip_prefix("input="))?;
            let v = l.split_whitespace().find_map(|t| t.strip_prefix("retval="))?;
            Some((i, v))
        })
        .collect();
    let interp: Vec<(&str, &str)> = CORPUS
        .lines()
        .filter(|l| l.starts_with("JITDIFF "))
        .filter_map(|l| {
            let i = l.split_whitespace().find_map(|t| t.strip_prefix("input="))?;
            let v = l.split_whitespace().find_map(|t| t.strip_prefix("retval_interp="))?;
            Some((i, v))
        })
        .collect();
    assert_eq!(jit.len(), 512);
    assert_eq!(interp.len(), 512, "every JITted run must have an interpreted twin");
    assert_eq!(jit, interp, "the JIT and the interpreter disagree on a return value");

    // The capture must also say which implementation the default run used — a JIT
    // differential whose capture is silent about the mode is ambiguous about the only
    // thing that matters.
    assert!(CORPUS.contains("JITMODE requested=default actual=1"));
}

/// Every sample carries a claim, and the claims are not all the same value.
///
/// A corpus where the reference could not model the body would print no expectation at
/// all, and one where every program returns the same constant would agree perfectly while
/// testing nothing.
#[test]
fn every_sample_carries_a_claim_and_the_claims_actually_differ() {
    use std::collections::BTreeSet;
    let claims: Vec<&str> = CORPUS
        .lines()
        .filter(|l| l.starts_with("RUNTIME "))
        .map(|l| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix("intended_retval="))
                .unwrap_or("MISSING")
        })
        .collect();
    assert_eq!(claims.len(), 512);
    assert!(!claims.contains(&"MISSING"), "a sample without a modelled expectation");
    let distinct: BTreeSet<&&str> = claims.iter().collect();
    assert!(distinct.len() >= 20, "claims collapse onto {} values", distinct.len());
    // And nothing fell back to the sentinel: a program that exits early on the null path
    // would agree with the reference while observing nothing about the computation.
    assert!(!claims.contains(&"57005"), "a sample returned the map-null sentinel");
}

/// THE PRECONDITION, and why the verifier-referenced retval oracle must stand down here.
///
/// `check_runtime_ground_truth` compares an observed return against the union of the r0
/// states the verifier PRINTED — but the verifier prints a state only where it scratches
/// registers, so on a program that reaches its exit along several paths the printed set is
/// a strict SUBSET of what it proved. The union is then narrower than the real claim.
///
/// Measured, not assumed: before the generator declared `paths=multi`, this fixture
/// produced 26 `runtime_bound_violation` findings. One of them had a log carrying a single
/// `22: (bf) r0 = r6 ; R0=0xffffffff` — the one path the verifier annotated — while the
/// program legitimately returned 0 along another. Every one was ours.
#[test]
fn the_verifier_referenced_retval_oracle_stands_down_on_multi_path_programs() {
    let (norm, out) = run_diff(CORPUS, "precond");
    assert!(
        norm.records.iter().all(|r| r.core.multi_path == Some(true)),
        "the generator must declare the property its programs have"
    );
    assert_eq!(
        out.summary.runtime_checked, 0,
        "the oracle whose precondition does not hold must not run at all — running it \
         anyway produced 26 findings, all of them ours"
    );
    // The oracle whose reference IS complete runs on exactly the same samples.
    assert_eq!(out.summary.runtime_intent_checked, 512);
}

/// A UNION MUST WIDEN ON SILENCE, NOT ABSTAIN — the seventh time an absence was misread.
///
/// A bound the verifier did not print sits at its EXTREME, so a path whose 32-bit view was
/// omitted has the FULL 32-bit range and a union containing it is the full range. The
/// retval oracle instead skipped such states, making its union narrower than the truth.
/// 0041 and 0050 were this same convention inside a SINGLE state; this was the first time
/// it hid in the combination of several, and it cost 13 false findings on this fixture.
#[test]
fn an_unprinted_32_bit_view_widens_the_union_instead_of_being_skipped() {
    use pipeline::normalize::RecordParser;
    // Two paths reach the same exit. One prints a narrow 32-bit window; the other prints
    // none, which means the full range — so the union admits everything and the observed
    // value cannot be a violation.
    let block = "===PROG u type=socket_filter ===\n\
                 RESULT decision=accept fd=1 errno=0 load_ns=0\n\
                 RUNTIME input=0x00000000 retval=0x00000000\n\
                 ---LOG---\n\
                 9: (bf) r0 = r6                       ; R0=scalar(smin=umin=smin32=umin32=6,smax=umax=umax32=0x7fffffff,var_off=(0x0; 0x7fffffff))\n\
                 9: (bf) r0 = r6                       ; R0=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))\n\
                 ---END---\n";
    let out = VerifierLogParser.parse("u", block.as_bytes());
    let rec = out.records.first().expect("one record");
    let states: Vec<_> = rec
        .core
        .register_evolution
        .iter()
        .flat_map(|s| s.regs.iter())
        .filter(|r| r.reg == 0)
        .collect();
    assert_eq!(states.len(), 2, "both paths must parse");
    assert!(states[0].u32_min.is_some(), "the narrow path prints its 32-bit view");
    assert!(states[1].u32_min.is_none(), "the other omits it — meaning the extreme");

    let dir = std::env::temp_dir().join(format!("vl-union-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, block).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("u", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let d = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !d.findings.iter().any(|f| f.kind == "runtime_bound_violation"),
        "retval 0 is inside the union once the silent path widens it: {:?}", d.findings
    );
}

/// The corpus must not open a parser blind spot — a family this new is exactly where one
/// would appear.
#[test]
fn the_intent_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(CORPUS, "blind");
    assert_eq!(
        norm.unparsed.iter().filter(|u| u.kind == UnparsedKind::Unrecognized).count(),
        0
    );
    // A blind spot is a shape the parser could not READ. The console-interleaving repair
    // is neither that nor a defect: the serial line is shared with the kernel's printk, so
    // a message can land mid-line, and 0027 taught the parser to mend it AND say so. The
    // note is the parser working, and forbidding it outright would fail every capture the
    // kernel happened to talk over.
    let unread: Vec<&String> = norm
        .records
        .iter()
        .flat_map(|r| r.parse_notes.iter())
        .filter(|n| !n.starts_with("repaired "))
        .collect();
    assert!(unread.is_empty(), "parser could not read: {unread:?}");
}
