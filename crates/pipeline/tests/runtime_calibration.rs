//! Runtime ground-truth oracle (--gen-rt) — the FIRST oracle that does not trust
//! the verifier's own log to be self-consistent.
//!
//! Each program loads a fully attacker-controlled 32-bit input (a map value the
//! harness sets from userspace), applies a verifier-tracked ALU/compare shape, and
//! RETURNS the bounded value. The harness then EXECUTES it via BPF_PROG_TEST_RUN
//! over a 12-value input sweep (extremes + edges) and records the ACTUAL retval.
//! The diff stage compares each retval against the UNION of r0's proven scalar
//! bounds: a retval outside it means the verifier accepted a program whose runtime
//! return value escaped what it proved — a soundness bug catchable even when the
//! tnum and u32 views AGREE with each other (the "consistent-but-wrong" blind spot
//! every log-only invariant shares). Shapes: and / andadd / andlsh / cmp / alu32
//! (the last is the CVE-2021-3490 32-bit-bounds flavour). 37 programs, all kept
//! within 32 bits so retval is the return register's exact value.
//! Captured in the bpf-next VM (kernel 5e289c5a), 2026-09-04.
//!
//! Result: 37 accept / 0 reject. runtime_checked = 444 (37 x 12 real executions
//! each checked against the verifier's own bound), finding_count = 0 — every
//! actual retval fell within the proven bound. The oracle is shown non-vacuous by
//! a planted-escape test (a corrupted retval DOES fire) and off-by-one-sound by a
//! boundary test (retval == umax does NOT fire, umax+1 does).

use contract::PeriodPaths;
use pipeline::diff::{self};
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const RT: &str = include_str!("fixtures/volume/gen-rt-37.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-rt-{}-{}", std::process::id(), tag));
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

/// Rebuild the fixture with one program's RUNTIME retval (for a given input)
/// replaced — used to plant an escape the real kernel never produced.
fn with_mutated_sample(label: &str, input_hex: &str, new_retval_hex: &str) -> String {
    let mut out = String::new();
    for block in RT.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        if blabel == label {
            for line in block.lines() {
                if line.starts_with(&format!("RUNTIME input={input_hex} ")) {
                    out.push_str(&format!("RUNTIME input={input_hex} retval={new_retval_hex}"));
                } else {
                    out.push_str(line);
                }
                out.push('\n');
            }
        } else {
            out.push_str(block);
        }
    }
    out
}

#[test]
fn the_runtime_oracle_ran_and_found_no_escape() {
    // The numbers the family lives by: runtime_checked > 0 (the oracle actually
    // executed programs and compared each retval against the verifier's own proven
    // bound) and finding_count == 0 (no runtime value escaped its bound).
    let (norm, out) = run_diff(RT, "base");
    eprintln!(
        "RT records={} runtime_checked={} finding_count={}",
        norm.records.len(), out.summary.runtime_checked, out.summary.finding_count
    );
    assert_eq!(norm.records.len(), 37);
    assert_eq!(RT.matches("decision=accept").count(), 37, "all 37 programs must accept");
    assert_eq!(out.summary.runtime_checked, 444, "37 programs x 12 inputs = 444 checked samples");
    assert_eq!(out.summary.finding_count, 0, "a runtime value escaped its bound: {:?}", out.findings);
}

#[test]
fn the_oracle_has_teeth_a_planted_escape_fires() {
    // Non-vacuity: if a retval is OUTSIDE the verifier's proven bound, the oracle
    // MUST fire. genrt#and#000 masks with 1 -> r0 in [0,1]; plant retval 0xdead0000.
    let mutated = with_mutated_sample("genrt#and#000", "0x00000000", "0xdead0000");
    let (_, out) = run_diff(&mutated, "teeth");
    let viols: Vec<_> = out.findings.iter()
        .filter(|f| f.kind == "runtime_bound_violation").collect();
    assert_eq!(viols.len(), 1, "the planted escape must produce exactly one finding: {:?}", out.findings);
    assert_eq!(out.summary.finding_count, 1, "only the planted escape should fire");
    // The denominator is unchanged — a violation is still a checked sample.
    assert_eq!(out.summary.runtime_checked, 444);
}

#[test]
fn the_oracle_is_off_by_one_sound_at_the_boundary() {
    // retval == umax is IN bounds and must NOT fire; umax+1 must fire. This pins the
    // comparison at the exact edge (a `>` bug would false-positive on the boundary,
    // a `>=` bug would miss umax+1). genrt#and#000: r0 in [0,1].
    let at_max = with_mutated_sample("genrt#and#000", "0x00000000", "0x00000001");
    let (_, ok) = run_diff(&at_max, "atmax");
    assert_eq!(ok.summary.finding_count, 0, "retval == umax must be in-bounds: {:?}", ok.findings);

    let over = with_mutated_sample("genrt#and#000", "0x00000000", "0x00000002");
    let (_, bad) = run_diff(&over, "over");
    assert_eq!(bad.summary.finding_count, 1, "retval == umax+1 must fire");
    assert_eq!(bad.findings[0].kind, "runtime_bound_violation");
}

#[test]
fn the_null_return_path_does_not_collapse_the_bound() {
    // Every program has a map-null path returning 0 (r0 in [0,0]); the reference
    // bound is the UNION over exits, so a legitimate non-zero retval must NOT fire.
    // Proven by the baseline: retvals well above 0 occur, yet finding_count is 0.
    let big = RT.lines()
        .filter_map(|l| l.strip_prefix("RUNTIME "))
        .filter_map(|l| l.split("retval=").nth(1))
        .filter_map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
        .any(|rv| rv > 0x1000);
    assert!(big, "the sweep must produce non-trivial retvals (bound not collapsed to 0)");
    let (_, out) = run_diff(RT, "null");
    assert_eq!(out.summary.finding_count, 0);
}

#[test]
fn runtime_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(RT, "parse");
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the runtime corpus");
    let non_console = norm.records.iter()
        .filter(|r| r.parse_notes.iter().any(|n| !n.contains("console-interleaved")))
        .count();
    assert_eq!(non_console, 0, "the only notes may be OI-10 console repairs");
}

#[test]
fn all_programs_present_and_uniquely_labelled() {
    let (norm, _) = run_diff(RT, "labels");
    let labels: Vec<&str> = norm.records.iter().filter_map(|r| r.source_label.as_deref()).collect();
    assert_eq!(labels.len(), 37);
    assert!(labels.contains(&"genrt#and#000"));
    assert!(labels.contains(&"genrt#alu32#036"));
    let mut s = labels.clone(); s.sort_unstable(); s.dedup();
    assert_eq!(s.len(), 37, "no two programs share a label");
}
