//! UNPARSED POLICY — a parser blind-spot must be kept apart from real signal.
//!
//! Before a high-volume period, the first thing volume surfaces is the PARSER's
//! blind-spots, not verifier bugs. This test pins the policy so the report can
//! tell them apart:
//!   * a block with no trustworthy verifier decision -> a SEPARATE `unparsed`
//!     bucket (never a default-filled record that could pass as a clean accept),
//!   * a recognized block with an unfamiliar reg-type -> a per-record `parse_note`
//!     (lower confidence), still an OBSERVATION,
//!   * and NEITHER is ever emitted as a diff anomaly.

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize};
use std::path::PathBuf;

// A clean, self-consistent accept.
const GOOD: &str = "\
===PROG good type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=0
1: (95) exit
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
";

// A block with NO RESULT line — decision unknown; must NOT become a fake accept.
const NO_RESULT: &str = "\
===PROG headless type=socket_filter ===
---LOG---
0: R1=ctx() R10=fp0
1: (95) exit
---END---
";

// A non-verifier RESULT (harness map-create failure).
const ERR: &str = "\
===PROG map_lookup type=socket_filter ===
RESULT decision=error map_create_failed errno=1
---LOG---
---END---
";

// A recognized accept whose register carries a reg-type the parser does not know.
const NOVEL_REG: &str = "\
===PROG novel type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=arena_ptr(off=0)
1: (95) exit
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
";

fn normalize_batch(native: &str, tag: &str) -> normalize::NormalizedMetrics {
    let dir = std::env::temp_dir().join(format!("vl-unparsed-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, native).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let n = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    n
}

#[test]
fn undecidable_blocks_go_to_the_unparsed_bucket_not_records() {
    let n = normalize_batch(&format!("{GOOD}{NO_RESULT}{ERR}"), "undecidable");
    // Only the GOOD block is a record; the other two are parser blind-spots.
    assert_eq!(n.records.len(), 1, "only the decidable block is a record");
    assert_eq!(n.unparsed.len(), 2, "no-RESULT + non-verifier-RESULT are unparsed");
    let reasons: Vec<&str> = n.unparsed.iter().map(|u| u.reason.as_str()).collect();
    assert!(reasons.iter().any(|r| r.contains("no RESULT")), "{reasons:?}");
    assert!(reasons.iter().any(|r| r.contains("non-verifier RESULT")), "{reasons:?}");
}

#[test]
fn unfamiliar_reg_type_is_a_note_not_a_dropped_record() {
    let n = normalize_batch(NOVEL_REG, "novel");
    assert_eq!(n.records.len(), 1, "the block is still parsed into a record");
    assert!(
        n.records[0].parse_notes.iter().any(|note| note.contains("arena_ptr")),
        "the novel reg-type is flagged as a note: {:?}",
        n.records[0].parse_notes
    );
}

#[test]
fn parse_issues_never_become_diff_anomalies() {
    // Run the full batch through diff: unparsed blocks and parse-notes must not
    // manufacture divergences. The only records are GOOD (clean) and NOVEL (note).
    let native = format!("{GOOD}{NO_RESULT}{ERR}{NOVEL_REG}");
    let dir = std::env::temp_dir().join(format!("vl-unparsed-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, &native).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();

    assert_eq!(norm.records.len(), 2, "GOOD + NOVEL are records");
    assert_eq!(norm.unparsed.len(), 2, "headless + error are unparsed");
    assert!(
        out.findings.is_empty(),
        "parse issues leaked into diff as anomalies: {:?}",
        out.findings
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = PathBuf::new();
}

#[test]
fn real_clean_sample_has_no_parse_issues() {
    // The authoritative 7-program in-VM sample must parse cleanly: no unparsed
    // blocks, no per-record notes. (Guards against the policy false-flagging real data.)
    const SAMPLE: &str = include_str!("../../../harness/samples/bpf-next-sample.txt");
    let n = normalize_batch(SAMPLE, "realclean");
    assert!(n.unparsed.is_empty(), "real sample had unparsed blocks: {:?}", n.unparsed);
    assert!(
        n.records.iter().all(|r| r.parse_notes.is_empty()),
        "real sample produced parse notes: {:?}",
        n.records.iter().map(|r| &r.parse_notes).collect::<Vec<_>>()
    );
}
