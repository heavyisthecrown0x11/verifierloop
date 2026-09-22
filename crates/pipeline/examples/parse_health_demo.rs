//! Shows how the UNPARSED distinction behaves in a period report: parser
//! blind-spots are reported in a SEPARATE "parse health" channel, never mixed
//! into the divergence count. This is the pre-volume gate — when a high-volume
//! period first surfaces log forms the parser has not seen, they must land here,
//! not masquerade as verifier signal.
//!
//!   cargo run -p pipeline --example parse_health_demo -- <base_dir>   (needs python3)

use contract::PeriodPaths;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize, report, score};
use std::fs;
use std::path::PathBuf;

// A mixed batch: one clean accept, one headless block (no RESULT), one harness
// error (non-verifier RESULT), and one accept with an unknown reg-type.
const BATCH: &str = "\
===PROG good type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=0
1: (95) exit
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
===PROG headless type=socket_filter ===
---LOG---
0: R1=ctx() R10=fp0
1: (95) exit
---END---
===PROG map_lookup type=socket_filter ===
RESULT decision=error map_create_failed errno=1
---LOG---
---END---
===PROG novel type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=arena_ptr(off=0)
1: (95) exit
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
";

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: parse_health_demo <base_dir>"));
    fs::create_dir_all(&base).unwrap();
    let src = base.join("diffharness.log");
    fs::write(&src, BATCH).unwrap();
    let period = PeriodPaths::new(&base.join("data"), 1);

    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).expect("ingest");
    let norm = normalize::run(&period, &raw, &VerifierLogParser).expect("normalize");
    let mut analyzer = score::PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }
    score::run(&period, &analyzer).expect("score");
    diff::run(&period, &norm, &StaticGroundTruth::default()).expect("diff");
    let rep = report::run(&period, Some(1_700_000_000)).expect("report");

    println!("PERIOD REPORT");
    println!("  SIGNAL   : divergences={}  flagged={}", rep.summary.divergence_count, rep.summary.flagged);
    let ph = rep.parse_health;
    println!(
        "  BLOCKS   {} = {} records + {} unparsed",
        ph.blocks, ph.records, ph.unparsed_blocks
    );
    println!(
        "  PARSE HEALTH (separate): unrecognized={}  not_observed={}  with_notes={}",
        ph.unrecognized, ph.unparsed_not_observed, ph.records_with_notes
    );
    println!("\nunparsed blocks (parser blind-spots, NOT anomalies):");
    for u in &norm.unparsed {
        println!("  - {:<10} {}", u.label, u.reason);
    }
    println!("records with parse notes (lower confidence, NOT anomalies):");
    for (i, r) in norm.records.iter().enumerate() {
        if !r.parse_notes.is_empty() {
            println!("  - rec{i}: {:?}", r.parse_notes);
        }
    }
    println!(
        "\nVerdict: {} unparsed + {} noted, but divergences={} — parser noise stays OUT of signal.",
        norm.unparsed.len(),
        norm.records.iter().filter(|r| !r.parse_notes.is_empty()).count(),
        rep.summary.divergence_count
    );
}
