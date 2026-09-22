//! T1-1b oracle probe measurement (run manually, not part of the suite).
//!
//! Reads a captured `--probe-t1b` log from the PROBE_LOG env var, splits it per program,
//! and prints each program's decision + reg32_checked + finding_count. The two numbers we
//! want: reg32_checked > 0 (the existing tnum32/reg32 invariants RUN on the CVE-2020-8835
//! state) and finding_count == 0 (they stay SILENT on this fixed kernel = a working
//! regression guard, not a false-positive generator).
//!
//!   PROBE_LOG=.lab/harness-probe-t1b.log cargo test -p pipeline --test probe_t1b_reg32 \
//!       -- --ignored --nocapture

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize;
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

fn run_diff(block: &str, tag: &str) -> (u64, u64) {
    let dir = std::env::temp_dir().join(format!("vl-probe-t1b-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, block).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.summary.reg32_checked, out.summary.finding_count)
}

#[test]
#[ignore = "manual: set PROBE_LOG to a captured --probe-t1b log"]
fn probe_t1b_per_program() {
    let path = match std::env::var("PROBE_LOG") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("PROBE-T1B: set PROBE_LOG=<captured --probe-t1b log>");
            return;
        }
    };
    let text = std::fs::read_to_string(&path).expect("read PROBE_LOG");
    for block in text.split("===PROG ").skip(1) {
        let label = block.split_whitespace().next().unwrap();
        let full = format!("===PROG {}", block);
        let accepted = block
            .lines()
            .find(|l| l.starts_with("RESULT "))
            .map(|l| l.contains("decision=accept"))
            .unwrap_or(false);
        let (reg32, findings) = run_diff(&full, label);
        eprintln!(
            "PROBE-T1B {label:<20} decision={} reg32_checked={} finding_count={}",
            if accepted { "accept" } else { "reject" },
            reg32,
            findings
        );
    }
}
