//! Demo: run the `score` stage against the real Python analyzer. Assumes a
//! NORMALIZED artifact already exists for period 1 (run `normalize_demo` with the
//! same <base_dir> first).
//!
//!   cargo run -p pipeline --example normalize_demo -- <base_dir>
//!   cargo run -p pipeline --example score_demo     -- <base_dir>

use contract::PeriodPaths;
use pipeline::score::{self, PythonAnalyzer};
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: score_demo <base_dir>"),
    );
    let period = PeriodPaths::new(&base.join("data"), 1);

    // Run the in-repo Python package (before install) via PYTHONPATH.
    let mut analyzer = PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }

    let scores = score::run(&period, &analyzer).expect("score failed");
    println!(
        "flagged {}/{} | max_score={} | method={}",
        scores.summary.flagged, scores.summary.record_count, scores.summary.max_score, scores.method
    );
    for s in &scores.scored {
        if !s.reasons.is_empty() {
            println!("  rec{} score={} {:?}", s.index, s.score, s.reasons);
        }
    }
}
