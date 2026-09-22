//! Generic whole-capture measurement (run manually, not part of the suite).
//!
//! Reads a captured harness log from the MEASURE_LOG env var and runs the full pipeline
//! over it, printing records / reg32_checked / tnum_bounds_checked / finding_count and the
//! kind of any finding. Used to measure a family before it is pinned as a fixture+test.
//!
//!   MEASURE_LOG=.lab/harness-sync-out.log cargo test -p pipeline --test measure_log \
//!       -- --ignored --nocapture

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

#[test]
#[ignore = "manual: set MEASURE_LOG to a captured harness log"]
fn measure_whole_capture() {
    let path = match std::env::var("MEASURE_LOG") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("MEASURE: set MEASURE_LOG=<captured harness log>");
            return;
        }
    };
    let text = std::fs::read_to_string(&path).expect("read MEASURE_LOG");
    let dir = std::env::temp_dir().join(format!("vl-measure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, &text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    // Anchor on the RESULT line: `decision=` alone is a substring of any token that
    // ENDS in it (a family that reports several loads per program writes e.g.
    // `base_verdict=`), and a loose match silently inflates the count.
    let accept = text.matches("RESULT decision=accept").count();
    let reject = text.matches("RESULT decision=reject").count();
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();

    eprintln!("MEASURE ==========================================");
    eprintln!("MEASURE records={} (accept={accept} reject={reject})", norm.records.len());
    // EVERY registered denominator, derived from the registry rather than listed here.
    // A hand-written list is exactly how six of the thirteen went unprinted for twenty
    // legs: the tool used to decide "is this family measured?" was itself hiding half the
    // measurement. Deriving it means a new invariant's denominator cannot be forgotten.
    let mut fields: Vec<&str> = diff::INVARIANT_DENOMINATORS.iter().map(|(_, f)| *f).collect();
    fields.sort_unstable();
    fields.dedup();
    for f in fields {
        match out.summary.denominator(f) {
            Some(v) => eprintln!("MEASURE {f}={v}"),
            // Unreachable while denominator_guard passes; printed rather than skipped so
            // a registry entry that stops resolving is visible here too.
            None => eprintln!("MEASURE {f}=UNRESOLVED"),
        }
    }
    eprintln!(
        "MEASURE prune_resource_artifacts={}",
        out.summary.prune_resource_artifacts
    );
    eprintln!("MEASURE finding_count={}", out.summary.finding_count);
    eprintln!("MEASURE parser_unrecognized={unrecognized}");
    for f in &out.findings {
        eprintln!("MEASURE   finding kind={} detail={}", f.kind, f.detail);
    }
    eprintln!("MEASURE ==========================================");
}
