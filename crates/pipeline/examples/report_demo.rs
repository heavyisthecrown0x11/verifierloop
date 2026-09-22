//! Demo: the FULL period pipeline end to end, then the triaged PERIOD_REPORT.
//!   ingest -> normalize -> score (real Python) -> diff -> report
//!
//! Shows the human-in-the-loop batch: records ordered by anomaly score, each
//! joined with its documented-vs-observed divergences. Requires `python3`.
//!
//!   cargo run -p pipeline --example report_demo -- <base_dir>

use contract::{Artifact, PeriodPaths};
use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize;
use pipeline::report::{self, PeriodReport};
use pipeline::{diff, score};
use std::fs;
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: report_demo <base_dir>"));
    let out = base.join("verifier.log");
    fs::create_dir_all(&base).unwrap();
    fs::write(&out, b"clean\nbuggy\n").unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);

    // 1-2. ingest + normalize.
    let raw = ingest::run(&period, &[Source::new("syzkaller", &out)], 4200).expect("ingest");
    normalize::run(&period, &raw, &normalize::ReferenceParser).expect("normalize");

    // 3. score (real Python analyzer over the contract).
    let mut analyzer = score::PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }
    score::run(&period, &analyzer).expect("score");

    // 4. diff against ground truth (helper proto oracle + intrinsic invariants).
    let norm = contract::read_artifact::<normalize::NormalizedMetrics>(&period.normalized())
        .expect("read NORMALIZED")
        .payload;
    let gt = StaticGroundTruth::with_helper_proto(
        HelperProtoModel::new().with_contract("bpf_map_lookup_elem", 1, "PTR_TO_MAP_KEY"),
    );
    diff::run(&period, &norm, &gt).expect("diff");

    // 5. report: join score + diff into the triaged batch (timestamp = label only).
    let report = report::run(&period, Some(1_700_000_000)).expect("report");

    println!(
        "PERIOD REPORT  exec_count={}  records={}  flagged={}  divergences={}  top_score={}",
        report.exec_count,
        report.summary.record_count,
        report.summary.flagged,
        report.summary.divergence_count,
        report.summary.top_score,
    );
    println!("triage (score DESC):");
    for it in &report.items {
        println!(
            "  rec{} score={} reasons={:?} divergences={}",
            it.record_index,
            it.score,
            it.score_reasons,
            it.divergences.len()
        );
        for d in &it.divergences {
            println!("      - [{:?}] {} ({})", d.source, d.kind, d.aspect);
        }
    }
    if !report.period_findings.is_empty() {
        println!("period-level findings: {}", report.period_findings.len());
    }

    // Prove PERIOD_REPORT round-trips through the contract.
    let art: Artifact<PeriodReport> =
        contract::read_artifact(&period.period_report()).expect("read PERIOD_REPORT");
    assert_eq!(art.payload.items.len(), report.items.len());
    println!("period_report artifact: {}", period.period_report().display());
}
