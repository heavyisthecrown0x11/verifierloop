//! Run the FIRST REAL period, LIVE: boot the disposable bpf-next VM, run the
//! differential/verifier-log harness inside it, harvest through the loop, then run
//! the downstream pipeline (normalize -> score -> diff -> report) on the REAL data.
//!
//! This is the real `FuzzDriver` wired end to end — it replaces `MockDriver`.
//!
//! HEAVY: boots a TCG VM (minutes). Needs root (loop-mount + qemu) and python3.
//! The loop's harvest boundary is exec-count; here one harness batch (its program
//! corpus) crosses the threshold, so the period completes after a single VM boot.
//!
//!   cargo run -p orchestrator --example real_period -- <base_dir>

use contract::PeriodPaths;
use orchestrator::driver::{ScriptRunner, VmHarnessDriver};
use orchestrator::loop_runtime::{run_period, LoopConfig};
use orchestrator::period::Period;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, ingest, normalize, report, score};
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: real_period <base_dir>"));
    // run-harness-vm.sh, relative to this crate (CARGO_MANIFEST_DIR = crates/orchestrator).
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-harness-vm.sh");

    let cfg = LoopConfig {
        data_root: base.join("data"),
        exec_threshold: 1, // one harness batch crosses it -> a single VM boot
    };
    let mut driver = VmHarnessDriver::new(base.join("fuzzout"), ScriptRunner::new(&script));
    let mut period = Period::new(1, 0, cfg.exec_threshold);

    // 1. LIVE harvest through the loop: boots the VM, runs the harness, ingests
    //    its native output UNCHANGED (the loop stops here — human-in-the-loop).
    println!("[real_period] booting VM + running harness (TCG, minutes) ...");
    let harvest = run_period(&cfg, &mut period, &mut driver).expect("run_period");
    println!(
        "HARVEST  period={} exec_count={} collected_files={}",
        harvest.period_id, harvest.exec_count, harvest.collected_files
    );

    // 2. Downstream pipeline on the REAL harvested data.
    let paths = PeriodPaths::new(&cfg.data_root, period.id);
    let raw = contract::read_artifact::<ingest::RawObservation>(&harvest.raw_index)
        .expect("read RAW_INDEX")
        .payload;
    let norm = normalize::run(&paths, &raw, &VerifierLogParser).expect("normalize");

    let mut analyzer = score::PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }
    score::run(&paths, &analyzer).expect("score");
    diff::run(&paths, &norm, &StaticGroundTruth::default()).expect("diff");
    let rep = report::run(&paths, Some(1_700_000_000)).expect("report");

    println!(
        "PERIOD REPORT  records={} flagged={} divergences={}",
        rep.summary.record_count, rep.summary.flagged, rep.summary.divergence_count
    );
    println!("real verifier observations (from the bpf-next VM):");
    for (i, rec) in norm.records.iter().enumerate() {
        let decision = match &rec.core.verifier_decision {
            metrics::core::VerifierDecision::Accept => "accept".to_string(),
            metrics::core::VerifierDecision::Reject { reason } => format!("reject: {reason}"),
        };
        println!(
            "  rec{i}: {decision}  insn_processed={}  reg_snapshots={}",
            rec.core.processed.insn_processed,
            rec.core.register_evolution.len()
        );
    }
    if rep.summary.divergence_count == 0 && rep.summary.flagged == 0 {
        println!("(no anomalies — correct for these clean + legitimately-rejected programs)");
    }
    println!("period_report: {}", paths.period_report().display());
}
