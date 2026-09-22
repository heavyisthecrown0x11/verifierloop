//! The first SYZKALLER-DRIVEN period, live.
//!
//!   syzkaller corpus -> syz-prog2c -> replay shim (log_level=2)
//!     -> disposable bpf-next VM -> ingest -> normalize(VerifierLogParser)
//!     -> score -> diff (intrinsic + bpf_func_proto slice) -> report
//!
//! The programs are syzkaller's own coverage-guided corpus; the shim only adds log
//! capture. The report separates SIGNAL (divergences) from PARSE HEALTH (parser
//! blind-spots) so a high-volume period cannot pass parser noise off as verifier
//! signal.
//!
//! HEAVY: boots a TCG VM and replays every corpus program (minutes). Needs root
//! and python3.
//!
//!   cargo run -p orchestrator --example syz_period -- <base_dir>

use contract::PeriodPaths;
use orchestrator::driver::{ScriptRunner, VmHarnessDriver};
use orchestrator::loop_runtime::{run_period, LoopConfig};
use orchestrator::period::Period;
use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, ingest, normalize, report, score};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: syz_period <base_dir>"));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("scripts/run-syzreplay-vm.sh");

    let cfg = LoopConfig {
        data_root: base.join("data"),
        exec_threshold: 1, // one replay batch (the whole corpus) crosses the boundary
    };
    let mut driver = VmHarnessDriver::new(base.join("fuzzout"), ScriptRunner::new(&script));
    let mut period = Period::new(1, 0, cfg.exec_threshold);

    println!("[syz_period] replaying the syzkaller corpus in the bpf-next VM (TCG, minutes) ...");
    let harvest = run_period(&cfg, &mut period, &mut driver).expect("run_period");
    println!(
        "HARVEST  period={} exec_count={} collected_files={}",
        harvest.period_id, harvest.exec_count, harvest.collected_files
    );

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

    // Ground truth: the curated bpf_func_proto slice (source 3).
    let gt = match HelperProtoModel::load_from_file(&root.join("data/groundtruth/helper_protos.tsv"))
    {
        Ok(p) => StaticGroundTruth::with_helper_proto(p),
        Err(_) => StaticGroundTruth::default(),
    };
    diff::run(&paths, &norm, &gt).expect("diff");
    let rep = report::run(&paths, Some(1_700_000_000)).expect("report");

    let accepts = norm
        .records
        .iter()
        .filter(|r| matches!(r.core.verifier_decision, metrics::core::VerifierDecision::Accept))
        .count();

    println!("\n=== PERIOD REPORT (syzkaller-driven) ===");
    println!(
        "RECORDS  {} (accept {} / reject {})   exec_count={}",
        norm.records.len(),
        accepts,
        norm.records.len() - accepts,
        rep.exec_count
    );
    println!(
        "SIGNAL   divergences={}  flagged={}  top_score={}",
        rep.summary.divergence_count, rep.summary.flagged, rep.summary.top_score
    );
    // The denominator: 0 findings out of MANY checks is evidence; 0 out of ZERO
    // checks is an idle detector leg. Print it so the two can never be confused.
    println!(
        "CHECKS   helper-arg comparisons actually performed: {}   (0 findings out of {} checks)",
        rep.summary.helper_args_checked, rep.summary.helper_args_checked
    );
    let ph = rep.parse_health;
    println!(
        "BLOCKS   {} = {} records + {} unparsed",
        ph.blocks, ph.records, ph.unparsed_blocks
    );
    let denom = ph.records + ph.unrecognized; // blocks that DID carry verifier output
    let rate = if denom == 0 { 0.0 } else { 100.0 * ph.unrecognized as f64 / denom as f64 };
    println!("PARSE HEALTH (separate, never signal)");
    println!(
        "  UNRECOGNIZED (parser blind-spots) : {}/{} = {:.1}%   <-- must stay ~0",
        ph.unrecognized, denom, rate
    );
    println!(
        "  not observed (verifier never ran) : {}   <-- expected, not a parser issue",
        ph.unparsed_not_observed
    );
    println!("  records with notes (lower confidence): {}", ph.records_with_notes);

    let mut notes: BTreeMap<String, usize> = BTreeMap::new();
    for r in &norm.records {
        for n in &r.parse_notes {
            *notes.entry(n.clone()).or_default() += 1;
        }
    }
    if !notes.is_empty() {
        println!("\nparse notes (blind-spots, NOT anomalies):");
        for (n, c) in &notes {
            println!("  {c:>4}x  {n}");
        }
    }
    let mut unp: BTreeMap<String, usize> = BTreeMap::new();
    for u in &norm.unparsed {
        *unp.entry(u.reason.clone()).or_default() += 1;
    }
    if !unp.is_empty() {
        println!("\nunparsed blocks (NOT anomalies):");
        for (r, c) in unp.iter().take(10) {
            println!("  {c:>4}x  {r}");
        }
    }
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for r in &norm.records {
        if let metrics::core::VerifierDecision::Reject { reason } = &r.core.verifier_decision {
            *reasons.entry(reason.clone()).or_default() += 1;
        }
    }
    if !reasons.is_empty() {
        println!("\ndistinct verifier reject reasons ({}):", reasons.len());
        for (r, c) in reasons.iter().take(15) {
            println!("  {c:>4}x  {r}");
        }
    }
    if rep.summary.divergence_count > 0 {
        println!("\nDIVERGENCES (real signal — triage these):");
        for it in &rep.items {
            for d in &it.divergences {
                println!(
                    "  rec{} [{:?}] {} expected={:?} observed={:?}",
                    it.record_index, d.source, d.kind, d.expected, d.observed
                );
            }
        }
    } else {
        println!("\n(no divergences — with both detector legs calibrated and parse-health");
        println!(" reported separately, this reads as 'clean', not 'deaf'.)");
    }
    println!("\nperiod_report: {}", paths.period_report().display());
}
