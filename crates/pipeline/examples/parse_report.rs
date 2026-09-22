//! Triage tool: run a captured native-output file through the real pipeline and
//! print SIGNAL (divergences) separately from PARSE HEALTH (parser blind-spots).
//!
//! Used to inspect a volume capture before/without a full period run.
//!
//!   cargo run -p pipeline --example parse_report -- <native-file> [base_dir]

use contract::PeriodPaths;
use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize, report, score};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let native = PathBuf::from(args.next().expect("usage: parse_report <native-file> [base_dir]"));
    let base = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("vl-parse-report"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzreplay", &native)], 0).expect("ingest");
    let norm = normalize::run(&period, &raw, &VerifierLogParser).expect("normalize");

    let mut analyzer = score::PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }
    score::run(&period, &analyzer).expect("score");

    // Ground truth: the curated bpf_func_proto slice (source 3).
    let proto_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/groundtruth/helper_protos.tsv");
    let gt = match HelperProtoModel::load_from_file(&proto_path) {
        Ok(p) => StaticGroundTruth::with_helper_proto(p),
        Err(_) => StaticGroundTruth::default(),
    };
    let dif = diff::run(&period, &norm, &gt).expect("diff");
    let rep = report::run(&period, None).expect("report");

    let accepts = norm
        .records
        .iter()
        .filter(|r| matches!(r.core.verifier_decision, metrics::core::VerifierDecision::Accept))
        .count();

    println!("=== CAPTURE: {} ===", native.display());
    println!(
        "RECORDS  {} (accept {} / reject {})",
        norm.records.len(),
        accepts,
        norm.records.len() - accepts
    );
    println!(
        "SIGNAL   divergences={}  flagged={}  top_score={}",
        rep.summary.divergence_count, rep.summary.flagged, rep.summary.top_score
    );
    // The denominator: 0 findings out of MANY checks is evidence; 0 out of ZERO
    // checks is an idle detector leg. Print it so the two can never be confused.
    println!(
        "CHECKS   helper-arg: {} comparisons   |   tnum-vs-bounds: {} checkable register\n\
         \x20        observations   |   documented cases: {}",
        rep.summary.helper_args_checked,
        dif.summary.tnum_bounds_checked,
        dif.summary.documented_cases_checked
    );
    println!(
        "         32<->64 subregister views carrying independent information: {}",
        dif.summary.reg32_checked
    );
    // The ordering checks are ungated — an inverted range contradicts itself and needs
    // no partner tracker — which is exactly why nothing counted them for 35 legs. It
    // does now (0065).
    println!(
        "         bound-ordering comparisons that could have failed: {}",
        dif.summary.bounds_order_checked
    );
    println!(
        "         tnum well-formedness: {}   |   REG_INVARIANTS loads on accepted \
         programs: {}",
        dif.summary.tnum_wellformed_checked, dif.summary.reg_invariants_checked
    );
    // The only denominator here whose reference is not the verifier (0071).
    println!(
        "         runtime samples checked against the GENERATOR's intent: {}",
        dif.summary.runtime_intent_checked
    );
    // The gap the registry guard exposed (0066): this invariant has never examined a
    // record, because the parser sets jit_interp_diff to None unconditionally.
    if dif.summary.jit_interp_checked == 0 {
        println!(
            "         JIT-vs-interpreter: 0 comparisons — this leg has NEVER run. Its\n\
             \x20          silence is an absence of evidence, not a clean result."
        );
    }
    // The intrinsic leg's denominator is the one that was missing until 0025, and
    // its absence hid the real state of the corpus: the committed syzkaller volume
    // scores ZERO here, so that leg's "0 findings" was 0 out of 0.
    if dif.summary.tnum_bounds_checked == 0 {
        println!(
            "         ^ ZERO: this corpus never gives the tnum-vs-bounds check anything to\n\
             \x20          check. Its \"0 divergences\" is an absence of evidence, not evidence\n\
             \x20          of absence."
        );
    }
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

    // Aggregate the parser's blind-spots so they are actionable, not just counted.
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
        for (r, c) in &unp {
            println!("  {c:>4}x  {r}");
        }
    }

    // Distinct reject reasons — evidence the parser is reading real verifier text.
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for r in &norm.records {
        if let metrics::core::VerifierDecision::Reject { reason } = &r.core.verifier_decision {
            *reasons.entry(reason.clone()).or_default() += 1;
        }
    }
    if !reasons.is_empty() {
        println!("\ndistinct reject reasons ({}):", reasons.len());
        for (r, c) in reasons.iter().take(15) {
            println!("  {c:>4}x  {r}");
        }
    }

    if rep.summary.divergence_count > 0 {
        println!("\nDIVERGENCES (real signal):");
        for it in &rep.items {
            for d in &it.divergences {
                println!(
                    "  rec{} [{:?}] {} expected={:?} observed={:?}",
                    it.record_index, d.source, d.kind, d.expected, d.observed
                );
            }
        }
    }
}
