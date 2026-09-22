//! Demo: ingest fake native output → normalize → DIFF against ground truth.
//! Shows both check kinds: intrinsic logical invariants (a malformed tnum and a
//! JIT/interp divergence) and a source-backed helper `arg_type` mismatch via an
//! in-memory ground-truth oracle. Writes and reads back the DIFF_FINDINGS artifact.
//!
//!   cargo run -p pipeline --example diff_demo -- <base_dir>

use contract::{Artifact, PeriodPaths};
use metrics::core::{
    CoreMetrics, CoverageDelta, HelperArgViolation, JitInterpDiff, Processed, RegSnapshot,
    RegState, Tnum, VerifierDecision,
};
use pipeline::diff::{self, DiffFindings};
use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, ParseOutput, ParsedRecord, RecordParser};
use std::fs;
use std::path::PathBuf;

/// Demo parser: `clean` → a well-formed accepted record; `buggy` → a record that
/// trips the intrinsic checks (malformed tnum + JIT/interp divergence) and reports
/// a helper arg_type violation. Real parsers are TODO (native formats).
struct DemoParser;
impl RecordParser for DemoParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> ParseOutput {
        let records = String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let buggy = l.trim() == "buggy";
                let tnum = if buggy {
                    // bit 0 known-1 AND unknown => value & mask != 0 (malformed).
                    Tnum { value: 1, mask: 0xff }
                } else {
                    Tnum { value: 0, mask: 0xff }
                };
                CoreMetrics {
                    verifier_decision: VerifierDecision::Accept,
                    register_evolution: vec![RegSnapshot {
                        insn_idx: 0,
                        regs: vec![RegState {
                            reg: 0,
                            reg_type: "scalar".to_string(),
                            tnum,
                            umin: 0,
                            umax: 255,
                            smin: 0,
                            smax: 255,
                            ..Default::default()
                        }],
                    }],
                    processed: Processed {
                        insn_processed: 12,
                        states_processed: 3,
                    },
                    jit_interp_diff: Some(JitInterpDiff {
                        retval_jit: if buggy { 1 } else { 0 },
                        retval_interp: 0,
                        data_out_equal: true,
                    }),
                    coverage_delta: CoverageDelta::default(),
                    helper_arg_observations: Vec::new(),
                    runtime_samples: Vec::new(),
                    intended_retval: None,
                    multi_path: None,
                    store_site: None,
                    prune_probe: None,
                    liveness_gate: None,
                    helper_arg_violations: if buggy {
                        vec![HelperArgViolation {
                            helper: "bpf_map_lookup_elem".to_string(),
                            arg_index: 1,
                            expected: "PTR_TO_MAP_KEY".to_string(),
                            observed: "SCALAR_VALUE".to_string(),
                        }]
                    } else {
                        Vec::new()
                    },
                }
            })
            .map(|core| ParsedRecord {
                core,
                notes: Vec::new(),
                label: None,
            })
            .collect();
        ParseOutput {
            records,
            unparsed: Vec::new(),
        }
    }
}

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: diff_demo <base_dir>"));

    let out = base.join("verifier.log");
    fs::create_dir_all(&base).unwrap();
    fs::write(&out, b"clean\nbuggy\n").unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzkaller", &out)], 4200).expect("ingest");
    let norm = normalize::run(&period, &raw, &DemoParser).expect("normalize");

    // Ground-truth oracle: one documented helper arg_type contract (source 3).
    // The other three external sources need a bpf-next tree — TODO.
    let gt = StaticGroundTruth::with_helper_proto(
        HelperProtoModel::new().with_contract("bpf_map_lookup_elem", 1, "PTR_TO_MAP_KEY"),
    );

    let findings = diff::run(&period, &norm, &gt).expect("diff");

    println!(
        "diff: {} findings over {} records (exec_count={})",
        findings.summary.finding_count, findings.summary.record_count, findings.exec_count
    );
    let s = &findings.summary.by_source;
    println!(
        "  by source: logical_invariant={} helper_proto={} verifier_c={} documentation={} patch_diff={}",
        s.logical_invariant, s.helper_proto, s.verifier_c, s.documentation, s.patch_diff
    );
    for f in &findings.findings {
        println!(
            "  [{:?}/{}] rec{:?} {}: expected {:?}, observed {:?}",
            f.source, f.kind, f.record_index, f.aspect, f.expected, f.observed
        );
    }

    // Prove the DIFF_FINDINGS artifact round-trips through the contract.
    let art: Artifact<DiffFindings> =
        contract::read_artifact(&period.diff_findings()).expect("read DIFF_FINDINGS");
    assert_eq!(art.payload.summary.finding_count, findings.summary.finding_count);
    println!("diff_findings artifact: {}", period.diff_findings().display());
}
