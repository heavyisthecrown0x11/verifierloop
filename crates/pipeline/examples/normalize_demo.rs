//! Demo: ingest fake native output, then normalize it into the metric schema and
//! write the NORMALIZED artifact. Uses a small in-example parser to show the full
//! frozen CORE schema (decision, register evolution, tnum, JIT/interp diff, ...).
//!
//!   cargo run -p pipeline --example normalize_demo -- <base_dir>

use contract::PeriodPaths;
use metrics::core::{
    CoreMetrics, CoverageDelta, HelperArgViolation, JitInterpDiff, Processed, RegSnapshot,
    RegState, Tnum, VerifierDecision,
};
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, ParseOutput, ParsedRecord, RecordParser};
use std::fs;
use std::path::PathBuf;

/// Demo parser: each line `accept` / `reject <reason>` -> one CORE record with a
/// representative register snapshot. Real parsers are TODO (native formats).
struct DemoParser;
impl RecordParser for DemoParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> ParseOutput {
        let records = String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let mut it = l.split_whitespace();
                let accepted = it.next() == Some("accept");
                let decision = if accepted {
                    VerifierDecision::Accept
                } else {
                    VerifierDecision::Reject {
                        reason: it.next().unwrap_or("unknown").to_string(),
                    }
                };
                CoreMetrics {
                    verifier_decision: decision,
                    register_evolution: vec![RegSnapshot {
                        insn_idx: 0,
                        regs: vec![RegState {
                            reg: 0,
                            reg_type: "scalar".to_string(),
                            tnum: Tnum { value: 0, mask: 0xff },
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
                        retval_jit: 0,
                        retval_interp: 0,
                        data_out_equal: true,
                    }),
                    coverage_delta: CoverageDelta::default(), // exec_n stamped by normalize
                    helper_arg_observations: Vec::new(),
                    runtime_samples: Vec::new(),
                    intended_retval: None,
                    multi_path: None,
                    store_site: None,
                    prune_probe: None,
                    liveness_gate: None,
                    helper_arg_violations: if accepted {
                        Vec::new()
                    } else {
                        vec![HelperArgViolation {
                            helper: "bpf_map_lookup_elem".to_string(),
                            arg_index: 1,
                            expected: "PTR_TO_MAP_KEY".to_string(),
                            observed: "SCALAR_VALUE".to_string(),
                        }]
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
    let base = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: normalize_demo <base_dir>"),
    );

    let out = base.join("verifier.log");
    fs::create_dir_all(&base).unwrap();
    fs::write(&out, b"accept\nreject bad_ptr\n").unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzkaller", &out)], 4200).expect("ingest");
    let norm = normalize::run(&period, &raw, &DemoParser).expect("normalize");

    println!(
        "normalized {} records at exec_count={} (derived.record_count={})",
        norm.records.len(),
        norm.exec_count,
        norm.derived.record_count
    );
    println!("normalized artifact: {}", period.normalized().display());
}
