//! Stage 2 — NORMALIZE: shape harvested raw output into the metric schema.
//!
//! This is the ONLY place normalization happens. It reads the period's harvested
//! raw blobs (the UNCHANGED copies under `raw/`), interprets each via a
//! [`RecordParser`], and assembles [`NormalizedMetrics`] — CORE records plus the
//! opt-in COUNTERFACTUAL layer, the expectation flag, and period-level DERIVED.
//!
//! UNCHANGED-AT-SOURCE: parsers read raw bytes and never mutate them; shaping into
//! the schema is interpretation, done here and nowhere earlier.
//!
//! Real per-tool parsers (syzkaller verifier log, differential harness, KCOV)
//! depend on each tool's native format and are TODO — see [`UnimplementedParser`].
//! The parser is injected so the assembly/provenance/artifact logic is testable
//! now with a reference parser, and real parsers slot in later.

use crate::ingest::RawObservation;
use contract::{Artifact, PeriodPaths, Producer};
use metrics::core::{
    CoreMetrics, CoverageDelta, HelperArgViolation, JitInterpDiff, Processed, RegSnapshot,
    RegState, Tnum, VerifierDecision,
};
use metrics::counterfactual::CounterfactualLayer;
use metrics::derived::DerivedMetrics;
use metrics::expectation::ExpectationFlag;
use serde::{Deserialize, Serialize};

/// One normalized record: a CORE observation plus the opt-in counterfactual layer
/// and the expectation flag that sit ON TOP of it (never inside core).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricRecord {
    /// Raw CORE observation.
    pub core: CoreMetrics,
    /// Opt-in counterfactual layer (default OFF; never mutates `core`).
    pub counterfactual: CounterfactualLayer,
    /// Confirmation-bias probe (default NoPrediction).
    pub expectation: ExpectationFlag,
    /// Partial-parse caveats for this record (empty = fully recognized). A record
    /// with notes is a lower-confidence OBSERVATION, never an anomaly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parse_notes: Vec<String>,
    /// Which program produced this observation (the tool's own label). PROVENANCE,
    /// not a verifier fact — it is what joins a record to a documented case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
}

/// The NORMALIZED payload for a period: many CORE records + period-level derived.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedMetrics {
    /// Total exec count N (provenance carried from ingest).
    pub exec_count: u64,
    /// One record per verifier invocation parsed from the raw output.
    pub records: Vec<MetricRecord>,
    /// Period-level derived metrics.
    pub derived: DerivedMetrics,
    /// Native blocks the parser could not shape into records (parser blind-spots,
    /// kept apart from real signal). Skipped when empty so existing artifacts stay
    /// byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unparsed: Vec<UnparsedBlock>,
}

/// WHY a native block produced no record. These two are categorically different
/// and must not share a number: one is the data having nothing to observe, the
/// other is the parser failing on data it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnparsedKind {
    /// There was no observation to make — the tool produced no verifier output
    /// (e.g. the load failed at the syscall boundary, so the verifier never ran).
    /// EXPECTED at volume; NOT a parser deficiency.
    NotObserved,
    /// The parser WAS given verifier output and could not shape it. This is the
    /// real blind-spot metric — the number that must stay near zero.
    Unrecognized,
}

/// A native block that produced no record. Kept in a SEPARATE bucket (see
/// [`NormalizedMetrics::unparsed`]) — never silently dropped, and NEVER treated as
/// a verifier anomaly. This is the policy that keeps a parser's own blind-spots
/// distinguishable from real verifier signal, especially once a high-volume period
/// surfaces log forms the parser has not seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnparsedBlock {
    /// Short label for triage (e.g. the program name, or a positional id).
    pub label: String,
    /// Whether there was nothing to observe, or the parser failed on real output.
    pub kind: UnparsedKind,
    /// Why the block could not be turned into a record.
    pub reason: String,
}

/// One parsed CORE observation plus any partial-parse caveats for THIS record.
/// A record with non-empty `notes` was parsed but at reduced confidence — it is
/// still an OBSERVATION, never an anomaly.
pub struct ParsedRecord {
    /// The CORE observation.
    pub core: CoreMetrics,
    /// Partial-parse caveats (empty = fully recognized).
    pub notes: Vec<String>,
    /// The tool's label for the program this came from (provenance).
    pub label: Option<String>,
}

/// A parser's output: the records it could shape, and the blocks it could not.
/// The two are kept apart on purpose (see [`UnparsedBlock`]).
pub struct ParseOutput {
    /// Records the parser produced (each with its own parse notes).
    pub records: Vec<ParsedRecord>,
    /// Blocks the parser could not shape into a trustworthy record.
    pub unparsed: Vec<UnparsedBlock>,
}

/// Converts one tool's native output blob into CORE observations, keeping whatever
/// it could NOT interpret in a separate `unparsed` bucket rather than guessing.
///
/// A parser reads raw bytes and does not mutate them; it only *interprets* them.
pub trait RecordParser {
    /// Parse `bytes` (one collected file from `tool`) into a [`ParseOutput`].
    fn parse(&self, tool: &str, bytes: &[u8]) -> ParseOutput;
}

/// Placeholder parser: yields no records. Swap in real per-tool parsers as their
/// native formats are wired up.
///
/// TODO(normalize): implement real parsers (syzkaller verifier log, differential
/// harness retvals, KCOV coverage). Until then this yields nothing.
pub struct UnimplementedParser;

impl RecordParser for UnimplementedParser {
    fn parse(&self, _tool: &str, _bytes: &[u8]) -> ParseOutput {
        ParseOutput {
            records: Vec::new(),
            unparsed: Vec::new(),
        }
    }
}

/// Synthetic **reference** parser — the known-good transform behind the golden
/// regression fixture (`crates/pipeline/tests/fixtures/golden/`). This is NOT a
/// real tool parser; it interprets a tiny sentinel format so the fixture is
/// deterministic.
///
/// Each non-empty line is one record. The sentinel `buggy` yields a record that
/// deliberately trips every downstream signal — a malformed tnum
/// (`value & mask != 0`), a JIT/interpreter retval divergence, and a helper
/// `arg_type` violation; any other line yields a clean, well-formed accepted
/// record. Every CORE field is populated, so the fixture exercises the full
/// frozen schema.
///
/// Purpose (parser-layer guardrail): the real per-tool parser, once written, must
/// reproduce this exact raw -> `NormalizedMetrics` mapping. The golden test then
/// tells a *parser regression* apart from a *genuine verifier anomaly* — without
/// it, the first real period's "bugs" would most likely be the parser's own.
pub struct ReferenceParser;

impl RecordParser for ReferenceParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> ParseOutput {
        let records = String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let buggy = l.trim() == "buggy";
                CoreMetrics {
                    verifier_decision: VerifierDecision::Accept,
                    register_evolution: vec![RegSnapshot {
                        insn_idx: 0,
                        regs: vec![RegState {
                            reg: 0,
                            reg_type: "scalar".to_string(),
                            tnum: if buggy {
                                Tnum { value: 1, mask: 0xff }
                            } else {
                                Tnum { value: 0, mask: 0xff }
                            },
                            umin: 0,
                            umax: 255,
                            smin: 0,
                            smax: 255,
                            ..Default::default()
                        }],
                    }],
                    processed: Processed { insn_processed: 12, states_processed: 3 },
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

/// Errors from the normalize stage.
#[derive(Debug)]
pub enum NormalizeError {
    /// Filesystem I/O failure (reading a harvested blob).
    Io(std::io::Error),
    /// Failed to write the NORMALIZED contract artifact.
    Contract(contract::ContractError),
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NormalizeError::Io(e) => write!(f, "normalize i/o error: {e}"),
            NormalizeError::Contract(e) => write!(f, "normalize contract error: {e}"),
        }
    }
}

impl std::error::Error for NormalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NormalizeError::Io(e) => Some(e),
            NormalizeError::Contract(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for NormalizeError {
    fn from(e: std::io::Error) -> Self {
        NormalizeError::Io(e)
    }
}

impl From<contract::ContractError> for NormalizeError {
    fn from(e: contract::ContractError) -> Self {
        NormalizeError::Contract(e)
    }
}

/// Normalize a period's harvested raw output into the metric schema and write the
/// NORMALIZED artifact.
///
/// Reads each entry's harvested copy under the period's `raw/` dir, dispatches it
/// to `parser`, wraps each CORE observation with a default (OFF) counterfactual
/// layer and a NoPrediction expectation flag, and stamps the exec counter N onto
/// any record that did not already carry it.
pub fn run(
    period: &PeriodPaths,
    raw: &RawObservation,
    parser: &dyn RecordParser,
) -> Result<NormalizedMetrics, NormalizeError> {
    let raw_root = period.artifact("raw");
    let mut records = Vec::new();
    let mut unparsed = Vec::new();

    for entry in &raw.entries {
        let path = raw_root.join(&entry.stored_path);
        let bytes = std::fs::read(&path)?;
        let out = parser.parse(&entry.tool, &bytes);
        for ParsedRecord { mut core, notes, label } in out.records {
            // Carry provenance: stamp exec counter N if the parser left it unset.
            if core.coverage_delta.exec_n == 0 {
                core.coverage_delta.exec_n = raw.exec_count;
            }
            records.push(MetricRecord {
                core,
                counterfactual: CounterfactualLayer::default(), // opt-in; OFF here
                expectation: ExpectationFlag::default(),         // NoPrediction
                parse_notes: notes,
                source_label: label,
            });
        }
        // Parser blind-spots kept in a SEPARATE bucket — never records, never anomalies.
        unparsed.extend(out.unparsed);
    }

    let derived = DerivedMetrics {
        // Report-only; needs more execs to be meaningful. TODO(derived).
        efficiency_per_exec: None,
        record_count: records.len() as u64,
    };

    let normalized = NormalizedMetrics {
        exec_count: raw.exec_count,
        records,
        derived,
        unparsed,
    };

    // Write NORMALIZED (borrow the payload so we can return it after the block).
    {
        let artifact = Artifact::new(period.period_id, Producer::Normalize, &normalized);
        contract::write_artifact(&period.normalized(), &artifact)?;
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{self, Source};
    use metrics::core::{CoverageDelta, Processed, VerifierDecision};
    use metrics::expectation::Expectation;
    use std::path::PathBuf;

    /// A trivial reference parser for tests: each non-empty line is one record.
    /// Format: `accept` | `reject <reason>`. Proves the assembly logic without
    /// depending on any real tool's native format.
    struct LineParser;
    impl RecordParser for LineParser {
        fn parse(&self, _tool: &str, bytes: &[u8]) -> ParseOutput {
            let records = String::from_utf8_lossy(bytes)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let mut it = l.split_whitespace();
                    let kind = it.next().unwrap_or("");
                    let decision = if kind == "accept" {
                        VerifierDecision::Accept
                    } else {
                        VerifierDecision::Reject {
                            reason: it.next().unwrap_or("unknown").to_string(),
                        }
                    };
                    CoreMetrics {
                        verifier_decision: decision,
                        register_evolution: Vec::new(),
                        processed: Processed::default(),
                        jit_interp_diff: None,
                        coverage_delta: CoverageDelta::default(),
                        helper_arg_observations: Vec::new(),
                        runtime_samples: Vec::new(),
                        intended_retval: None,
                        multi_path: None,
                        store_site: None,
                        prune_probe: None,
                        liveness_gate: None,
                        helper_arg_violations: Vec::new(),
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

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-normalize-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn assembles_records_stamps_provenance_and_writes_artifact() {
        let base = scratch_dir("assemble");
        let out = base.join("verifier.log");
        std::fs::write(&out, b"accept\nreject bad_ptr\n").unwrap();

        let period = PeriodPaths::new(&base.join("data"), 1);
        let raw = ingest::run(&period, &[Source::new("syzkaller", &out)], 99).unwrap();

        let norm = run(&period, &raw, &LineParser).unwrap();

        assert_eq!(norm.exec_count, 99);
        assert_eq!(norm.records.len(), 2);
        assert_eq!(norm.derived.record_count, 2);

        // Provenance stamped onto each record.
        assert_eq!(norm.records[0].core.coverage_delta.exec_n, 99);
        // Decisions parsed.
        assert_eq!(norm.records[0].core.verifier_decision, VerifierDecision::Accept);
        assert_eq!(
            norm.records[1].core.verifier_decision,
            VerifierDecision::Reject { reason: "bad_ptr".into() }
        );
        // Counterfactual OFF, expectation NoPrediction (defaults on top of core).
        assert!(!norm.records[0].counterfactual.enabled);
        assert_eq!(norm.records[0].expectation.expected, Expectation::NoPrediction);

        // The NORMALIZED artifact round-trips through the contract.
        let art: Artifact<NormalizedMetrics> =
            contract::read_artifact(&period.normalized()).unwrap();
        assert_eq!(art.producer, Producer::Normalize);
        assert_eq!(art.period_id, 1);
        assert_eq!(art.payload.records.len(), 2);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn unimplemented_parser_yields_no_records() {
        let base = scratch_dir("unimpl");
        let out = base.join("blob.bin");
        std::fs::write(&out, b"whatever native bytes").unwrap();
        let period = PeriodPaths::new(&base.join("data"), 5);
        let raw = ingest::run(&period, &[Source::new("trinity", &out)], 3).unwrap();

        let norm = run(&period, &raw, &UnimplementedParser).unwrap();
        assert!(norm.records.is_empty());
        assert_eq!(norm.derived.record_count, 0);
        assert_eq!(norm.exec_count, 3);

        std::fs::remove_dir_all(&base).ok();
    }
}
