//! Stage 3 — ANOMALY SCORING (Rust side of the language boundary).
//!
//! Statistics / anomaly scoring is owned by PYTHON. Rust does not score here; it
//! invokes the Python analyzer over the file-based contract and reads the scores
//! back. Assumes `normalize` already wrote the NORMALIZED artifact for the period.
//!
//! GUARDRAIL: anomaly scores RANK records for human triage at the period boundary.
//! They MUST NOT feed back into fuzzer input selection (confirmation-bias guardrail).
//!
//! The analyzer is injected ([`Analyzer`]) so this stage is testable without a
//! Python runtime; [`PythonAnalyzer`] is the real subprocess-backed implementation.

use contract::{Artifact, PeriodPaths};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

/// Anomaly score for one NORMALIZED record (aligned by `index`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordScore {
    /// Index of the record in `NormalizedMetrics.records`.
    pub index: u64,
    /// Anomaly score in `0.0..=1.0` (higher = more worth a human's attention).
    pub score: f64,
    /// Human-readable reasons, for triage.
    pub reasons: Vec<String>,
}

/// Period-level scoring summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreSummary {
    /// Number of records scored.
    pub record_count: u64,
    /// Number of records at or above the flag threshold.
    pub flagged: u64,
    /// Maximum score observed.
    pub max_score: f64,
}

/// The ANOMALY_SCORES payload read back from Python.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyScores {
    /// Exec count N (carried through from NORMALIZED).
    pub exec_count: u64,
    /// Per-record scores.
    pub scored: Vec<RecordScore>,
    /// Period-level summary.
    pub summary: ScoreSummary,
    /// Which scoring method produced these (e.g. "baseline-hard-signals-v0").
    pub method: String,
}

/// Produces the ANOMALY_SCORES artifact for a period (reads NORMALIZED, writes
/// ANOMALY_SCORES). Injected so the stage is testable without Python.
pub trait Analyzer {
    /// Run analysis for `period`; on success the ANOMALY_SCORES artifact exists.
    fn analyze(&self, period: &PeriodPaths) -> Result<(), AnalyzerError>;
}

/// Errors from an analyzer.
#[derive(Debug)]
pub enum AnalyzerError {
    /// Failed to spawn / wait on the analyzer process.
    Io(std::io::Error),
    /// The analyzer process exited non-zero.
    NonZeroExit(Option<i32>),
    /// Contract read/write failure inside the analyzer.
    Contract(contract::ContractError),
}

impl std::fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyzerError::Io(e) => write!(f, "analyzer i/o error: {e}"),
            AnalyzerError::NonZeroExit(code) => {
                write!(f, "analyzer exited non-zero: {code:?}")
            }
            AnalyzerError::Contract(e) => write!(f, "analyzer contract error: {e}"),
        }
    }
}

impl std::error::Error for AnalyzerError {}

impl From<std::io::Error> for AnalyzerError {
    fn from(e: std::io::Error) -> Self {
        AnalyzerError::Io(e)
    }
}

impl From<contract::ContractError> for AnalyzerError {
    fn from(e: contract::ContractError) -> Self {
        AnalyzerError::Contract(e)
    }
}

/// Real analyzer: spawns the Python package
/// (`python -m verifierloop_analysis --period-dir <dir>`).
#[derive(Debug, Clone)]
pub struct PythonAnalyzer {
    /// Python interpreter program (e.g. "python3").
    pub program: String,
    /// Args before `--period-dir` (e.g. `["-m", "verifierloop_analysis"]`).
    pub module_args: Vec<String>,
    /// Optional path prepended to `PYTHONPATH` (e.g. the repo's `python/src`).
    pub pythonpath: Option<String>,
}

impl Default for PythonAnalyzer {
    fn default() -> Self {
        Self {
            program: "python3".to_string(),
            module_args: vec!["-m".to_string(), "verifierloop_analysis".to_string()],
            pythonpath: None,
        }
    }
}

impl PythonAnalyzer {
    /// Analyzer using `python3 -m verifierloop_analysis`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepend `path` to `PYTHONPATH` (for running against the in-repo package
    /// before it is installed).
    pub fn with_pythonpath(mut self, path: impl Into<String>) -> Self {
        self.pythonpath = Some(path.into());
        self
    }
}

impl Analyzer for PythonAnalyzer {
    fn analyze(&self, period: &PeriodPaths) -> Result<(), AnalyzerError> {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.module_args);
        cmd.arg("--period-dir").arg(&period.root);
        if let Some(pp) = &self.pythonpath {
            let existing = std::env::var("PYTHONPATH").unwrap_or_default();
            let combined = if existing.is_empty() {
                pp.clone()
            } else {
                format!("{pp}:{existing}")
            };
            cmd.env("PYTHONPATH", combined);
        }
        let status = cmd.status()?;
        if !status.success() {
            return Err(AnalyzerError::NonZeroExit(status.code()));
        }
        Ok(())
    }
}

/// Errors from the score stage.
#[derive(Debug)]
pub enum ScoreError {
    /// The analyzer failed.
    Analyzer(AnalyzerError),
    /// Reading the ANOMALY_SCORES artifact failed.
    Contract(contract::ContractError),
}

impl std::fmt::Display for ScoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScoreError::Analyzer(e) => write!(f, "score analyzer error: {e}"),
            ScoreError::Contract(e) => write!(f, "score contract error: {e}"),
        }
    }
}

impl std::error::Error for ScoreError {}

impl From<AnalyzerError> for ScoreError {
    fn from(e: AnalyzerError) -> Self {
        ScoreError::Analyzer(e)
    }
}

impl From<contract::ContractError> for ScoreError {
    fn from(e: contract::ContractError) -> Self {
        ScoreError::Contract(e)
    }
}

/// Run anomaly scoring for a period: invoke the analyzer, then read back the
/// ANOMALY_SCORES artifact via the contract.
pub fn run(period: &PeriodPaths, analyzer: &dyn Analyzer) -> Result<AnomalyScores, ScoreError> {
    analyzer.analyze(period)?;
    let artifact: Artifact<AnomalyScores> = contract::read_artifact(&period.anomaly_scores())?;
    Ok(artifact.payload)
}

/// Convenience: locate the in-repo Python package path (`<crate>/../../python/src`)
/// so examples/tests can run against it before install. Best-effort.
pub fn repo_pythonpath() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../python/src")
        .canonicalize()
        .ok()?;
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::Producer;

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-score-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Hermetic analyzer: writes a canned ANOMALY_SCORES (no Python needed).
    struct CannedAnalyzer;
    impl Analyzer for CannedAnalyzer {
        fn analyze(&self, period: &PeriodPaths) -> Result<(), AnalyzerError> {
            let scores = AnomalyScores {
                exec_count: 42,
                scored: vec![RecordScore {
                    index: 0,
                    score: 0.95,
                    reasons: vec!["jit/interp divergence".to_string()],
                }],
                summary: ScoreSummary {
                    record_count: 1,
                    flagged: 1,
                    max_score: 0.95,
                },
                method: "test".to_string(),
            };
            let artifact = Artifact::new(period.period_id, Producer::Score, &scores);
            contract::write_artifact(&period.anomaly_scores(), &artifact)?;
            Ok(())
        }
    }

    #[test]
    fn reads_back_scores_from_analyzer() {
        let base = scratch_dir("readback");
        let period = PeriodPaths::new(&base.join("data"), 7);

        let scores = run(&period, &CannedAnalyzer).unwrap();

        assert_eq!(scores.exec_count, 42);
        assert_eq!(scores.summary.flagged, 1);
        assert_eq!(scores.scored[0].index, 0);
        assert!(scores.scored[0].score >= 0.9);
        assert_eq!(scores.method, "test");

        // The artifact on disk carries Producer::Score + the period id.
        let art: Artifact<AnomalyScores> =
            contract::read_artifact(&period.anomaly_scores()).unwrap();
        assert_eq!(art.producer, Producer::Score);
        assert_eq!(art.period_id, 7);

        std::fs::remove_dir_all(&base).ok();
    }
}
