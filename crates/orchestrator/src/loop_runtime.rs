//! Loop runtime — the period loop that drives one hunting cycle.
//!
//! ============================================================================
//! HARD DESIGN GUARDRAIL — confirmation-biased fuzzer risk (DO NOT REMOVE)
//! ----------------------------------------------------------------------------
//! The loop is obliged to produce counterfactual output. That obligation MUST
//! NOT turn the loop into a counterfactual-OPTIMIZING process that generates
//! input in order to confirm its own expectation. That failure mode is a
//! confirmation-biased fuzzer: it would steer fuzzing toward inputs that make
//! the loop "right" instead of toward inputs that expose verifier bugs.
//!
//! This is NOT a solved problem. It is a LIVE stress point that every change to
//! the scoring / counterfactual / input-selection path must be checked against.
//!
//! The guards, and why each matters:
//!   * CORE metrics stay INDEPENDENT of the counterfactual layer — the diff
//!     engine reads raw observation, never the loop's own generated alternatives.
//!   * The "did the loop expect this?" flag is recorded SEPARATELY, so
//!     confirmation bias is *measured* rather than hidden.
//!   * HUMAN-IN-THE-LOOP at every period boundary — a person triages the batch;
//!     the loop does not close the loop on itself. The spine below STOPS at the
//!     harvest (ingest) boundary for exactly this reason.
//!   * The counterfactual layer is OPT-IN and MUST NOT feed back into fuzzer
//!     input selection.
//! ============================================================================
//!
//! PERIOD MODEL:
//!   * Period N is measured by TOTAL FUZZING EXEC COUNT (a counter) — NOT time.
//!   * Wall-clock time is only a timestamp stamped onto data. It is NEVER a
//!     stopping criterion.
//!   * A secondary efficiency observation (new coverage / new state per exec) is
//!     recorded for the report ONLY — it is NOT a decision or steering criterion.

use crate::driver::{DriverError, FuzzDriver};
use crate::period::Period;
use contract::PeriodPaths;
use pipeline::ingest;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for a loop run.
#[derive(Debug, Clone)]
pub struct LoopConfig {
    /// Root under which per-period artifacts are written (`<root>/periods/<N>/…`).
    pub data_root: PathBuf,
    /// Execs each period must accrue before its boundary (the harvest point).
    pub exec_threshold: u64,
}

/// What one period produced at its harvest boundary. The downstream stages
/// (normalize/score/diff/report) are not run yet, so a harvest is the raw,
/// unchanged batch handed to the human-in-the-loop.
#[derive(Debug, Clone)]
pub struct Harvest {
    /// Period id N.
    pub period_id: u64,
    /// Cumulative exec count at harvest.
    pub exec_count: u64,
    /// Path to the `RAW_INDEX` artifact for this period.
    pub raw_index: PathBuf,
    /// Number of native-output files collected.
    pub collected_files: usize,
}

/// Errors from running the loop.
#[derive(Debug)]
pub enum LoopError {
    /// The fuzzer driver failed.
    Driver(DriverError),
    /// The ingest stage failed.
    Ingest(ingest::IngestError),
}

impl std::fmt::Display for LoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoopError::Driver(e) => write!(f, "loop driver error: {e}"),
            LoopError::Ingest(e) => write!(f, "loop ingest error: {e}"),
        }
    }
}

impl std::error::Error for LoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoopError::Driver(e) => Some(e),
            LoopError::Ingest(e) => Some(e),
        }
    }
}

impl From<DriverError> for LoopError {
    fn from(e: DriverError) -> Self {
        LoopError::Driver(e)
    }
}

impl From<ingest::IngestError> for LoopError {
    fn from(e: ingest::IngestError) -> Self {
        LoopError::Ingest(e)
    }
}

/// Run a single period to its harvest boundary.
///
/// Drives the fuzzers until the period reaches its EXEC-COUNT threshold, then
/// harvests: `ingest` collects the native output UNCHANGED and writes `RAW_INDEX`.
/// The loop STOPS here — the downstream pipeline is the human-in-the-loop handoff.
pub fn run_period(
    cfg: &LoopConfig,
    period: &mut Period,
    driver: &mut dyn FuzzDriver,
) -> Result<Harvest, LoopError> {
    period.exec_count = driver.exec_count();
    while !period.is_complete() {
        // The boundary is exec count, never elapsed time.
        period.exec_count = driver.pump()?;
    }
    period.harvest_unix = now_unix(); // label only

    let paths = PeriodPaths::new(&cfg.data_root, period.id);
    let obs = ingest::run(&paths, &driver.sources(), period.exec_count)?;

    // TODO(loop): downstream stages — normalize -> score (Python, over the
    // contract) -> diff (vs the 4 ground-truth sources) -> report. They are still
    // stubs; keeping the spine stopped at the harvest boundary is intentional
    // (human-in-the-loop; see the guardrail above).

    Ok(Harvest {
        period_id: period.id,
        exec_count: period.exec_count,
        raw_index: paths.raw_index(),
        collected_files: obs.entries.len(),
    })
}

/// Run `count` consecutive periods. Each period starts where the previous ended
/// (cumulative exec count), so period boundaries fall at N, 2N, 3N, … execs.
pub fn run_periods(
    cfg: &LoopConfig,
    driver: &mut dyn FuzzDriver,
    count: u64,
) -> Result<Vec<Harvest>, LoopError> {
    let mut harvests = Vec::new();
    for id in 0..count {
        let start = driver.exec_count();
        let mut period = Period::new(id, start, cfg.exec_threshold);
        harvests.push(run_period(cfg, &mut period, driver)?);
    }
    Ok(harvests)
}

/// Current time as Unix epoch seconds — a label only.
fn now_unix() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Binary entry point.
///
/// The loop control flow (`run_period` / `run_periods`) is complete and tested,
/// but the real VM-backed `FuzzDriver` is not wired yet (see `driver` TODO), so
/// there is no production driver to construct here.
pub fn run() {
    // A real VM-backed driver now exists: `driver::VmHarnessDriver` +
    // `ScriptRunner` (boots the disposable bpf-next VM, runs the differential/
    // verifier-log harness, ingests its native output). Run one real period with
    // the `real_period` example; syzkaller-driven execs are still to be wired in.
    eprintln!(
        "verifierloop: loop ready (period = exec-count N). Real VM-backed driver: \
`cargo run -p orchestrator --example real_period -- <dir>` (boots the VM + runs \
the harness). Spine-only (mock) demo: `--example period_spine -- <dir>`."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::MockDriver;

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-loop-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn period_completes_at_exec_boundary_and_harvests() {
        let base = scratch_dir("one");
        let cfg = LoopConfig {
            data_root: base.join("data"),
            exec_threshold: 100,
        };
        let mut driver = MockDriver::new(base.join("fuzzout"), &["syzkaller", "differential"], 30);
        let mut period = Period::new(0, 0, cfg.exec_threshold);

        let h = run_period(&cfg, &mut period, &mut driver).unwrap();

        assert!(period.is_complete());
        assert!(period.exec_count >= 100, "reached the exec boundary");
        assert!(period.harvest_unix.is_some(), "harvest stamped a label");
        assert_eq!(h.collected_files, 2, "one native file per tool");
        assert!(h.raw_index.exists());

        // The harvest's RAW_INDEX carries the exec count and ingest provenance.
        let art: contract::Artifact<ingest::RawObservation> =
            contract::read_artifact(&h.raw_index).unwrap();
        assert_eq!(art.producer, contract::Producer::Ingest);
        assert_eq!(art.period_id, 0);
        assert_eq!(art.payload.exec_count, period.exec_count);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn periods_advance_by_cumulative_exec_count() {
        let base = scratch_dir("many");
        let cfg = LoopConfig {
            data_root: base.join("data"),
            exec_threshold: 50,
        };
        let mut driver = MockDriver::new(base.join("fuzzout"), &["syzkaller"], 20);

        let harvests = run_periods(&cfg, &mut driver, 3).unwrap();

        assert_eq!(harvests.len(), 3);
        // Monotonic, distinct per-period exec counts and dirs.
        assert!(harvests[0].exec_count >= 50);
        assert!(harvests[1].exec_count >= 100);
        assert!(harvests[2].exec_count >= 150);
        assert_ne!(harvests[0].raw_index, harvests[1].raw_index);
        assert_ne!(harvests[1].raw_index, harvests[2].raw_index);

        std::fs::remove_dir_all(&base).ok();
    }
}
