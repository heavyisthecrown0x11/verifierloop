//! Rust <-> Python boundary: the typed JSON artifact-file contract.
//!
//! LANGUAGE BOUNDARY (see README):
//!   * Rust owns orchestration + produces normalized metric artifacts.
//!   * Python owns statistics / anomaly scoring; it reads/writes JSON artifacts.
//!   * They exchange *files* under a period directory — a file-based contract that
//!     matches the "periodic harvest" model. No shared process memory.
//!
//! This module defines the artifact *envelope* and the on-disk layout. The
//! Python mirror lives in `python/.../contract.py` — keep the two in lockstep.
//!
//! The envelope is now FINALIZED and (de)serializes via serde. The *payload* is
//! generic (`Artifact<T>`): metric payload types are still `Tbd` in the `metrics`
//! crate, so callers use `Artifact<serde_json::Value>` (see [`read_raw`]) for now
//! and switch to `Artifact<ConcreteMetric>` once those types are frozen.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// On-disk envelope schema version. Bump on any breaking change to the envelope
/// shape (field names/semantics). Payload schemas evolve independently while
/// their types remain `Tbd`. Both sides (Rust here, Python `contract.py`) check it.
pub const CONTRACT_VERSION: u32 = 1;

/// Canonical file names inside a period directory. Rust writes the inputs,
/// Python writes the outputs; neither side renames or normalizes the other's
/// files (the "collect native output unchanged" principle applies across the wire).
pub mod filenames {
    /// Raw, unchanged native tool output index (written by the `ingest` stage).
    pub const RAW_INDEX: &str = "raw/index.json";
    /// Normalized metrics (Rust `normalize` stage -> Python).
    pub const NORMALIZED: &str = "normalized_metrics.json";
    /// Anomaly scores (Python -> Rust).
    pub const ANOMALY_SCORES: &str = "anomaly_scores.json";
    /// Documented-vs-observed diff findings (the `diff` stage).
    pub const DIFF_FINDINGS: &str = "diff_findings.json";
    /// Human-facing triaged period report.
    pub const PERIOD_REPORT: &str = "period_report.json";
}

/// Which pipeline stage / language side produced an artifact.
///
/// Serializes as snake_case (`"ingest"`, `"normalize"`, `"score"`, ...) — the
/// Python mirror must use the same string values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Producer {
    /// `ingest` stage (Rust): raw native-output index.
    Ingest,
    /// `normalize` stage (Rust): normalized metrics.
    Normalize,
    /// Python analyzer: anomaly scores.
    Score,
    /// `diff` stage (Rust): documented-vs-observed findings.
    Diff,
    /// `report` stage (Rust): the triaged period report.
    Report,
}

/// Envelope wrapping any artifact payload with provenance + schema version.
///
/// Generic over the payload `T`. Default `T = serde_json::Value` keeps the type
/// usable while metric payloads are still `Tbd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact<T = serde_json::Value> {
    /// `CONTRACT_VERSION` at write time. Checked on read.
    pub contract_version: u32,
    /// Which period produced it (N = the exec-count boundary).
    pub period_id: u64,
    /// Which pipeline stage / language side produced this.
    pub producer: Producer,
    /// The payload (a metrics group, scores, diff findings, ...).
    pub payload: T,
}

impl<T> Artifact<T> {
    /// Build an envelope stamped with the current [`CONTRACT_VERSION`].
    pub fn new(period_id: u64, producer: Producer, payload: T) -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            period_id,
            producer,
            payload,
        }
    }
}

/// Resolves the on-disk paths for a single period's artifacts.
///
/// Layout: `<data_root>/periods/<period_id>/<artifact>`.
#[derive(Debug, Clone)]
pub struct PeriodPaths {
    /// Root dir for this period: `<data_root>/periods/<period_id>/`.
    pub root: PathBuf,
    /// The period id (N) — used to stamp the artifact envelope's `period_id`.
    pub period_id: u64,
}

impl PeriodPaths {
    /// Build the period directory path from a data root + period id.
    pub fn new(data_root: &Path, period_id: u64) -> Self {
        Self {
            root: data_root.join("periods").join(period_id.to_string()),
            period_id,
        }
    }

    /// Absolute path to a named artifact within this period.
    pub fn artifact(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Create the period directory if it does not exist.
    pub fn ensure(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)
    }

    /// Path to the raw native-output index.
    pub fn raw_index(&self) -> PathBuf {
        self.artifact(filenames::RAW_INDEX)
    }
    /// Path to the normalized-metrics artifact.
    pub fn normalized(&self) -> PathBuf {
        self.artifact(filenames::NORMALIZED)
    }
    /// Path to the anomaly-scores artifact.
    pub fn anomaly_scores(&self) -> PathBuf {
        self.artifact(filenames::ANOMALY_SCORES)
    }
    /// Path to the diff-findings artifact.
    pub fn diff_findings(&self) -> PathBuf {
        self.artifact(filenames::DIFF_FINDINGS)
    }
    /// Path to the period-report artifact.
    pub fn period_report(&self) -> PathBuf {
        self.artifact(filenames::PERIOD_REPORT)
    }
}

/// Errors from reading/writing artifacts.
#[derive(Debug)]
pub enum ContractError {
    /// Filesystem I/O failure.
    Io(std::io::Error),
    /// JSON (de)serialization failure.
    Json(serde_json::Error),
    /// On-disk `contract_version` did not match [`CONTRACT_VERSION`].
    VersionMismatch {
        /// Version found in the file.
        found: u32,
        /// Version this build expects.
        expected: u32,
    },
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractError::Io(e) => write!(f, "contract i/o error: {e}"),
            ContractError::Json(e) => write!(f, "contract json error: {e}"),
            ContractError::VersionMismatch { found, expected } => write!(
                f,
                "contract version mismatch: file is v{found}, this build expects v{expected}"
            ),
        }
    }
}

impl std::error::Error for ContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ContractError::Io(e) => Some(e),
            ContractError::Json(e) => Some(e),
            ContractError::VersionMismatch { .. } => None,
        }
    }
}

impl From<std::io::Error> for ContractError {
    fn from(e: std::io::Error) -> Self {
        ContractError::Io(e)
    }
}

impl From<serde_json::Error> for ContractError {
    fn from(e: serde_json::Error) -> Self {
        ContractError::Json(e)
    }
}

/// Minimal header used to check the schema version before deserializing the full,
/// possibly-incompatible, payload.
#[derive(Deserialize)]
struct VersionHeader {
    contract_version: u32,
}

/// Read a typed artifact from disk, verifying the schema version first.
///
/// The version is checked before the payload is deserialized, so a
/// version-incompatible file reports [`ContractError::VersionMismatch`] rather
/// than a confusing payload-shape error.
pub fn read_artifact<T: DeserializeOwned>(path: &Path) -> Result<Artifact<T>, ContractError> {
    let bytes = std::fs::read(path)?;
    let header: VersionHeader = serde_json::from_slice(&bytes)?;
    if header.contract_version != CONTRACT_VERSION {
        return Err(ContractError::VersionMismatch {
            found: header.contract_version,
            expected: CONTRACT_VERSION,
        });
    }
    let artifact: Artifact<T> = serde_json::from_slice(&bytes)?;
    Ok(artifact)
}

/// Read an artifact with an untyped (`serde_json::Value`) payload — for the phase
/// where metric payload types are not yet finalized.
pub fn read_raw(path: &Path) -> Result<Artifact<serde_json::Value>, ContractError> {
    read_artifact::<serde_json::Value>(path)
}

/// Write a typed artifact to disk (pretty JSON), atomically.
///
/// Creates the parent directory if needed, writes to a temp sibling, flushes, and
/// renames over the destination so a reader never sees a partially-written file.
pub fn write_artifact<T: Serialize>(
    path: &Path,
    artifact: &Artifact<T>,
) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = tmp_sibling(path);
    {
        let file = std::fs::File::create(&tmp)?;
        let mut w = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(&mut w, artifact)?;
        w.write_all(b"\n")?;
        w.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// A temp path next to `path` (same directory, so `rename` is atomic), tagged with
/// the pid to avoid collisions between concurrent processes.
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    fn scratch_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("verifierloop-contract-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn period_paths_layout() {
        let p = PeriodPaths::new(Path::new("/data"), 7);
        assert_eq!(p.root, Path::new("/data/periods/7"));
        assert_eq!(p.period_id, 7);
        assert_eq!(
            p.normalized(),
            Path::new("/data/periods/7/normalized_metrics.json")
        );
        assert_eq!(p.raw_index(), Path::new("/data/periods/7/raw/index.json"));
    }

    #[test]
    fn producer_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Producer::Score).unwrap(),
            "\"score\""
        );
    }

    #[test]
    fn round_trip_untyped() {
        let path = scratch_dir().join("rt_untyped.json");
        let payload = serde_json::json!({ "k": 1, "list": [1, 2, 3] });
        let art = Artifact::new(3, Producer::Score, payload.clone());
        write_artifact(&path, &art).unwrap();

        let back = read_raw(&path).unwrap();
        assert_eq!(back.contract_version, CONTRACT_VERSION);
        assert_eq!(back.period_id, 3);
        assert_eq!(back.producer, Producer::Score);
        assert_eq!(back.payload, payload);
        std::fs::remove_file(&path).ok();
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct DummyPayload {
        decision: String,
        processed: u64,
    }

    #[test]
    fn round_trip_typed() {
        let path = scratch_dir().join("rt_typed.json");
        let art = Artifact::new(
            1,
            Producer::Normalize,
            DummyPayload {
                decision: "reject".into(),
                processed: 42,
            },
        );
        write_artifact(&path, &art).unwrap();

        let back: Artifact<DummyPayload> = read_artifact(&path).unwrap();
        assert_eq!(
            back.payload,
            DummyPayload {
                decision: "reject".into(),
                processed: 42
            }
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn version_mismatch_detected() {
        let path = scratch_dir().join("bad_version.json");
        std::fs::write(
            &path,
            br#"{"contract_version":9999,"period_id":0,"producer":"ingest","payload":null}"#,
        )
        .unwrap();
        let err = read_raw(&path).unwrap_err();
        assert!(matches!(
            err,
            ContractError::VersionMismatch {
                found: 9999,
                expected: CONTRACT_VERSION
            }
        ));
        std::fs::remove_file(&path).ok();
    }
}
