//! Stage 1 — INGEST: collect fuzzer/recon output.
//!
//! Ingest collects each tool's DEFAULT-mode native output **unchanged**. It does
//! NOT parse, normalize, filter, or rename anything — that is `normalize`'s job
//! (the "collect native output unchanged, shape it only in a later stage"
//! principle). Ingest only:
//!   * copies each raw blob **byte-for-byte** into the period's `raw/<tool>/…`,
//!   * records provenance (tool, original path, size, mtime label, a content
//!     fingerprint, and the exec counter N),
//!   * writes the catalog as the `RAW_INDEX` contract artifact.
//!
//! Ingest does NOT run the fuzzers or touch VMs; it operates on the files those
//! tools already wrote. The orchestrator supplies the [`Source`] list from config.
//!
//! Blobs are copied (not referenced): the hunt runs in DISPOSABLE VMs, so a
//! period's harvest must be self-contained on the host once the VM is torn down.

use contract::{Artifact, PeriodPaths, Producer};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// One raw-output source produced by a fuzzer/recon tool. `path` may be a single
/// file or a directory (collected recursively). The bytes are treated as opaque.
#[derive(Debug, Clone)]
pub struct Source {
    /// Tool name, used as the sub-directory under `raw/` (e.g. "syzkaller").
    pub tool: String,
    /// Where the tool wrote its DEFAULT-mode native output on the host.
    pub path: PathBuf,
}

impl Source {
    /// Convenience constructor.
    pub fn new(tool: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            tool: tool.into(),
            path: path.into(),
        }
    }
}

/// Provenance record for one collected file. The file's *content* is never
/// parsed — only catalogued.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawEntry {
    /// Producing tool (the `raw/<tool>/…` bucket).
    pub tool: String,
    /// Original absolute source path on the host (provenance).
    pub source_path: String,
    /// Stored location, relative to the period's `raw/` directory.
    pub stored_path: String,
    /// Size in bytes (of the unchanged blob).
    pub bytes: u64,
    /// Source mtime as a Unix-epoch-seconds LABEL. `None` if unavailable.
    /// A timestamp is a label only — never a stopping/decision criterion.
    pub mtime_unix: Option<u64>,
    /// Content fingerprint of the unchanged bytes. Non-cryptographic (FNV-1a-64,
    /// hex) — for dedup / change-detection.
    /// TODO(ingest): swap to SHA-256 if cryptographic integrity is needed.
    pub fingerprint: String,
}

/// The `RAW_INDEX` payload: the catalog of everything collected this batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawObservation {
    /// Total fuzzing exec count N at collection time (provenance; supplied by the
    /// orchestrator — ingest does not count execs itself).
    pub exec_count: u64,
    /// One entry per collected file, in collection order.
    pub entries: Vec<RawEntry>,
}

/// Errors from the ingest stage.
#[derive(Debug)]
pub enum IngestError {
    /// Filesystem I/O failure.
    Io(std::io::Error),
    /// Failed to write the `RAW_INDEX` contract artifact.
    Contract(contract::ContractError),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Io(e) => write!(f, "ingest i/o error: {e}"),
            IngestError::Contract(e) => write!(f, "ingest contract error: {e}"),
        }
    }
}

impl std::error::Error for IngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngestError::Io(e) => Some(e),
            IngestError::Contract(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for IngestError {
    fn from(e: std::io::Error) -> Self {
        IngestError::Io(e)
    }
}

impl From<contract::ContractError> for IngestError {
    fn from(e: contract::ContractError) -> Self {
        IngestError::Contract(e)
    }
}

/// Collect all `sources` into the period's `raw/` directory, unchanged, and write
/// the `RAW_INDEX` artifact. Returns the in-memory catalog.
///
/// `exec_count` is the provenance N stamped onto the batch (supplied by caller).
pub fn run(
    period: &PeriodPaths,
    sources: &[Source],
    exec_count: u64,
) -> Result<RawObservation, IngestError> {
    let raw_root = period.artifact("raw");
    std::fs::create_dir_all(&raw_root)?;

    let mut entries = Vec::new();
    for src in sources {
        let tool_root = raw_root.join(&src.tool);
        let meta = std::fs::metadata(&src.path)?;
        if meta.is_dir() {
            collect_dir(&src.tool, &src.path, &src.path, &tool_root, &mut entries)?;
        } else {
            let file_name = src
                .path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("output"));
            collect_file(&src.tool, &src.path, &file_name, &tool_root, &mut entries)?;
        }
    }

    let obs = RawObservation {
        exec_count,
        entries,
    };

    // Write the catalog as the RAW_INDEX contract artifact. Borrow the payload so
    // we can return `obs` afterwards; the borrow ends when this block closes.
    {
        let artifact = Artifact::new(period.period_id, Producer::Ingest, &obs);
        contract::write_artifact(&period.raw_index(), &artifact)?;
    }

    Ok(obs)
}

/// Recursively collect every file under `dir`, preserving structure relative to
/// `base` (the source root) beneath `tool_root`.
fn collect_dir(
    tool: &str,
    base: &Path,
    dir: &Path,
    tool_root: &Path,
    entries: &mut Vec<RawEntry>,
) -> Result<(), IngestError> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    // Deterministic order so the index is stable across runs.
    children.sort();
    for child in children {
        let meta = std::fs::symlink_metadata(&child)?;
        if meta.is_dir() {
            collect_dir(tool, base, &child, tool_root, entries)?;
        } else if meta.is_file() {
            let rel = child.strip_prefix(base).unwrap_or(&child).to_path_buf();
            collect_file(tool, &child, &rel, tool_root, entries)?;
        }
        // Symlinks and other special files are skipped (nothing to collect).
    }
    Ok(())
}

/// Copy one file unchanged into `tool_root/rel` and record its provenance.
fn collect_file(
    tool: &str,
    source_abs: &Path,
    rel: &Path,
    tool_root: &Path,
    entries: &mut Vec<RawEntry>,
) -> Result<(), IngestError> {
    let bytes = std::fs::read(source_abs)?;
    let dest = tool_root.join(rel);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Write the bytes verbatim — no transformation of tool output at the source.
    std::fs::write(&dest, &bytes)?;

    let mtime_unix = std::fs::metadata(source_abs)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    // stored_path is relative to the period's raw/ dir: "<tool>/<rel>".
    let stored_rel = Path::new(tool).join(rel);

    entries.push(RawEntry {
        tool: tool.to_string(),
        source_path: source_abs.display().to_string(),
        stored_path: stored_rel.display().to_string(),
        bytes: bytes.len() as u64,
        mtime_unix,
        fingerprint: fnv1a64_hex(&bytes),
    });
    Ok(())
}

/// FNV-1a 64-bit content fingerprint, hex-encoded. Deterministic and
/// cross-platform (unlike `DefaultHasher`), but NOT cryptographic.
fn fnv1a64_hex(bytes: &[u8]) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001B3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-ingest-{}-{}",
            std::process::id(),
            tag
        ));
        // Start clean.
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn collects_files_and_dirs_unchanged() {
        let base = scratch_dir("collect");

        // Fake native tool output already on disk.
        let syz = base.join("syz_out");
        std::fs::create_dir_all(syz.join("crashes")).unwrap();
        std::fs::write(syz.join("log0.txt"), b"syz log, unchanged\n").unwrap();
        std::fs::write(syz.join("crashes").join("report0"), b"KASAN raw\n").unwrap();
        let diff = base.join("diff_out.txt");
        std::fs::write(&diff, b"jit=1 interp=0\n").unwrap();

        let period = PeriodPaths::new(&base.join("data"), 1);
        let sources = vec![
            Source::new("syzkaller", &syz),
            Source::new("differential", &diff),
        ];

        let obs = run(&period, &sources, 4200).unwrap();

        // 3 files collected, exec_count preserved.
        assert_eq!(obs.entries.len(), 3);
        assert_eq!(obs.exec_count, 4200);

        // Copied bytes are byte-identical to the originals.
        let stored_log = period.artifact("raw").join("syzkaller/log0.txt");
        assert_eq!(std::fs::read(stored_log).unwrap(), b"syz log, unchanged\n");
        let stored_diff = period.artifact("raw").join("differential/diff_out.txt");
        assert_eq!(std::fs::read(stored_diff).unwrap(), b"jit=1 interp=0\n");

        // Nested structure preserved.
        assert!(period
            .artifact("raw")
            .join("syzkaller/crashes/report0")
            .exists());

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn writes_readable_raw_index_artifact() {
        let base = scratch_dir("index");
        let out = base.join("t.log");
        std::fs::write(&out, b"hello").unwrap();
        let period = PeriodPaths::new(&base.join("data"), 2);

        run(&period, &[Source::new("trinity", &out)], 7).unwrap();

        // The RAW_INDEX artifact exists and round-trips back through the contract.
        let art: Artifact<RawObservation> = contract::read_artifact(&period.raw_index()).unwrap();
        assert_eq!(art.producer, Producer::Ingest);
        assert_eq!(art.period_id, 2);
        assert_eq!(art.payload.exec_count, 7);
        assert_eq!(art.payload.entries.len(), 1);
        let e = &art.payload.entries[0];
        assert_eq!(e.tool, "trinity");
        assert_eq!(e.bytes, 5);
        assert_eq!(e.stored_path, "trinity/t.log");

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn fingerprint_is_deterministic_and_content_sensitive() {
        assert_eq!(fnv1a64_hex(b"abc"), fnv1a64_hex(b"abc"));
        assert_ne!(fnv1a64_hex(b"abc"), fnv1a64_hex(b"abd"));
        // Known FNV-1a-64 vector for "" is the offset basis.
        assert_eq!(fnv1a64_hex(b""), "cbf29ce484222325");
    }
}
