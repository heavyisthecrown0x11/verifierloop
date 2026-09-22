//! The fuzzer-driver abstraction.
//!
//! The loop advances a period by **exec count** and, at the boundary, ingests the
//! native output the fuzzers wrote. A [`FuzzDriver`] hides *how* execs are produced
//! so the loop control flow is testable without a real VM/syzkaller.
//!
//! The real driver (VM-backed: `vmctl` + syzkaller + differential harness) is not
//! implemented yet — see the TODO on [`FuzzDriver`]. [`MockDriver`] simulates
//! progress + native output for tests and the `period_spine` example.

use pipeline::ingest::Source;
use std::path::{Path, PathBuf};

/// Errors from a fuzzer driver.
#[derive(Debug)]
pub enum DriverError {
    /// Filesystem I/O failure (e.g. writing/locating native output).
    Io(std::io::Error),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriverError::Io(e) => write!(f, "driver i/o error: {e}"),
        }
    }
}

impl std::error::Error for DriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DriverError::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for DriverError {
    fn from(e: std::io::Error) -> Self {
        DriverError::Io(e)
    }
}

/// Drives the fuzzers and reports progress by cumulative exec count.
///
/// TODO(driver): implement a real VM-backed driver — boot a disposable bpf-next
/// VM via `vmctl`, launch syzkaller + the differential harness, read the KCOV/exec
/// counter, and point `sources()` at each tool's DEFAULT-mode native output dir.
pub trait FuzzDriver {
    /// Total fuzzing execs observed so far (cumulative, monotonically increasing).
    /// This is the ONLY quantity that advances a period — never wall-clock time.
    fn exec_count(&self) -> u64;

    /// Advance the fuzzers and return the new cumulative exec count. Implementations
    /// MUST make progress (strictly increase the count) so a period can terminate.
    fn pump(&mut self) -> Result<u64, DriverError>;

    /// Where each tool has written its DEFAULT-mode native output, for `ingest` to
    /// collect UNCHANGED at the harvest point.
    fn sources(&self) -> Vec<Source>;
}

/// A deterministic in-process driver: each `pump` bumps the exec count by a fixed
/// step and (re)writes a fake native-output file per tool. For tests/examples only.
#[derive(Debug)]
pub struct MockDriver {
    exec: u64,
    per_pump: u64,
    out_root: PathBuf,
    tools: Vec<String>,
}

impl MockDriver {
    /// `out_root` is where fake native output is written (one sub-dir per tool);
    /// each `pump` adds `per_pump` execs.
    pub fn new(out_root: impl Into<PathBuf>, tools: &[&str], per_pump: u64) -> Self {
        Self {
            exec: 0,
            per_pump: per_pump.max(1),
            out_root: out_root.into(),
            tools: tools.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl FuzzDriver for MockDriver {
    fn exec_count(&self) -> u64 {
        self.exec
    }

    fn pump(&mut self) -> Result<u64, DriverError> {
        self.exec += self.per_pump;
        // Simulate each tool appending to its native output (opaque to the loop).
        for tool in &self.tools {
            let dir = self.out_root.join(tool);
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                dir.join("log.txt"),
                format!("mock {tool} native output @ exec={}\n", self.exec),
            )?;
        }
        Ok(self.exec)
    }

    fn sources(&self) -> Vec<Source> {
        self.tools
            .iter()
            .map(|t| Source::new(t, self.out_root.join(t)))
            .collect()
    }
}


// ---------------------------------------------------------------------------
// Real VM-backed driver: the differential/verifier-log harness in a disposable VM.
// ---------------------------------------------------------------------------

/// Produces the harness's native output on demand. Abstracts the (heavy, VM-backed)
/// run so the driver and the loop stay unit-testable without booting a VM.
pub trait HarnessRunner {
    /// Run the harness once and write its DEFAULT native output to `dest`. Returns
    /// the number of programs (execs) produced in this batch.
    fn run(&mut self, dest: &Path) -> Result<u64, DriverError>;
}

/// Runs the real in-VM harness by shelling out to `scripts/run-harness-vm.sh`
/// (boot disposable bpf-next VM -> run diffharness -> capture native output).
pub struct ScriptRunner {
    script: PathBuf,
}

impl ScriptRunner {
    /// `script` is the path to `run-harness-vm.sh`.
    pub fn new(script: impl Into<PathBuf>) -> Self {
        Self {
            script: script.into(),
        }
    }
}

impl HarnessRunner for ScriptRunner {
    fn run(&mut self, dest: &Path) -> Result<u64, DriverError> {
        let status = std::process::Command::new("bash")
            .arg(&self.script)
            .arg(dest)
            .status()?;
        if !status.success() {
            return Err(DriverError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("run-harness-vm.sh exited with {status}"),
            )));
        }
        let text = std::fs::read_to_string(dest)?;
        Ok(count_programs(&text))
    }
}

/// Count `===PROG` blocks in harness native output (the batch's exec count).
fn count_programs(text: &str) -> u64 {
    text.lines().filter(|l| l.starts_with("===PROG ")).count() as u64
}

/// Real driver: each `pump` runs the differential/verifier-log harness (via a
/// [`HarnessRunner`]) and points `ingest` at its captured native output. The exec
/// count is the cumulative number of programs the verifier processed — the period
/// boundary, exactly as the model requires (never wall-clock time).
pub struct VmHarnessDriver<R: HarnessRunner> {
    exec: u64,
    runner: R,
    out_dir: PathBuf,
}

impl<R: HarnessRunner> VmHarnessDriver<R> {
    /// `out_dir` holds the collected native output (`<out_dir>/diffharness.log`).
    pub fn new(out_dir: impl Into<PathBuf>, runner: R) -> Self {
        Self {
            exec: 0,
            runner,
            out_dir: out_dir.into(),
        }
    }

    fn dest(&self) -> PathBuf {
        self.out_dir.join("diffharness.log")
    }
}

impl<R: HarnessRunner> FuzzDriver for VmHarnessDriver<R> {
    fn exec_count(&self) -> u64 {
        self.exec
    }

    fn pump(&mut self) -> Result<u64, DriverError> {
        std::fs::create_dir_all(&self.out_dir)?;
        let n = self.runner.run(&self.dest())?;
        // Guarantee forward progress so a period can always terminate.
        self.exec += n.max(1);
        Ok(self.exec)
    }

    fn sources(&self) -> Vec<Source> {
        vec![Source::new("diffharness", self.dest())]
    }
}

#[cfg(test)]
mod vm_driver_tests {
    use super::*;

    /// In-process runner that writes a canned harness sample (no VM).
    struct FakeRunner {
        sample: &'static str,
    }
    impl HarnessRunner for FakeRunner {
        fn run(&mut self, dest: &Path) -> Result<u64, DriverError> {
            std::fs::write(dest, self.sample)?;
            Ok(count_programs(self.sample))
        }
    }

    const SAMPLE: &str = "\
===PROG a type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
===PROG b type=socket_filter ===
RESULT decision=reject fd=-1 errno=13 load_ns=1
---LOG---
R0 !read_ok
processed 1 insns (limit 1000000) total_states 0 peak_states 0
---END---
";

    #[test]
    fn count_programs_counts_prog_blocks() {
        assert_eq!(count_programs(SAMPLE), 2);
    }

    #[test]
    fn pump_writes_output_and_advances_exec_count() {
        let dir = std::env::temp_dir().join(format!("vl-vmdrv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut d = VmHarnessDriver::new(&dir, FakeRunner { sample: SAMPLE });

        assert_eq!(d.exec_count(), 0);
        assert_eq!(d.pump().unwrap(), 2, "two programs per batch");
        assert_eq!(d.exec_count(), 2);

        // sources() points ingest at the captured native output, which now exists.
        assert_eq!(d.sources().len(), 1);
        assert!(d.dest().exists());

        // Cumulative across pumps.
        assert_eq!(d.pump().unwrap(), 4);

        std::fs::remove_dir_all(&dir).ok();
    }
}
