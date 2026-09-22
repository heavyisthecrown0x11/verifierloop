//! Demo: run the period-loop spine with a MockDriver over several periods and
//! print each period's harvest. Doubles as documentation of how the orchestrator
//! drives periods by exec count.
//!
//!   cargo run -p orchestrator --example period_spine -- <base_dir>

use orchestrator::driver::MockDriver;
use orchestrator::loop_runtime::{run_periods, LoopConfig};
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: period_spine <base_dir>"),
    );

    let cfg = LoopConfig {
        data_root: base.join("data"),
        exec_threshold: 100, // period boundary = every 100 execs (N, not time)
    };
    let mut driver = MockDriver::new(base.join("fuzzout"), &["syzkaller", "differential"], 40);

    let harvests = run_periods(&cfg, &mut driver, 3).expect("loop spine failed");
    for h in &harvests {
        println!(
            "period {} | exec_count={} | files={} | {}",
            h.period_id,
            h.exec_count,
            h.collected_files,
            h.raw_index.display()
        );
    }
}
