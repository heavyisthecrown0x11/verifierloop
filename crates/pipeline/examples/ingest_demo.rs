//! Demo: run the `ingest` stage over some fake native tool output and print where
//! the RAW_INDEX artifact landed. Doubles as documentation of how the
//! orchestrator will call ingest.
//!
//!   cargo run -p pipeline --example ingest_demo -- <base_dir>

use contract::PeriodPaths;
use pipeline::ingest::{self, Source};
use std::fs;
use std::path::PathBuf;

fn main() {
    let base = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: ingest_demo <base_dir>"),
    );

    // Simulate tool output already written to the host in each tool's native form.
    let syz = base.join("syz_out");
    fs::create_dir_all(syz.join("crashes")).unwrap();
    fs::write(syz.join("log0.txt"), b"syzkaller native log, unchanged\n").unwrap();
    fs::write(syz.join("crashes").join("report0"), b"KASAN: ...raw...\n").unwrap();
    let diff = base.join("diff_out.txt");
    fs::write(&diff, b"differential harness: jit=1 interp=0\n").unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);
    let sources = vec![
        Source::new("syzkaller", &syz),
        Source::new("differential", &diff),
    ];

    let obs = ingest::run(&period, &sources, 4200).expect("ingest failed");
    println!(
        "ingested {} files at exec_count={}",
        obs.entries.len(),
        obs.exec_count
    );
    println!("raw index: {}", period.raw_index().display());
}
