//! Cross-language interop helper for the artifact contract.
//!
//! Usage:
//!   cargo run -p contract --example interop -- write <path>   # Rust writes a sample
//!   cargo run -p contract --example interop -- read  <path>   # Rust reads + prints
//!
//! Paired with the Python side, this proves the file-based contract round-trips
//! across the Rust<->Python boundary.

use contract::{read_raw, write_artifact, Artifact, Producer};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    let path = args.get(2).map(String::as_str).unwrap_or("");
    if path.is_empty() {
        eprintln!("usage: interop <write|read> <path>");
        std::process::exit(2);
    }
    match mode {
        "write" => {
            let payload = serde_json::json!({
                "note": "written by rust",
                "verifier_decision": "reject",
                "processed": 128
            });
            let art = Artifact::new(5, Producer::Normalize, payload);
            write_artifact(Path::new(path), &art).expect("write");
            println!("rust wrote {path}");
        }
        "read" => {
            let art = read_raw(Path::new(path)).expect("read");
            println!(
                "rust read: v={} period={} producer={:?} payload={}",
                art.contract_version, art.period_id, art.producer, art.payload
            );
        }
        _ => {
            eprintln!("usage: interop <write|read> <path>");
            std::process::exit(2);
        }
    }
}
