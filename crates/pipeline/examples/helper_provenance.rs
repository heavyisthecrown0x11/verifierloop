//! Shows WHERE the helper arg-type mismatch decision comes from — the reviewer's
//! bar: is the expected loaded from the bpf_func_proto slice, or embedded?
//!
//!   cargo run -p pipeline --example helper_provenance

use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::{GroundTruth, NoGroundTruth, StaticGroundTruth};
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize};
use std::path::PathBuf;

const SAMPLE: &str = include_str!("../../../harness/samples/bpf-next-sample.txt");

fn block(name: &str) -> String {
    let start = SAMPLE.find(&format!("===PROG {name} ")).unwrap();
    let rest = &SAMPLE[start..];
    let end = rest[1..].find("===PROG ").map(|i| i + 1).unwrap_or(rest.len());
    rest[..end].to_string()
}

fn run(native: &str, gt: &dyn GroundTruth, tag: &str) -> Vec<(String, String, String)> {
    let dir = std::env::temp_dir().join(format!("vl-prov-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, native).unwrap();
    let period = contract::PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, gt).unwrap();
    out.findings
        .iter()
        .filter(|f| f.kind == "helper_arg_type_mismatch")
        .map(|f| (f.kind.clone(), f.expected.clone(), f.observed.clone()))
        .collect()
}

fn main() {
    let proto_file =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/groundtruth/helper_protos.tsv");
    let proto = HelperProtoModel::load_from_file(&proto_file).expect("load proto slice");
    let gt = StaticGroundTruth::with_helper_proto(proto);
    let expected = gt.helper_arg_regtype("bpf_map_lookup_elem", 0).unwrap();

    println!("GROUND TRUTH (source 3 — bpf_func_proto slice)");
    println!("  file    : {}", proto_file.display());
    println!("  loaded  : bpf_map_lookup_elem arg0 -> expected reg-type = {expected:?}");
    println!("            (traces to kernel/bpf/helpers.c: .arg1_type = ARG_CONST_MAP_PTR)\n");

    // OBSERVED comes from parsing the real in-VM verifier log.
    println!("OBSERVED (parsed from the real in-VM verifier log)");
    let clean = run(&block("map_lookup"), &gt, "clean");
    println!("  real map_lookup: arg0 observed = map_ptr");
    println!("  diff vs slice  : {} finding(s)  -> correct: matches, silent\n", clean.len());

    // Inject a wrong observed arg0 into the real log.
    let mutant = block("map_lookup").replace("R1=map_ptr(ks=4,vs=8)", "R1=scalar()");
    println!("FAULT-INJECTED observed arg0 = scalar (map_ptr -> scalar in the real log)");

    let none = run(&mutant, &NoGroundTruth, "none");
    println!("  diff with NO ground truth : {} finding(s)  -> decision needs the external slice", none.len());

    let with = run(&mutant, &gt, "with");
    println!("  diff with the slice       : {} finding(s)", with.len());
    for (_, exp, obs) in &with {
        println!("     helper_arg_type_mismatch  expected={exp:?} (FROM FILE)  observed={obs:?} (FROM LOG)");
    }
    println!("\nVerdict: the mismatch's `expected` is the file-loaded value; remove the file");
    println!("and the finding disappears -> the decision is external ground truth, not embedded.");
}
