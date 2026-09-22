//! Helper-leg detector calibration — proves the helper `arg_type` mismatch is
//! decided from an EXTERNAL bpf_func_proto slice loaded from a FILE, not from an
//! expectation embedded in the test or in CORE.
//!
//! Unlike tnum well-formedness (intrinsic, computable from CORE alone), a helper
//! arg-type mismatch REQUIRES ground truth. So "calibrated on real data" is only
//! honest if the EXPECTED comes from a real loaded slice. These tests show exactly
//! where the decision comes from:
//!   * OBSERVED  -> parsed by VerifierLogParser from a REAL in-VM verifier log.
//!   * EXPECTED  -> HelperProtoModel::load_from_file(data/groundtruth/helper_protos.tsv),
//!                  whose value traces to kernel/bpf/helpers.c (ARG_CONST_MAP_PTR).
//!   * DECISION  -> diff compares the two; remove the file and the finding vanishes.

use contract::PeriodPaths;
use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::{GroundTruth, NoGroundTruth, StaticGroundTruth};
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize};
use std::path::PathBuf;

const SAMPLE: &str = include_str!("../../../harness/samples/bpf-next-sample.txt");

fn proto_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/groundtruth/helper_protos.tsv")
}

/// The `===PROG <name> ===` block from the authoritative sample.
fn block(name: &str) -> String {
    let start = SAMPLE
        .find(&format!("===PROG {name} "))
        .expect("named block present in the authoritative sample");
    let rest = &SAMPLE[start..];
    let end = rest[1..].find("===PROG ").map(|i| i + 1).unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Full real path for one native block against a given ground-truth oracle.
fn kinds(native: &str, gt: &dyn GroundTruth, tag: &str) -> Vec<(String, String, String)> {
    let scratch =
        std::env::temp_dir().join(format!("vl-helpercal-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let src = scratch.join("diffharness.log");
    std::fs::write(&src, native).unwrap();
    let period = PeriodPaths::new(&scratch.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, gt).unwrap();
    let r = out
        .findings
        .iter()
        .map(|f| (f.kind.clone(), f.expected.clone(), f.observed.clone()))
        .collect();
    let _ = std::fs::remove_dir_all(&scratch);
    r
}

fn map_ptr_mismatch(v: &[(String, String, String)]) -> Option<&(String, String, String)> {
    v.iter().find(|(k, _, _)| k == "helper_arg_type_mismatch")
}

#[test]
fn silent_when_observed_matches_the_loaded_proto() {
    // Real map_lookup: arg0 observed = map_ptr; the file says expected = map_ptr.
    let proto = HelperProtoModel::load_from_file(&proto_file()).unwrap();
    let gt = StaticGroundTruth::with_helper_proto(proto);
    let out = kinds(&block("map_lookup"), &gt, "clean");
    assert!(
        map_ptr_mismatch(&out).is_none(),
        "false positive on a correct helper call: {out:?}"
    );
}

#[test]
fn mismatch_requires_the_loaded_proto_slice_not_the_parser() {
    // Inject a wrong observed arg0 reg-type into the REAL log (map_ptr -> scalar).
    let mutant = block("map_lookup").replace("R1=map_ptr(ks=4,vs=8)", "R1=scalar()");
    assert_ne!(mutant, block("map_lookup"), "injection must change the observed arg0");

    // WITHOUT the slice, diff cannot decide a helper mismatch — it stays silent.
    let none = kinds(&mutant, &NoGroundTruth, "mutant_nogt");
    assert!(
        map_ptr_mismatch(&none).is_none(),
        "a helper mismatch appeared with NO ground truth — decision is not external: {none:?}"
    );

    // WITH the file-loaded slice, the same observation is now a mismatch.
    let proto = HelperProtoModel::load_from_file(&proto_file()).unwrap();
    let gt = StaticGroundTruth::with_helper_proto(proto);
    let with = kinds(&mutant, &gt, "mutant_gt");
    assert!(
        map_ptr_mismatch(&with).is_some(),
        "diff missed the injected helper arg-type mismatch: {with:?}"
    );
}

#[test]
fn expected_value_comes_from_the_file_not_the_test() {
    // The value the LOADER read from the file — obtained via the oracle, not a
    // literal in this test.
    let proto = HelperProtoModel::load_from_file(&proto_file()).unwrap();
    assert!(proto.len() >= 1, "the slice file actually loaded contracts");
    let gt = StaticGroundTruth::with_helper_proto(proto);
    let loaded_expected = gt
        .helper_arg_regtype("bpf_map_lookup_elem", 0)
        .expect("slice covers bpf_map_lookup_elem arg0");

    let mutant = block("map_lookup").replace("R1=map_ptr(ks=4,vs=8)", "R1=scalar()");
    let out = kinds(&mutant, &gt, "provenance");
    let finding = map_ptr_mismatch(&out).expect("mismatch present");

    // The finding's EXPECTED is exactly what the loader read from the file, and the
    // OBSERVED is exactly the injected reg-type — so the decision is file-vs-log.
    assert_eq!(
        finding.1, loaded_expected,
        "mismatch EXPECTED must be the file-loaded value, not embedded in the test"
    );
    assert_eq!(finding.2, "scalar", "mismatch OBSERVED is the injected reg-type");
}

// ---------------------------------------------------------------------------
// Widened slice (devlog 0019): the helper leg must be AWAKE at volume without
// manufacturing noise, and must not fire on rejected programs.
// ---------------------------------------------------------------------------

const VOLUME: &str = include_str!("fixtures/volume/syz-replay-95.log");

fn volume_normalized(tag: &str) -> pipeline::normalize::NormalizedMetrics {
    let dir = std::env::temp_dir().join(format!("vl-helpervol-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, VOLUME).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzreplay", &src)], 95).unwrap();
    let n = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    n
}

#[test]
fn widened_slice_is_awake_on_real_volume_without_false_positives() {
    let proto = HelperProtoModel::load_from_file(&proto_file()).unwrap();
    let gt = StaticGroundTruth::with_helper_proto(proto);
    let n = volume_normalized("awake");

    // The leg is actually exercised: a real share of the volume's helper-arg
    // observations are covered by the slice (it was 0 before widening).
    let total = n
        .records
        .iter()
        .map(|r| r.core.helper_arg_observations.len())
        .sum::<usize>();
    let covered = n
        .records
        .iter()
        .flat_map(|r| r.core.helper_arg_observations.iter())
        .filter(|o| gt.helper_arg_regtype(&o.helper, o.arg_index).is_some())
        .count();
    assert!(total >= 100, "volume should carry plenty of helper calls: {total}");
    assert!(
        covered * 3 >= total,
        "the slice should corroborate a real share of them, got {covered}/{total}"
    );

    // And it stays silent on this data: these are real programs the verifier
    // handled correctly, so a mismatch here would be a false positive.
    let dir = std::env::temp_dir().join(format!("vl-helpervol-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let out = diff::run(&period, &n, &gt).unwrap();
    let helper_findings: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind == "helper_arg_type_mismatch")
        .collect();
    assert!(
        helper_findings.is_empty(),
        "widened slice produced false positives on real volume data: {helper_findings:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mismatch_on_a_rejected_program_is_not_a_divergence() {
    // A rejected program with a bad arg type is the verifier WORKING, not a bug.
    // The bug-hunting signal is the opposite: accepted despite violating the proto.
    let proto = HelperProtoModel::load_from_file(&proto_file()).unwrap();
    let gt = StaticGroundTruth::with_helper_proto(proto);

    let accepted = block("map_lookup").replace("R1=map_ptr(ks=4,vs=8)", "R1=scalar()");
    let rejected = accepted.replace("decision=accept fd=4", "decision=reject fd=-1");
    assert_ne!(accepted, rejected, "the reject variant must differ");

    let acc = kinds(&accepted, &gt, "gate_accept");
    assert!(
        map_ptr_mismatch(&acc).is_some(),
        "an ACCEPTED program violating the proto is the real signal: {acc:?}"
    );

    let rej = kinds(&rejected, &gt, "gate_reject");
    assert!(
        map_ptr_mismatch(&rej).is_none(),
        "a REJECTED program must not be reported as a helper divergence: {rej:?}"
    );
}
