//! Parser blind-spot RATE on a real volume capture — the result metric, not a
//! process claim.
//!
//! A period's "0 divergences" is only trustworthy if the parser actually read the
//! data. This pins that on the real 95-block capture from replaying the syzkaller
//! corpus in the bpf-next VM (devlog 0018), and enforces the distinction that
//! makes the number readable:
//!
//!   blocks = records + unparsed
//!   unparsed = not_observed (verifier never ran)  +  unrecognized (PARSER FAILED)
//!
//! Only `unrecognized` measures the parser. `not_observed` is the data having
//! nothing to observe (loads rejected at the syscall boundary) and is expected at
//! volume — conflating the two makes a healthy parser look 26% broken.

use contract::PeriodPaths;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const VOLUME: &str = include_str!("fixtures/volume/syz-replay-95.log");
/// A second, larger and more diverse capture (grown corpus, 30-min campaign).
/// The blind-spot rate must hold across BOTH — one sample could be luck.
const VOLUME2: &str = include_str!("fixtures/volume/syz-replay-184.log");

fn normalized_of(text: &str, tag: &str) -> normalize::NormalizedMetrics {
    let dir = std::env::temp_dir().join(format!("vl-volume-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzreplay", &src)], 95).unwrap();
    let n = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    n
}

fn normalized(tag: &str) -> normalize::NormalizedMetrics {
    normalized_of(VOLUME, tag)
}

#[test]
fn no_unrecognized_blocks_in_either_real_volume_capture() {
    // The rate must hold on BOTH captures — a single sample could be luck, and the
    // second is ~2x larger with 44 distinct reject reasons (vs 20).
    for (text, tag, blocks) in [(VOLUME, "unrec95", 95usize), (VOLUME2, "unrec184", 184)] {
        let n = normalized_of(text, tag);
        let unrecognized: Vec<_> = n
            .unparsed
            .iter()
            .filter(|u| u.kind == UnparsedKind::Unrecognized)
            .collect();
        assert!(
            unrecognized.is_empty(),
            "parser blind-spots in the {blocks}-block capture (must stay 0): {unrecognized:?}"
        );
        assert_eq!(
            n.records.len() + n.unparsed.len(),
            blocks,
            "counts must reconcile in the {blocks}-block capture"
        );
    }
}

/// The bigger capture: same 0% rate, and a much wider spread of real verifier text.
#[test]
fn larger_capture_holds_the_rate_and_widens_coverage() {
    let n = normalized_of(VOLUME2, "big");
    assert_eq!(n.records.len(), 151);
    assert_eq!(n.unparsed.len(), 33);
    assert!(n.unparsed.iter().all(|u| u.kind == UnparsedKind::NotObserved));

    let distinct: std::collections::BTreeSet<_> = n
        .records
        .iter()
        .filter_map(|r| match &r.core.verifier_decision {
            metrics::core::VerifierDecision::Reject { reason } if reason != "unknown" => {
                Some(reason.clone())
            }
            _ => None,
        })
        .collect();
    assert!(
        distinct.len() >= 40,
        "the grown corpus should yield a much wider reject spread, got {}",
        distinct.len()
    );
}

#[test]
fn counts_reconcile_and_every_observable_block_became_a_record() {
    let n = normalized("reconcile");
    let blocks = VOLUME.lines().filter(|l| l.starts_with("===PROG ")).count();
    assert_eq!(blocks, 95, "the committed capture is the 95-block volume run");
    assert_eq!(
        n.records.len() + n.unparsed.len(),
        blocks,
        "blocks must reconcile: records + unparsed"
    );
    // Every block that carried verifier output produced a record.
    assert_eq!(n.records.len(), 70);
    assert_eq!(n.unparsed.len(), 25);
    assert!(
        n.unparsed.iter().all(|u| u.kind == UnparsedKind::NotObserved),
        "all 25 are 'verifier never ran', not parser failures"
    );
}

#[test]
fn parsed_records_are_mostly_caveat_free_and_reasons_are_real_text() {
    let n = normalized("caveats");
    let with_notes = n.records.iter().filter(|r| !r.parse_notes.is_empty()).count();
    // Volume-quality bar: caveats stay a small minority of parsed records.
    assert!(
        with_notes * 10 <= n.records.len(),
        "records with parse caveats should stay under 10%: {with_notes}/{}",
        n.records.len()
    );

    // The reject reasons must be real verifier text, not a fabricated placeholder.
    let mut unknown = 0;
    let mut distinct = std::collections::BTreeSet::new();
    for r in &n.records {
        if let metrics::core::VerifierDecision::Reject { reason } = &r.core.verifier_decision {
            if reason == "unknown" {
                unknown += 1;
            } else {
                distinct.insert(reason.clone());
            }
        }
    }
    assert!(
        distinct.len() >= 15,
        "volume should yield a wide spread of real reject texts, got {}",
        distinct.len()
    );
    // A few loads genuinely print no failure text; those are noted, not invented.
    assert!(unknown <= 5, "too many unidentified reject reasons: {unknown}");
}

/// The detector-leg denominator: "0 helper findings" is only evidence if real
/// comparisons happened. This pins that the helper leg is NOT idle on real volume
/// data — if the slice or the accept-gate ever silently stops matching, the count
/// drops to zero and this fails, instead of a silent "clean" report.
#[test]
fn helper_leg_actually_performs_checks_on_volume() {
    use pipeline::groundtruth::helper_proto::HelperProtoModel;
    use pipeline::groundtruth::StaticGroundTruth;

    let proto_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/groundtruth/helper_protos.tsv");
    let gt = StaticGroundTruth::with_helper_proto(
        HelperProtoModel::load_from_file(&proto_path).expect("load proto slice"),
    );

    let dir = std::env::temp_dir().join(format!("vl-volume-checks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, VOLUME).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzreplay", &src)], 95).unwrap();
    let n = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = pipeline::diff::run(&period, &n, &gt).unwrap();

    assert!(
        out.summary.helper_args_observed > 100,
        "volume carries plenty of helper-arg observations: {}",
        out.summary.helper_args_observed
    );
    assert!(
        out.summary.helper_args_checked >= 45,
        "the helper leg must actually compare against ground truth, not idle: \
         {} checks out of {} observations",
        out.summary.helper_args_checked,
        out.summary.helper_args_observed
    );
    // And on this (sound) data those checks all agree — 0 findings out of N checks.
    assert_eq!(
        out.findings
            .iter()
            .filter(|f| f.kind == "helper_arg_type_mismatch")
            .count(),
        0
    );
    let _ = std::fs::remove_dir_all(&dir);
}
