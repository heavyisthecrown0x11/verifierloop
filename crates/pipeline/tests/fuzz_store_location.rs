//! THE STORE-LOCATION CHANNEL, FED FROM THE FUZZ LOOP (leg 0110).
//!
//! 0109 measured the channel's volume and found it ample; what it did not settle was WHO
//! judges. The first attempt put the judgment in the VM, because that is what worked twice
//! before (the liveness gate in 0094, the subsumption model in 0105). It did not work here,
//! and the way it failed is the result worth keeping:
//!
//!     false desyncs on a kernel known to be correct, over five corrections:
//!         79  ->  247  ->  8  ->  18  ->  49
//!
//! Every correction was a real bug and not one of them was in the PREDICATE — the
//! map_value print shape, the store's own immediate, what `had_claim` must mean, an
//! unreadable occurrence silently narrowing the union, `imm=N` as a fifth spelling of a
//! constant offset. The difference from the subsumption port is structural: there the
//! second implementation faced a CLOSED-FORM predicate (`cnum_is_subset`, `check_scalar_ids`)
//! and matched the reference on eight counters exactly; here it faces the kernel's PRINTING
//! CONVENTIONS, which the offline parser learned over forty legs and which 0065 and 0070
//! each charged this project for once already.
//!
//! So the loop keeps only what it can measure honestly — how many observable stores exist —
//! and SAMPLES the rest out with its verifier log for the mature oracle to judge. Measured:
//! 20,327 storing programs per 150s, of which 1-in-256 is 79 blocks (1.5 MB), or roughly
//! 1,900 blocks and 36 MB per hour. The hand-built corpus has 4,560 store comparisons in
//! total, so an hour of sampled fuzz shapes is the same order — with the verdict coming
//! from `check_store_location` itself rather than a fifth guess at a log format.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self};
use pipeline::verifier_log::VerifierLogParser;

const SAMPLE: &str = include_str!("fixtures/volume/fuzz-storesample-12.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-fsl-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (norm, out)
}

/// THE DENOMINATOR FIRST. A sampled block the pipeline cannot read reports zero findings
/// exactly like a clean one — the 0025 trap, and the whole reason this leg stopped trusting
/// its own in-VM reader. So the check that matters is that the store comparisons actually
/// happened, in the oracle that has been calibrated against a real bug (`3878ae04e9fc`).
#[test]
fn sampled_fuzz_stores_reach_the_store_location_oracle() {
    let (norm, out) = run_diff(SAMPLE, "denom");
    let checked = out.summary.store_locations_checked;
    assert!(
        checked > 0,
        "the sampled blocks produced no store comparisons at all — that is a FORMAT \
         mismatch between what the fuzz loop emits and what the oracle reads, not a clean \
         result: store_locations_checked={checked}"
    );
    assert!(
        norm.unparsed.is_empty(),
        "sampled blocks must parse completely; an unparsed line is a silent hole in the \
         denominator: {:?}",
        norm.unparsed
    );
}

/// AND THE VERDICT, now that the input it judges is trustworthy.
///
/// It took two more corrections to get here, and neither was in the oracle. First, a
/// program with two variable store sites emitted two claims and every observed byte was
/// judged against one of them. Then — the harder one — the declared instruction did not
/// match the log at all: `STORE insn=36` against `36: (bf) r6 = (s32)r7`. A self-check of
/// the site list against the instruction array came back clean (`storestale=0`), which is
/// what forced the search to the other side: the level-2 load rides the
/// `fresh > 0 || (iters & 7) == 0` gate, so on seven eighths of iterations `g_log` still
/// held an EARLIER program's log. The sampler was pairing this program's stores with that
/// program's claims. 0085's stale-artefact shape, arriving in a new place.
///
/// Eight corrections in this channel, and not one of them was in the PREDICATE — every
/// single one was either attribution (which observation belongs to which claim) or
/// freshness (which program the evidence describes).
///
#[test]
fn sampled_fuzz_stores_show_no_desync() {
    let (norm, out) = run_diff(SAMPLE, "verdict");
    let desync: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind.contains("store_location"))
        .collect();
    assert!(
        desync.is_empty(),
        "store-location desync on a kernel believed correct — replay the genome with \
         `--fuzz-replay` and re-derive by hand BEFORE calling it anything: {desync:?} \
         (checked={})",
        out.summary.store_locations_checked
    );
}
