//! Golden regression test for the NORMALIZE stage — the parser-layer guardrail.
//!
//! It pins a committed (raw input -> normalized output) pair:
//!   tests/fixtures/golden/verifier.log            — the raw sentinel input
//!   tests/fixtures/golden/normalized.expected.json — the known-good NormalizedMetrics
//!
//! WHY THIS EXISTS. Anomaly signals (diff invariants, scoring) sit DOWNSTREAM of
//! normalization, so a mis-shaping parser manufactures false "verifier bugs". When
//! the real per-tool parser lands, it must reproduce this exact mapping. Any drift
//! here is therefore a *parser/schema regression* — caught before it is mistaken
//! for a *genuine verifier anomaly* in a real period. This is the parser-layer
//! analogue of the loop's confirmation-bias guardrail.
//!
//! If a schema change is intentional, regenerate the golden:
//!   cargo run -q -p pipeline --example report_demo -- <scratch>
//!   jq .payload <scratch>/data/periods/1/normalized_metrics.json > \
//!     crates/pipeline/tests/fixtures/golden/normalized.expected.json

use contract::PeriodPaths;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, NormalizedMetrics, ReferenceParser};
use std::path::PathBuf;

/// Must match the exec count baked into the golden payload (see fixture).
const GOLDEN_EXEC_N: u64 = 4200;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden")
        .join(name)
}

#[test]
fn reference_parser_reproduces_golden_normalized() {
    // Isolated scratch period dir (ingest copies the raw input under raw/).
    let scratch =
        std::env::temp_dir().join(format!("verifierloop-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let period = PeriodPaths::new(&scratch.join("data"), 1);

    // ingest the committed raw fixture, then normalize with the reference parser.
    let raw_input = fixture("verifier.log");
    let raw = ingest::run(&period, &[Source::new("syzkaller", &raw_input)], GOLDEN_EXEC_N)
        .expect("ingest golden raw");
    let produced = normalize::run(&period, &raw, &ReferenceParser).expect("normalize");

    // The committed known-good output.
    let golden_bytes =
        std::fs::read(fixture("normalized.expected.json")).expect("read golden json");
    let golden: NormalizedMetrics =
        serde_json::from_slice(&golden_bytes).expect("deserialize golden");

    assert_eq!(
        produced, golden,
        "NORMALIZE output drifted from the committed golden fixture. If this schema \
         change is intentional, regenerate normalized.expected.json (see header); \
         otherwise a parser/schema regression has been introduced."
    );

    let _ = std::fs::remove_dir_all(&scratch);
}
