//! THE DENOMINATOR RULE, MADE STRUCTURAL (devlog 0066).
//!
//! 0025 produced this project's oldest standing rule: never report zero findings without
//! the denominator that says how often the check could have fired. It was enforced by
//! habit — every leg since has added a counter alongside its check.
//!
//! 0065 showed the habit has a hole the rule cannot see. An invariant can be added with
//! NO denominator at all, and then "warn when the denominator is zero" never fires,
//! because there is no counter to look at. Four checks had lived that way since 0026 —
//! the two 64-bit and two 32-bit bound-ORDERING checks — and auditing the rest of the
//! stage turned up three more:
//!
//!   * `tnum_malformed`            — well-formedness, uncounted since the first leg.
//!   * `reg_invariants_violation`  — the VERDICT channel that calibration pair two
//!                                   certified, uncounted since 0042.
//!   * `jit_interp_divergence`     — and this one is the real catch. See below.
//!
//! So the rule is now a guard rather than a habit: every finding kind the diff stage can
//! emit must name its denominator in `INVARIANT_DENOMINATORS`, and that name must resolve
//! to a real field. A new invariant cannot reach CI without declaring what it was
//! measured against.

use contract::PeriodPaths;
use pipeline::diff::{self, INVARIANT_DENOMINATORS};
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize;
use pipeline::verifier_log::VerifierLogParser;

/// The stage's own source. Scanning it is the point: a new `kind:` literal appears here
/// the moment someone writes a new check, whether or not they remembered the counter.
const DIFF_SRC: &str = include_str!("../src/diff.rs");

/// Every finding kind the diff stage can emit, read out of its own source.
///
/// Comment lines are skipped — this file's own prose mentions the pattern it looks for,
/// and a scanner that swallowed that would report a phantom kind. The extracted name must
/// also look like a kind (lowercase, digits, underscores), so a formatted string or a
/// doc example cannot be mistaken for one.
fn emitted_kinds() -> Vec<String> {
    let mut out = Vec::new();
    for line in DIFF_SRC.lines() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        let mut rest = t;
        while let Some(i) = rest.find("kind: \"") {
            let after = &rest[i + "kind: \"".len()..];
            let Some(j) = after.find('"') else { break };
            let name = &after[..j];
            if !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                out.push(name.to_string());
            }
            rest = &after[j..];
        }
    }
    out.sort();
    out.dedup();
    out
}

/// THE GUARD. Adding a check without a denominator must fail here, not go unnoticed for
/// thirty-five legs.
#[test]
fn denominator_registry_covers_every_finding_kind() {
    let kinds = emitted_kinds();
    assert!(
        kinds.len() >= 20,
        "the scan found only {} kinds — it has stopped matching the source, which would \
         make this guard silently vacuous: {kinds:?}",
        kinds.len()
    );
    let missing: Vec<&String> = kinds
        .iter()
        .filter(|k| !INVARIANT_DENOMINATORS.iter().any(|(rk, _)| *rk == k.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these findings can be reported but nothing counts how often their check could \
         have fired — add each to INVARIANT_DENOMINATORS with the counter it belongs to: \
         {missing:?}"
    );
}

/// A registry entry naming a field nobody can read is not a denominator.
#[test]
fn every_registered_denominator_resolves_to_a_real_counter() {
    let summary = diff::DiffSummary::default();
    for (kind, field) in INVARIANT_DENOMINATORS {
        assert!(
            summary.denominator(field).is_some(),
            "{kind} declares the denominator `{field}`, which DiffSummary::denominator \
             does not know about"
        );
    }
}

/// The registry must not drift the other way either: an entry for a kind the stage no
/// longer emits is a claim about coverage that is no longer true.
#[test]
fn the_registry_has_no_entries_for_kinds_that_are_never_emitted() {
    let kinds = emitted_kinds();
    let stale: Vec<&str> = INVARIANT_DENOMINATORS
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !kinds.iter().any(|e| e == k))
        .collect();
    assert!(stale.is_empty(), "registry entries with no emitting check: {stale:?}");
}

fn run(text: &str, tag: &str) -> diff::DiffFindings {
    let dir = std::env::temp_dir().join(format!("vl-den-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

const COMP: &str = include_str!("fixtures/volume/gen-comp-896.log");

/// What the guard bought, measured on the current corpus: the three newly-counted
/// invariants, and which of them the corpus actually exercises.
#[test]
fn the_newly_counted_invariants_report_what_the_corpus_really_reaches() {
    let out = run(COMP, "comp");
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);

    // tnum well-formedness. MEASURED: 351 on 704 programs — far thinner than it looks,
    // because `value & mask` can only be non-zero when a register carries known-1 bits
    // AND unknown bits at once, and most states are one or the other.
    assert!(
        out.summary.tnum_wellformed_checked > 300,
        "got {}",
        out.summary.tnum_wellformed_checked
    );
    // The REG_INVARIANTS verdict channel — the one calibration pair two certified. Every
    // program in this corpus gets the flagged load, so the denominator is the accept
    // count, and "no violations" finally means something here.
    assert!(
        out.summary.reg_invariants_checked > 500,
        "got {}",
        out.summary.reg_invariants_checked
    );
}

/// THE ONE THE GUARD CAUGHT — and the gap it named is now CLOSED (0075).
///
/// When this test was written, `jit_interp_divergence` had never examined a single record:
/// the lab kernel is built `CONFIG_BPF_JIT_ALWAYS_ON`, which compiles the interpreter out,
/// so the parser hardcoded `jit_interp_diff: None` and the invariant's silence across every
/// capture the project had ever taken was pure absence of evidence — the shape 0025 exists
/// to expose, hiding for forty legs because nothing counted it.
///
/// The original test pinned that zero and said: "when an interpreter channel is eventually
/// built, this assertion flips and the test should be rewritten to demand a real
/// denominator." A kernel variant without that symbol was built, the harness now loads each
/// program twice — once JITted, once with `net.core.bpf_jit_enable=0` — and this is that
/// rewrite.
///
/// Both halves are asserted, because the gap is closed only where a family MEASURES it: the
/// composition corpus does not do the double load and still scores zero, and reading its
/// zero as a clean result would be the original mistake all over again.
#[test]
fn the_jit_interpreter_invariant_finally_has_a_denominator() {
    const INTENT: &str = include_str!("fixtures/volume/gen-intent-64.log");
    let intent = run(INTENT, "jit-live");
    assert_eq!(
        intent.summary.jit_interp_checked, 64,
        "every program in the intent corpus is loaded twice and both results compared"
    );
    assert_eq!(
        intent.summary.denominator_for_kind("jit_interp_divergence"),
        Some(64)
    );
    assert!(
        !intent.findings.iter().any(|f| f.kind == "jit_interp_divergence"),
        "{:?}", intent.findings
    );

    // And the gap PERSISTS where nothing measures it. A family that never performs the
    // second load has nothing to compare, and its zero is still an absence of evidence.
    let comp = run(COMP, "jit-gap");
    assert_eq!(
        comp.summary.jit_interp_checked, 0,
        "the composition family does not do the double load — if this became non-zero it \
         started to, and the claim above needs re-measuring"
    );
}

/// And the other half of the same measurement: nine committed families score ZERO on
/// well-formedness, including both syzkaller corpora and the 240-program packet-compare
/// sweep. Their "no malformed tnum" was 0 out of 0 the whole time.
///
/// This is pinned rather than fixed, because it is not a defect — those corpora simply
/// never produce a register with known-1 bits and unknown bits at once. What would be a
/// defect is reading their silence as evidence, which is exactly what an uncounted check
/// invites.
#[test]
fn several_committed_corpora_never_reach_the_wellformedness_check_at_all() {
    const SYZ: &str = include_str!("fixtures/volume/syz-replay-184.log");
    const PKTCMP: &str = include_str!("fixtures/volume/gen-pktcmp-240.log");
    for (tag, text) in [("syz", SYZ), ("pktcmp", PKTCMP)] {
        let out = run(text, tag);
        assert!(out.summary.record_count > 100, "{tag}: corpus present");
        assert_eq!(
            out.summary.tnum_wellformed_checked, 0,
            "{tag}: if this became non-zero the corpus or the parser changed — re-measure \
             before trusting a clean result from it"
        );
        assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
    }
}
