//! PRUNING-SOUNDNESS differential — a KERNEL-vs-KERNEL oracle (devlog 0042, `--gen-prune`).
//!
//! Every earlier leg compares the verifier against something WE compute: an invariant
//! we assert, a bound we parse, a value we observe at runtime. Each of those has an
//! oracle of ours that can itself be wrong — 0041 shipped two such bugs and caught them
//! only because the family was new. This leg has none: BOTH sides of the comparison are
//! the kernel's own verdict on the SAME program bytes. The only question asked is
//! whether the verifier agrees with itself when its pruning frequency changes.
//!
//! WHY PRUNING. `reg_bounds_sanity_check` (verifier.c:2189) is literally our invariants
//! A/B/C, run by the kernel at every ALU op, every branch, every helper return. So the
//! internal-consistency class we spent 0025–0035 on is self-monitored in-tree, and the
//! single-instruction transfer functions are the most formally attacked part of the
//! verifier. State pruning is neither: `regsafe`/`states_equal` (states.c:507, :980)
//! judge a RELATION between two abstract states, it is the densest historical bug
//! region, and no internal-consistency or runtime-value oracle can reach it.
//!
//! THE INSTRUMENT. `BPF_F_TEST_STATE_FREQ` sets `force_new_state` (states.c:1248), so
//! the verifier checkpoints at EVERY instruction instead of waiting for the default
//! ">= 2 jumps AND >= 8 instructions" heuristic. It therefore makes pruning MORE
//! aggressive, not less — `regsafe` gets far more candidate pairs to judge. That fixes
//! the DIRECTION of the finding, which is the whole design:
//!   * flagged ACCEPT + default REJECT -> a path that produced the rejection was pruned
//!     away. Only an unsound `regsafe` does that. This is the finding.
//!   * flagged REJECT + default ACCEPT -> the extra checkpoints inflate the state count,
//!     so BPF_COMPLEXITY_LIMIT_INSNS can reject what the default accepts. An artefact of
//!     the instrument: classified by the rejection reason, counted separately, never a
//!     finding. (A reject in that direction that is NOT a limit is still a real
//!     disagreement and is reported as an over-rejection.)
//!
//! THE DENOMINATOR. A pair only counts once the flag DEMONSTRABLY changed the state
//! space (`freq_states > base_states`). Two runs that explored the same states agreeing
//! is not evidence about pruning — it is evidence that nothing was tried. State-count
//! difference is therefore not noise to discard and not a finding either: it is the
//! proof the experiment ran, exactly like `store_locations_checked` in 0041.
//!
//! THE INPUT. A wrong prune is only OBSERVABLE if the program has convergent control
//! flow, two incoming states `regsafe` must genuinely judge, and a downstream access
//! whose safety depends on which path was taken. The family supplies all three: two
//! attacker values (offset source, branch selector) are read from one map value so the
//! split does not constrain the offset; each path shapes the offset differently; the
//! paths converge on a 1-byte store at `map_value + r6 + 56`, in bounds iff
//! `umax(r6) <= 7`. The verifier explores the FALL-THROUGH first, so that path records
//! the checkpoint the other is judged against — which is why ORDER is an axis.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const PRUNE: &str = include_str!("fixtures/volume/gen-prune-16.log");
const PROGRAMS: usize = 16;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-prune-{}-{tag}", std::process::id()));
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

/// Rebuild the fixture with one program's PRUNE line replaced — used to plant a
/// differential the real kernel never produced.
fn with_mutated_prune(label: &str, new_line: &str) -> String {
    let mut out = String::new();
    let mut hit = false;
    for block in PRUNE.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        for line in block.lines() {
            if blabel == label && line.starts_with("PRUNE ") {
                out.push_str(new_line);
                hit = true;
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
    }
    assert!(hit, "planting target {label} not found — fixture changed?");
    out
}

fn prune_line_of(label: &str) -> String {
    for block in PRUNE.split("===PROG ").skip(1) {
        if block.split_whitespace().next().unwrap() == label {
            for line in block.lines() {
                if line.starts_with("PRUNE ") {
                    return line.to_string();
                }
            }
        }
    }
    panic!("no PRUNE line for {label}");
}

fn of_kind<'a>(out: &'a diff::DiffFindings, kind: &str) -> Vec<&'a diff::DivergenceFinding> {
    out.findings.iter().filter(|f| f.kind == kind).collect()
}

/// The decision is DERIVED, not observed: the store at +56 is in bounds iff the offset's
/// umax is <= 7, and the verifier must consider BOTH paths, so a program is acceptable
/// exactly when both shapers are safe. Pinning this separately from the differential
/// means a change in the family's shape cannot quietly make the leg vacuous.
#[test]
fn the_decision_is_a_pure_function_of_whether_both_paths_are_safe() {
    let (norm, _) = run_diff(PRUNE, "decide");
    assert_eq!(norm.records.len(), PROGRAMS);
    let mut accepts = 0;
    for rec in &norm.records {
        let p = rec.core.prune_probe.as_ref().expect("every program declares its differential");
        let expect_accept = p.fall_safe && p.taken_safe;
        assert_eq!(
            p.base_accept, expect_accept,
            "{}: fall={} taken={} — accept iff both paths keep the store in bounds",
            rec.source_label.as_deref().unwrap_or("?"), p.fall, p.taken
        );
        accepts += expect_accept as usize;
    }
    assert_eq!(accepts, 2, "only the two both-safe arms are acceptable");
}

/// The headline: the verifier's verdict does not depend on how often it checkpoints.
#[test]
fn the_verdict_does_not_depend_on_checkpoint_frequency() {
    let (_, out) = run_diff(PRUNE, "base");
    eprintln!(
        "PRUNE pairs_checked={} artifacts={} finding_count={}",
        out.summary.prune_pairs_checked, out.summary.prune_resource_artifacts,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.prune_pairs_checked as usize, PROGRAMS,
        "every program must be a USABLE differential; a short denominator means the \
         flag changed nothing, not that pruning is sound"
    );
    assert_eq!(
        out.summary.finding_count, 0,
        "the verdict changed with checkpoint frequency: {:?}", out.findings
    );
    assert_eq!(out.summary.prune_resource_artifacts, 0, "no complexity-limit rejections here");
}

/// A zero finding count is worth nothing unless the instrument actually perturbed the
/// verifier. Pin that the flag widened the explored state space on EVERY program.
#[test]
fn the_flag_engaged_on_every_program() {
    let (norm, _) = run_diff(PRUNE, "engaged");
    for rec in &norm.records {
        let p = rec.core.prune_probe.as_ref().unwrap();
        assert!(
            p.freq_states > p.base_states,
            "{}: base_states={} freq_states={} — the flag explored no extra states, so \
             agreement between the two runs proves nothing",
            rec.source_label.as_deref().unwrap_or("?"), p.base_states, p.freq_states
        );
    }
}

/// TOOTH 1 — the soundness direction. A flagged run that ACCEPTS what the default run
/// rejects means the extra checkpoints pruned away the path that produced the
/// rejection. This is the only outcome the leg exists to produce.
#[test]
fn the_oracle_has_teeth_a_flagged_accept_over_a_default_reject_fires() {
    let base = prune_line_of("genprune#n7-w63#002");
    assert!(base.contains("base_verdict=reject"), "fixture arm must reject by default");
    let planted = base.replace("freq_verdict=reject", "freq_verdict=accept");
    let (_, out) = run_diff(&with_mutated_prune("genprune#n7-w63#002", &planted), "teeth-sound");
    assert_eq!(
        of_kind(&out, "prune_soundness_desync").len(), 1,
        "a flagged accept over a default reject must fire exactly once: {:?}", out.findings
    );
}

/// TOOTH 2 — the reverse direction must be CLASSIFIED, not counted. State-freq inflates
/// the state count by construction, so a complexity-limit rejection is an artefact of
/// the instrument. Counting it would drown the real signal in noise the flag creates.
#[test]
fn a_complexity_limit_rejection_is_an_artifact_not_a_finding() {
    let base = prune_line_of("genprune#n7-n7#000");
    assert!(base.contains("base_verdict=accept"), "fixture arm must accept by default");
    let planted = base
        .replace("freq_verdict=accept", "freq_verdict=reject")
        .replace("freq_reason=none", "freq_reason=too_large");
    let (_, out) = run_diff(&with_mutated_prune("genprune#n7-n7#000", &planted), "teeth-artifact");
    assert_eq!(
        out.summary.finding_count, 0,
        "a complexity-limit rejection is not a verifier disagreement: {:?}", out.findings
    );
    assert_eq!(
        out.summary.prune_resource_artifacts, 1,
        "but it must still be COUNTED — an unclassified flip would be invisible"
    );
}

/// TOOTH 3 — the same reverse flip WITHOUT a resource reason is a real disagreement.
/// This is what keeps tooth 2 from becoming a blanket excuse for the whole direction.
#[test]
fn a_flagged_rejection_that_is_not_a_resource_limit_still_fires() {
    let base = prune_line_of("genprune#n7-n7#000");
    let planted = base.replace("freq_verdict=accept", "freq_verdict=reject");
    let (_, out) = run_diff(&with_mutated_prune("genprune#n7-n7#000", &planted), "teeth-overreject");
    assert_eq!(
        of_kind(&out, "prune_verdict_disagreement").len(), 1,
        "an over-rejection is still the verifier contradicting itself: {:?}", out.findings
    );
    assert_eq!(out.summary.prune_resource_artifacts, 0, "and it is NOT excused as an artefact");
}

/// TOOTH 4 — the third channel, one flag bit wide. BPF_F_TEST_REG_INVARIANTS promotes
/// the kernel's own `reg_bounds_sanity_check` from warn-and-recover to a hard -EFAULT,
/// so a program that loads clean by default but faults under the flag is an internal
/// inconsistency we could never observe from outside.
#[test]
fn the_kernels_own_invariant_channel_has_teeth() {
    let base = prune_line_of("genprune#n7-n7#000");
    let planted = base
        .replace("inv_verdict=accept", "inv_verdict=reject")
        .replace("inv_errno=0", "inv_errno=14")
        .replace("inv_reason=none", "inv_reason=efault");
    let (_, out) = run_diff(&with_mutated_prune("genprune#n7-n7#000", &planted), "teeth-inv");
    assert_eq!(
        of_kind(&out, "reg_invariants_violation").len(), 1,
        "an EFAULT under REG_INVARIANTS on an otherwise-accepted program must fire: {:?}",
        out.findings
    );
}

/// The denominator guard: a pair where the flag explored no extra states must NOT be
/// counted, because agreement there says nothing about pruning.
#[test]
fn a_pair_the_flag_did_not_perturb_is_not_counted() {
    let base = prune_line_of("genprune#n7-n7#000");
    let states = base
        .split_whitespace()
        .find(|t| t.starts_with("base_states="))
        .unwrap()
        .to_string();
    let n = states.trim_start_matches("base_states=");
    let planted = base
        .split_whitespace()
        .map(|t| {
            if t.starts_with("freq_states=") { format!("freq_states={n}") } else { t.to_string() }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let (_, out) = run_diff(&with_mutated_prune("genprune#n7-n7#000", &planted), "denom");
    assert_eq!(
        out.summary.prune_pairs_checked as usize, PROGRAMS - 1,
        "an unperturbed pair must drop out of the denominator"
    );
}

#[test]
fn prune_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(PRUNE, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
