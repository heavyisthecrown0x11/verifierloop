//! ID-MAP BIJECTION / partition structure (devlog 0047, `--gen-idpart`) — and the first
//! non-zero finding this project produced, which turned out to be ours.
//!
//! 0046 asked whether a link is PRESENT. This asks whether the mapping between two
//! states' ids is a BIJECTION, the actual contract of `check_ids` (states.c:319):
//! consistency (one old id maps to one cur id) and injectivity (two old ids never map to
//! the same cur id). Which of those two `if`s fires is not controllable from the program
//! — registers are compared in order and the first inconsistency decides — so the family
//! varies the thing that IS controllable: the id STRUCTURE, i.e. the partition of
//! registers into linked classes.
//!
//! THE COMPLETENESS HALF, which every earlier leg is missing. Everything so far tests
//! soundness: never accept something unsafe. `swap` tests the other direction — the SAME
//! partition built in a different instruction order mints different id NUMBERS, because
//! `++env->id_gen` is global. Accepting those is only possible if the remapping genuinely
//! works; a `check_ids` that demanded identical ids would over-reject them. The fixture
//! shows the two paths minting `id=1` and `id=2` for structurally identical partitions,
//! and the verifier accepts.
//!
//! THE FINDING, AND WHY IT WAS OURS. The first capture fired two `store_location_desync`
//! on `same-addc`, where one path proves `r9 = r6` in [0,7] and the other `r9 = r6 + 4`
//! in [4,11]. Hand-derivation from the log settled it: the verifier printed TWO states at
//! the store instruction, and the runtime offsets 56 and 58 sit inside the SECOND one
//! (48 + [4,11] = [52,59]). The store landed exactly where the verifier proved it could,
//! on the path it took. `check_store_location` was taking the FIRST claim at the
//! instruction — a single-path assumption inherited from every earlier family, which had
//! only one path to the store. The fix is the treatment 0036 already gave the retval
//! channel: use the UNION of the claims, which is a conservative superset and can only
//! MISS a violation, never fabricate one.
//!
//! That is the third time an oracle assumption from earlier families broke on a new input
//! shape (see 0041's `store_off = none` and 0044's iteration counts), which is exactly
//! what makes the a-b-c triage order non-negotiable: re-derive by hand first, and a
//! hand-derivation that clears the kernel points the finger back at us.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const IDPART: &str = include_str!("fixtures/volume/gen-idpart-12.log");
const PROGRAMS: usize = 12;
const ACCEPTED: usize = 7;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-idpart-{}-{tag}", std::process::id()));
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

fn with_mutated_sample(label: &str, input_hex: &str, new_tail: &str) -> String {
    let mut out = String::new();
    let mut hit = false;
    for block in IDPART.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        for line in block.lines() {
            if blabel == label && line.starts_with(&format!("RUNTIME input={input_hex} ")) {
                out.push_str(&format!("RUNTIME input={input_hex} {new_tail}"));
                hit = true;
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
    }
    assert!(hit, "planting target {label}/{input_hex} not found — fixture changed?");
    out
}

fn accepted(prefix: &str) -> bool {
    IDPART
        .split("===PROG ")
        .find(|b| b.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing arm {prefix}"))
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap()
        .contains("decision=accept")
}

/// Derived: the state reaching the store is the join of both paths, so the program is
/// acceptable iff BOTH paths put r9 in the class the narrowing check touches.
#[test]
fn the_verdict_is_the_join_over_both_partitions() {
    for arm in ["same-same", "chain-chain", "addc-addc", "same-chain", "same-addc"] {
        assert!(accepted(&format!("genidpart#{arm}#")), "{arm}: both paths narrow r9");
    }
    for arm in ["same-tied8", "tied8-same", "chain-tied8", "addc-tied8", "tied8-tied8"] {
        assert!(!accepted(&format!("genidpart#{arm}#")), "{arm}: one path leaves r9 wide");
    }
}

/// THE COMPLETENESS HALF. The same partition built in a different order mints different
/// id numbers; accepting it proves the remapping actually maps rather than demanding
/// equality. Pin both the verdict AND the distinct numbers, because the verdict alone
/// would also pass if the two paths happened to reuse one id.
#[test]
fn structurally_identical_partitions_with_different_id_numbers_are_accepted() {
    assert!(accepted("genidpart#same-swap#"), "same partition, different mint order");
    assert!(accepted("genidpart#swap-same#"), "and its mirror");
    let block = IDPART
        .split("===PROG ")
        .find(|b| b.starts_with("genidpart#same-swap#"))
        .unwrap();
    let mut ids: Vec<&str> = block
        .lines()
        .filter(|l| (l.contains("r7 = r6") || l.contains("r9 = r6")) && l.contains("R6=scalar(id="))
        .filter_map(|l| l.split("R6=scalar(id=").nth(1))
        .filter_map(|t| t.split(',').next())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert!(
        ids.len() >= 2,
        "the two paths must mint DIFFERENT id numbers, or this arm proves nothing about \
         remapping — saw {ids:?}"
    );
}

/// The oracles, all inherited, all silent — with the denominator that makes it mean
/// something.
#[test]
fn no_oracle_fires_once_the_claims_are_unioned() {
    let (norm, out) = run_diff(IDPART, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "IDPART locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(out.summary.store_locations_checked as usize, ACCEPTED * SWEEP);
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// REGRESSION GUARD for the false positive itself. On `same-addc` the verifier proves
/// [0,7] on one path and [4,11] on the other; a landing site admitted by the SECOND claim
/// must not fire. This is the assertion that would have failed before the union fix.
#[test]
fn a_site_admitted_by_a_later_path_is_not_a_desync() {
    let (norm, out) = run_diff(IDPART, "union");
    let rec = norm
        .records
        .iter()
        .find(|r| r.source_label.as_deref() == Some("genidpart#same-addc#010"))
        .unwrap();
    let seen: Vec<i64> = rec
        .core
        .runtime_samples
        .iter()
        .filter_map(|s| s.store_off)
        .filter(|o| *o >= 0)
        .collect();
    assert!(
        seen.iter().any(|o| *o > 55),
        "the arm must actually land beyond the FIRST path's window, or it cannot guard \
         the regression: {seen:?}"
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 0,
        "those sites are admitted by the second claim at the same instruction: {:?}",
        out.findings
    );
}

/// TOOTH — the union must not blunt the check. A site outside EVERY claim still fires.
/// With two claims spanning 48+[0,7] and 48+[4,11], offset 20 is outside both.
#[test]
fn the_oracle_still_has_teeth_across_a_union_of_claims() {
    let planted = with_mutated_sample(
        "genidpart#same-addc#010", "0x00000000", "store_off=20 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    let hits: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind == "store_location_desync")
        .collect();
    assert_eq!(hits.len(), 1, "outside every claim must still fire once: {:?}", out.findings);
    assert!(
        hits[0].observed.contains("claims at this insn"),
        "and the report must say the union was considered: {}", hits[0].observed
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "offset 20 is still inside the value, so memory safety stays silent"
    );
}

#[test]
fn idpart_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(IDPART, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
