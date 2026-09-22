//! SCALAR ID REMAPPING — the thing states.c calls "too simplistic" (devlog 0046,
//! `--gen-idmap`).
//!
//! `check_ids()` (states.c:319) builds a BIJECTIVE old<->cur id mapping while comparing
//! two states; `check_scalar_ids()` wraps it for scalars. The kernel's own comment in
//! `regsafe` explains why it must exist, using a program rather than a hypothesis:
//!
//!   1: r6 = ... unbound scalar, ID=a ...
//!   2: r7 = ... unbound scalar, ID=b ...
//!   3: if (r6 > r7) goto +1
//!   4: r6 = r7                 <- both now carry id=b: LINKED
//!   5: if (r6 > X) goto ...    <- sync_linked_regs narrows r7 too, via the shared id
//!   6: ... memory operation using r7 ...
//!
//! Instruction 6 is reached in two states — I. r6{id=b}, r7{id=b} and II. r6{id=a},
//! r7{id=b} — and in state II the bound check at 5 never touched r7. If `check_ids()`
//! equated them, state II would be PRUNED against state I and an unsafe access accepted.
//!
//! THE FAMILY makes that difference the ONLY thing that varies. The split tests a third
//! scalar, so neither r6 nor r7 is constrained by the branch itself; the narrowing check
//! names r6 alone, so r7 can only be narrowed through a shared id; and every REJECT shape
//! is paired with an ACCEPT control that differs solely in whether the link exists on
//! both paths. Without that pairing a rejection would only prove the shape is unsafe,
//! not that LINKAGE is what decides it.
//!
//! THE AXIS is how the link is formed, because each form carries a different id:
//! a bare `r7 = r6` shares a plain id; `r7 = r6; r7 += 4` sets BPF_ADD_CONST64 (bit 31)
//! so the pair carries id and id|flag and `check_scalar_ids` must map BOTH the compound
//! and the base id; the 32-bit form sets BPF_ADD_CONST32 (bit 30) instead, and the
//! kernel refuses to prune across differing flag types because alu32 zero-extends.
//!
//! 0042's three-load instrument rides along unchanged and fits this leg especially well:
//! BPF_F_TEST_STATE_FREQ multiplies pruning attempts, so an id-mapping mistake gets far
//! more chances to be exercised with the flag than without.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const IDMAP: &str = include_str!("fixtures/volume/gen-idmap-9.log");
const PROGRAMS: usize = 9;
const ACCEPTED: usize = 5;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-idmap-{}-{tag}", std::process::id()));
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
    for block in IDMAP.split("===PROG ").skip(1) {
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

fn accepted(label: &str) -> bool {
    IDMAP
        .split("===PROG ")
        .find(|b| b.starts_with(label))
        .unwrap_or_else(|| panic!("missing arm {label}"))
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap()
        .contains("decision=accept")
}

/// THE HEADLINE OF THIS LEG, and its non-vacuity in one assertion. For every way of
/// forming the link, having it on ONE path must reject and having it on BOTH must
/// accept. The two programs are otherwise identical, so the difference isolates linkage
/// exactly: the accept proves `sync_linked_regs` really does narrow r7 through the
/// shared id, and the reject proves the unlinked state was NOT pruned against the linked
/// one. A leg where both sides rejected would prove only that the shape is unsafe.
#[test]
fn linkage_alone_decides_and_the_unlinked_state_is_never_pruned_away() {
    for form in ["mov", "addc64", "addc32"] {
        let one = format!("genidmap#{form}.one.r7#");
        let both = format!("genidmap#{form}.both.r7#");
        assert!(
            !accepted(&one),
            "{form}: the link exists on one path only, so a state arrives with r7 \
             un-narrowed — accepting it means that state was pruned away"
        );
        assert!(
            accepted(&both),
            "{form}: with the link on both paths r7 is narrowed through the shared id, \
             so this must accept — otherwise the reject above says nothing about linkage"
        );
    }
}

/// The baseline and the direct-use control, which fence the result from the other side:
/// no link at all still rejects (so the reject is not manufactured by the link forms),
/// and storing through the register the check narrows directly always accepts.
#[test]
fn the_baseline_and_the_direct_use_control_bracket_the_result() {
    assert!(!accepted("genidmap#nolink.one.r7#"), "r7 is never narrowed without a link");
    assert!(accepted("genidmap#nolink.one.r6#"), "r6 is narrowed by the check itself");
    assert!(accepted("genidmap#mov.one.r6#"), "so is r6 when a link exists on one path");
}

/// The mechanism must be visible in the state dump, not merely inferred from verdicts:
/// the two registers share an id, and the check on r6 narrows r7 as well.
#[test]
fn the_shared_id_and_its_propagation_are_visible_in_the_log() {
    let block = IDMAP
        .split("===PROG ")
        .find(|b| b.starts_with("genidmap#mov.one.r7#"))
        .unwrap();
    // The plain listing prints the mnemonic with no state, and the state dump prints it
    // again with `; R6=...`. Only the annotated one carries the ids.
    let link = block
        .lines()
        .find(|l| l.contains("r7 = r6") && l.contains("R6=scalar(id="))
        .expect("the linking MOV must appear with its register state");
    let id = link
        .split("R6=scalar(id=")
        .nth(1)
        .and_then(|t| t.split(',').next())
        .expect("r6 must carry an id after the MOV");
    assert!(
        link.contains(&format!("R7=scalar(id={id},")),
        "both registers must carry the SAME id after the move: {link}"
    );
    let narrow = block
        .lines()
        .find(|l| l.contains("if r6 > 0x7") && l.contains("R7=scalar(id="))
        .expect("the narrowing check must appear with its register state");
    assert!(
        narrow.contains("R7=scalar(id=") && narrow.contains("umax=smax32=umax32=7"),
        "sync_linked_regs must narrow r7 through the shared id, or the whole leg is \
         testing nothing: {narrow}"
    );
}

/// All three link forms must actually be present, or the axis is narrower than claimed.
#[test]
fn every_link_form_is_represented() {
    for form in ["nolink", "mov", "addc64", "addc32"] {
        assert!(
            IDMAP.contains(&format!("genidmap#{form}.")),
            "missing link form {form}"
        );
    }
}

/// The oracles, all inherited, all silent — with denominators.
#[test]
fn no_oracle_fired_on_the_idmap_family() {
    let (norm, out) = run_diff(IDMAP, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "IDMAP locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.store_locations_checked as usize, ACCEPTED * SWEEP,
        "every run of every accepted program must be compared against the claim"
    );
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_oracle_has_teeth_on_an_idmap_program() {
    let planted = with_mutated_sample(
        "genidmap#mov.both.r7#003", "0x00000000", "store_off=20 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "a store outside the proven set must fire exactly once: {:?}", out.findings
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "and the memory-safety leg stays silent — offset 20 is still inside the value"
    );
}

#[test]
fn idmap_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(IDMAP, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
