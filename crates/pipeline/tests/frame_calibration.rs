//! MULTI-FRAME STATES / subprograms (devlog 0048, `--gen-frame`).
//!
//! Every program this project had generated lived in ONE frame. `states_equal` opens with
//! `if (old->curframe != cur->curframe) return false` and then compares each frame in
//! turn, so the whole multi-frame half of state comparison was untouched — and `calls.c`
//! is on the kernel's own danger list, one of the files that sets BPF_F_TEST_STATE_FREQ.
//!
//! A subprog call needs no BTF and no kfunc: `BPF_CALL` with `src_reg = BPF_PSEUDO_CALL`
//! and `imm` = the pc-relative offset of the callee. The question the family answers by
//! construction is what CROSSES the boundary. Only r1-r5 are passed and the callee's
//! r6-r9 start uninitialised, so if a scalar's link id survives into an argument
//! register, then narrowing one argument narrows the other through `sync_linked_regs`
//! inside a DIFFERENT frame from the one where the link was formed.
//!
//! IT DOES. `both.a2` accepts while `one.a2` rejects — had ids stopped at the boundary
//! both would reject, and that pairing is this leg's non-vacuity proof. The log shows it
//! directly:
//!   22: (bf) r7 = r2      ; frame1: R7=scalar(id=1,...)
//!   23: (25) if r6 > 0x7  ; frame1: R6=scalar(id=1,...umax=7...) R7=scalar(id=1,...umax=7...)
//! — an id minted in frame0 alive in frame1, narrowing one argument through the other.
//!
//! THE PARSER GAP THIS LEG EXPOSED, and why the denominator rule earns its keep. The
//! first capture reported `store_locations_checked = 0` on a log full of frame1 states:
//! the verifier prefixes every multi-frame state with `frameN:`, and the prefix sits
//! ahead of the register tokens, so a full-state line did not look like one and was
//! dropped. It failed SILENTLY — an empty register evolution rather than an unrecognized
//! line — so `parser_unrecognized` stayed 0 and the only symptom was a zero denominator.
//! Without the rule that zero findings mean nothing unless the claim was read, this leg
//! would have reported a clean result while seeing nothing at all.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const FRAME: &str = include_str!("fixtures/volume/gen-frame-6.log");
const PROGRAMS: usize = 6;
const ACCEPTED: usize = 4;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-frame-{}-{tag}", std::process::id()));
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
    for block in FRAME.split("===PROG ").skip(1) {
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
    FRAME
        .split("===PROG ")
        .find(|b| b.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing arm {prefix}"))
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap()
        .contains("decision=accept")
}

/// The answer, and the leg's non-vacuity in one assertion. If link ids stopped at the
/// frame boundary, `both.a2` would reject exactly like `one.a2` and the family would be
/// testing nothing about frames.
#[test]
fn a_scalar_link_survives_the_subprogram_boundary() {
    assert!(
        !accepted("genframe#one.a2#"),
        "link on one path only: a state reaches the callee with the second argument \
         un-narrowed, so this must reject"
    );
    assert!(
        accepted("genframe#both.a2#"),
        "link on both paths: narrowing arg1 inside the callee must narrow arg2 through \
         the id minted in the CALLER — if it did not, this would reject too and the \
         rejection above would say nothing about frames"
    );
    assert!(!accepted("genframe#nolink.a2#"), "baseline: no link, arg2 stays wide");
    for ctrl in ["nolink.a1", "one.a1", "both.a1"] {
        assert!(accepted(&format!("genframe#{ctrl}#")), "{ctrl}: arg1 is narrowed directly");
    }
}

/// The cross-frame propagation must be visible in the state dump, not inferred from
/// verdicts: an id minted in frame0 appearing on a frame1 register, and the check on one
/// argument narrowing the other.
#[test]
fn the_caller_minted_id_is_visible_inside_the_callee_frame() {
    let block = FRAME
        .split("===PROG ")
        .find(|b| b.starts_with("genframe#both.a2#"))
        .unwrap();
    assert!(
        block.contains("frame1:"),
        "the callee's states must actually be present in the log"
    );
    let narrow = block
        .lines()
        .find(|l| l.contains("if r6 > 0x7") && l.contains("frame1:") && l.contains("R7=scalar(id="))
        .expect("the callee's narrowing check must appear with its register state");
    assert!(
        narrow.contains("umax=smax32=umax32=7"),
        "narrowing arg1 must narrow arg2 through the shared id: {narrow}"
    );
}

/// THE DENOMINATOR, which is the whole reason the parser gap was caught. A multi-frame
/// family whose states do not parse reports zero findings while seeing nothing.
#[test]
fn the_callees_claims_are_actually_read() {
    let (norm, out) = run_diff(FRAME, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "FRAME locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.store_locations_checked as usize, ACCEPTED * SWEEP,
        "the store lives in the CALLEE, so a zero here means frame states were dropped \
         by the parser, not that the kernel is clean"
    );
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// Registers in the callee frame must reach the pipeline with real bounds, not as empty
/// states — the direct form of the same guard.
#[test]
fn callee_frame_registers_reach_the_pipeline_with_bounds() {
    let (norm, _) = run_diff(FRAME, "states");
    let rec = norm
        .records
        .iter()
        .find(|r| r.source_label.as_deref() == Some("genframe#both.a2#003"))
        .unwrap();
    let site = rec.core.store_site.expect("the generator declares the store site");
    let claims: Vec<_> = rec
        .core
        .register_evolution
        .iter()
        .filter(|s| s.insn_idx == site.insn_idx)
        .filter_map(|s| s.regs.iter().find(|r| r.reg == site.base_reg))
        .collect();
    assert!(!claims.is_empty(), "no state parsed for the callee's store pointer");
    assert!(
        claims.iter().any(|p| p.reg_type != "scalar" && p.umax <= 7),
        "the callee's store pointer must carry the narrowed bound: {claims:?}"
    );
}

#[test]
fn the_oracle_has_teeth_inside_a_callee_frame() {
    let planted = with_mutated_sample(
        "genframe#both.a2#003", "0x00000000", "store_off=20 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "a store outside the callee's proven set must fire once: {:?}", out.findings
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "offset 20 is still inside the value"
    );
}

#[test]
fn frame_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(FRAME, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
