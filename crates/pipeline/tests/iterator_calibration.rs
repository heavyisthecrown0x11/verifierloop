//! OPEN-CODED ITERATORS — the loop mechanism the kernel special-cases in its own pruning
//! path (devlog 0045, `--gen-iter`).
//!
//! `bpf_is_state_visited` (states.c) skips its usual loop detection for iterators, with
//! the comment that `states_maybe_looping()` is "too simplistic in detecting states that
//! *might* be equivalent, because it doesn't know about ID remapping, so don't even
//! perform it". A special case in the pruning path, justified by an admitted
//! simplification, is the densest target OI-13 identified.
//!
//! THE MACHINERY THIS LEG PAID FOR. An iterator loop is built from kfunc calls, and a
//! kfunc call is `BPF_CALL` with `src_reg = BPF_PSEUDO_KFUNC_CALL` and `imm` = the
//! function's BTF id — a number that exists only in the running kernel. With no libbpf,
//! the harness reads /sys/kernel/btf/vmlinux and walks the type section itself. The walk
//! is unforgiving: each type is a 12-byte header plus kind-specific trailing data, so
//! skipping one wrong desynchronises every id after it — and a wrong id is not a load
//! error, it is a call to a DIFFERENT function. The distro header stops at
//! BTF_KIND_FLOAT, so DECL_TAG/TYPE_TAG/ENUM64 are defined in the harness; without them
//! the walk drifts silently on any modern vmlinux. The probe (probe-iter-3.log) reports
//! the resolved ids precisely so that a silent drift would be visible.
//!
//! THREE ORACLES RIDE ALONG, none of them new: 0042's three-load pruning differential,
//! 0041's store-location check, and 0037's write-safety check. Iterators are cheap to
//! execute — at most eight trips, with none of may_goto's 250ms budget (0044) — so the
//! runtime half costs almost nothing here.
//!
//! WHAT THE CAPTURE CORRECTED. The `.o48` arms were designed as a mechanism-sensitive
//! pair: at store offset 48 the access is in bounds iff `umax(r6) <= 15`, which an
//! 8-trip `inc` should satisfy and an unbounded may_goto loop cannot. It rejected. The
//! log says why, and it is a fact about the verifier worth pinning: it tracks the
//! iterator depth (`fp-8=iter_num(id=1,state=active,depth=9)`) but does NOT use the
//! constant `[0, 8)` range to bound the trip count — it relies on state convergence, so
//! it explores depths beyond the real maximum, reaching `R6=[9,16]` at depth 9 and
//! rejecting on `umax=16`. At runtime the loop takes exactly eight trips and the program
//! is safe. That is an OVER-rejection: imprecision in the safe direction, not a bug.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use std::collections::BTreeSet;

const ITER: &str = include_str!("fixtures/volume/gen-iter-12.log");
const PROBE: &str = include_str!("fixtures/volume/probe-iter-3.log");
/// The may_goto family from 0043 — same bodies, different loop mechanism.
const MAYGOTO: &str = include_str!("fixtures/volume/gen-loop-12.log");
const PROGRAMS: usize = 12;
const ACCEPTED: usize = 7;
const SWEEP: usize = 8;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-iter-{}-{tag}", std::process::id()));
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
    for block in ITER.split("===PROG ").skip(1) {
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

/// Map body name -> accepted, from a fixture whose labels are `<prefix>#<body>.<tag>#NNN`.
fn verdicts(text: &str, prefix: &str) -> Vec<(String, String, bool)> {
    let mut v = Vec::new();
    for block in text.split("===PROG ").skip(1) {
        let label = block.split_whitespace().next().unwrap();
        if !label.starts_with(prefix) {
            continue;
        }
        let body = label[prefix.len()..].split('.').next().unwrap().to_string();
        let accepted = block
            .lines()
            .find(|l| l.starts_with("RESULT "))
            .map(|l| l.contains("decision=accept"))
            .unwrap();
        v.push((body, label.to_string(), accepted));
    }
    v
}

#[test]
fn the_iterator_state_machine_was_actually_exercised() {
    // Non-vacuity for the mechanism itself: if the loop never became an iterator loop,
    // the verifier would print no iterator states at all and every other assertion here
    // would be about an ordinary branch.
    assert!(
        ITER.contains("state=active"),
        "the verifier must have tracked an ACTIVE iterator"
    );
    assert!(
        ITER.contains("state=drained"),
        "and a DRAINED one — process_iter_next_call forks both, and only seeing one \
         means the loop exit was never explored as an iterator exit"
    );
    assert!(
        ITER.contains("fp-8=iter_num("),
        "the iterator must live in the tracked stack slot"
    );
}

/// The BTF ids the probe resolved. A WRONG id is not a load error — it is a call to a
/// different function — so pin that the probe reported them and that the loop it built
/// with them verified.
#[test]
fn btf_resolution_produced_working_kfunc_ids() {
    let ok = PROBE.lines().find(|l| l.starts_with("CHANNEL btf=")).unwrap();
    assert!(ok.contains("btf=ok"), "vmlinux BTF walk must resolve all three kfuncs: {ok}");
    for key in ["new=", "next=", "destroy="] {
        let id: i64 = ok
            .split_whitespace()
            .find_map(|t| t.strip_prefix(key))
            .unwrap()
            .parse()
            .unwrap();
        assert!(id > 0, "{key} resolved to {id}");
    }
    let arms: Vec<&str> = PROBE.lines().filter(|l| l.contains("arm=")).collect();
    assert!(
        arms[0].contains("verdict=accept"),
        "a bare iterator loop must verify — that is the proof the ids are right: {}",
        arms[0]
    );
    assert!(arms[1].contains("verdict=accept"), "masked accumulator + store: {}", arms[1]);
    assert!(arms[2].contains("verdict=reject"), "unbounded accumulator + store: {}", arms[2]);
}

/// THE MECHANISM DIFFERENTIAL. The same loop bodies driven by may_goto (0043) and by an
/// open-coded iterator must reach the same verdict: both are back-edges over the same
/// transfer function, so a disagreement would mean one mechanism's convergence is wrong.
#[test]
fn the_two_loop_mechanisms_agree_on_every_shared_body() {
    let iter = verdicts(ITER, "geniter#");
    let mg = verdicts(MAYGOTO, "genloop#");
    let mut compared = 0;
    for (body, label, iter_ok) in &iter {
        // Only the o56 arms share may_goto's store offset and entry mask. Filter on THIS
        // arm's label, not on whether the body has an o56 arm somewhere — `inc` and `nop`
        // each have both offsets, so the looser test silently compared the o48 arms too.
        if !label.contains(".o56#") {
            continue;
        }
        if let Some((_, _, mg_ok)) = mg.iter().find(|(b, _, _)| b == body) {
            assert_eq!(
                iter_ok, mg_ok,
                "body `{body}`: iterator says {iter_ok}, may_goto says {mg_ok} — two \
                 back-edge mechanisms over the same transfer function disagreed"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 10, "all ten shared bodies must be compared, got {compared}");
}

/// The headline: three oracles, none of them new, all silent — with a denominator.
#[test]
fn every_iterator_store_landed_where_the_verifier_said() {
    let (norm, out) = run_diff(ITER, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "ITER locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.store_locations_checked as usize, ACCEPTED * SWEEP,
        "every run of every accepted iterator program must be compared against the claim"
    );
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(
        out.summary.finding_count, 0,
        "an iterator program diverged: {:?}", out.findings
    );
}

/// The `.o48` correction, pinned as a FACT about the verifier rather than a bug: it
/// tracks iterator depth but does not use a constant range to bound the trip count, so
/// it explores past the real maximum and over-rejects.
#[test]
fn the_verifier_does_not_bound_trip_count_by_the_iterators_constant_range() {
    let block = ITER
        .split("===PROG ")
        .find(|b| b.starts_with("geniter#inc.o48#"))
        .expect("the o48 growth arm must exist");
    assert!(
        block.lines().find(|l| l.starts_with("RESULT ")).unwrap().contains("decision=reject"),
        "with the trip count unbounded by the range, the accumulator escapes umax<=15"
    );
    assert!(
        block.contains("depth=9"),
        "the verifier explored a ninth trip although the range [0,8) admits eight — \
         that is the over-approximation, and it is the SAFE direction"
    );
    // The control at the same offset must still accept, or the arm proves nothing.
    let ctrl = ITER
        .split("===PROG ")
        .find(|b| b.starts_with("geniter#nop.o48#"))
        .unwrap();
    assert!(ctrl.lines().find(|l| l.starts_with("RESULT ")).unwrap().contains("decision=accept"));
}

/// TOOTH — 0041's location oracle must fire on THIS capture too.
#[test]
fn the_oracle_has_teeth_on_an_iterator_program() {
    let planted = with_mutated_sample(
        "geniter#mask.o56#001", "0x00000000", "store_off=40 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "a store outside the proven set must fire exactly once: {:?}", out.findings
    );
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "and the memory-safety leg stays silent — offset 40 is still inside the value"
    );
}

#[test]
fn the_runtime_landed_only_inside_the_proven_windows() {
    let (norm, _) = run_diff(ITER, "window");
    for rec in &norm.records {
        let label = rec.source_label.as_deref().unwrap_or("").to_string();
        let base: i64 = if label.contains(".o48#") { 48 } else { 56 };
        let seen: BTreeSet<i64> = rec
            .core
            .runtime_samples
            .iter()
            .filter_map(|s| s.store_off)
            .filter(|o| *o >= 0)
            .collect();
        for off in &seen {
            assert!(
                (base..base + 8).contains(off),
                "{label}: landed at {off}, outside base+[0,7]"
            );
        }
    }
}

#[test]
fn iterator_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(ITER, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
