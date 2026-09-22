//! DYNPTR SLICES — a two-part safety contract, and the first leg on a FRESH surface
//! (devlog 0053, `--gen-dyn`).
//!
//! Everything before this probed the verifier's most hardened regions: ALU transfer
//! functions, ranges, pruning, state comparison. dynptr is recent code, and what makes it
//! worth aiming at is visible in what the verifier actually proves about a slice
//! (verifier.c:13729):
//!
//!     regs[BPF_REG_0].mem_size = meta->arg_constant.value;   /* = buffer__szk */
//!     regs[BPF_REG_0].type = PTR_TO_MEM | type_flag;
//!
//! The static bound is THE CALLER'S CONSTANT — not the dynptr's extent, not
//! `size - offset`. The real bound is enforced at runtime (helpers.c):
//!
//!     u64 len = buffer__szk;
//!     err = bpf_dynptr_check_off_len(ptr, offset, len);
//!     if (err) return NULL;
//!     case BPF_DYNPTR_TYPE_LOCAL: return ptr->data + ptr->offset + offset;
//!
//! So safety is a TWO-PART CONTRACT and neither half suffices alone. No earlier family
//! has had a shape where the halves come from different places. For a LOCAL dynptr the
//! slice points INTO the original memory, so the existing sentinel readback observes the
//! composition end to end with NO new oracle — only the input surface changed.
//!
//! THE COORDINATE TRANSLATION was decided before the capture rather than after a false
//! positive. The slice pointer's base is `map_value + dynptr_offset`, the verifier sees
//! only a `mem(sz=N)` with no relation to the map value, and the runtime readback is in
//! map-value coordinates. The STORE line is generator provenance, so the generator
//! declares the store at `dynptr_offset + k`. That keeps a real property checkable: the
//! slice must hand back a pointer at exactly `data + offset`, which the `o24.z8.k7` arm
//! confirms by landing at exactly 31.
//!
//! AND 0041'S WITNESS PAID FOR ITSELF ON A NEW SURFACE. A NULL slice is a DESIGNED
//! outcome here, not a branch artefact, so two arms legitimately never store. Without the
//! `executed` witness their `store_off = none` would have fired `runtime_oob_write` three
//! times per arm — the same conflation 0041 fixed at the source, arriving from a
//! completely different direction.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use std::collections::BTreeSet;

const DYN: &str = include_str!("fixtures/volume/gen-dyn-6.log");
const PROGRAMS: usize = 6;
const EXECUTING_ARMS: usize = 3; // the arms whose slice is non-NULL and whose store runs
const SWEEP: usize = 8;
const DYNPTR_SIZE: i64 = 32;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-dyn-{}-{tag}", std::process::id()));
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
    for block in DYN.split("===PROG ").skip(1) {
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
    assert!(hit, "planting target {label}/{input_hex} not found");
    out
}

fn block_of(prefix: &str) -> &'static str {
    DYN.split("===PROG ")
        .find(|b| b.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing arm {prefix}"))
}

fn accepted(prefix: &str) -> bool {
    block_of(prefix)
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap()
        .contains("decision=accept")
}

fn landings(prefix: &str) -> BTreeSet<i64> {
    block_of(prefix)
        .lines()
        .filter(|l| l.starts_with("RUNTIME "))
        .filter_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("store_off=")))
        .filter(|v| *v != "none")
        .map(|v| v.parse().unwrap())
        .collect()
}

/// The verifier's half: the bound is the caller's constant, with an exact one-byte edge.
#[test]
fn the_static_bound_is_the_callers_constant_with_a_one_byte_edge() {
    assert!(accepted("gendyn#o0.z8.k0#"), "interior of an 8-byte slice");
    assert!(accepted("gendyn#o0.z8.k7#"), "the last byte of an 8-byte slice");
    assert!(!accepted("gendyn#o0.z8.k8#"), "one past it — k == szk must reject");
}

/// The point of the leg: the verifier accepts a slice claim it has NO basis for, because
/// it takes the size from the caller. `sz=64` is printed for a dynptr that is 32 bytes.
#[test]
fn the_verifier_trusts_a_constant_larger_than_the_dynptr() {
    assert!(
        accepted("gendyn#o0.z64.k0#"),
        "a 64-byte slice over a 32-byte dynptr is accepted statically"
    );
    assert!(
        block_of("gendyn#o0.z64.k0#").contains("sz=64"),
        "and the proven size is printed as the caller's constant, not the dynptr's extent"
    );
    assert!(
        accepted("gendyn#o28.z8.k0#"),
        "so is a slice whose offset + size runs past the dynptr"
    );
}

/// The runtime's half, and 0041's witness earning its keep on a new surface: those two
/// arms are kept safe ONLY by the slice returning NULL, the store never runs, and that
/// must NOT be reported as an out-of-bounds write.
#[test]
fn the_runtime_null_is_the_other_half_and_is_not_mistaken_for_an_oob_write() {
    for arm in ["gendyn#o28.z8.k0#", "gendyn#o0.z64.k0#"] {
        assert!(landings(arm).is_empty(), "{arm}: the slice is NULL, nothing is stored");
        for line in block_of(arm).lines().filter(|l| l.starts_with("RUNTIME ")) {
            assert!(
                line.contains("executed=0"),
                "{arm}: the program must report that it never reached the store: {line}"
            );
        }
    }
    let (_, out) = run_diff(DYN, "null");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0,
        "an absent sentinel on a path that never stored is not an OOB write: {:?}",
        out.findings
    );
}

/// The coordinate translation, confirmed by the arm that sits at the very end of the
/// dynptr: a slice at offset 24 with a store at +7 must land at exactly 31.
#[test]
fn a_slice_hands_back_a_pointer_at_exactly_data_plus_offset() {
    assert_eq!(landings("gendyn#o0.z8.k0#"), BTreeSet::from([0]));
    assert_eq!(landings("gendyn#o0.z8.k7#"), BTreeSet::from([7]));
    assert_eq!(
        landings("gendyn#o24.z8.k7#"), BTreeSet::from([DYNPTR_SIZE - 1]),
        "offset 24 plus store offset 7 is the dynptr's last byte, and nothing else"
    );
}

#[test]
fn no_oracle_fires_on_the_dynptr_family() {
    let (norm, out) = run_diff(DYN, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    eprintln!(
        "DYN locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert_eq!(
        out.summary.store_locations_checked as usize, EXECUTING_ARMS * SWEEP,
        "only the arms whose slice is non-NULL contribute — the others never store"
    );
    assert_eq!(out.summary.prune_pairs_checked as usize, PROGRAMS);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_oracle_has_teeth_on_a_dynptr_slice() {
    let planted = with_mutated_sample(
        "gendyn#o24.z8.k7#003", "0x00000000", "store_off=20 store_len=1 store_size=1 executed=1");
    let (_, out) = run_diff(&planted, "teeth");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "store_location_desync").count(), 1,
        "a slice store landing anywhere but data+offset+k must fire: {:?}", out.findings
    );
    assert_eq!(out.findings.iter().filter(|f| f.kind == "runtime_oob_write").count(), 0);
}

#[test]
fn dynptr_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(DYN, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
