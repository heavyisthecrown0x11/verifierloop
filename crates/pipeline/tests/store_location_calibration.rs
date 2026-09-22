//! STORE-LOCATION DESYNC — "where it SAID", not just "inside" (devlog 0041, `--gen-loc`).
//!
//! CAPTURED 2026-09-05 on the self-built bpf-next kernel: 15 programs, 15 accept,
//! `store_locations_checked = 170`, `finding_count = 0` — every accepted store landed
//! inside the set the verifier proved for it. **A finding here is NOT automatically a
//! bug in the kernel and NOT automatically a bug in this code — it is the one outcome
//! this whole era was built to produce, so investigate it, in this order: (a) re-derive
//! the proven window by hand from the log line the finding quotes, (b) check the
//! harness's declared `STORE insn=` really is the store, (c) only then call it a
//! verifier finding.**
//!
//! WHAT THE FIRST CAPTURE CHANGED. The pre-run derivation said 180 checks (15 x 12) and
//! zero findings; the capture returned 170 checks and TEN `runtime_oob_write` findings,
//! all in the `jmp` arm. Hand-derivation cleared the kernel — every store was inside
//! its proven set — and located the fault in this oracle: `store_off = none` means "no
//! sentinel in the value", which conflates the store going OUT OF BOUNDS with the store
//! never RUNNING. Every earlier runtime-write family (--gen-rtw, --gen-rtw2,
//! --gen-pktw) reaches its store unconditionally, so `none` could only mean the first,
//! and the predicate was written on that unstated assumption. `jmp` bounds the offset
//! with a BRANCH, so the 10 sweep inputs above the bound skip the store entirely.
//! The fix disambiguates at the SOURCE rather than guessing in the diff stage: the
//! program returns a distinct value on the storing path, the harness reports it as
//! `executed=`, and a run that never reached the store is not judged. The teeth are
//! untouched — a family with an unconditional store reports no witness at all and
//! keeps the original reading, and `executed=1` with an absent sentinel is still an
//! OOB write. 170 is therefore the DERIVED count, not a lowered bar: 180 sweep runs
//! minus the 10 that provably never stored.
//!
//! WHY THIS LEG EXISTS. Every runtime-write leg so far (0037 map value, 0038 store
//! width, 0039 packet) asks one question: did the store stay INSIDE the object? A
//! verifier can pass that and still be wrong. If its abstract arithmetic for the offset
//! is unsound, the store lands at an offset its OWN state says is impossible — while
//! still landing inside the object, so every earlier leg stays silent. That is the
//! "consistent-but-wrong" class: the verifier's two views agree with each other and
//! disagree only with reality, which an internal-consistency oracle cannot see by
//! construction (see [[store-location-desync-is-the-hunt]]).
//!
//! WHAT IS COMPARED. The verifier prints its own claim at the store instruction:
//!   17: R7=map_value(ks=4,vs=64,smin=0,smax=umax=7,var_off=(0x0; 0x7))
//!   17: (72) *(u8 *)(r7 +0) = -1
//! i.e. "in [0,7], and only at offsets whose bits fit (0x0; 0x7)". The runtime says
//! where the sentinel actually landed. `check_store_location` compares them:
//!   proven window = ptr_off + insn_off + [umin, umax], narrowed by the var_off tnum.
//! The tnum half carries as much weight as the interval: `r6 &= 3; r6 <<= 2` proves
//! {0,4,8,12}, so an offset of 6 is inside [0,12] and still impossible.
//!
//! PROVENANCE. Which instruction stores, and through which register, comes from the
//! GENERATOR (the harness's `STORE insn= reg= off= size=` line), never from the
//! verifier's own disassembly — the oracle must not learn the question from the
//! component it is auditing.
//!
//! THE FAMILY is one program per abstract transfer function, because that is where an
//! unsound (too narrow) bound would come from: and7, and31, orand, addc, subc, lsh2,
//! lsh3, rsh, mul, xor, alu32 (32-bit op), jmp (bounded by a BRANCH — reg_set_min_max,
//! a different code path from masking), shpair (<<60 then >>60), compose (chained
//! and/add/lsh), off4 (the store carries its own +4, exercising the ptr_off + insn_off
//! arithmetic on both sides). All 15 land well inside the 64-byte value, so the
//! DECISION is not the surface — all accept, and the surface is WHERE they land.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const LOC: &str = include_str!("fixtures/volume/gen-loc-15.log");
const PROGRAMS: usize = 15;
const SWEEP: usize = 12; // RT_INPUTS_N in the harness
/// Sweep runs that never reached the store: the `jmp` arm bounds the offset with
/// `if r6 > 7 goto exit`, and 10 of the 12 sweep inputs exceed 7. They are the only
/// skipped runs in the family, and the program itself reports the skip (`executed=0`).
const SKIPPED: usize = 10;
/// The denominator that matters: sweep runs whose store actually executed and could
/// therefore be compared against the verifier's claim.
const STORES_EXECUTED: usize = PROGRAMS * SWEEP - SKIPPED;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-loc-{}-{}", std::process::id(), tag));
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

/// Rebuild the fixture with one program's RUNTIME line (for a given input) replaced —
/// used to plant a landing site the real kernel never produced.
fn with_mutated_sample(label: &str, input_hex: &str, new_tail: &str) -> String {
    let mut out = String::new();
    let mut hit = false;
    for block in LOC.split("===PROG ").skip(1) {
        out.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        if blabel == label {
            for line in block.lines() {
                if line.starts_with(&format!("RUNTIME input={input_hex} ")) {
                    out.push_str(&format!("RUNTIME input={input_hex} {new_tail}"));
                    hit = true;
                } else {
                    out.push_str(line);
                }
                out.push('\n');
            }
        } else {
            out.push_str(block);
        }
    }
    assert!(hit, "planting target {label}/{input_hex} not found — fixture changed?");
    out
}

fn of_kind<'a>(out: &'a diff::DiffFindings, kind: &str) -> Vec<&'a diff::DivergenceFinding> {
    out.findings.iter().filter(|f| f.kind == kind).collect()
}

#[test]
fn all_shapes_present_accepted_and_declare_a_store_site() {
    let (norm, _) = run_diff(LOC, "shapes");
    assert_eq!(norm.records.len(), PROGRAMS);
    assert_eq!(LOC.matches("decision=accept").count(), PROGRAMS, "the decision is not the surface");
    assert_eq!(LOC.matches("decision=reject").count(), 0);
    for shape in [
        "and7", "and31", "orand", "addc", "subc", "lsh2", "lsh3", "rsh", "mul", "xor",
        "alu32", "jmp", "shpair", "compose", "off4",
    ] {
        assert_eq!(
            LOC.matches(&format!("genloc#{shape}#")).count(),
            1,
            "exactly one program per abstract transfer function: {shape}"
        );
    }
    for rec in &norm.records {
        assert!(rec.core.store_site.is_some(), "the generator must declare the store site");
        assert_eq!(rec.core.runtime_samples.len(), SWEEP, "each program runs the full sweep");
    }
}

/// The headline: every accepted store landed inside the set the verifier PROVED for it.
#[test]
fn every_store_landed_where_the_verifier_said_it_could() {
    let (norm, out) = run_diff(LOC, "base");
    eprintln!(
        "LOC records={} locations_checked={} finding_count={}",
        norm.records.len(), out.summary.store_locations_checked, out.summary.finding_count
    );
    assert_eq!(
        out.summary.store_locations_checked as usize,
        STORES_EXECUTED,
        "every store that RAN must be COMPARED against the proven window; a short \
         denominator means the claim was not read, not that the kernel is clean"
    );
    assert_eq!(
        out.summary.finding_count, 0,
        "a store landed somewhere the verifier proved it could not: {:?}",
        out.findings
    );
}

/// A zero finding count only means something if the claims being checked are TIGHT.
/// A window as wide as the object would make this leg pass vacuously, so pin that the
/// verifier's proven set at each store is genuinely narrow.
#[test]
fn the_proven_windows_are_tight_not_vacuous() {
    let (norm, _) = run_diff(LOC, "tight");
    for rec in &norm.records {
        let site = rec.core.store_site.expect("store site");
        let ptr = rec
            .core
            .register_evolution
            .iter()
            .filter(|s| s.insn_idx == site.insn_idx)
            .find_map(|s| s.regs.iter().find(|r| r.reg == site.base_reg))
            .expect("the verifier printed a state for the store's pointer");
        assert_ne!(ptr.reg_type, "scalar", "the store base must be a pointer");
        let width = ptr.umax.saturating_sub(ptr.umin);
        assert!(
            width <= 56,
            "proven window [{}, {}] is too wide to be a real constraint: {:?}",
            ptr.umin, ptr.umax, rec.core.store_site
        );
    }
}

/// TOOTH 1 — the whole point of the leg. Plant a landing site that is INSIDE the map
/// value (so the memory-safety predicate of 0037/0038 stays silent) but OUTSIDE the
/// proven window. `orand` proves [8,15]; offset 3 is a perfectly safe write and still a
/// contradiction of what the verifier proved.
#[test]
fn the_oracle_has_teeth_an_in_bounds_but_unproven_offset_fires() {
    let mutated = with_mutated_sample(
        "genloc#orand#002", "0x00000000", "store_off=3 store_len=1 store_size=1");
    let (_, out) = run_diff(&mutated, "teeth-window");
    assert_eq!(
        of_kind(&out, "store_location_desync").len(), 1,
        "the planted out-of-window store must fire exactly once: {:?}", out.findings
    );
    assert_eq!(
        of_kind(&out, "runtime_oob_write").len(), 0,
        "and the memory-safety leg must stay SILENT — that silence is precisely the \
         blind spot this leg exists to cover: {:?}", out.findings
    );
}

/// TOOTH 2 — the tnum half, which an interval check alone cannot express. `lsh2` proves
/// {0,4,8,12} (var_off=(0x0; 0xc)); offset 6 is INSIDE [0,12], inside the map value, and
/// still impossible under the verifier's own claim.
#[test]
fn the_oracle_has_teeth_an_in_window_but_tnum_impossible_offset_fires() {
    let mutated = with_mutated_sample(
        "genloc#lsh2#005", "0x00000000", "store_off=6 store_len=1 store_size=1");
    let (_, out) = run_diff(&mutated, "teeth-tnum");
    let found = of_kind(&out, "store_location_desync");
    assert_eq!(found.len(), 1, "the planted tnum-impossible store must fire once: {:?}", out.findings);
    assert!(
        found[0].observed.contains("impossible under var_off"),
        "and it must be reported as a tnum violation, not merely an interval one: {:?}", found[0]
    );
    assert_eq!(of_kind(&out, "runtime_oob_write").len(), 0, "still memory-safe, still a desync");
}

/// The off4 arm shifts the landing site by the store instruction's own offset. Planting
/// an offset that would be legal WITHOUT that +4 checks that both sides of the
/// comparison actually apply it (a missing insn_off would make this plant pass).
#[test]
fn the_instruction_offset_is_part_of_the_claim() {
    let mutated = with_mutated_sample(
        "genloc#off4#014", "0x00000000", "store_off=0 store_len=1 store_size=1");
    let (_, out) = run_diff(&mutated, "teeth-insnoff");
    assert_eq!(
        of_kind(&out, "store_location_desync").len(), 1,
        "offset 0 is below the +4 base, so it contradicts the claim: {:?}", out.findings
    );
}

#[test]
fn store_location_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(LOC, "parse");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind != UnparsedKind::NotObserved)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}

/// The execution witness is the thing that makes `store_off = none` readable, so pin
/// its shape directly: exactly the `jmp` arm's over-the-bound inputs report a skip, and
/// a skipped run NEVER carries a sentinel (a skip that somehow wrote would be a
/// contradiction in the witness itself, and would silently suppress a real OOB).
#[test]
fn only_the_branch_arm_skips_its_store_and_a_skip_never_wrote() {
    let (norm, _) = run_diff(LOC, "witness");
    let mut skipped = 0usize;
    for rec in &norm.records {
        let is_jmp = rec.source_label.as_deref() == Some("genloc#jmp#011");
        for smp in &rec.core.runtime_samples {
            match smp.executed {
                Some(false) => {
                    skipped += 1;
                    assert!(is_jmp, "only the branch-bounded arm can skip its store");
                    assert_eq!(
                        smp.store_off, Some(-1),
                        "a run that never stored cannot have left a sentinel"
                    );
                }
                Some(true) => assert_ne!(
                    smp.store_off, Some(-1),
                    "the store ran and left nothing in the value — that is an OOB write, \
                     and it must be reported, not explained away by the witness"
                ),
                None => panic!("every --gen-loc sample must carry the execution witness"),
            }
        }
    }
    assert_eq!(skipped, SKIPPED, "the branch bound admits exactly 2 of the 12 sweep inputs");
}

/// TOOTH 4 — the witness must DISCRIMINATE, not merely excuse. The same absent
/// sentinel is an OOB write when the store ran and a non-event when it did not, so
/// plant both on a run that really did store and pin that only the first fires.
#[test]
fn an_absent_sentinel_still_fires_when_the_store_actually_ran() {
    let ran = with_mutated_sample(
        "genloc#and7#000", "0x00000001", "store_off=none store_len=0 store_size=1 executed=1");
    let (_, out) = run_diff(&ran, "teeth-witness-ran");
    assert_eq!(
        of_kind(&out, "runtime_oob_write").len(), 1,
        "an executed store that left no sentinel is an OOB write: {:?}", out.findings
    );

    let skipped = with_mutated_sample(
        "genloc#and7#000", "0x00000001", "store_off=none store_len=0 store_size=1 executed=0");
    let (_, out) = run_diff(&skipped, "teeth-witness-skipped");
    assert_eq!(
        of_kind(&out, "runtime_oob_write").len(), 0,
        "a store that never ran is not a memory-safety violation: {:?}", out.findings
    );
}
