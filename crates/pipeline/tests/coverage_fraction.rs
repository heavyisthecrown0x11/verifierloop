//! `seen_pcs` finally has a denominator (devlog 0086).
//!
//! Since 0078 the fuzz loop has reported a coverage number — 4789, 5203, 5406, 5443 — and
//! every one of them was a bare count. A count says the number went up. It never says how
//! much is left, and this project's standing rule is that a numerator without a
//! denominator is not evidence. `scripts/coverage-fraction.py` supplies the other half by
//! enumerating every `__sanitizer_cov_trace_pc` return address in vmlinux, which is
//! exactly the set of points KCOV can report.
//!
//! These tests pin the report, not the fuzzer. What they protect is the MEASUREMENT: if
//! the capture and the image ever come apart — a KASLR slide, a stale `.lab/build/vmlinux`
//! like the one 0085 found — the intersection collapses and every percentage in the report
//! becomes fiction while still reading like a result. That is the failure mode worth a
//! loud test.

const REPORT: &str = include_str!("fixtures/calibration/coverage-fraction.txt");

fn covfrac_field(key: &str) -> f64 {
    for line in REPORT.lines() {
        if let Some(rest) = line.strip_prefix("COVFRAC ") {
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix(key) {
                    return v.parse().unwrap_or_else(|_| panic!("bad value for {key}: {tok}"));
                }
            }
        }
    }
    panic!("no COVFRAC field {key} in the report");
}

fn theme(name: &str) -> u64 {
    for line in REPORT.lines() {
        if let Some(rest) = line.strip_prefix("COVFRAC theme ") {
            let rest = rest.trim_end();
            if let Some(v) = rest.strip_prefix(name) {
                return v.trim().parse().unwrap_or_else(|_| panic!("bad theme line: {rest}"));
            }
        }
    }
    panic!("no theme {name}");
}

#[test]
fn the_capture_and_the_image_are_the_same_kernel() {
    // THE GUARD THAT MATTERS. 5370 PCs were recorded in the guest; 5234 of them land
    // exactly on an address this script located statically as a coverage point. That is
    // not something a wrong image can produce by accident — a KASLR slide or a different
    // build gives ~0% overlap, not 97%. Every other assertion in this file is downstream
    // of this one.
    let observed = covfrac_field("observed=");
    let matched = covfrac_field("matched=");
    assert!(observed > 5000.0, "the run must have recorded a real PC set: {observed}");
    assert!(
        matched / observed > 0.95,
        "capture and vmlinux disagree ({matched}/{observed}) — re-check which kernel \
         .lab/build/vmlinux actually is before believing any percentage below"
    );
}

#[test]
fn the_unmatched_remainder_is_accounted_for_and_not_one_sided() {
    // 136 PCs did not match. They are not a mystery and not a bias: a jump table inside
    // .text desynchronises the objdump walk, so the walk loses sites on BOTH sides of the
    // ratio. The report names where they land, and they land in functions we do reach.
    let unmatched = covfrac_field("unmatched=");
    let observed = covfrac_field("observed=");
    assert!(unmatched / observed < 0.05, "too much unexplained: {unmatched}/{observed}");
    let lands = REPORT
        .lines()
        .find(|l| l.starts_with("COVFRAC unmatched-lands-in"))
        .expect("the unmatched PCs must be attributed, not merely counted");
    assert!(
        lands.contains("check_mem_access") || lands.contains("do_check_common"),
        "unmatched PCs should fall inside functions we demonstrably enter: {lands}"
    );
}

#[test]
fn the_verification_pass_has_a_real_denominator_now() {
    let hit = covfrac_field("hit=");
    let total = covfrac_field("total=");
    let pct = covfrac_field("pct=");
    assert!(total > 5_000.0, "the denominator must be the whole pass, not a corner: {total}");
    // A fraction, in both directions: neither "we have seen nothing" nor a saturated 100%
    // that would mean the denominator was drawn too tight to be informative.
    assert!(pct > 5.0 && pct < 90.0, "not a usable fraction: {pct}");
    assert!((hit / total * 100.0 - pct).abs() < 0.2, "the report contradicts itself");
    // 0085 reported seen_pcs=5443 with no scale at all. This is the scale.
    assert_eq!(hit as u64, 3104);
    assert_eq!(total as u64, 10244);
}

#[test]
fn most_of_what_we_touch_is_actually_the_verifier() {
    // A coverage-guided loop can drift: `bpf_prog_load` drags in vmalloc, per-cpu
    // allocation and the JIT, and every new PC there counts as "coverage" while telling
    // us nothing about verification logic. 59% says the guidance is aimed at the right
    // half of the kernel; if this ever falls, the corpus is being rewarded for noise.
    assert!(
        covfrac_field("share_of_our_coverage_that_is_the_verifier=") > 50.0,
        "the coverage signal has drifted off the verifier"
    );
}

#[test]
fn the_two_kinds_of_unreached_are_separated() {
    // 33% sits in functions we have NEVER entered — a feature the grammar cannot express
    // at all — and 37% in blocks of functions we do enter. These are different problems
    // with different fixes, and a single "70% unreached" would hide that.
    let reached = covfrac_field("reached=");
    let partial = covfrac_field("unreached_in_entered_functions=");
    let never = covfrac_field("in_functions_never_entered=");
    assert!((reached + partial + never - covfrac_field("total=")).abs() < 0.5);
    assert!(never > 2_000.0 && partial > 2_000.0, "both halves are large: {never} {partial}");
}

#[test]
fn the_largest_unreached_region_is_named_and_it_is_kfuncs() {
    // THE AIM. 1318 of the 3397 never-entered points are kfunc and BTF-call handling —
    // 13% of the entire verification pass behind one feature the grammar has never
    // emitted. Everything else is smaller by a factor of four.
    //
    // When this test fails because kfuncs stopped being the largest theme, that is the
    // frontier moving and the number should be re-read, not the assertion relaxed.
    let kfunc = theme("kfunc / BTF calls");
    let others = [
        "log + disasm printing",
        "reference / spin lock",
        "attach target / trampoline",
        "callbacks / subprogs",
        "dynptr / iterator",
        "packet pointers",
    ];
    for o in others {
        assert!(kfunc > theme(o) * 2, "{o} has caught up with kfuncs — re-read the report");
    }
    assert!(kfunc > 1_000);
}

#[test]
fn the_numeric_core_is_the_part_we_have_saturated() {
    // The complement of the aim, and the reason the hunt has produced zero findings.
    // Our oracles are strongest on scalar arithmetic, and that is exactly where coverage
    // is nearly exhausted: cnum.o at 95%, tnum.o at 65%, states.o at 59%. The thin
    // regions are the ones our oracles say the least about — types, references, kfuncs.
    // The instrument is not starved of programs; it is pointed at a solved surface.
    let line = REPORT
        .lines()
        .find(|l| l.contains("cnum.o"))
        .expect("cnum.o must appear in the per-object table");
    let pct: f64 = line
        .split_whitespace()
        .last()
        .unwrap()
        .trim_end_matches('%')
        .parse()
        .unwrap();
    assert!(pct > 90.0, "the numeric core is no longer saturated: {line}");
}
