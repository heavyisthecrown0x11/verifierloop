//! Corpus-quality measurement (devlog 0025): how much CHECKABLE abstract state does
//! a capture produce PER EXECUTION?
//!
//! This is not a detector and never feeds the signal path. It answers the question
//! the reviewer's "bug hunting = oracle x input" diagnosis raises: with a fixed and
//! very small input budget (TCG, KVM blocked), which corpus is worth spending it on?
//!
//! The metric is derived from what the intrinsic-invariant leg actually needs. That
//! leg checks the verifier against ITSELF, and its strongest check —
//! `tnum_bounds_inconsistent` — can only fire on a register that has BOTH:
//!   * a partially-known tnum  (some bits known, some unknown), and
//!   * narrowed bounds         (a range tighter than "anything")
//! A register that is fully known, or fully unknown, or unbounded cannot expose a
//! disagreement between the two trackers, because there is nothing to disagree
//! about. So "cross-domain register observations per record" is a direct measure of
//! how many chances at a finding an execution buys.
//!
//!   cargo run -p pipeline --example signal_density -- <capture> [<capture> ...]

use pipeline::normalize::RecordParser;
use pipeline::verifier_log::VerifierLogParser;
use std::path::PathBuf;

/// What one capture buys.
#[derive(Default)]
struct Density {
    blocks: usize,
    records: usize,
    reg_observations: usize,
    /// Some bits known and some unknown (`mask != 0` and not every bit unknown).
    partial_tnum: usize,
    /// A range tighter than the full unsigned domain.
    narrowed_bounds: usize,
    /// BOTH at once — the only shape `tnum_bounds_inconsistent` can fire on.
    cross_domain: usize,
    /// Records carrying at least one such register.
    records_with_cross: usize,
    /// Distinct branch merges the verifier had to perform (`total_states`).
    states: u64,
    /// Registers where the verifier printed ANY 32-bit field at all.
    has32: usize,
    /// Of those, the ones carrying information independent of the 64-bit view —
    /// the 32<->64 denominator (`diff::reg32_checkable`).
    cross32: usize,
}

fn measure(path: &PathBuf) -> Density {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let out = VerifierLogParser.parse("capture", &bytes);
    let mut d = Density {
        blocks: out.records.len() + out.unparsed.len(),
        records: out.records.len(),
        ..Default::default()
    };
    for rec in &out.records {
        d.states += rec.core.processed.states_processed;
        let mut cross_here = 0usize;
        for snap in &rec.core.register_evolution {
            for r in &snap.regs {
                d.reg_observations += 1;
                // Partially known: at least one unknown bit, but not all 64.
                if r.tnum.mask != 0 && r.tnum.mask.count_ones() < 64 {
                    d.partial_tnum += 1;
                }
                // Narrowed: the unsigned range is not the whole domain.
                if r.umin > 0 || r.umax < u64::MAX {
                    d.narrowed_bounds += 1;
                }
                // The exact predicate `diff` counts as its denominator — one
                // definition, so the corpus metric and the detector cannot drift
                // apart and quietly disagree about what "checkable" means.
                if pipeline::diff::tnum_bounds_checkable(r) {
                    d.cross_domain += 1;
                    cross_here += 1;
                }
                if r.u32_min.is_some()
                    || r.u32_max.is_some()
                    || r.s32_min.is_some()
                    || r.s32_max.is_some()
                {
                    d.has32 += 1;
                }
                if pipeline::diff::reg32_checkable(r) {
                    d.cross32 += 1;
                }
            }
        }
        if cross_here > 0 {
            d.records_with_cross += 1;
        }
    }
    d
}

fn main() {
    let paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    assert!(!paths.is_empty(), "usage: signal_density <capture> [<capture> ...]");

    println!(
        "{:<30} {:>7} {:>7} {:>7} {:>8} {:>7} {:>9} {:>8} {:>9}",
        "capture", "blocks", "records", "regs", "partial", "cross", "cross/rec", "32-view", "32-chk"
    );
    println!("{}", "-".repeat(106));
    for p in &paths {
        let d = measure(p);
        let name = p.file_name().unwrap().to_string_lossy();
        let per_rec = if d.records > 0 {
            d.cross_domain as f64 / d.records as f64
        } else {
            0.0
        };
        let pct = if d.records > 0 {
            100.0 * d.records_with_cross as f64 / d.records as f64
        } else {
            0.0
        };
        let _ = pct;
        println!(
            "{:<30} {:>7} {:>7} {:>7} {:>8} {:>7} {:>9.2} {:>8} {:>9}",
            name, d.blocks, d.records, d.reg_observations, d.partial_tnum,
            d.cross_domain, per_rec, d.has32, d.cross32
        );
    }
    println!();
    println!("cross = register observations with BOTH a partially-known tnum AND narrowed");
    println!("        bounds — the only shape the intrinsic tnum-vs-bounds check can fire on.");
    println!("cross/rec = chances at a finding bought per execution. THIS is the number the");
    println!("        input budget should be spent to maximise.");
    println!("32-view = registers where the verifier printed a 32-bit field at all.");
    println!("32-chk  = of those, the ones whose 32-bit view says something the 64-bit view");
    println!("        does not — the only shape a 32<->64 desync can show in. A corpus of");
    println!("        single-width programs scores 0 here however large it gets.");
}
