//! Regenerate the committed `bpf_func_proto` slice from a bpf-next checkout
//! (ground-truth source 3). Mechanical extraction; the ARG_* -> reg-type mapping is
//! the reviewable judgement in `helper_proto::SINGLE_FAMILY_ARG_TYPES`.
//!
//!   cargo run -p pipeline --example extract_protos -- [kernel_src] [out.tsv]

use pipeline::groundtruth::helper_proto;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let src = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".lab/bpf-next"));
    let out = args.next().map(PathBuf::from);

    let model = helper_proto::extract_from_tree(&src).expect("scan kernel tree");
    let tsv = helper_proto::to_tsv(&model);
    let lines = tsv.lines().count();
    let distinct: std::collections::BTreeSet<&str> =
        tsv.lines().filter_map(|l| l.split('\t').next()).collect();

    eprintln!("extracted {lines} contracts across {} helpers", distinct.len());
    let header = format!(
        "# bpf_func_proto slice — ground-truth source 3.\n\
         # GENERATED, do not edit by hand:\n\
         #   cargo run -p pipeline --example extract_protos -- <kernel_src> <this file>\n\
         # Mechanically extracted from a bpf-next checkout by\n\
         # pipeline::groundtruth::helper_proto::extract_from_tree.\n\
         #\n\
         # Columns: helper <TAB> arg_index(0-based) <TAB> arg_type(ARG_*) <TAB> expected_regtype\n\
         #\n\
         # INCLUSION RULE (the reviewable judgement; see SINGLE_FAMILY_ARG_TYPES in\n\
         # helper_proto.rs): an arg becomes a contract ONLY when its arg_type pins it to\n\
         # exactly ONE verifier reg-type family. ARG_ANYTHING, ARG_PTR_TO_MEM variants,\n\
         # map key/value pointers and BTF/sock/timer pointers are DROPPED — asserting a\n\
         # single family there would manufacture false positives. Dropped means the diff\n\
         # stage cannot corroborate and stays silent, which is not \"no violation\".\n\
         #\n\
         # {lines} contracts across {helpers} helpers.\n\
         # ----------------------------------------------------------------------\n",
        lines = lines,
        helpers = distinct.len(),
    );

    match out {
        Some(p) => {
            std::fs::write(&p, format!("{header}{tsv}")).expect("write tsv");
            eprintln!("wrote {}", p.display());
        }
        None => print!("{tsv}"),
    }
}
