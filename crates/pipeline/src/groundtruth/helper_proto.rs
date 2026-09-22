//! Ground-truth source 3 — helper `bpf_func_proto` / `arg_type` contracts.
//!
//! A helper's `bpf_func_proto` documents the `arg_type` each argument must have.
//! This model is the reference table the `diff` stage checks the CORE
//! `helper_arg_violation` signal against.
//!
//! The real extraction (parsing `bpf_func_proto` definitions out of a bpf-next
//! checkout) is TODO — it needs the kernel tree. Until then the table can be
//! populated in-memory (see [`HelperProtoModel::with_contract`]) so the diff
//! oracle path is exercised now.

use std::collections::BTreeMap;
use std::path::Path;

/// Reference view of helper argument-type contracts:
/// `(helper, arg_index) -> documented arg_type` (verbatim, drift-robust String).
#[derive(Debug, Default, Clone)]
pub struct HelperProtoModel {
    contracts: BTreeMap<(String, u8), String>,
    /// Expected verifier reg-type FAMILY per (helper, arg_index) — what the real
    /// path compares an observed arg reg-type against.
    regtypes: BTreeMap<(String, u8), String>,
}

impl HelperProtoModel {
    /// An empty model (no contracts loaded).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one documented `(helper, arg_index) -> arg_type` contract (builder).
    pub fn with_contract(
        mut self,
        helper: impl Into<String>,
        arg_index: u8,
        arg_type: impl Into<String>,
    ) -> Self {
        self.contracts
            .insert((helper.into(), arg_index), arg_type.into());
        self
    }

    /// Documented `arg_type` for `(helper, arg_index)`, if this source knows it.
    /// `None` means the contract is not loaded (real loader TODO) — the diff stage
    /// treats that as "cannot corroborate", not "no violation".
    pub fn arg_type(&self, helper: &str, arg_index: u8) -> Option<&str> {
        self.contracts
            .get(&(helper.to_string(), arg_index))
            .map(String::as_str)
    }

    /// Expected verifier reg-type family for `(helper, arg_index)`, if loaded.
    /// This is what the real-path helper check compares an OBSERVED arg reg-type
    /// against. `None` = the slice does not cover this arg (cannot corroborate).
    pub fn arg_regtype(&self, helper: &str, arg_index: u8) -> Option<&str> {
        self.regtypes
            .get(&(helper.to_string(), arg_index))
            .map(String::as_str)
    }

    /// Add an expected reg-type family contract (builder; for tests).
    pub fn with_regtype(
        mut self,
        helper: impl Into<String>,
        arg_index: u8,
        regtype: impl Into<String>,
    ) -> Self {
        self.regtypes
            .insert((helper.into(), arg_index), regtype.into());
        self
    }

    /// Load a curated `bpf_func_proto` slice from a TSV file:
    /// `helper <TAB> arg_index <TAB> arg_type(ARG_*) <TAB> expected_regtype`.
    /// `#` lines and blanks are ignored. This is a real ground-truth LOADER — the
    /// expected values come from the file, never from the caller/test.
    pub fn load_from_file(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut m = HelperProtoModel::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').map(str::trim).collect();
            if cols.len() < 4 {
                continue;
            }
            let arg_index: u8 = match cols[1].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            m.contracts
                .insert((cols[0].to_string(), arg_index), cols[2].to_string());
            m.regtypes
                .insert((cols[0].to_string(), arg_index), cols[3].to_string());
        }
        Ok(m)
    }

    /// Number of loaded contracts.
    pub fn len(&self) -> usize {
        self.contracts.len()
    }

    /// Whether no contracts are loaded.
    pub fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }
}

/// The ONLY `arg_type`s promoted to a checkable contract: those that pin an
/// argument to exactly ONE verifier reg-type family.
///
/// This table is a deliberate, reviewable judgement call — the extraction below is
/// mechanical, but deciding "this arg_type means this reg-type" is not. Everything
/// absent from this table is DROPPED, which the diff stage reads as "cannot
/// corroborate" (silence), never as "no violation". Kept conservative on purpose:
///
///   * `ARG_ANYTHING` — any reg type is valid, nothing to check.
///   * `ARG_PTR_TO_MEM` and friends — legitimately `fp` OR `map_value` OR `pkt`…
///   * `ARG_PTR_TO_MAP_KEY` / `_MAP_VALUE` — likewise multi-family.
///   * BTF/sock/timer pointer args — the verifier's printed family varies.
///
/// Asserting a single family for any of those would manufacture false positives.
const SINGLE_FAMILY_ARG_TYPES: &[(&str, &str)] = &[
    // A const map pointer is always printed as `map_ptr(...)`.
    ("ARG_CONST_MAP_PTR", "map_ptr"),
    // The context pointer is always printed as `ctx(...)`.
    ("ARG_PTR_TO_CTX", "ctx"),
    // Size/length arguments are always scalars.
    ("ARG_MEM_SIZE", "scalar"),
    ("ARG_MEM_SIZE_OR_ZERO", "scalar"),
    ("ARG_CONST_SIZE", "scalar"),
    ("ARG_CONST_SIZE_OR_ZERO", "scalar"),
    ("ARG_CONST_ALLOC_SIZE_OR_ZERO", "scalar"),
    // A reserved ringbuf record, printed as `ringbuf_mem(...)`.
    ("ARG_PTR_TO_RINGBUF_MEM", "ringbuf_mem"),
    // A const string lives in a frozen read-only map value.
    ("ARG_PTR_TO_CONST_STR", "map_value"),
];

/// Map one `.argN_type = ...` expression to a single verifier reg-type family.
///
/// Flags after `|` (`MEM_RDONLY`, `OBJ_RELEASE`, `PTR_MAYBE_NULL`, …) are modifiers,
/// not families: the base token decides. `PTR_MAYBE_NULL` only means the pointer may
/// be null — the observed family (after the parser strips `_or_null`) is unchanged.
/// Returns `None` for anything not in [`SINGLE_FAMILY_ARG_TYPES`].
fn arg_type_to_regtype(expr: &str) -> Option<&'static str> {
    let base = expr.split('|').next()?.trim();
    SINGLE_FAMILY_ARG_TYPES
        .iter()
        .find(|(a, _)| *a == base)
        .map(|(_, r)| *r)
}

/// Extract helper `arg_type` contracts from a bpf-next checkout (ground-truth
/// source 3, the real loader).
///
/// Scans `kernel/` and `net/` for `const struct bpf_func_proto <name> = { … };`
/// blocks and reads their `.argN_type` fields. `argN` is 1-based in the kernel and
/// 0-based here, matching the verifier-log parser's arg indices.
///
/// Only single-family arg types become contracts (see [`SINGLE_FAMILY_ARG_TYPES`]);
/// the rest are dropped so the oracle stays silent where it cannot corroborate.
pub fn extract_from_tree(kernel_src: &Path) -> std::io::Result<HelperProtoModel> {
    let mut model = HelperProtoModel::new();
    for dir in ["kernel", "net"] {
        let root = kernel_src.join(dir);
        if root.is_dir() {
            extract_dir(&root, &mut model)?;
        }
    }
    Ok(model)
}

fn extract_dir(dir: &Path, model: &mut HelperProtoModel) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            extract_dir(&path, model)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("c") {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            extract_text(&text, model);
        }
    }
    Ok(())
}

/// Parse every `const struct bpf_func_proto <name>_proto = { … };` block in one
/// translation unit. Exposed for testing against a literal snippet.
pub(crate) fn extract_text(text: &str, model: &mut HelperProtoModel) {
    const MARK: &str = "struct bpf_func_proto ";
    let mut rest = text;
    while let Some(i) = rest.find(MARK) {
        let after = &rest[i + MARK.len()..];

        // Distinguish a DEFINITION (`<name> = { … };`) from a mere DECLARATION
        // (`<name> __weak;`, `*fn(void);`). The kernel has runs of `__weak`
        // declarations right before real definitions, so an unbounded search for
        // the next `=` would skip past a real definition and silently lose it.
        // Decide by whichever of `;` / `{` comes first.
        let semi = after.find(';').unwrap_or(usize::MAX);
        let Some(open) = after.find('{') else { break };
        if semi < open {
            rest = &after[semi + 1..]; // declaration: resume just past it
            continue;
        }
        let head = &after[..open];
        let Some(eq) = head.find('=') else {
            rest = &after[open + 1..];
            continue;
        };
        let name_tok = head[..eq].trim();
        let body_start = open + 1;
        let Some(close) = after[body_start..].find('}') else {
            rest = &after[body_start..];
            continue;
        };
        let body = &after[body_start..body_start + close];

        // Helper name: strip the `_proto` suffix the kernel uses by convention.
        if let Some(helper) = name_tok
            .strip_suffix("_proto")
            .filter(|h| !h.is_empty() && h.chars().all(|c| c.is_alphanumeric() || c == '_'))
        {
            for line in body.lines() {
                let t = line.trim();
                let Some(after_arg) = t.strip_prefix(".arg") else { continue };
                let Some(digit) = after_arg.chars().next().and_then(|c| c.to_digit(10)) else {
                    continue;
                };
                let Some(v) = after_arg.split('=').nth(1) else { continue };
                let value = v.trim().trim_end_matches(',').trim();
                if let Some(regtype) = arg_type_to_regtype(value) {
                    // kernel arg1 == our arg_index 0
                    let idx = (digit as u8).saturating_sub(1);
                    model
                        .contracts
                        .insert((helper.to_string(), idx), value.to_string());
                    model
                        .regtypes
                        .insert((helper.to_string(), idx), regtype.to_string());
                }
            }
        }
        rest = &after[body_start + close..];
    }
}

/// Serialize the model as the committed TSV slice (see
/// `data/groundtruth/helper_protos.tsv`), so tests and CI do not need a kernel tree.
pub fn to_tsv(model: &HelperProtoModel) -> String {
    let mut out = String::new();
    for ((helper, idx), arg_type) in &model.contracts {
        if let Some(rt) = model.arg_regtype(helper, *idx) {
            out.push_str(&format!("{helper}\t{idx}\t{arg_type}\t{rt}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_family_args_and_drops_the_rest() {
        let src = r#"
const struct bpf_func_proto bpf_example_proto = {
	.func		= bpf_example,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_MEM_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};
"#;
        let mut m = HelperProtoModel::new();
        extract_text(src, &mut m);
        // kernel arg1 == our index 0
        assert_eq!(m.arg_regtype("bpf_example", 0), Some("map_ptr"));
        assert_eq!(m.arg_regtype("bpf_example", 2), Some("scalar"));
        // Multi-family and "anything" args must be DROPPED (silence, not a guess).
        assert_eq!(m.arg_regtype("bpf_example", 1), None, "ARG_PTR_TO_MEM is multi-family");
        assert_eq!(m.arg_regtype("bpf_example", 3), None, "ARG_ANYTHING pins nothing");
        assert_eq!(m.len(), 2);
    }

    /// Regression: the kernel has runs of `__weak` DECLARATIONS just before real
    /// definitions (kernel/bpf/core.c). An unbounded search for the next `=` used to
    /// skip past a following definition and lose it SILENTLY — bpf_tail_call went
    /// missing that way.
    #[test]
    fn declarations_before_a_definition_do_not_swallow_it() {
        let src = r#"
const struct bpf_func_proto bpf_map_lookup_elem_proto __weak;
const struct bpf_func_proto bpf_map_update_elem_proto __weak;
const struct bpf_func_proto bpf_spin_lock_proto __weak;

const struct bpf_func_proto bpf_tail_call_proto = {
	/* func is unused for tail_call, we set it to pass the
	 * get_helper_proto check
	 */
	.func		= BPF_PTR_POISON,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
"#;
        let mut m = HelperProtoModel::new();
        extract_text(src, &mut m);
        assert_eq!(m.arg_regtype("bpf_tail_call", 0), Some("ctx"));
        assert_eq!(m.arg_regtype("bpf_tail_call", 1), Some("map_ptr"));
        // The declarations themselves contribute nothing.
        assert_eq!(m.arg_regtype("bpf_map_lookup_elem", 0), None);
    }

    #[test]
    fn flags_after_the_base_type_are_modifiers_not_families() {
        // OBJ_RELEASE / MEM_RDONLY / PTR_MAYBE_NULL qualify, they do not re-type.
        assert_eq!(
            arg_type_to_regtype("ARG_PTR_TO_RINGBUF_MEM | OBJ_RELEASE"),
            Some("ringbuf_mem")
        );
        assert_eq!(arg_type_to_regtype("ARG_PTR_TO_CTX"), Some("ctx"));
        assert_eq!(arg_type_to_regtype("ARG_PTR_TO_MEM | MEM_RDONLY"), None);
        assert_eq!(arg_type_to_regtype("ARG_ANYTHING"), None);
    }

    /// The committed slice must stay usable without a kernel tree, and must keep
    /// covering the helpers the volume captures actually exercise.
    #[test]
    fn committed_slice_loads_and_covers_the_volume_helpers() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/groundtruth/helper_protos.tsv");
        let m = HelperProtoModel::load_from_file(&path).expect("committed slice loads");
        assert!(m.len() >= 250, "generated slice should be broad, got {}", m.len());
        for (helper, idx, want) in [
            ("bpf_map_lookup_elem", 0u8, "map_ptr"),
            ("bpf_ringbuf_reserve", 0, "map_ptr"),
            ("bpf_ringbuf_submit", 0, "ringbuf_mem"),
            ("bpf_tail_call", 0, "ctx"),
            ("bpf_tail_call", 1, "map_ptr"),
            ("bpf_snprintf", 2, "map_value"),
            ("bpf_trace_printk", 1, "scalar"),
        ] {
            assert_eq!(m.arg_regtype(helper, idx), Some(want), "{helper} arg{idx}");
        }
    }
}
