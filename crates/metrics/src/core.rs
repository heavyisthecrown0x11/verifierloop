//! CORE metrics — the operational bedrock of the loop.
//!
//! Design contract (do not weaken):
//!   * Fixed schema. Pure, raw operational observation.
//!   * Tied to ground truth; ALWAYS on.
//!   * INDEPENDENT of the counterfactual layer — core is read straight from
//!     observation, never from loop-generated alternatives.
//!
//! `reg_type` and reject `reason` are verbatim Strings: the verifier's own text,
//! robust across kernel versions and consistent with "don't reshape raw output".

use serde::{Deserialize, Serialize};

/// The verifier's final decision on a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum VerifierDecision {
    /// Program accepted.
    Accept,
    /// Program rejected, with the verifier's reason text (verbatim).
    Reject { reason: String },
}

/// A tnum (tristate number): known bit values + unknown-bit mask
/// (kernel `struct tnum`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tnum {
    /// Known bit values.
    pub value: u64,
    /// Unknown-bit mask (1 = unknown).
    pub mask: u64,
}

/// One register's abstract state at a point in verification.
///
/// The verifier tracks a scalar TWICE: as a full 64-bit value and as its 32-bit
/// subregister, and it must keep the two views reconciled (`__reg32_deduce_bounds`
/// / `__reg64_deduce_bounds`). Both views are recorded here because a disagreement
/// BETWEEN them is a bug class neither view can show on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegState {
    /// Register number (0..=10).
    pub reg: u8,
    /// Verifier `reg_type`, verbatim (e.g. "scalar", "map_value", "ptr_to_ctx").
    pub reg_type: String,
    /// tnum (known bits + unknown mask).
    pub tnum: Tnum,
    /// Unsigned min bound.
    pub umin: u64,
    /// Unsigned max bound.
    pub umax: u64,
    /// Signed min bound.
    pub smin: i64,
    /// Signed max bound.
    pub smax: i64,
    /// 32-bit unsigned min, when the verifier printed a 32-bit view.
    ///
    /// `None` means the verifier did NOT print one — which is not the same as zero,
    /// and the difference matters: an absent view is nothing to check, a present
    /// zero is an observation. Serialized only when present, so artifacts written
    /// before the 32-bit view existed stay byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub u32_min: Option<u64>,
    /// 32-bit unsigned max, when printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub u32_max: Option<u64>,
    /// 32-bit signed min, when printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s32_min: Option<i64>,
    /// 32-bit signed max, when printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s32_max: Option<i64>,
    /// For a POINTER register: the CONSTANT part of its offset, as the verifier
    /// printed it (`map_value(off=8,...)`). The variable part lives in `tnum` /
    /// `umin` / `umax`, so the verifier's full claim about where a store through
    /// this pointer can land is `ptr_off + [umin, umax]`, narrowed by the tnum.
    /// `None` for scalars and for pointers the verifier printed with no `off=`
    /// (which means a constant part of exactly zero, not an unknown one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptr_off: Option<i64>,
    /// Whether ANY bound in this state was read from the log rather than synthesized.
    ///
    /// A constant scalar prints as a bare number and nothing else — `print_reg_state`
    /// (kernel/bpf/log.c) does `verbose_snum(value); return;` when `tnum_is_const`, in the
    /// CURRENT tree as much as in 2021. The parser then derives umin, umax, smin and smax
    /// from that single token, so comparing them against the tnum compares the value with
    /// itself. `tnum_bounds_checkable` already excludes exactly that for the intersection
    /// check — "a constant is not a check, it is a tautology" — but the const-pins-bounds
    /// check added in 0061 did not, and counted a denominator of comparisons that cannot
    /// fail. Measured (0076): the composition, intent and store-location corpora contain
    /// ZERO const-tnum states with a printed bound, so that check's honest denominator on
    /// a modern capture is nil.
    #[serde(default)]
    pub bounds_from_log: bool,
}

/// Registers of interest at one instruction index — a snapshot in the evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegSnapshot {
    /// Instruction index this snapshot was taken at.
    pub insn_idx: u32,
    /// Register states of interest at this point.
    pub regs: Vec<RegState>,
}

/// Processed-work counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Processed {
    /// `insn_processed` reported by the verifier.
    pub insn_processed: u64,
    /// Number of verifier states processed.
    pub states_processed: u64,
}

/// JIT vs interpreter divergence for one program run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JitInterpDiff {
    /// Return value under the JIT.
    pub retval_jit: i64,
    /// Return value under the interpreter.
    pub retval_interp: i64,
    /// Whether the `data_out` buffers matched.
    pub data_out_equal: bool,
}

/// KCOV coverage delta for one exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoverageDelta {
    /// New basic blocks covered by this exec.
    pub new_bb: u64,
    /// The exec counter N at which this was observed (provenance).
    pub exec_n: u64,
}

/// One helper-call argument OBSERVATION: which helper, which argument, and the
/// verifier reg-type family observed for it at the call site (e.g. "map_ptr",
/// "fp", "scalar"). PURE observation — the EXPECTED `arg_type` is deliberately
/// NOT stored here; it lives in ground truth (`bpf_func_proto`), so a mismatch is
/// DECIDED at `diff`, never pre-baked into CORE. This is the real-path counterpart
/// of the (legacy, synthetic) [`HelperArgViolation`] which carried its own expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperArgObservation {
    /// Helper name, verbatim (e.g. "bpf_map_lookup_elem").
    pub helper: String,
    /// Argument index (0-based; arg N is register R(N+1)).
    pub arg_index: u8,
    /// Observed verifier reg-type family for this argument.
    pub observed: String,
}

/// Helper `arg_type` contract-violation signal (from `bpf_func_proto` checks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperArgViolation {
    /// Helper name (or id), verbatim.
    pub helper: String,
    /// Argument index that violated its contract.
    pub arg_index: u8,
    /// Expected `arg_type`, verbatim.
    pub expected: String,
    /// Observed `arg_type`, verbatim.
    pub observed: String,
}

/// One CORE observation for a single verifier invocation / fuzzing exec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMetrics {
    /// accept/reject + reason.
    pub verifier_decision: VerifierDecision,
    /// Register-state evolution (per-insn snapshots).
    pub register_evolution: Vec<RegSnapshot>,
    /// insn_processed / states processed.
    pub processed: Processed,
    /// JIT<->interpreter retval + data_out diff (absent if not run).
    pub jit_interp_diff: Option<JitInterpDiff>,
    /// KCOV coverage delta + exec counter N.
    pub coverage_delta: CoverageDelta,
    /// Helper arg_type contract violations (zero or more). LEGACY / synthetic path
    /// (carries its own expected); the real path uses `helper_arg_observations`.
    pub helper_arg_violations: Vec<HelperArgViolation>,
    /// Helper-call argument observations from the real verifier log. Expected
    /// arg_type comes from ground truth, so mismatches are decided at `diff`.
    /// Skipped when empty so existing artifacts stay byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub helper_arg_observations: Vec<HelperArgObservation>,
    /// Runtime ground-truth samples from BPF_PROG_TEST_RUN: for each attacker-
    /// controlled input, the ACTUAL value the program returned. The diff stage
    /// checks each retval against the verifier's own proven bound on the return
    /// register — a violation is a soundness bug caught WITHOUT trusting the
    /// verifier log to be self-consistent. Skipped when empty so existing
    /// artifacts stay byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_samples: Vec<RuntimeSample>,
    /// What the program is SUPPOSED to return, declared by the generator from the
    /// program's own semantics — never read out of the verifier log.
    ///
    /// Every other oracle here uses the verifier's own printed claim as its reference, so
    /// none of them can see a bug that makes the verifier WRONG in a self-consistent way.
    /// Devlog 0070 measured the sharpest case: when the verifier resolves a branch on a
    /// corrupted constant, `bpf_opt_hard_wire_dead_code_branches()` removes the other side
    /// from the emitted program, so the runtime then agrees with the wrong proof and the
    /// retval check passes. The reference has to come from outside the verifier, and for a
    /// closed-form generated program the generator already knows it.
    ///
    /// `None` means the generator made no claim — most families cannot, and a fabricated
    /// expectation would be worse than none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_retval: Option<u64>,
    /// Whether the program reaches its exit along MORE THAN ONE path, declared by the
    /// generator.
    ///
    /// It decides whether one oracle's precondition holds. `check_runtime_ground_truth`
    /// compares an observed return value against the union of the r0 states the verifier
    /// PRINTED — but the verifier prints a state only when it scratches registers, and on
    /// a multi-path program the printed set is a strict SUBSET of what it proved. The
    /// union is then narrower than the real claim, and a perfectly sound program is
    /// reported. Measured on --gen-intent (0074): one program's log carried a single
    /// `R0=0xffffffff` for the path it annotated, while the runtime legitimately returned
    /// 0 along another.
    ///
    /// `None` keeps the historical behaviour, so the single-path families this oracle was
    /// built for are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_path: Option<bool>,
    /// Where the program's store instruction is, declared by the GENERATOR that
    /// built the program (not read out of the verifier log). Knowing which
    /// instruction stores, and through which register, is a fact about the program
    /// we wrote; it lets the diff stage look up the verifier's proven state for
    /// that pointer AT that instruction and compare it with where the store
    /// actually landed. Skipped when absent so existing artifacts stay
    /// byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_site: Option<StoreSite>,
    /// The pruning-soundness differential for this program, when the harness ran one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune_probe: Option<PruneProbe>,
    /// The register-liveness GATE on state equality, from two independent sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_gate: Option<LivenessGate>,
}

/// Register liveness at each instruction — the gate `func_states_equal` applies before it
/// compares anything (`states.c`: `if (((1 << i) & live_regs) && !regsafe(...))`). A
/// register the verifier calls dead is never compared, so a wrong liveness is a prune that
/// never had to justify itself.
///
/// Two independent sources are carried side by side and never merged: the kernel's own
/// printed table and the harness's `bpflive.h` recomputation from the EMITTED instruction
/// bytes. Masks use bit j for r_j, r0..r9 — r10 is the frame pointer and the kernel does
/// not track it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessGate {
    /// The harness's own analysis, one mask per instruction index. `None` when the harness
    /// declared the program outside its model rather than guessing at it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Vec<u16>>,
    /// The harness's status verbatim (`ok`, or `unsupported: <why>`), so an absent claim is
    /// always distinguishable from a claim that was never emitted.
    pub claim_status: String,
    /// The kernel's `live_regs_before`, as (insn_idx, mask). Sparse: the table skips the
    /// second slot of an LD_IMM64, exactly as `liveness.c` prints it.
    pub kernel: Vec<(u32, u16)>,
}

/// The store instruction's coordinates, declared by the program generator.
///
/// This is deliberately NOT parsed out of the disassembly: the harness built the
/// program, so it knows the store's index, base register and immediate offset as
/// ground truth about the INPUT. Reading them back out of the verifier's own
/// output would make the oracle depend on the thing it is auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSite {
    /// Index of the store instruction.
    pub insn_idx: u32,
    /// Base pointer register the store goes through.
    pub base_reg: u8,
    /// The store instruction's own immediate offset (`*(u8 *)(r7 + off)`).
    pub insn_off: i64,
    /// Store width in bytes.
    pub size: u32,
}

/// One runtime observation: the program was executed via BPF_PROG_TEST_RUN with a
/// chosen attacker-controlled `input`, and returned `retval` (the low 32 bits of
/// the return register). `error` marks a sample the harness could not run (the
/// diff stage never treats an errored sample as a violation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSample {
    /// The attacker-controlled input fed to the program (a 32-bit map value).
    pub input: u64,
    /// The value the program actually returned (retval, low 32 bits).
    pub retval: u64,
    /// Whether a return value was actually OBSERVED for this sample.
    ///
    /// Most families print `store_off=` and no `retval=` at all, because the store
    /// location is their signal. `retval` then defaults to 0, which is indistinguishable
    /// from a program that really returned 0 — the same "absence read as an observed zero"
    /// that produced ten false OOB findings in 0041, arriving from a new direction. Any
    /// check that consumes `retval` must gate on this flag.
    #[serde(default)]
    pub retval_observed: bool,
    /// What THIS sample's input should produce, when the generator can say so per-input.
    ///
    /// The record-level `CoreMetrics::intended_retval` covers a program with one answer;
    /// a family that sweeps inputs has a different answer per input, so the claim belongs
    /// on the sample. When both are present this one wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_retval: Option<u64>,
    /// For a STORE program: the offset inside the map value where the sentinel
    /// actually landed, or `Some(-1)` if it was absent (the store went out of the
    /// readable value — an OOB write). `None` for return-value samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_off: Option<i64>,
    /// For a multi-byte STORE (--gen-rtw2): the length of the consecutive sentinel
    /// run actually observed inside the value. A run shorter than `store_size` means
    /// some sentinel bytes fell outside the value — a PARTIAL OOB write. `None` for
    /// the single-byte --gen-rtw family (which reports presence via `store_off`
    /// alone) and for return-value samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_len: Option<i64>,
    /// For a multi-byte STORE (--gen-rtw2): the store's width in bytes (the number
    /// of sentinel bytes it should have written). The write is memory-safe iff
    /// `store_len == store_size`. `None` for the single-byte family and return-value
    /// samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_size: Option<i64>,
    /// For a STORE program whose store sits behind a BRANCH (--gen-loc's `jmp` arm):
    /// whether this run actually REACHED the store, reported by the program itself
    /// (it returns a distinct value on the storing path). This disambiguates the two
    /// readings of `store_off = none`: with `Some(true)` the store ran and its bytes
    /// are not in the value — an OOB write; with `Some(false)` the store never ran,
    /// so there is nothing to judge. `None` for families whose store is
    /// unconditional (--gen-rtw / --gen-rtw2 / --gen-pktw), where absence can only
    /// mean OOB and the older reading stands unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed: Option<bool>,
    /// True if the harness could not execute this sample (skipped by the oracle).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub error: bool,
}

/// One PRUNING-SOUNDNESS differential (--gen-prune): the SAME program loaded three
/// times, and what the kernel said each time. This is a kernel-vs-kernel oracle —
/// nothing here is a bound we parsed or a value we computed, so there is no oracle of
/// ours that can be wrong; the only question is whether the verifier agrees with
/// itself when its own pruning frequency changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneProbe {
    /// The offset shaper on the FALL-THROUGH path — explored first, so this is the
    /// state that records the checkpoint the other path is then judged against.
    pub fall: String,
    /// The offset shaper on the branch-taken path — the one that may be pruned.
    pub taken: String,
    /// Whether the deciding store is in bounds under each path's range. The correct
    /// verdict is accept iff BOTH are safe: a wrong prune of an unsafe path is what
    /// would turn a reject into an accept.
    pub fall_safe: bool,
    pub taken_safe: bool,
    /// Whether the two states differ in a STACK SLOT rather than a register, i.e.
    /// whether `stacksafe` or `regsafe` is the judge.
    pub stack: bool,
    /// Default load: no flags.
    pub base_accept: bool,
    pub base_errno: i64,
    pub base_states: u64,
    pub base_reason: String,
    /// BPF_F_TEST_STATE_FREQ: a checkpoint at EVERY instruction, so pruning is
    /// attempted far more often than the default heuristic allows.
    pub freq_accept: bool,
    pub freq_errno: i64,
    pub freq_states: u64,
    /// Why the flagged load rejected: `verdict` (the verifier decided) vs
    /// `too_large` / `too_many_states` (a resource limit the extra checkpoints
    /// pushed it into) vs `efault` vs `none`. The distinction is what keeps the
    /// reverse direction of the differential out of the finding count.
    pub freq_reason: String,
    /// BPF_F_TEST_REG_INVARIANTS: the kernel's own bounds sanity check
    /// (`reg_bounds_sanity_check`) promoted from a warn-and-recover to a hard
    /// -EFAULT. Accepting by default but faulting under this flag is a desync
    /// that is invisible from outside the kernel.
    pub inv_accept: bool,
    pub inv_errno: i64,
    pub inv_reason: String,
}
