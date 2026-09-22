"""CORE metrics (mirror of crates/metrics/src/core.rs) — FROZEN schema.

Fixed, raw operational observation. Always on. INDEPENDENT of the counterfactual
layer. `reg_type` and reject `reason` are verbatim strings.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Tnum:
    """tnum: known bit values + unknown-bit mask (kernel struct tnum)."""

    value: int = 0
    mask: int = 0


@dataclass
class RegState:
    reg: int
    reg_type: str  # verbatim verifier reg_type
    tnum: Tnum
    umin: int
    umax: int
    smin: int
    smax: int
    # The 32-bit subregister view. The verifier tracks a scalar twice and must keep
    # the two reconciled; a disagreement BETWEEN them is a bug class neither view
    # shows alone. None = the verifier omitted the field, which per
    # kernel/bpf/log.c:print_scalar_ranges() means it sits at its extreme — the
    # consumer resolves that, the parser only records the silence.
    u32_min: Optional[int] = None
    u32_max: Optional[int] = None
    s32_min: Optional[int] = None
    s32_max: Optional[int] = None


@dataclass
class RegSnapshot:
    insn_idx: int
    regs: "list[RegState]"


@dataclass
class Processed:
    insn_processed: int = 0
    states_processed: int = 0


@dataclass
class JitInterpDiff:
    retval_jit: int
    retval_interp: int
    data_out_equal: bool


@dataclass
class CoverageDelta:
    new_bb: int = 0
    exec_n: int = 0  # exec counter N (provenance)


@dataclass
class HelperArgObservation:
    # Real-path helper-call arg observation; expected comes from ground truth
    # (bpf_func_proto), NOT from CORE -> mismatch is decided at diff.
    helper: str
    arg_index: int
    observed: str


@dataclass
class HelperArgViolation:  # legacy / synthetic path (carries its own expected)
    helper: str
    arg_index: int
    expected: str
    observed: str


# NOTE: `verifier_decision` is a serde-tagged enum in JSON:
#   {"decision": "accept"}
#   {"decision": "reject", "reason": "<verbatim verifier text>"}
@dataclass
class CoreMetrics:
    verifier_decision: dict
    register_evolution: "list[RegSnapshot]"
    processed: Processed
    jit_interp_diff: Optional[JitInterpDiff]
    coverage_delta: CoverageDelta
    helper_arg_violations: "list[HelperArgViolation]"
    helper_arg_observations: "list[HelperArgObservation]" = None  # optional (skipped when empty)
