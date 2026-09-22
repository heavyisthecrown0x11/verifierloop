"""COUNTERFACTUAL layer (mirror of crates/metrics/src/counterfactual.rs).

Opt-in; sits ON TOP of core and never mutates it. MUST NOT feed back into fuzzer
input selection (confirmation-bias guardrail).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CounterfactualLayer:
    enabled: bool = False
    alternatives: list = field(default_factory=list)
