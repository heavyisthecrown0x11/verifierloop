"""DERIVED metrics (mirror of crates/metrics/src/derived.rs).

Schema fixed now; values fill as the loop grows. Never a decision criterion.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DerivedMetrics:
    # REPORT-ONLY efficiency observation (new coverage / new state per exec).
    efficiency_per_exec: Optional[float] = None
    record_count: int = 0
