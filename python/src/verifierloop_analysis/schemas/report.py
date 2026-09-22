"""PERIOD_REPORT payload (mirror of crates/pipeline/src/report.rs) — FROZEN schema.

The triaged human-in-the-loop batch the `report` stage writes at the period
boundary. It JOINS ANOMALY_SCORES (score's ranking) with DIFF_FINDINGS (diff's
divergences); it carries no new score/severity of its own. `generated_unix` is a
timestamp LABEL only — never a stopping criterion. Kept in lockstep with Rust.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .diff import DivergenceFinding


@dataclass
class TriageItem:
    record_index: int
    score: float
    score_reasons: "list[str]"
    divergences: "list[DivergenceFinding]"


@dataclass
class ReportSummary:
    record_count: int = 0
    flagged: int = 0
    divergence_count: int = 0
    top_score: float = 0.0


@dataclass
class ParseHealth:
    # Parse-health accounting; kept separate from divergences.
    records: int = 0
    records_with_notes: int = 0
    unparsed_blocks: int = 0


@dataclass
class PeriodReport:
    exec_count: int
    generated_unix: Optional[int]  # label only, never a criterion
    items: "list[TriageItem]"      # ordered by score descending
    period_findings: "list[DivergenceFinding]"  # diff findings with record_index=None
    summary: ReportSummary = field(default_factory=ReportSummary)
    parse_health: ParseHealth = field(default_factory=ParseHealth)
