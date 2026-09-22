"""Anomaly scoring — Python owns the statistics.

GUARDRAIL: scores RANK records for human triage at the period boundary. They MUST
NOT feed back into fuzzer input selection (confirmation-bias guardrail).

Baseline method ("baseline-hard-signals-v0"): transparent, rule-based hard signals
derived straight from CORE — no training data, deterministic. These are the actual
verifier-bug indicators:
  * JIT <-> interpreter divergence (retval mismatch or data_out mismatch).
  * helper arg_type contract violation.
TODO(scoring): add a statistical outlier component (z-score / IQR over numeric
CORE fields across the period) as a follow-up method.
"""
from __future__ import annotations

from typing import Any

METHOD = "baseline-hard-signals-v0"
FLAG_THRESHOLD = 0.5


def score_normalized(normalized: dict) -> dict:
    """Score a NORMALIZED payload (dict) -> an ANOMALY_SCORES payload (dict).

    Reads raw observation only; never generates or consumes counterfactuals.
    """
    records = normalized.get("records", [])
    scored: list[dict[str, Any]] = []
    max_score = 0.0
    flagged = 0

    for i, rec in enumerate(records):
        core = rec.get("core", {})
        score = 0.0
        reasons: list[str] = []

        # Hard signal: JIT <-> interpreter divergence.
        jid = core.get("jit_interp_diff")
        if jid is not None:
            if jid.get("retval_jit") != jid.get("retval_interp"):
                score = max(score, 0.95)
                reasons.append(
                    "jit/interp retval divergence (jit=%s interp=%s)"
                    % (jid.get("retval_jit"), jid.get("retval_interp"))
                )
            if not jid.get("data_out_equal", True):
                score = max(score, 0.95)
                reasons.append("jit/interp data_out mismatch")

        # Hard signal: helper arg_type contract violation.
        for v in core.get("helper_arg_violations", []) or []:
            score = max(score, 0.85)
            reasons.append(
                "helper arg_type violation: %s arg%s expected %s observed %s"
                % (v.get("helper"), v.get("arg_index"), v.get("expected"), v.get("observed"))
            )

        scored.append({"index": i, "score": round(score, 4), "reasons": reasons})
        max_score = max(max_score, score)
        if score >= FLAG_THRESHOLD:
            flagged += 1

    return {
        "exec_count": normalized.get("exec_count", 0),
        "scored": scored,
        "summary": {
            "record_count": len(records),
            "flagged": flagged,
            "max_score": round(max_score, 4),
        },
        "method": METHOD,
    }
