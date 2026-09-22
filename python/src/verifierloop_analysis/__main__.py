"""CLI entry for the analysis side. Invoked by the Rust `score` stage.

Usage: python -m verifierloop_analysis --period-dir <period_dir>

Reads the NORMALIZED artifact from the period dir, computes anomaly scores, and
writes the ANOMALY_SCORES artifact back — the Python half of the file-based
Rust<->Python contract.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import contract as c
from .scoring import score_normalized


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(prog="verifierloop_analysis")
    parser.add_argument(
        "--period-dir",
        required=True,
        help="period directory containing normalized_metrics.json",
    )
    ns = parser.parse_args(argv)
    period_dir = Path(ns.period_dir)

    normalized = c.read_artifact(period_dir / c.NORMALIZED)
    payload = score_normalized(normalized.payload)
    art = c.Artifact(
        period_id=normalized.period_id,
        producer=c.Producer.SCORE,
        payload=payload,
    )
    c.write_artifact(period_dir / c.ANOMALY_SCORES, art)
    print(
        "wrote %s (flagged=%d/%d, method=%s)"
        % (
            period_dir / c.ANOMALY_SCORES,
            payload["summary"]["flagged"],
            payload["summary"]["record_count"],
            payload["method"],
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
