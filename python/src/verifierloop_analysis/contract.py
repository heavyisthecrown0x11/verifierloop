"""File-based JSON artifact contract — Python mirror of the Rust `contract` crate.

Kept in lockstep with crates/contract/src/lib.rs: same envelope fields, the same
`Producer` string values, the same on-disk layout, and the same schema-version
check. Rust owns orchestration and writes the inputs; Python (this side) reads
them and writes anomaly scores back. The payload is left untyped (JSON) while the
metric payload types are still `Tbd`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

# On-disk envelope schema version. Must equal the Rust crate's CONTRACT_VERSION.
CONTRACT_VERSION = 1

# Canonical file names inside a period directory (mirror of Rust `filenames`).
RAW_INDEX = "raw/index.json"
NORMALIZED = "normalized_metrics.json"
ANOMALY_SCORES = "anomaly_scores.json"
DIFF_FINDINGS = "diff_findings.json"
PERIOD_REPORT = "period_report.json"


class Producer(str, Enum):
    """Which pipeline stage / language side produced an artifact.

    Values are the snake_case strings the Rust `Producer` enum serializes to.
    """

    INGEST = "ingest"
    NORMALIZE = "normalize"
    SCORE = "score"
    DIFF = "diff"
    REPORT = "report"


class ContractVersionError(ValueError):
    """Raised when a file's contract_version does not match CONTRACT_VERSION."""

    def __init__(self, found: Any, expected: int) -> None:
        super().__init__(
            f"contract version mismatch: file is v{found}, this build expects v{expected}"
        )
        self.found = found
        self.expected = expected


@dataclass
class PeriodPaths:
    """Resolves on-disk artifact paths for one period. Mirror of Rust PeriodPaths.

    Layout: ``<data_root>/periods/<period_id>/<artifact>``.
    """

    root: Path
    period_id: int

    @classmethod
    def new(cls, data_root: os.PathLike | str, period_id: int) -> "PeriodPaths":
        return cls(root=Path(data_root) / "periods" / str(period_id), period_id=period_id)

    def artifact(self, name: str) -> Path:
        return self.root / name

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def raw_index(self) -> Path:
        return self.artifact(RAW_INDEX)

    def normalized(self) -> Path:
        return self.artifact(NORMALIZED)

    def anomaly_scores(self) -> Path:
        return self.artifact(ANOMALY_SCORES)

    def diff_findings(self) -> Path:
        return self.artifact(DIFF_FINDINGS)

    def period_report(self) -> Path:
        return self.artifact(PERIOD_REPORT)


@dataclass
class Artifact:
    """Envelope wrapping any payload with provenance + schema version."""

    period_id: int
    producer: Producer
    payload: Any
    contract_version: int = CONTRACT_VERSION


def read_artifact(path: os.PathLike | str) -> Artifact:
    """Read + version-check an artifact from disk."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    found = data.get("contract_version")
    if found != CONTRACT_VERSION:
        raise ContractVersionError(found, CONTRACT_VERSION)
    return Artifact(
        period_id=data["period_id"],
        producer=Producer(data["producer"]),
        payload=data["payload"],
        contract_version=found,
    )


def write_artifact(path: os.PathLike | str, artifact: Artifact) -> None:
    """Write an artifact as pretty JSON, atomically (tmp sibling + os.replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    producer = artifact.producer
    obj = {
        "contract_version": artifact.contract_version,
        "period_id": artifact.period_id,
        "producer": producer.value if isinstance(producer, Producer) else producer,
        "payload": artifact.payload,
    }
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
