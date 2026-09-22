"""Expectation flag (mirror of crates/metrics/src/expectation.rs).

The "did the loop expect this?" field — measures confirmation bias, kept separate
from raw core observation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Expectation(str, Enum):
    """JSON values match the Rust `Expectation` enum (snake_case)."""

    NO_PREDICTION = "no_prediction"
    EXPECTED = "expected"
    UNEXPECTED = "unexpected"


@dataclass
class ExpectationFlag:
    expected: Expectation = Expectation.NO_PREDICTION
    predicted: Optional[str] = None
