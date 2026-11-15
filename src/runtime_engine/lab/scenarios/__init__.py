"""Security-lab scenario runners. Each generates real activity or isolated fixtures."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from runtime_engine.lab.scenarios import (
    anomaly,
    atomic,
    exposure,
    integrity,
    network,
    persistence,
    process,
    ransomware,
)
from runtime_engine.lab.status import LabStatus, ScenarioResult

ScenarioFn = Callable[[Path, LabStatus, bool], ScenarioResult]

SCENARIOS: dict[str, ScenarioFn] = {
    "process": process.run,
    "network": network.run,
    "persistence": persistence.run,
    "integrity": integrity.run,
    "exposure": exposure.run,
    "anomaly": anomaly.run,
    "ransomware": ransomware.run,
    "atomic": atomic.run,
}

# Safe default set for --scenario all (no real Atomic execution).
SAFE_ALL = (
    "process",
    "network",
    "persistence",
    "integrity",
    "exposure",
    "anomaly",
    "ransomware",
)

__all__ = ["SAFE_ALL", "SCENARIOS", "ScenarioFn"]
