"""Scenario G: safe ransomware simulator in a dedicated temp lab directory."""

from __future__ import annotations

import time
from pathlib import Path

from runtime_engine.lab.paths import ransomware_lab_path
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso
from runtime_engine.security import ransomware_sim


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    lab = ransomware_lab_path(session.name)
    result = ScenarioResult(
        name="ransomware",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["SYNTHETIC_LAB_FIXTURE"],
        behavior=[
            "Create a dedicated rte-ransomware-lab* directory under system temp",
            "Run the built-in safe simulator (XOR dummy files — no real encryption)",
            "Let RansomwareMonitor watch that directory for RW001 behavioural indicators",
        ],
        collectors=["RansomwareMonitor"],
        expected_rules=[],
        expected_modules=["ransomware"],
        notes=[
            "Simulator refuses paths outside <tmp>/rte-ransomware-lab*.",
            "Never touches home directories or user documents.",
            "Dashboard: s → ransomware.",
        ],
        grade_hint="expect RW001 when modification/rename/entropy thresholds are met",
        evidence={"ransomware_lab": str(lab)},
    )
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    ransomware_sim.create_lab(str(lab))
    # Brief pause so the monitor can attach watches if it just started.
    time.sleep(1.5)
    stats = ransomware_sim.simulate(lab, files=40, delay=0.02)
    result.evidence["simulator"] = stats
    time.sleep(3.0)
    result.status = "completed"
    result.ended_at = now_iso()
    return result
