"""Scenario D: Merkle file-integrity create/modify/delete inside the lab tree."""

from __future__ import annotations

import time
from pathlib import Path

from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    dirs = session_dirs(session)
    base = dirs["integrity"]
    tracked = base / "tracked.txt"
    created = base / "created-later.txt"
    result = ScenarioResult(
        name="integrity",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["SYNTHETIC_LAB_FIXTURE"],
        behavior=[
            "Seed integrity files for an initial Merkle baseline",
            "Modify one file, create another, delete a third",
            "Allow IntegrityMonitor to re-hash and report root/file changes",
        ],
        collectors=["IntegrityMonitor (Merkle SHA-256 over lab integrity path)"],
        expected_rules=[],
        expected_modules=["integrity"],
        notes=[
            "Only files under the lab integrity directory are watched.",
            "Dashboard: s → integrity (FI* findings, coverage, baseline status).",
        ],
        grade_hint="expect FI* findings after the second integrity scan",
        evidence={"directory": str(base)},
    )
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    tracked.write_text("baseline content v1\n", encoding="utf-8")
    doomed = base / "will-delete.txt"
    doomed.write_text("delete me\n", encoding="utf-8")
    # Allow baseline-created scan.
    time.sleep(9.0)
    tracked.write_text("baseline content v2 — modified\n", encoding="utf-8")
    created.write_text("new file after baseline\n", encoding="utf-8")
    doomed.unlink(missing_ok=True)
    time.sleep(9.0)
    result.evidence.update(
        {
            "modified": str(tracked),
            "created": str(created),
            "deleted": str(doomed),
        }
    )
    result.status = "completed"
    result.ended_at = now_iso()
    return result
