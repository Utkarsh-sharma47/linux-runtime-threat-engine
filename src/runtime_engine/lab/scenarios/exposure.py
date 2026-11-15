"""Scenario E: unexpected SUID fixture for the exposure analyzer (lab-only)."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    dirs = session_dirs(session)
    tool = dirs["exposure"] / "unexpected-suid"
    result = ScenarioResult(
        name="exposure",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["SYNTHETIC_LAB_FIXTURE"],
        behavior=[
            "Place an unexpected SUID binary under the lab exposure scan path",
            "Let ExposureAnalyzer report posture findings without weakening the host",
        ],
        collectors=["ExposureAnalyzer"],
        expected_rules=[],
        expected_modules=["exposure"],
        notes=[
            "Lab config sets expected_suid: [] for lab paths so any SUID is unexpected.",
            "Does not modify real /usr binaries or host hardening.",
            "Dashboard: s → exposure.",
        ],
        grade_hint="expect EX001 (or related) for unexpected SUID in the lab path",
        evidence={"suid_fixture": str(tool)},
    )
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    shutil.copy2("/bin/true", tool)
    os.chmod(tool, 0o4755)
    time.sleep(13.0)
    result.status = "completed"
    result.ended_at = now_iso()
    return result
