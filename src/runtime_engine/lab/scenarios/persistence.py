"""Scenario C: isolated cron/systemd/SUID fixtures under the lab temp tree."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    dirs = session_dirs(session)
    cron = dirs["cron"] / "lab-job"
    unit = dirs["systemd"] / "rte-lab.service"
    suid = dirs["privileged"] / "lab-suid-tool"
    result = ScenarioResult(
        name="persistence",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["SYNTHETIC_LAB_FIXTURE"],
        behavior=[
            "Create a cron-like file under the lab cron_paths directory",
            "Create a systemd-like unit file under the lab systemd_paths directory",
            "Copy a binary and set the SUID bit inside the lab privileged_dirs path",
        ],
        collectors=["PersistenceMonitor (configured lab paths only)"],
        expected_rules=[],
        expected_modules=["persistence"],
        notes=[
            "All paths are under the lab temp root — real /etc persistence is never touched.",
            "Evidence is labeled SYNTHETIC_LAB_FIXTURE.",
            "First module scan may create a baseline; a second scan after changes finds diffs.",
            "Dashboard: s → persistence.",
        ],
        grade_hint="expect PM001/PM002/PM005 (or similar) after the module's next scan",
        evidence={
            "cron": str(cron),
            "unit": str(unit),
            "suid": str(suid),
        },
    )
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    # Wait so an initial empty baseline can be recorded if the monitor just started.
    time.sleep(2.0)
    cron.write_text(
        "# SYNTHETIC LAB FIXTURE — not installed into system cron\n"
        "* * * * * root /tmp/rte-security-lab/does-not-run\n",
        encoding="utf-8",
    )
    unit.write_text(
        "# SYNTHETIC LAB FIXTURE — not a real systemd unit\n"
        "[Unit]\nDescription=RTE lab fixture\n"
        "[Service]\nExecStart=/bin/true\n",
        encoding="utf-8",
    )
    shutil.copy2("/bin/true", suid)
    os.chmod(suid, 0o4755)
    # Give the persistence module time for a scan after the change.
    time.sleep(10.0)
    result.status = "completed"
    result.ended_at = now_iso()
    result.notes.append(
        "If the monitor was started with the lab config, PersistenceMonitor scanned these paths."
    )
    return result
