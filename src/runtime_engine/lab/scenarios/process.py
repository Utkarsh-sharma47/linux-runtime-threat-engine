"""Scenario A: process execution from a temp lab binary with parent/child ancestry."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    dirs = session_dirs(session)
    binary = dirs["bin"] / "lab-worker"
    result = ScenarioResult(
        name="process",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["REAL_HOST_TELEMETRY", "SYNTHETIC_LAB_FIXTURE"],
        behavior=[
            "Copy a real interpreter into the lab bin directory",
            "Launch it so the executable path is under the lab temp tree (/tmp/...)",
            "Spawn a short-lived child (sleep) to show parent/child ancestry",
        ],
        collectors=["ProcCollector"],
        expected_rules=["RT002"],
        expected_modules=[],
        notes=[
            "RT002 fires when executable_path is under /tmp (lab lives under system temp).",
            "Dashboard: p (process), t (tree), e (events), r (alerts), i (incidents).",
        ],
        grade_hint="expect RT002 if the process is still visible during a /proc poll",
    )
    cmd = [str(binary), "-c", "import time,os; time.sleep(6)"]
    result.evidence = {
        "binary": str(binary),
        "command": cmd,
        "provenance": "REAL_HOST_TELEMETRY (process) + SYNTHETIC_LAB_FIXTURE (binary location)",
    }
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result
    shutil.copy2("/usr/bin/python3", binary)
    os.chmod(binary, 0o755)
    child = subprocess.Popen(  # noqa: S603 — fixed inert sleep via lab-owned binary
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result.evidence["pid"] = child.pid
    status.active_processes = [f"lab-worker:{child.pid}"]
    # Keep the process alive long enough for at least one /proc poll.
    time.sleep(3.5)
    child.wait(timeout=10)
    result.status = "completed"
    result.ended_at = now_iso()
    result.notes.append(f"lab-worker exited with code {child.returncode}")
    return result
