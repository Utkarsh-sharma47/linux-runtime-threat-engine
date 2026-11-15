"""Scenario H: Atomic Red Team — inspect + optional approved offline run (not in --scenario all)."""

from __future__ import annotations

import json
from pathlib import Path

from runtime_engine.atomic import preflight
from runtime_engine.atomic.profiles import load_profiles
from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso

# Benign, risk-A profile used for demonstration inspect (and optional approved run).
DEFAULT_TECHNIQUE = "T1059.004"
DEFAULT_TEST = 8


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    """By default only inspects. Set RTE_LAB_ATOMIC_APPROVE=<token> to execute offline."""
    import os

    dirs = session_dirs(session)
    result = ScenarioResult(
        name="atomic",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["ATOMIC_EXECUTION_EVIDENCE"],
        behavior=[
            f"Inspect Atomic {DEFAULT_TECHNIQUE} #{DEFAULT_TEST}",
            "Display risk, exact commands, cleanup, and expectation profile",
            "Execute only when RTE_LAB_ATOMIC_APPROVE matches the inspect token",
        ],
        collectors=["atomic/strace offline runner (not the live TUI by itself)"],
        expected_rules=[],
        expected_modules=[],
        notes=[
            "Not included in --scenario all.",
            "Offline Atomic evaluation is not the live monitor. "
            "For live TUI visibility use process/network scenarios.",
            "LiveAtomicBridge remains available for synthetic live-accept demos.",
        ],
        evidence={"technique": DEFAULT_TECHNIQUE, "test_number": DEFAULT_TEST},
    )
    profiles = load_profiles()
    env = preflight.environment(Path.home() / "AtomicRedTeam" / "atomics")
    pre = preflight.check(env, DEFAULT_TECHNIQUE, DEFAULT_TEST, profiles, {})
    inspect_path = dirs["evidence"] / "atomic-inspect.json"
    payload = pre.as_dict()
    inspect_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    result.evidence["inspect"] = str(inspect_path)
    result.evidence["token"] = pre.token
    result.evidence["risk"] = payload.get("risk")
    result.evidence["command"] = payload.get("command")
    result.notes.append(f"Approval token: {pre.token}")
    result.notes.append(f"Exact command: {payload.get('command')}")

    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    approve = os.environ.get("RTE_LAB_ATOMIC_APPROVE", "").strip()
    if not approve:
        result.status = "completed"
        result.grade_hint = "INSPECTED_ONLY"
        result.notes.append(
            "No RTE_LAB_ATOMIC_APPROVE set — inspect only. "
            f"To run offline: RTE_LAB_ATOMIC_APPROVE={pre.token} "
            f"./scripts/run-security-lab.sh --scenario atomic"
        )
        result.ended_at = now_iso()
        return result
    if approve != pre.token:
        result.status = "failed"
        result.notes.append("RTE_LAB_ATOMIC_APPROVE did not match the inspect token — refused")
        result.ended_at = now_iso()
        return result
    if pre.refusals:
        result.status = "failed"
        result.notes.extend(pre.refusals)
        result.ended_at = now_iso()
        return result

    from runtime_engine.atomic import analysis, runner
    from runtime_engine.config.settings import Settings
    from runtime_engine.detection.rule_loader import load_rules

    run_dir = runner.execute(pre, settings=Settings(), results=dirs["evidence"] / "atomic-runs")
    evaluation = analysis.analyze(run_dir, load_rules(), Settings(), profiles)
    result.evidence["run_dir"] = str(run_dir)
    result.evidence["evaluation_grade"] = evaluation.get("overall", {}).get("grade")
    result.provenance = ["ATOMIC_EXECUTION_EVIDENCE"]
    result.status = "completed"
    result.ended_at = now_iso()
    result.notes.append(
        "Offline Atomic run completed. Open atomic report under evidence/; "
        "live TUI Atomic sessions page is for LiveAtomicBridge sessions."
    )
    return result
