"""Security-lab orchestrator, isolation, cleanup and provenance tests.

Uses temporary directories and fake status — never runs real Atomic attacks.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from runtime_engine.lab import cleanup as lab_cleanup
from runtime_engine.lab import orchestrator
from runtime_engine.lab.paths import (
    MARKER_NAME,
    LabPathError,
    create_session_tree,
    ensure_lab_root,
    lab_root,
    status_path,
    validate_under_lab_root,
)
from runtime_engine.lab.session import prepare_session
from runtime_engine.lab.status import read_status, write_status
from runtime_engine.monitor.state import DashboardState
from runtime_engine.terminal.dashboard import lab_status_line, render_dashboard

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "terminal"))
from terminal_helpers import make_info, render  # noqa: E402


@pytest.fixture
def isolated_lab(tmp_path, monkeypatch):
    """Point the lab root under a pytest tempdir instead of system /tmp."""
    fake_tmp = tmp_path / "tmp"
    fake_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(fake_tmp))
    monkeypatch.setattr("runtime_engine.lab.paths.tempfile.gettempdir", lambda: str(fake_tmp))
    monkeypatch.setattr(
        "runtime_engine.security.ransomware_sim.tempfile.gettempdir", lambda: str(fake_tmp)
    )
    # Clear any env from prior runs.
    monkeypatch.delenv("RTE_LAB_STATUS", raising=False)
    return fake_tmp


def test_argument_parsing_list_and_scenarios():
    args = orchestrator.parse_args(["--list"])
    assert args.list is True
    args = orchestrator.parse_args(["--scenario", "process", "--scenario", "network", "--dry-run"])
    assert args.dry_run and args.scenarios == ["process", "network"]
    assert orchestrator.resolve_scenario_names(["all"]) == list(orchestrator.SAFE_ALL)
    with pytest.raises(SystemExit):
        orchestrator.resolve_scenario_names(["not-a-scenario"])


def test_lab_isolation_rejects_escape(isolated_lab):
    ensure_lab_root()
    outside = isolated_lab / "escape"
    outside.mkdir()
    with pytest.raises(LabPathError):
        validate_under_lab_root(outside)
    session = lab_root() / "lab-test"
    create_session_tree(session)
    assert (session / MARKER_NAME).is_file()
    assert session.is_relative_to(lab_root())


def test_prepare_session_writes_config_and_status(isolated_lab):
    session, config, ransom, status = prepare_session("lab-unit")
    assert session.name == "lab-unit"
    assert config.is_file()
    assert status.session_id == "lab-unit"
    loaded = read_status(status_path(session))
    assert loaded is not None and loaded.phase == "idle"
    text = config.read_text(encoding="utf-8")
    assert "include_loopback: true" in text
    assert str(session / "cron") in text
    assert ransom.name.startswith("rte-ransomware-lab")


def test_dry_run_orchestration(isolated_lab, capsys):
    prepare_session("lab-dry")
    code = orchestrator.main(
        ["--dry-run", "--skip-monitor-check", "--scenario", "process", "--scenario", "anomaly"]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "scenario: process" in out and "dry-run" in out
    status = read_status()
    assert status is not None and status.phase == "completed"
    assert status.scenarios["process"]["status"] == "dry-run"
    assert "SYNTHETIC_LAB_FIXTURE" in status.scenarios["anomaly"]["provenance"]


def test_process_scenario_creates_lab_binary(isolated_lab):
    from runtime_engine.lab.scenarios import process

    session, _, _, status = prepare_session("lab-proc")
    result = process.run(session, status, dry_run=False)
    assert result.status == "completed"
    assert (session / "bin" / "lab-worker").is_file()
    assert "REAL_HOST_TELEMETRY" in result.provenance
    assert "RT002" in result.expected_rules


def test_cleanup_safety_and_confirmation(isolated_lab, monkeypatch):
    session, _, ransom, _ = prepare_session("lab-clean")
    marker = session / "bin" / "keep-me"
    marker.write_text("x", encoding="utf-8")
    # Refuse without yes / DELETE
    monkeypatch.setattr("builtins.input", lambda _: "no")
    refused = lab_cleanup.cleanup_session(session, preserve_reports=False, yes=False)
    assert refused == 1
    assert session.exists()
    # Accept with --yes
    assert lab_cleanup.cleanup_session(session, preserve_reports=False, yes=True) == 0
    assert not session.exists()
    assert not ransom.exists()


def test_cleanup_refuses_paths_outside_lab(isolated_lab, tmp_path):
    outsider = tmp_path / "not-lab"
    outsider.mkdir()
    with pytest.raises(LabPathError):
        lab_cleanup.cleanup_session(outsider, preserve_reports=False, yes=True)


def test_status_provenance_and_dashboard_panel(isolated_lab):
    session, _, _, status = prepare_session("lab-dash")
    os.environ["RTE_LAB_STATUS"] = str(status_path(session))
    status.phase = "running"
    status.current_scenario = "network"
    status.scenarios["network"] = {
        "name": "network",
        "status": "completed",
        "provenance": ["REAL_HOST_TELEMETRY"],
    }
    write_status(status)
    state = DashboardState(make_info())
    snap = state.snapshot(log_limit=0)
    assert snap.lab_status is not None
    assert snap.lab_status["session_id"] == "lab-dash"
    text = render(lab_status_line(snap.lab_status, snap.counters, 0))
    assert "SECURITY LAB" in text and "network" in text
    dash = render(render_dashboard(snap, 160, 45), 160, 45)
    assert "SECURITY LAB" in dash


def test_interrupted_phase_recorded(isolated_lab):
    session, _, _, status = prepare_session("lab-int")
    status.phase = "interrupted"
    status.message = "Interrupted by operator"
    write_status(status, status_path(session))
    loaded = read_status(status_path(session))
    assert loaded is not None and loaded.phase == "interrupted"


def test_evidence_summary_written(isolated_lab):
    prepare_session("lab-ev")
    orchestrator.main(["--dry-run", "--skip-monitor-check", "--scenario", "all", "--json"])
    session = lab_root() / "lab-ev"
    summary = json.loads((session / "evidence" / "summary.json").read_text(encoding="utf-8"))
    assert summary["dry_run"] is True
    assert len(summary["scenarios"]) == len(orchestrator.SAFE_ALL)
