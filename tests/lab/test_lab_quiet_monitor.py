"""Lab monitor must not invent incidents from ambient laptop activity."""

from __future__ import annotations

from pathlib import Path

import pytest

from runtime_engine.config.settings import ExposureSettings
from runtime_engine.detection.engine import DetectionEngine
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import EventType
from runtime_engine.lab.paths import lab_root
from runtime_engine.lab.rules import write_lab_rules
from runtime_engine.lab.session import prepare_session
from runtime_engine.process.ancestry import AncestryTracker
from runtime_engine.security.exposure import ExposureAnalyzer


@pytest.fixture
def isolated_lab(tmp_path, monkeypatch):
    fake_tmp = tmp_path / "tmp"
    fake_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(fake_tmp))
    monkeypatch.setattr("runtime_engine.lab.paths.tempfile.gettempdir", lambda: str(fake_tmp))
    monkeypatch.setattr(
        "runtime_engine.security.ransomware_sim.tempfile.gettempdir", lambda: str(fake_tmp)
    )
    monkeypatch.delenv("RTE_LAB_STATUS", raising=False)
    return fake_tmp


def test_lab_rt002_ignores_ambient_tmp_but_matches_lab_bin(isolated_lab, make_event):
    session, _, _, _ = prepare_session("lab-quiet-rules")
    rules_path = write_lab_rules(session)
    rt002 = next(r for r in load_rules(rules_path) if r.rule_id == "RT002")
    engine = DetectionEngine([rt002])
    ancestry = AncestryTracker()
    ambient = make_event(
        event_type=EventType.PROCESS_START,
        executable_path="/tmp/github-desktop/WebKitWebProcess",
        process_name="WebKitWebProces",
    )
    lab_bin = make_event(
        event_type=EventType.PROCESS_START,
        executable_path=str(session / "bin" / "lab-worker"),
        process_name="lab-worker",
    )
    assert engine.evaluate(ambient, ancestry) == []
    assert [a.rule_id for a in engine.evaluate(lab_bin, ancestry)] == ["RT002"]
    assert str(lab_root()) in rules_path.read_text(encoding="utf-8")


def test_lab_exposure_skips_host_services_and_processes(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    settings = ExposureSettings(
        suid_paths=[str(empty)],
        expected_suid=[],
        scan_services=False,
        scan_processes=False,
        scan_sudo=False,
        scan_sensitive=False,
        scan_path_dirs=False,
    )
    report = ExposureAnalyzer(settings, proc=Path("/proc")).scan(full=True)
    assert all(f.rule_id not in {"EX005", "EX007", "EX008", "EX004"} for f in report.findings)
