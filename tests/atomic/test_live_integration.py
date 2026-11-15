"""Live Atomic ↔ MonitorSession integration with synthetic evidence only.

No real Atomic Red Team test is executed. All telemetry is labeled SYNTHETIC.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
from rich.console import Console

from runtime_engine.atomic.live import (
    LiveAtomicBridge,
    synthetic_network_event,
    synthetic_process_event,
)
from runtime_engine.atomic.profiles import ModuleExpectation, Profile
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.monitor.state import DashboardState
from runtime_engine.pipeline import Pipeline
from runtime_engine.storage.database import Database
from runtime_engine.terminal.dashboard import render_dashboard
from runtime_engine.terminal.views import network_investigation

# Reuse terminal FakeCollector helpers without depending on pytest path quirks.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "terminal"))
from terminal_helpers import FakeCollector, make_info, render  # noqa: E402


def wait_for(predicate, timeout=10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def live_session(tmp_path):
    database = Database(tmp_path / "live.db")
    state = DashboardState(make_info(database_path=str(tmp_path / "live.db")))
    pipeline = Pipeline(database, load_rules())
    # Empty collector: live Atomic evidence is injected via submit_event, not /proc.
    collector = FakeCollector([])
    session = MonitorSession(
        pipeline,
        collector,
        state,
        poll_interval=0.05,
        queue_capacity=200,
        put_timeout=0.05,
    )
    session.start()
    bridge = LiveAtomicBridge(session, database)
    yield session, state, bridge, database, pipeline
    session.shutdown("user_quit")
    database.close()


def fake_profile() -> Profile:
    return Profile(
        technique="T1071.001",
        name="Synthetic live acceptance profile",
        key_processes=["curl"],
        expected_rules=["RT002", "RT005", "RT006"],
        telemetry=["PROCESS_START", "NETWORK_CONNECTION"],
        rationale="Acceptance-only fake profile; never run as a real Atomic test.",
        reviewed_risk="A",
        benign=False,
        modules={
            "rules": ModuleExpectation(rules=["RT002", "RT005", "RT006"]),
        },
    )


def test_live_atomic_synthetic_end_to_end(live_session):
    session, state, bridge, database, pipeline = live_session
    collectors = bridge.verify_collectors()
    assert collectors["pipeline"] == "active"
    assert collectors["proc_collector"] == "active"

    record = bridge.register(
        technique="T1071.001",
        test_number=99,
        guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        name="Fake Atomic profile (synthetic acceptance)",
        synthetic=True,
        note="SYNTHETIC acceptance evidence; not real host Atomic activity",
    )
    assert record.synthetic
    assert state.atomic_sessions[record.run_id]["synthetic"] is True

    host = "synthetic-host"
    start = "9001"
    parent_start = "8000"
    process = synthetic_process_event(
        pid=4242,
        name="curl",
        exe="/tmp/curl",
        start=start,
        host_id=host,
        ppid=1111,
        parent_name="bash",
        parent_start=parent_start,
    )
    network = synthetic_network_event(
        pid=4242,
        name="curl",
        start=start,
        destination="203.0.113.10",
        host_id=host,
        attribution="unique",
    )
    # Unrelated host process must not be correlated by time window alone.
    unrelated = synthetic_process_event(
        pid=9999,
        name=" innocuous",
        exe="/usr/bin/sleep",
        start="7000",
        host_id=host,
    )
    unrelated["process_name"] = "sleep"
    unrelated["metadata"]["atomic_run_id"] = "should-be-overwritten-only-if-ingested-into-session"

    stats = bridge.ingest(record.run_id, [process, network])
    assert stats["accepted"] == 2
    assert wait_for(lambda: state.counters.processed >= 2)

    # Ingest unrelated without attaching to the Atomic session (direct submit).
    from runtime_engine.events.normalizer import normalize

    unrelated_event = normalize(unrelated)
    assert session.submit_event(unrelated_event)
    assert wait_for(lambda: state.counters.processed >= 3)

    correlated = bridge.correlate(record.run_id)
    assert record.process_keys  # curl process key only
    expected_key = json.dumps([host, 4242, start], separators=(",", ":"))
    assert expected_key in record.process_keys
    # Unrelated sleep must not appear on the Atomic session.
    assert all("9999" not in key for key in record.process_keys)

    rule_ids = {a["rule_id"] for a in correlated["alerts"]}
    assert {"RT002", "RT005", "RT006"} <= rule_ids
    assert correlated["incidents"], "expected a correlated incident from the rule matches"
    assert database.event(process["event_id"]) is not None
    assert database.event(network["event_id"]) is not None

    stored = database.atomic_session(record.run_id)
    assert stored is not None
    assert stored["synthetic"] is True
    assert stored["live_monitor_used"] is True

    bridge.finish(record.run_id, "COMPLETED")
    evaluation = bridge.evaluate(record.run_id, fake_profile())
    assert evaluation["synthetic"] is True
    assert evaluation["evidence_label"] == "SYNTHETIC"
    assert evaluation["overall"]["grade"] == "DETECTED"
    rules = next(c for c in evaluation["components"] if c["name"] == "rules")
    assert set(rules["observed"]) >= {"RT002", "RT005", "RT006"}

    # Dashboard surfaces the Atomic session.
    snap = state.snapshot(log_limit=20)
    assert any(item["run_id"] == record.run_id for item in snap.atomic_sessions)
    text = render(render_dashboard(snap, 140, 40))
    assert "ATOMIC SESSIONS" in text
    assert "SYNTHETIC" in text

    # Network investigation associates the connection with the Atomic session.
    rows = network_investigation.build_rows(
        connections=[],
        network_events=list(state.events),
        processes=dict(state.processes),
        alerts=list(state.alerts.values()),
        incidents=list(state.incidents.values()),
        findings=[],
        atomic_sessions=state.atomic_session_list(),
    )
    net_rows = [r for r in rows if r.get("remote", "").startswith("203.0.113.10")]
    assert net_rows
    assert net_rows[0]["atomic_run_id"] == record.run_id
    assert net_rows[0]["atomic_synthetic"] is True
    assert "RT006" in net_rows[0]["detections"]
    assert net_rows[0]["incidents"]
    view = render(
        network_investigation.render_network_investigation(
            None, rows, atomic_sessions=state.atomic_session_list()
        )
    )
    assert "NETWORK INVESTIGATION" in view
    assert "SYNTHETIC" in view
    assert "Not system-wide continuous capture" in view

    persisted = database.atomic_session(record.run_id)
    assert persisted is not None
    assert persisted.get("evaluation", {}).get("overall", {}).get("grade") == "DETECTED"


def test_time_window_alone_does_not_attribute(live_session):
    session, state, bridge, database, _pipeline = live_session
    record = bridge.register(
        technique="T1059.004",
        test_number=1,
        guid="00000000-0000-0000-0000-000000000099",
        name="synthetic isolation",
        synthetic=True,
    )
    other = synthetic_process_event(
        pid=1,
        name="systemd",
        exe="/usr/lib/systemd/systemd",
        start="1",
        host_id="synthetic-host",
    )
    from runtime_engine.events.normalizer import normalize

    session.submit_event(normalize(other))
    assert wait_for(lambda: state.counters.processed >= 1)
    correlated = bridge.correlate(record.run_id)
    assert correlated["alerts"] == []
    assert correlated["incidents"] == []
    assert record.process_keys == set()


def test_status_labels_include_untrained_and_not_baselined():
    from runtime_engine.terminal.views.security_common import STATUS_DISPLAY, status_text

    assert STATUS_DISPLAY["no-model"] == "UNTRAINED"
    assert STATUS_DISPLAY["no-baseline"] == "NOT BASELINED"
    assert STATUS_DISPLAY["disabled"] == "DISABLED"
    assert STATUS_DISPLAY["unavailable"] == "UNAVAILABLE"
    console = Console(record=True, width=80)
    console.print(status_text("no-model"))
    assert "UNTRAINED" in console.export_text()
