import json
import logging
import signal
import subprocess
import sys
import time
from io import StringIO
from pathlib import Path

import pytest
from terminal_helpers import FakeCollector, FakeKeys, make_console, proc_event, text_of

from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.main import main
from runtime_engine.monitor.state import DashboardState, Verbosity
from runtime_engine.storage.database import Database
from runtime_engine.terminal import app

LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc only")


class TTY(StringIO):
    def isatty(self) -> bool:
        return True


def chain_batches():
    parent = proc_event(9000, name="dropper", exe="/tmp/dropper", start="90000")
    child = proc_event(
        9001, ppid=9000, name="bash", exe="/bin/bash", start="90010", parent_start="90000"
    )
    return [[parent], [child]]


def monitor(database, options, **kwargs):
    settings = Settings(poll_interval_seconds=0.1, reports_directory="unused-reports")
    return app.run_monitor(database, load_rules(), settings, options, **kwargs)


def test_dashboard_session_stops_on_q_and_is_persisted(database):
    console = make_console(140, 45)
    keys = FakeKeys([None] * 30 + ["q"])
    code = monitor(
        database,
        app.MonitorOptions(dashboard=True, refresh=0.01),
        collector=FakeCollector(chain_batches()),
        console=console,
        keys=keys,
    )
    assert code == 0
    [session] = database.sessions()
    assert session["status"] == "STOPPED_GRACEFULLY" and session["stop_reason"] == "user_quit"
    assert session["events"]["processed"] == 2 == session["events"]["observed"]
    assert session["incident_ids"] == ["INC-0001"]
    assert session["configuration"]["dashboard"] is True
    text = text_of(console)
    assert "MONITORING SESSION COMPLETED" in text and "STOPPED GRACEFULLY" in text
    assert "INC-0001" in text and "Stop Reason" in text and "q command" in text
    assert len(database.metrics()) == 1


def test_dashboard_ctrl_c_shutdown_is_graceful(database):
    console = make_console(140, 45)
    code = monitor(
        database,
        app.MonitorOptions(dashboard=True, refresh=0.01),
        collector=FakeCollector(chain_batches()),
        console=console,
        keys=FakeKeys([None] * 10 + [KeyboardInterrupt]),
    )
    assert code == 0
    session = database.sessions()[0]
    assert session["stop_reason"] == "keyboard_interrupt"
    assert session["status"] == "STOPPED_GRACEFULLY"
    assert session["events"]["unprocessed_at_shutdown"] == 0
    assert "Ctrl+C" in text_of(console)


def test_non_interactive_fallback_prints_lines_and_report(database):
    stdout = StringIO()
    console = make_console(160, 50)
    code = monitor(
        database,
        app.MonitorOptions(duration=0.4, verbosity=Verbosity.VERBOSE),
        collector=FakeCollector(chain_batches()),
        console=console,
        stdin=StringIO(),
        stdout=stdout,
    )
    assert code == 0
    text = text_of(console)
    assert "MONITORING_STARTED" in text and "BASELINE_SNAPSHOT" in text
    assert "PROCESS_START [baseline]" in text and "RULE_MATCH" in text
    assert "INCIDENT_CREATED" in text and "MONITORING_STOPPED" in text
    assert "--duration elapsed" in text and "MONITORING SESSION COMPLETED" in text
    assert database.sessions()[0]["configuration"]["dashboard"] is False
    assert not app.interactive_terminal(StringIO(), StringIO())
    assert not app.interactive_terminal(TTY(), StringIO())


def test_json_output_keeps_stdout_machine_readable(database):
    stdout = StringIO()
    code = monitor(
        database,
        app.MonitorOptions(duration=0.2, json_output=True),
        collector=FakeCollector(chain_batches()),
        console=make_console(),
        stdout=stdout,
    )
    assert code == 0
    metrics = json.loads(stdout.getvalue())
    assert metrics["total_events_processed"] == 2 and metrics["total_alerts_generated"] == 1


def test_monitoring_failure_returns_error_code(database):
    console = make_console()
    code = monitor(
        database,
        app.MonitorOptions(duration=5),
        collector=FakeCollector([], fail=True),
        console=console,
        stdin=StringIO(),
    )
    assert code == 1
    session = database.sessions()[0]
    assert session["status"] == "FAILED" and "collector failure" in session["error"]
    assert "MONITORING ERROR" in text_of(console)


def test_final_summary_matches_pipeline_measurements(tmp_path, capsys):
    db = tmp_path / "replay.db"
    assert main(["--db", str(db), "replay", "--input", "datasets/chain.jsonl", "--summary"]) == 0
    text = capsys.readouterr().out
    assert "REPLAY SESSION COMPLETED" in text and "INC-0001" in text
    database = Database(db)
    try:
        [session] = database.sessions()
        [metrics] = database.metrics()
    finally:
        database.close()
    assert session["mode"] == "REPLAY" and session["status"] == "STOPPED_GRACEFULLY"
    assert session["events"]["processed"] == metrics["total_events_processed"] == 6
    assert session["security"]["rule_matches"] == metrics["total_alerts_generated"] == 6
    assert session["security"]["unique_alerts"] == 6
    assert session["security"]["incidents_generated"] == metrics["total_incidents_created"] == 1
    assert session["security"]["matches_by_severity"] == {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 0,
    }
    assert session["performance"]["latency_samples"] == 6
    assert session["performance"]["p95_latency_ms"] is not None
    assert session["top_processes"][0]["process_name"] == "bash"
    # Default replay output is still the original JSON metrics.
    assert (
        main(["--db", str(tmp_path / "plain.db"), "replay", "--input", "datasets/chain.jsonl"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["total_events_processed"] == 6


def test_replay_failure_records_failed_session(tmp_path):
    database = Database(tmp_path / "f.db")
    try:
        with pytest.raises(OSError):
            app.run_replay(database, load_rules(), Settings(), tmp_path / "missing.jsonl")
        assert database.sessions()[0]["status"] == "FAILED"
    finally:
        database.close()


def test_session_persistence_and_history_commands(tmp_path, capsys):
    db = tmp_path / "history.db"
    prefix = ["--db", str(db)]
    assert main(prefix + ["sessions"]) == 0
    assert "No monitoring sessions are recorded" in capsys.readouterr().out
    assert main(prefix + ["replay", "--input", "datasets/chain.jsonl"]) == 0
    capsys.readouterr()
    assert main(prefix + ["sessions", "--json"]) == 0
    [session] = json.loads(capsys.readouterr().out)
    assert main(prefix + ["sessions"]) == 0
    listing = capsys.readouterr().out
    assert session["session_id"] in listing and "GRACEFUL" in listing
    assert main(prefix + ["session", "--id", session["session_id"]]) == 0
    report = capsys.readouterr().out
    assert f"MONITORING SESSION {session['session_id']}" in report
    assert "SEVERITY BREAKDOWN" in report and "NEXT COMMANDS" in report
    assert main(prefix + ["session", "--id", session["session_id"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == session
    assert main(prefix + ["session", "--id", "SES-missing"]) == 3
    assert "session not found" in capsys.readouterr().err


def test_process_and_events_commands(tmp_path, capsys):
    prefix = ["--db", str(tmp_path / "cli.db")]
    assert main(prefix + ["replay", "--input", "datasets/chain.jsonl"]) == 0
    capsys.readouterr()
    assert main(prefix + ["process", "--pid", "110"]) == 0
    text = capsys.readouterr().out
    assert "PROCESS DETAILS" in text and "HISTORICAL" in text and "soffice (PID 100)" in text
    assert main(prefix + ["process", "--pid", "110", "--json"]) == 0
    [details] = json.loads(capsys.readouterr().out)
    assert details["incident_ids"] == ["INC-0001"] and len(details["lineage"]) == 2
    assert main(prefix + ["process", "--pid", "4242"]) == 3
    assert "no stored process" in capsys.readouterr().err
    assert main(prefix + ["events", "--limit", "50"]) == 0
    events = capsys.readouterr().out
    assert "RECENT EVENTS" in events and "INCIDENT EVIDENCE" in events and "OBSERVED" in events
    assert main(prefix + ["events", "--pid", "120", "--type", "network_connection", "--json"]) == 0
    [network] = json.loads(capsys.readouterr().out)
    assert network["rule_ids"] == ["RT006"] and network["incident_ids"] == ["INC-0001"]
    assert main(prefix + ["events", "--filter", "severity=HIGH", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 3
    assert main(prefix + ["events", "--name", "soffice", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["rule_ids"] == []
    assert main(prefix + ["events", "--limit", "0"]) == 1


def test_dashboard_logging_routes_records_to_diagnostics():
    from terminal_helpers import make_info

    state = DashboardState(make_info(verbosity=Verbosity.DEBUG))
    with app.dashboard_logging(state):
        logging.getLogger("runtime_engine.test").warning("probe %d", 7)
    assert any(("MESSAGE", "probe 7") in e.fields for e in state.visible_entries(Verbosity.DEBUG))


def test_cli_console_is_wide_for_pipes():
    assert app.cli_console(StringIO()).width == 140


def run_cli(args, **kwargs):
    return subprocess.Popen(
        [sys.executable, "-m", "runtime_engine.main", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )


@LINUX
def test_real_proc_monitor_non_interactive(tmp_path):
    process = run_cli(["--db", str(tmp_path / "live.db"), "monitor", "--duration", "1"])
    out, err = process.communicate(timeout=30)
    assert process.returncode == 0, err
    assert "BASELINE_SNAPSHOT" in out and "PROCESSES_VISIBLE=" in out
    assert "MONITORING SESSION COMPLETED" in out and "STOPPED GRACEFULLY" in out


@LINUX
@pytest.mark.parametrize("sig,label", [(signal.SIGTERM, "SIGTERM"), (signal.SIGINT, "Ctrl+C")])
def test_real_proc_monitor_stops_gracefully_on_signal(tmp_path, sig, label):
    db = tmp_path / "signal.db"
    process = run_cli(["--db", str(db), "monitor"])
    deadline = time.monotonic() + 20
    database = Database(db)
    try:
        while time.monotonic() < deadline and not database.sessions():
            time.sleep(0.1)
        time.sleep(1)
        process.send_signal(sig)
        out, err = process.communicate(timeout=30)
        assert process.returncode == 0, err
        assert label in out and "STOPPED GRACEFULLY" in out
        [session] = database.sessions()
        assert session["status"] == "STOPPED_GRACEFULLY"
        assert session["events"]["processed"] == session["events"]["accepted"] > 0
    finally:
        database.close()


def test_paths_are_resolved_in_session_info(tmp_path):
    database = Database(tmp_path / "x.db")
    try:
        info = app.session_info(
            "LIVE",
            database,
            Settings(),
            telemetry="t",
            verbosity=Verbosity.NORMAL,
            poll_interval=1,
            queue_capacity=1,
        )
        assert Path(info.database_path).is_absolute() and info.session_id.startswith("SES-")
    finally:
        database.close()
