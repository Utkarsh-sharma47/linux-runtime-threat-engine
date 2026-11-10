import functools
import json
import threading
from pathlib import Path

from terminal_helpers import (
    BOOT,
    FakeCollector,
    FakeKeys,
    make_console,
    make_info,
    proc_event,
    scripted,
    text_of,
)

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.monitor.investigation import (
    DatabaseSource,
    LiveSource,
    filter_records,
    parse_filter,
    process_details,
)
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.monitor.state import DashboardState
from runtime_engine.pipeline import Pipeline
from runtime_engine.process import liveness
from runtime_engine.terminal.interactions import Inspector, InteractiveMonitor


def inspector(state, database, answers, tmp_path, **kwargs):
    console = make_console(160, 60)
    source = LiveSource(state, database) if state is not None else DatabaseSource(database)
    return (
        Inspector(
            console,
            scripted(answers),
            database=database,
            rules=load_rules(),
            source=source,
            reports_directory=tmp_path / "reports",
            state=state,
            **kwargs,
        ),
        console,
    )


def test_process_inspection_live(chain, database, tmp_path):
    state, _ = chain
    answers = ["abc", "999", "110", "3", "4", "5", "", "2", "1", "1", "6"]
    page, console = inspector(state, database, answers, tmp_path)
    page.dispatch("p")
    text = text_of(console)
    assert "Monitoring continues in the background" in text
    assert "Select a process to inspect" in text and "INC-0001" in text
    assert "A PID must be a whole number." in text
    assert "No process with PID 999 was observed in this session." in text
    assert "PROCESS DETAILS" in text and "PROCESS NAME      bash" in text
    assert "HISTORICAL" in text and "replayed or non-/proc telemetry" in text
    assert "RT001: Shell from unusual application parent" in text
    assert "soffice (PID 100)" in text and "<- selected" in text
    assert "COMPLETE ANCESTRY" in text and "ASSOCIATED ALERTS" in text
    assert "CHILD PROCESSES (observed)" in text
    assert "PROCESS NAME      curl" in text  # navigated to the child, then back to bash
    assert "rule match on this process" in text


def test_historical_process_with_reused_pid_is_not_confused(database, tmp_path):
    (tmp_path / "proc/sys/kernel/random").mkdir(parents=True)
    (tmp_path / "proc/sys/kernel/random/boot_id").write_text(BOOT)
    (tmp_path / "proc/stat").write_text("cpu 1\nbtime 1700000000\n")
    (tmp_path / "proc/777").mkdir()
    tail = ["S", "1"] + ["0"] * 17 + ["99999"]
    (tmp_path / "proc/777/stat").write_text("777 (other) " + " ".join(tail))
    pipeline = Pipeline(database, load_rules())
    old = proc_event(777, name="dropper", exe="/tmp/dropper", start="5000")
    reused = proc_event(777, name="sleep", exe="/usr/bin/sleep", start="99999")
    pipeline.process(old)
    pipeline.process(reused)
    check = functools.partial(liveness.check, root=tmp_path / "proc")
    started = functools.partial(liveness.start_time, root=tmp_path / "proc")
    page, console = inspector(
        None, database, ["777", "1", "6"], tmp_path, liveness=check, started=started
    )
    page.dispatch("p")
    text = text_of(console)
    assert "This PID was used by more than one process identity" in text
    assert "PID now belongs to a different process" in text
    assert "Showing HISTORICAL information" in text
    assert "PROCESS NAME      dropper" in text and "derived from boot time" in text
    details = process_details(DatabaseSource(database), reused.process_key, check)
    assert details is not None and details.liveness.running
    assert liveness.check(old, tmp_path / "missing").label == "UNKNOWN"


def test_liveness_edge_cases(tmp_path):
    root = tmp_path / "proc"
    (root / "sys/kernel/random").mkdir(parents=True)
    (root / "sys/kernel/random/boot_id").write_text("other-boot")
    event = proc_event(1)
    assert liveness.check(event, root).detail == "observed during a different boot"
    assert liveness.start_time(event, root) is None
    (root / "sys/kernel/random/boot_id").write_text(BOOT)
    assert "no longer visible" in liveness.check(event, root).detail
    assert liveness.start_time(event, root) is None  # /proc/stat missing


def test_incident_inspection_and_export(chain, database, tmp_path):
    state, _ = chain
    target = tmp_path / "out" / "incident.json"
    answers = ["", "1", "1", "3", "4", str(target), "4", str(target), "9", "2", "1", "6"]
    page, console = inspector(state, database, answers, tmp_path)
    page.dispatch("i")  # blank answer: list only
    page.dispatch("i")
    text = text_of(console)
    assert "SECURITY INCIDENT: INC-0001" in text
    assert "WHY WAS THIS FLAGGED?" in text
    assert "Rule description  A configured application launched a Unix shell." in text
    assert "process_name in ['bash', 'sh', 'dash', 'zsh']" in text
    assert "does not confirm that a compromise" in text
    assert "SUPPORTING EVENTS (matched a rule)" in text
    assert "CONTEXT EVENTS (ancestor observations; no rule match)" in text
    assert "COMPLETE EVIDENCE: INC-0001" in text
    assert "Refusing to overwrite existing file" in text and "Unknown action." in text
    assert "RELATED PROCESSES" in text and "PROCESS DETAILS" in text
    report = json.loads(target.read_text())
    assert report["incident_id"] == "INC-0001" and report["event_count"] == 5
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert state.exported_reports == [str(target.resolve())]


def test_incident_lookup_errors_and_empty_list(database, tmp_path):
    state = DashboardState(make_info())
    page, console = inspector(state, database, [""], tmp_path)
    page.dispatch("i")
    page.open_incident("INC-9999")
    text = text_of(console)
    assert "No security incidents were generated during this session." in text
    assert "Unknown incident INC-9999." in text
    assert Inspector.normalize_incident("7") == "INC-0007"


def test_event_filtering(chain, database, tmp_path):
    state, _ = chain
    answers = ["bogus", "pid=x", "kind=match severity=HIGH", "1", "99", "f", "kind=observed", ""]
    page, console = inspector(state, database, answers, tmp_path)
    page.dispatch("e")
    text = text_of(console)
    assert "Invalid filter" in text
    assert "RAW OBSERVED EVENT (normalized telemetry; not a finding by itself)" in text
    assert "RULE MATCHES ON THIS EVENT" in text and "CORRELATED INCIDENTS: INC-0001" in text
    assert "Unknown row." in text
    records = state.event_records()
    assert len(filter_records(records, parse_filter("kind=match severity=HIGH"))) == 3
    assert len(filter_records(records, parse_filter("kind=observed"))) == 1
    assert len(filter_records(records, parse_filter("pid=120"))) == 2
    assert len(filter_records(records, parse_filter("name=bash type=FILE_ACCESS"))) == 1
    assert len(filter_records(records, parse_filter("incident=inc-0001"))) == 5
    assert len(filter_records(records, parse_filter("kind=incident"))) == 5
    since = "since=2026-01-01T00:00:03+00:00 until=2026-01-01T00:00:04+00:00"
    assert len(filter_records(records, parse_filter(since))) == 2
    assert filter_records(records, parse_filter("since=5m")) == []
    assert parse_filter("since=14:05").since is not None
    for bad in ("kind=nope", "type=UNKNOWN", "color=red", "pid=", "since=2026-01-01T00:00:00"):
        try:
            parse_filter(bad)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_metrics_alerts_and_help_pages(chain, database, tmp_path):
    state, _ = chain
    assert state.notifications.active()
    page, console = inspector(state, database, ["", "", "INC-0001", "5", ""], tmp_path)
    page.dispatch("m")
    page.dispatch("h")
    page.dispatch("r")
    text = text_of(console)
    assert "LIVE METRICS (measured in this session)" in text
    assert "COMMANDS" in text and "RECENT ALERTS" in text and "SECURITY INCIDENT" in text
    assert state.notifications.active() == []  # acknowledged by opening the alert list


def session_for(database, batches, state=None):
    state = state or DashboardState(make_info())
    session = MonitorSession(
        Pipeline(database, load_rules()),
        FakeCollector(batches),
        state,
        poll_interval=0.01,
        queue_capacity=50,
    )
    return session, state


def monitor_for(session, keys, answers, tmp_path, database, **kwargs):
    console = make_console(140, 45)
    page = Inspector(
        console,
        scripted(answers),
        database=database,
        rules=load_rules(),
        source=LiveSource(session.state, database),
        reports_directory=tmp_path,
        state=session.state,
    )
    return InteractiveMonitor(session, console, keys, page, refresh=0.01, **kwargs), console


def test_q_command_stops_after_opening_a_page(database, tmp_path):
    session, state = session_for(database, [[proc_event(8000, exe="/tmp/x")]])
    keys = FakeKeys([None, None, "M", "q"])
    monitor, console = monitor_for(session, keys, [""], tmp_path, database)
    session.start()
    reason = monitor.run()
    monitor.drain(reason)
    result = session.shutdown(reason)
    assert reason == "user_quit" and keys.suspended == 1
    assert result.status == "STOPPED_GRACEFULLY"
    assert "LIVE METRICS" in text_of(console)
    assert state.status == "STOPPED"


def test_ctrl_c_on_dashboard_and_inside_a_page(database, tmp_path):
    session, _ = session_for(database, [])
    monitor, _ = monitor_for(session, FakeKeys([KeyboardInterrupt]), [], tmp_path, database)
    session.start()
    assert monitor.run() == "keyboard_interrupt"
    assert session.shutdown("keyboard_interrupt").status == "STOPPED_GRACEFULLY"

    session, _ = session_for(database, [])

    def interrupt(message: str) -> str:
        raise KeyboardInterrupt

    monitor, _ = monitor_for(session, FakeKeys(["p"]), [], tmp_path, database)
    monitor.inspector.prompt = interrupt
    session.start()
    assert monitor.run() == "keyboard_interrupt"
    session.shutdown("keyboard_interrupt")


def test_external_stop_ends_dashboard_loop(database, tmp_path):
    session, _ = session_for(database, [])
    monitor, _ = monitor_for(session, FakeKeys([]), [], tmp_path, database)
    session.start()
    threading.Timer(0.1, session.request_stop, ["duration_elapsed"]).start()
    assert monitor.run() == "duration_elapsed"
    session.shutdown("duration_elapsed")


def test_renderer_failure_falls_back_to_line_output(database, tmp_path):
    class BrokenLive:
        def __init__(self, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "BrokenLive":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def update(self, *args: object, **kwargs: object) -> None:
            raise OSError("terminal gone")

    session, state = session_for(database, [[proc_event(8100)]])
    monitor, console = monitor_for(
        session, FakeKeys([]), [], tmp_path, database, live_factory=BrokenLive
    )
    session.start()
    threading.Timer(0.3, session.request_stop, ["user_quit"]).start()
    assert monitor.run() == "user_quit"
    assert monitor.fell_back and state.counters.render_errors == 3
    monitor.drain("user_quit")  # rendering failures during drain are contained too
    session.shutdown("user_quit")
    assert "continuing with line output" in text_of(console)
    assert "MONITORING_STARTED" in text_of(console)


def test_second_interrupt_during_drain_forces_stop(database, tmp_path):
    session, _ = session_for(database, [])

    class InterruptingLive:
        def __init__(self, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "InterruptingLive":
            raise KeyboardInterrupt

        def __exit__(self, *args: object) -> None:
            pass

    monitor, _ = monitor_for(
        session, FakeKeys([]), [], tmp_path, database, live_factory=InterruptingLive
    )
    session.start()
    monitor.drain("keyboard_interrupt")
    assert session.forced
    assert session.shutdown("keyboard_interrupt").status == "FORCED_STOP"


def test_database_source_lookups(chain, database):
    source = DatabaseSource(database)
    bash = source.identities(110)[0]
    assert bash.process_name == "bash" and bash.process_key
    assert [c.pid for c in source.children(bash.process_key)] == [120]
    assert {a.rule_id for a in source.alerts(bash.process_key)} == {"RT001", "RT003", "RT004"}
    assert [i.incident_id for i in source.incidents(bash.process_key)] == ["INC-0001"]
    assert source.children("not-json") == []
    assert source.lookup('["x", 1, "1"]') is None
    assert source.first_observed('["x", 1, "1"]') == (None, None)
    soffice = source.identities(100)[0]
    details = process_details(source, soffice.process_key)
    assert details is not None and details.severity is None
    assert Path("datasets/chain.jsonl").exists()
