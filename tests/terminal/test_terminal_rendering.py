from datetime import UTC, datetime, timedelta

import pytest
from rich.console import Console
from terminal_helpers import make_console, make_info, proc_event, render, text_of

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import Severity
from runtime_engine.monitor.state import (
    DashboardState,
    EntryKind,
    LogEntry,
    Verbosity,
    percentile,
)
from runtime_engine.pipeline import Pipeline
from runtime_engine.terminal import formatting
from runtime_engine.terminal.dashboard import render_dashboard
from runtime_engine.terminal.live_logs import log_panel, plain_line
from runtime_engine.terminal.renderer import DashboardRenderer, PlainLogRenderer, SafeConsole
from runtime_engine.terminal.views.metrics_view import (
    render_alert_list,
    render_help,
    render_metrics,
)


def entry(**overrides: object) -> LogEntry:
    values: dict[str, object] = dict(
        seq=1,
        at=datetime(2026, 1, 1, 12, 40, 1, 204000, tzinfo=UTC),
        kind=EntryKind.OBSERVED,
        title="PROCESS_START",
        fields=(("PID", "2201"), ("PPID", "1100"), ("PROCESS", "python"), ("SOURCE", "proc")),
        min_verbosity=Verbosity.NORMAL,
    )
    values.update(overrides)
    return LogEntry(**values)  # type: ignore[arg-type]


def test_dashboard_initialization_shows_empty_states():
    state = DashboardState(make_info())
    text = render(render_dashboard(state.snapshot(), 140, 45), 140, 45)
    assert "LINUX RUNTIME THREAT DETECTION ENGINE" in text
    assert "STATUS: STARTING" in text and "MODE: LIVE" in text
    assert "SESSION: SES-TEST" in text and "ENGINE PID: 4242" in text
    assert "No incidents correlated in this session." in text
    assert "No processes observed yet." in text
    assert "No events to display yet" in text
    assert "[q] Stop monitoring" in text


def test_dashboard_refresh_reflects_new_pipeline_results(database):
    state = DashboardState(make_info())
    state.set_status("RUNNING")
    before = render(render_dashboard(state.snapshot(), 140, 45), 140, 45)
    assert "Suspicious Detections" in before
    pipeline = Pipeline(database, load_rules())
    state.record_observed()
    state.apply(pipeline.process(proc_event(500, name="dropper", exe="/tmp/dropper")))
    after = render(render_dashboard(state.snapshot(), 140, 45), 140, 45)
    assert "INC-0001" in after and "RT002" in after
    assert "SUSPICIOUS (MEDIUM)" in after
    assert "SECURITY ALERT" in after and "Press [i] to inspect" in after
    assert "STATUS: RUNNING" in after


def test_event_formatting_includes_required_fields():
    line = plain_line(entry())
    assert line.startswith("[") and "INFO" in line and "PROCESS_START" in line
    assert "PID=2201" in line and "PPID=1100" in line and "PROCESS=python" in line
    assert "SOURCE=proc" in line
    local = formatting.clock_ms(datetime(2026, 1, 1, 12, 40, 1, 204000, tzinfo=UTC))
    assert local.endswith(".204") and f"[{local}]" in line


def test_severity_formatting_uses_labels_not_only_colour():
    for severity in Severity:
        assert formatting.severity_text(severity).plain == severity.value
        assert formatting.severity_style(severity)
    assert formatting.severity_text(None).plain == "NORMAL"
    alert = entry(kind=EntryKind.RULE_MATCH, title="RULE_MATCH", severity=Severity.HIGH, seq=2)
    assert "SEVERITY=HIGH" in plain_line(alert) and "WARNING" in plain_line(alert)
    error = entry(kind=EntryKind.ERROR, title="MONITORING_FAILURE", seq=3)
    assert "ERROR" in plain_line(error) and "not a security finding" in plain_line(error)
    incident = entry(kind=EntryKind.INCIDENT, title="INCIDENT_CREATED", severity=Severity.LOW)
    assert "ALERT" in plain_line(incident) and "[CORRELATED INCIDENT]" in plain_line(incident)


def test_no_colour_terminal_still_shows_severity(database):
    state = DashboardState(make_info())
    pipeline = Pipeline(database, load_rules())
    state.apply(pipeline.process(proc_event(501, name="x", exe="/dev/shm/x")))
    console = Console(file=make_console().file, width=140, height=45, no_color=True)
    console.print(render_dashboard(state.snapshot(), 140, 45))
    assert "MEDIUM" in text_of(console)


def test_long_command_line_is_truncated_in_stream_but_full_in_details(database):
    from runtime_engine.terminal.views.event_view import render_event_details

    argv = ["/usr/bin/tool"] + [f"--option-{i}=value" for i in range(80)]
    state = DashboardState(make_info(verbosity=Verbosity.VERBOSE))
    pipeline = Pipeline(database, load_rules())
    state.apply(pipeline.process(proc_event(600, command_line=argv)))
    observed = [e for e in state.visible_entries(Verbosity.VERBOSE) if e.title.startswith("PROC")]
    line = plain_line(observed[0])
    assert "CMD=" in line and "..." in line and "--option-79=value" not in line
    record = state.event_records()[0]
    details = render(render_event_details(record, []), 400, 200)
    assert "--option-79=value" in details


def test_control_characters_are_escaped():
    assert formatting.clean("a\x1b[31mb\x07") == "a\\x1b[31mb\\x07"
    assert "\x1b" not in plain_line(entry(fields=(("PROCESS", "evil\x1b[2J"),)))
    assert formatting.clean(None) == "-" and formatting.truncate("abcdef", 2) == "ab"


def test_empty_event_stream_panel():
    text = render(log_panel([], 10, Verbosity.NORMAL))
    assert "No events to display yet" in text


def test_empty_incident_list_message():
    from runtime_engine.terminal.views.incident_view import render_incident_list

    text = render(render_incident_list([], []))
    assert "No security incidents were generated" in text
    assert "does not prove that the machine is safe" in text


@pytest.mark.parametrize(
    "width,height", [(20, 6), (40, 10), (60, 15), (80, 24), (90, 30), (150, 50), (300, 100)]
)
def test_terminal_resize_never_crashes(chain, width, height):
    state, _ = chain
    state.notifications.items.clear()
    for verbosity in Verbosity:
        snap = state.snapshot(verbosity)
        console = make_console(width, height)
        console.print(render_dashboard(snap, width, height))
        assert text_of(console)
    # The dashboard fills the screen exactly; it must not scroll past the terminal height.
    console = make_console(150, 50)
    console.print(render_dashboard(state.snapshot(), 150, 50))
    assert len(text_of(console).splitlines()) == 50


def test_debug_verbosity_shows_separate_diagnostics_panel(database):
    state = DashboardState(make_info(verbosity=Verbosity.DEBUG))
    state.record_diagnostic("internal_probe", [("DETAIL", "x")])
    text = render(render_dashboard(state.snapshot(), 150, 60), 150, 60)
    assert "INTERNAL DIAGNOSTICS (debug; not security events)" in text
    assert "internal_probe" in text
    normal = DashboardState(make_info())
    normal.record_diagnostic("internal_probe")
    assert "internal_probe" not in render(render_dashboard(normal.snapshot(), 150, 60), 150, 60)


def test_renderer_failure_is_contained():
    state = DashboardState(make_info())

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    renderer = DashboardRenderer(state, interactive=True, builder=broken)
    text = render(renderer.build(100, 30))
    assert "RENDER ERROR" in text and "Monitoring continues" in text
    assert state.counters.render_errors == 1


def test_metrics_display_with_and_without_measurements(chain):
    state, pipeline = chain
    text = render(render_metrics(state.snapshot()))
    assert "Processed by pipeline" in text and " 6 " in text
    assert "Rule matches" in text
    assert "ms" in text
    empty = render(render_metrics(DashboardState(make_info()).snapshot()))
    assert "N/A" in empty


def test_alert_list_and_help(chain):
    state, _ = chain
    processes = {k: v for k, v in state.processes.items()}
    text = render(render_alert_list(state.alert_list(), processes), 200)
    for rule in ("RT001", "RT002", "RT003", "RT004", "RT005", "RT006"):
        assert rule in text
    assert "No rule has matched" in render(render_alert_list([], {}))
    assert "Ctrl+C" in render(render_help("telemetry note"))


def test_plain_renderer_streams_each_entry_once_and_survives_broken_pipe(chain):
    state, _ = chain
    console = make_console()
    renderer = PlainLogRenderer(state, console, Verbosity.NORMAL, heartbeat_seconds=0)
    printed = renderer.flush()
    assert printed > 0
    assert renderer.flush() == 0
    assert "[status]" in text_of(console)

    class Broken:
        def write(self, text: str) -> int:
            raise BrokenPipeError

        def flush(self) -> None:
            raise BrokenPipeError

    state.record_lifecycle("AFTER")
    broken = PlainLogRenderer(state, SafeConsole(file=Broken()), Verbosity.NORMAL)  # type: ignore[arg-type]
    broken.flush()
    assert broken.broken and broken.flush() == 0


def test_plain_renderer_reports_evicted_entries():
    state = DashboardState(make_info(), log_capacity=3)
    for number in range(10):
        state.record_lifecycle(f"E{number}", verbosity=Verbosity.NORMAL)
    console = make_console()
    PlainLogRenderer(state, console, Verbosity.NORMAL).flush()
    assert "evicted" in text_of(console)
    assert state.counters.logs_evicted == 7


def test_formatting_helpers():
    assert formatting.duration(3725) == "01:02:05"
    assert formatting.duration(None) == "N/A"
    assert formatting.number(12450) == "12,450" and formatting.number(None) == "N/A"
    assert formatting.number(1.5) == "1.50"
    assert formatting.milliseconds(None) == "N/A"
    assert formatting.memory(2048) == "2.0 MiB (peak RSS)" and formatting.memory(None) == "N/A"
    assert formatting.timestamp(None) == "N/A"
    assert formatting.timestamp("2026-01-01T00:00:00+00:00").startswith("2026-01-01")
    assert formatting.command_line(None) == "-"
    assert formatting.user(None, True) == "-" and formatting.user(5, False) == "5"
    assert formatting.user(0, True).startswith("0")
    assert formatting.user(4_000_000, True) == "4000000"
    assert percentile([], 0.95) is None
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95) == 10
    assert percentile([3.0], 0.95) == 3.0


def test_active_incident_window(database):
    state = DashboardState(make_info(window_seconds=1))
    pipeline = Pipeline(database, load_rules())
    old = proc_event(700, exe="/tmp/a", timestamp=datetime.now(UTC) - timedelta(seconds=30))
    state.apply(pipeline.process(old))
    assert state.active_incident_ids() == frozenset()
    fresh = proc_event(701, exe="/tmp/b")
    state.apply(pipeline.process(fresh))
    assert state.active_incident_ids() == frozenset({"INC-0002"})
    state.set_status("STOPPED")
    assert state.active_incident_ids() == frozenset()
