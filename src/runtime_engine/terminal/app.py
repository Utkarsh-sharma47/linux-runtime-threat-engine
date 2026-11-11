"""CLI glue: build a session, choose dashboard or line mode, stop cleanly, persist, report."""

import contextlib
import json
import logging
import os
import platform
import secrets
import signal
import sqlite3
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, TextIO

from rich.console import Console
from rich.markup import escape

from runtime_engine.collector.proc_collector import ProcCollector
from runtime_engine.collector.replay_collector import ReplayCollector
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.monitor.investigation import (
    DatabaseSource,
    LiveSource,
    filter_records,
    parse_filter,
    process_details,
    records_from_database,
)
from runtime_engine.monitor.session import MonitorSession, SnapshotCollector
from runtime_engine.monitor.state import DashboardState, SessionInfo, StateLogHandler, Verbosity
from runtime_engine.pipeline import Pipeline
from runtime_engine.storage.database import Database
from runtime_engine.terminal.interactions import (
    Inspector,
    InteractiveMonitor,
    KeyReader,
    TerminalKeys,
    run_plain,
)
from runtime_engine.terminal.renderer import PlainLogRenderer, SafeConsole
from runtime_engine.terminal.session_summary import render_session_list, render_session_report
from runtime_engine.terminal.views import event_view, process_view


def cli_console(stream: TextIO | None = None) -> Console:
    """Pipes and files get 140 columns (unless COLUMNS is set) so tables are not crushed."""
    stream = stream or sys.stdout
    try:
        tty = stream.isatty()
    except (AttributeError, ValueError):
        tty = False
    width = None if tty or "COLUMNS" in os.environ else 140
    return SafeConsole(file=stream, highlight=False, width=width)


@dataclass
class MonitorOptions:
    duration: float | None = None
    include_cmdline: bool = False
    verbosity: Verbosity = Verbosity.NORMAL
    refresh: float = 1.0
    dashboard: bool | None = None  # None: automatic (both stdin and stdout are terminals)
    json_output: bool = False
    queue_capacity: int = 10000


def new_session_id(now: datetime) -> str:
    return f"SES-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


def interactive_terminal(stdin: TextIO, stdout: TextIO) -> bool:
    try:
        return stdin.isatty() and stdout.isatty() and os.environ.get("TERM", "") not in ("", "dumb")
    except (AttributeError, ValueError, OSError):
        return False


def session_info(
    mode: str,
    database: Database,
    settings: Settings,
    *,
    telemetry: str,
    verbosity: Verbosity,
    poll_interval: float | None,
    queue_capacity: int | None,
    include_cmdline: bool = False,
    dashboard: bool = False,
) -> SessionInfo:
    started = datetime.now(UTC)
    path = database.path
    return SessionInfo(
        session_id=new_session_id(started),
        mode=mode,
        hostname=platform.node() or "unknown",
        kernel=platform.release(),
        engine_pid=os.getpid(),
        started_at=started,
        verbosity=verbosity,
        poll_interval=poll_interval,
        queue_capacity=queue_capacity,
        window_seconds=settings.correlation_window_seconds,
        telemetry=telemetry,
        database_path=path if path == ":memory:" else str(Path(path).resolve()),
        reports_directory=str(Path(settings.reports_directory).resolve()),
        include_cmdline=include_cmdline,
        dashboard=dashboard,
    )


@contextlib.contextmanager
def dashboard_logging(state: DashboardState) -> Iterator[None]:
    """While the dashboard owns the screen, log records go to the diagnostics buffer."""
    root = logging.getLogger()
    saved = list(root.handlers)
    handler = StateLogHandler(state)
    root.handlers = [handler]
    try:
        yield
    finally:
        root.handlers = saved


@contextlib.contextmanager
def termination_signal(session: MonitorSession) -> Iterator[None]:
    """SIGTERM and SIGHUP (closed SSH session) behave like Ctrl+C: a graceful stop."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum: int, frame: FrameType | None) -> None:
        session.request_stop("sigterm" if signum == signal.SIGTERM else "sighup")
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, handler) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)


def run_monitor(
    database: Database,
    rules: list[Rule],
    settings: Settings,
    options: MonitorOptions,
    *,
    collector: SnapshotCollector | None = None,
    console: Console | None = None,
    keys: KeyReader | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    interactive = (
        interactive_terminal(stdin, stdout) if options.dashboard is None else options.dashboard
    )
    if options.json_output:
        interactive = False
    collector = collector or ProcCollector(include_cmdline=options.include_cmdline)
    poll = settings.poll_interval_seconds
    info = session_info(
        "LIVE",
        database,
        settings,
        telemetry=(
            f"/proc polling every {poll:g}s (process discovery only; "
            "no live file, network or privilege events)"
        ),
        verbosity=options.verbosity,
        poll_interval=poll,
        queue_capacity=options.queue_capacity,
        include_cmdline=options.include_cmdline,
        dashboard=interactive,
    )
    state = DashboardState(info)
    pipeline = Pipeline(database, rules, settings.correlation_window_seconds)
    session = MonitorSession(
        pipeline,
        collector,
        state,
        poll_interval=poll,
        queue_capacity=options.queue_capacity,
        duration=options.duration,
    )
    # Line output goes to stderr with --json so stdout stays machine-readable.
    console = console or cli_console(sys.stderr if options.json_output else stdout)
    database.save_session(state.summary(status="RUNNING"))
    plain = PlainLogRenderer(state, console, options.verbosity)
    reason = "error"
    with termination_signal(session):
        try:
            session.start()
            if interactive:
                inspector = Inspector(
                    console,
                    lambda message: console.input(escape(message)),
                    database=database,
                    rules=rules,
                    source=LiveSource(state, database),
                    reports_directory=Path(settings.reports_directory),
                    state=state,
                )
                monitor = InteractiveMonitor(# type: ignore[arg-type]\n                    session,
                    session,
                    console,
                    keys or TerminalKeys(stdin),
                    inspector,
                    refresh=options.refresh,
                    fallback=plain,
                )
                with dashboard_logging(state):
                    reason = monitor.run()
                    if not monitor.fell_back:
                        monitor.drain(reason)
                interactive = not monitor.fell_back
            else:
                reason = run_plain(session, plain)
        except KeyboardInterrupt:
            reason = session.reason or "keyboard_interrupt"
        finally:
            result = session.shutdown(reason)
    if not interactive:
        plain.flush()
    summary = state.summary(status=result.status)
    report = pipeline.metrics.report()
    database.save_metrics(report)
    database.save_session(summary)
    if options.json_output:
        print(json.dumps(report, indent=2), file=stdout)
    else:
        console.print(render_session_report(summary))
    if result.status == "FAILED":
        return 1
    return 2 if pipeline.metrics.events_rejected else 0


def run_replay(
    database: Database,
    rules: list[Rule],
    settings: Settings,
    path: Path,
    *,
    sort: bool = False,
    summary_output: bool = False,
    console: Console | None = None,
) -> int:
    """Synchronous replay; records a REPLAY session. Default output stays the JSON metrics."""
    collector = ReplayCollector(path, sort=sort)
    info = session_info(
        "REPLAY",
        database,
        settings,
        telemetry=f"JSONL replay of {path.name}",
        verbosity=Verbosity.NORMAL,
        poll_interval=None,
        queue_capacity=None,
    )
    state = DashboardState(info)
    pipeline = Pipeline(database, rules, settings.correlation_window_seconds)
    state.set_status("RUNNING")
    database.save_session(state.summary())
    try:
        for event in collector.collect():
            state.record_observed()
            state.record_accepted(0)
            state.apply(pipeline.process(event))
    except Exception as exc:
        state.record_error(f"replay failure: {type(exc).__name__}", fatal=True)
        state.stop_reason = "error"
        state.set_status("FAILED")
        with contextlib.suppress(sqlite3.Error):
            database.save_session(state.summary(status="FAILED"))
        raise
    state.update_collector(collector.errors, 0, 0, collector.rejected)
    state.stop_reason = "replay_complete"
    state.set_status("STOPPED")
    pipeline.metrics.events_rejected += collector.rejected
    pipeline.metrics.collector_errors += collector.errors
    report = pipeline.metrics.report()
    database.save_metrics(report)
    summary = state.summary(status="STOPPED_GRACEFULLY")
    database.save_session(summary)
    if summary_output:
        (console or cli_console()).print(render_session_report(summary))
    else:
        print(json.dumps(report, indent=2))
    return 2 if pipeline.metrics.events_rejected else 0


# ----- historical commands -----


def show_sessions(database: Database, console: Console, as_json: bool) -> int:
    sessions = database.sessions()
    if as_json:
        print(json.dumps(sessions, indent=2))
    else:
        console.print(render_session_list(sessions))
    return 0


def show_session(database: Database, console: Console, session_id: str, as_json: bool) -> int:
    summary = database.session(session_id)
    if summary is None:
        raise KeyError(session_id)
    if as_json:
        print(json.dumps(summary, indent=2))
    else:
        console.print(render_session_report(summary, title=f"MONITORING SESSION {session_id}"))
    return 0


def show_process(database: Database, console: Console, pid: int, as_json: bool) -> int:
    source = DatabaseSource(database)
    identities = source.identities(pid)
    if not identities:
        raise KeyError(pid)
    details = [
        d
        for d in (process_details(source, e.process_key) for e in identities if e.process_key)
        if d is not None
    ]
    if as_json:
        print(json.dumps([_details_json(d) for d in details], indent=2, ensure_ascii=True))
        return 0
    if len(details) > 1:
        console.print(process_view.render_identity_choices([d.event for d in details]))
    for item in details:
        console.print(process_view.render_process_details(item))
    return 0


def _details_json(details: Any) -> dict[str, Any]:
    return {
        "process_key": details.key,
        "event": details.event.model_dump(mode="json"),
        "live_status": details.liveness.label,
        "live_detail": details.liveness.detail,
        "alerts": [a.model_dump(mode="json") for a in details.alerts],
        "incident_ids": [i.incident_id for i in details.incidents],
        "lineage": [n.key for n in details.lineage],
        "children": [c.process_key for c in details.children],
        "event_ids": [e.event_id for e in details.events],
    }


def show_events(
    database: Database,
    console: Console,
    *,
    limit: int,
    pid: int | None,
    event_type: str | None,
    name: str | None,
    filter_text: str,
    as_json: bool,
) -> int:
    if limit <= 0:
        raise ValueError("limit must be positive")
    spec = parse_filter(filter_text)
    stored = database.recent_events(
        limit if not filter_text else max(limit, 5000),
        pid=pid,
        event_type=event_type.upper() if event_type else None,
        process_name=name,
    )
    records = filter_records(records_from_database(database, stored), spec)[-limit:]
    if as_json:
        print(
            json.dumps(
                [
                    r.event.model_dump(mode="json")
                    | {"rule_ids": list(r.rule_ids), "incident_ids": list(r.incident_ids)}
                    for r in records
                ],
                indent=2,
                ensure_ascii=True,
            )
        )
    else:
        console.print(
            event_view.render_event_table(records, spec, len(stored), limit, width=console.width)
        )
    return 0
