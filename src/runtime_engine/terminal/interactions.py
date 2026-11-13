"""Keyboard handling, inspection pages and the interactive dashboard loop.
# type: ignore

Only the terminal (main) thread runs here. Opening a page pauses rendering, not monitoring:
the collector and pipeline threads keep running and the dashboard resumes afterwards.
"""

import contextlib
import os
import select
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TextIO

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Event, Severity
from runtime_engine.incidents.reporter import export_json
from runtime_engine.monitor.investigation import (
    EventFilter,
    InvestigationSource,
    filter_records,
    incident_details,
    parse_filter,
    process_details,
    records_from_database,
)
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.monitor.state import DashboardState, EventRecord
from runtime_engine.process.liveness import Liveness, check, start_time
from runtime_engine.security.findings import MODULES, Finding, ScanReport
from runtime_engine.storage.database import Database
from runtime_engine.terminal.formatting import clean, severity_text
from runtime_engine.terminal.live_logs import LiveLogRenderer
from runtime_engine.terminal.renderer import DashboardRenderer, PlainLogRenderer
from runtime_engine.terminal.views import (
    event_view,
    incident_view,
    metrics_view,
    process_view,
    security_view,
)
from runtime_engine.terminal.views.security_common import finding_detail

Prompt = Callable[[str], str]

# Core command sets used across all screens
DASHBOARD_COMMANDS = (
    ("h", "Help"),
    ("p", "Processes"),
    ("i", "Incidents"),
    ("e", "Events"),
    ("l", "Live logs"),
    ("r", "Alerts"),
    ("m", "Metrics"),
    ("t", "Process tree"),
    ("s", "Security modules"),
    ("q", "Stop monitoring"),
)

# Set of page keys that open inspection pages (used for dashboard loop)
PAGES = {"p", "i", "e", "m", "r", "l", "t", "s"}

INSPECTION_COMMANDS = (
    ("b", "Back"),
    ("q", "Stop monitoring"),
    ("h", "Help"),
)


class KeyReader(Protocol):
    def __enter__(self) -> "KeyReader": ...
    def __exit__(self, *args: object) -> None: ...
    def read_key(self, timeout: float) -> str | None: ...
    def suspend(self) -> contextlib.AbstractContextManager[None]: ...


class TerminalKeys:
    """Single-key input in cbreak mode; line input (prompts) restores normal mode."""

    def __init__(self, stream: TextIO = sys.stdin) -> None:
        self.stream = stream
        self.saved: list[Any] | None = None

    def __enter__(self) -> "TerminalKeys":  # pragma: no cover - requires a real TTY
        import termios
        import tty

        fd = self.stream.fileno()
        self.saved = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        return self

    def __exit__(self, *args: object) -> None:  # pragma: no cover - requires a real TTY
        self._restore()

    def _restore(self) -> None:  # pragma: no cover - requires a real TTY
        import termios

        if self.saved is not None:
            termios.tcsetattr(self.stream.fileno(), termios.TCSADRAIN, self.saved)

    def read_key(self, timeout: float) -> str | None:  # pragma: no cover - requires a real TTY
        fd = self.stream.fileno()
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return None
        data = os.read(fd, 32)  # also swallows the rest of escape sequences (arrow keys)
        return data[:1].decode("ascii", errors="ignore") or None

    @contextlib.contextmanager
    def suspend(self) -> Iterator[None]:  # pragma: no cover - requires a real TTY
        import tty

        self._restore()
        try:
            yield
        finally:
            tty.setcbreak(self.stream.fileno())


class RenderingUnavailable(Exception):
    """The terminal rejected dashboard output repeatedly; fall back to line output."""


class Inspector:
    """Inspection pages. With `state=None` they show stored (historical) data only."""

    def __init__(
        self,
        console: Console,
        prompt: Prompt,
        *,
        database: Database,
        rules: list[Rule],
        source: InvestigationSource,
        reports_directory: Path,
        state: DashboardState | None = None,
        liveness: Callable[[Event], Liveness] = check,
        started: Callable[[Event], datetime | None] = start_time,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.console = console
        self.prompt = prompt
        self.database = database
        self.rules = rules
        self.source = source
        self.reports_directory = reports_directory
        self.state = state
        self.liveness = liveness
        self.started = started
        self.clock = clock

    def ask(self, message: str) -> str:
        return self.prompt(message).strip()

    def say(self, message: str, style: str = "yellow") -> None:
        self.console.print(Text(message, style=style))

    def dispatch(self, key: str) -> None:
        """Dispatch a key press to the appropriate inspection page."""
        key = key.lower()
        if key == "h":
            self.help_page()
        elif key == "q":
            raise StopMonitoring("user_quit")
        elif key == "b":
            return  # return to dashboard
        elif key == "t":
            self.process_tree_page()
        elif key == "s":
            self.security_page()
        else:
            # Show banner for inspection pages
            self._banner()
            # Try as inspection command
            pages: dict[str, Callable[[], None]] = {
                "p": self.process_page,
                "i": self.incident_page,
                "e": self.event_page,
                "m": self.metrics_page,
                "r": self.alerts_page,
            }
            if key in pages:
                pages[key]()
            else:
                self.say(f"Unknown command [{key}].")

    def _banner(self) -> None:
        if self.state is None:
            return
        snap = self.state.snapshot(log_limit=0)
        self.console.print(
            Text(
                f"Monitoring continues in the background: {snap.counters.processed:,} events "
                f"processed, {snap.counters.rule_matches} rule matches, "
                f"{len(snap.incidents)} incidents. Blank input returns to the dashboard.",
                style="dim",
            )
        )

    # ----- help / metrics / alerts -----

    def help_page(self) -> None:
        telemetry = self.state.info.telemetry if self.state else "stored data"
        self.console.print(metrics_view.render_help(telemetry))
        self.ask("Press Enter to return to the dashboard ")

    def metrics_page(self) -> None:
        assert self.state is not None
        self.console.print(metrics_view.render_metrics(self.state.snapshot(log_limit=0)))
        self.ask("Press Enter to return to the dashboard ")

    def alerts_page(self) -> None:
        assert self.state is not None
        alerts = self.state.alert_list()
        processes = {
            a.process_key: p
            for a, _ in alerts
            if a.process_key and (p := self.state.process(a.process_key)) is not None
        }
        self.console.print(metrics_view.render_alert_list(alerts, processes))
        self.state.acknowledge_notifications()
        if not alerts:
            self.ask("Press Enter to return to the dashboard ")
            return
        answer = self.ask("Incident ID to inspect (blank to return): ")
        if answer:
            self.open_incident(answer)

    # ----- processes -----

    def process_page(self, key: str | None = None) -> None:
        if key is None:
            suspicious = self.state.suspicious_processes() if self.state else []
            self.console.print(
                process_view.render_process_list(suspicious, "Select a process to inspect")
            )
            while key is None:
                answer = self.ask("Enter PID (blank to return): ")
                if not answer:
                    return
                key = self.choose_identity(answer)
        self.show_process(key)

    def choose_identity(self, answer: str) -> str | None:
        try:
            pid = int(answer)
        except ValueError:
            self.say("A PID must be a whole number.")
            return None
        identities = [e for e in self.source.identities(pid) if e.process_key]
        if not identities:
            where = "in this session" if self.state else "in the database"
            self.say(f"No process with PID {pid} was observed {where}.")
            return None
        if len(identities) == 1:
            return identities[0].process_key
        self.console.print(process_view.render_identity_choices(identities))
        pick = self.ask("Row # (blank to cancel): ")
        if pick.isdigit() and 1 <= int(pick) <= len(identities):
            return identities[int(pick) - 1].process_key
        return None

    def show_process(self, key: str) -> None:
        current: str | None = key
        while current is not None:
            details = process_details(self.source, current, self.liveness, self.started)
            if details is None:
                self.say("That process identity is not in the session or the database.")
                return
            self.console.print(process_view.render_process_details(details))
            self.console.print(process_view.render_actions())
            current = None
            while current is None:
                choice = self.ask("Select action [1-6]: ")
                if choice in ("", "6", "b", "q"):
                    return
                if choice == "1":
                    parent = details.lineage[-2] if len(details.lineage) > 1 else None
                    if parent is not None and parent.event is not None:
                        current = parent.key
                    elif parent is not None:
                        self.say(
                            f"The parent (PID {clean(parent.pid)}) was referenced but never "
                            "observed, so no details are available."
                        )
                    else:
                        self.say("No parent identity was reported for this process.")
                elif choice == "2":
                    self.console.print(process_view.render_children(details))
                    if details.children:
                        pick = self.ask("Child # to inspect (blank to stay): ")
                        if pick.isdigit() and 1 <= int(pick) <= len(details.children):
                            current = details.children[int(pick) - 1].process_key
                elif choice == "3":
                    self.console.print(process_view.render_full_ancestry(details))
                elif choice == "4":
                    self.console.print(process_view.render_alerts(details))
                elif choice == "5":
                    if not details.incidents:
                        self.say("No incident involves this process.", "dim")
                        continue
                    for incident in details.incidents:
                        line = Text(f"  {incident.incident_id} ")
                        line.append_text(severity_text(incident.severity))
                        self.console.print(line)
                    answer = self.ask("Incident ID to open (blank to stay): ")
                    if answer:
                        self.open_incident(answer)
                        return
                else:
                    self.say("Unknown action.")

    # ----- incidents -----

    def _incidents(self) -> list[str]:
        incidents = self.state.incident_list() if self.state else self.database.incidents()
        return [i.incident_id for i in incidents]

    def incident_page(self) -> None:
        incidents = self.state.incident_list() if self.state else self.database.incidents()
        active = self.state.active_incident_ids() if self.state else frozenset()
        self.console.print(incident_view.render_incident_list(incidents, active))
        if not incidents:
            self.ask("Press Enter to return to the dashboard ")
            return
        answer = self.ask("Select incident ID (blank to return): ")
        if answer:
            self.open_incident(answer)

    @staticmethod
    def normalize_incident(answer: str) -> str:
        text = answer.strip().upper()
        if text.isdigit():
            return f"INC-{int(text):04d}"
        return text

    def open_incident(self, answer: str) -> None:
        incident_id = self.normalize_incident(answer)
        if incident_id not in self._incidents():
            self.say(f"Unknown incident {clean(incident_id)}.")
            return
        active = (incident_id in self.state.active_incident_ids()) if self.state else None
        details = incident_details(self.database, incident_id, self.rules, active)
        if details is None:
            self.say("The incident has not been persisted yet; try again in a moment.")
            return
        self.console.print(incident_view.render_incident_details(details))
        self.console.print(process_view.render_actions(incident_view.ACTIONS))
        while True:
            choice = self.ask("Select action [1-5]: ")
            if choice in ("", "5", "b", "q"):
                return
            if choice == "1":
                self.console.print(incident_view.render_related_events(details))
            elif choice == "2":
                processes = sorted(
                    details.processes,
                    key=lambda e: e.process_key not in details.incident.process_keys,
                )
                if not processes:
                    self.say("No process identity was recorded for this incident.")
                    continue
                table = Table(title="RELATED PROCESSES", title_justify="left")
                for column in ("#", "PID", "PROCESS", "ROLE"):
                    table.add_column(column)
                for index, event in enumerate(processes, 1):
                    role = (
                        "rule match"
                        if event.process_key in details.incident.process_keys
                        else "context"
                    )
                    table.add_row(str(index), clean(event.pid), clean(event.process_name, 24), role)
                self.console.print(table)
                pick = self.ask("Process # (blank to stay): ")
                if pick.isdigit() and 1 <= int(pick) <= len(processes):
                    key = processes[int(pick) - 1].process_key
                    if key:
                        self.show_process(key)
                        return
            elif choice == "3":
                self.console.print(incident_view.render_evidence(details))
            elif choice == "4":
                self.export(incident_id, details.report)
            else:
                self.say("Unknown action.")

    def export(self, incident_id: str, report: dict[str, object]) -> Path | None:
        stamp = self.clock().astimezone().strftime("%Y%m%dT%H%M%S")
        default = self.reports_directory / f"{incident_id}-{stamp}.json"
        answer = self.ask(f"Export path [{default}]: ")
        path = Path(answer).expanduser() if answer else default
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Never overwrite; reports may contain sensitive telemetry, so owner-only mode.
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(export_json(report))
        except FileExistsError:
            self.say(f"Refusing to overwrite existing file {clean(str(path))}.")
            return None
        except OSError as exc:
            self.say(f"Export failed: {type(exc).__name__} for {clean(str(path))}.")
            return None
        resolved = str(path.resolve())
        if self.state is not None:
            self.state.record_export(resolved)
        self.say(f"Exported {incident_id} to {clean(resolved)} (mode 0600).", "green")
        return path

    # ----- events -----

    def _records(self) -> list[EventRecord]:
        if self.state is not None:
            return self.state.event_records()
        return records_from_database(self.database, self.database.recent_events(500))

    # ----- process tree -----

    def process_tree_page(self) -> None:
        """Open the process tree view."""
        from runtime_engine.terminal.dashboard import render_process_tree

        tree = self.state.build_process_tree() if self.state else {}
        selected_key = None

        # Root the view at a process with a rule match, if any.
        if self.state:
            for key in tree:
                record = self.state.process(key)
                if record is not None and record.severity is not None:
                    selected_key = key
                    break

        if selected_key is None:
            selected_key = next(iter(tree)) if tree else None

        # Render the tree
        try:
            tree_render = render_process_tree(
                self.state,
                self.console.width,
                self.console.height,
                process_tree=tree,
                selected_key=selected_key,
            )
            self.console.print(tree_render)
        except Exception as e:
            self.say(f"Error rendering process tree: {e}")

        # Ask to go back
        self.ask("Press Enter to return to the dashboard ")

    def event_page(self) -> None:
        self.console.print(Text(event_view.FILTER_HELP, style="dim"))
        while True:
            answer = self.ask("Filter (blank = all recent, 'q' to return): ")
            if answer.lower() in ("q", "b"):
                return
            try:
                spec = parse_filter(answer, self.clock())
            except ValueError as exc:
                self.say(f"Invalid filter: {clean(str(exc))}")
                continue
            if not self.show_events(spec):
                return

    def show_events(self, spec: EventFilter, limit: int = 40) -> bool:
        """Show matches; False means return to the dashboard, True means new filter."""
        records = self._records()
        matches = filter_records(records, spec)
        self.console.print(
            event_view.render_event_table(
                matches, spec, len(records), limit, width=self.console.width
            )
        )
        shown = matches[-limit:]
        while True:
            pick = self.ask("Row # for full details, 'f' for a new filter, blank to return: ")
            if not pick:
                return False
            if pick.lower() == "f":
                return True
            if pick.isdigit() and 1 <= int(pick) <= len(shown):
                record = shown[int(pick) - 1]
                alerts = (
                    self.state.alerts_by_id(record.alert_ids)
                    if self.state
                    else self.database.alerts(list(record.alert_ids))
                )
                self.console.print(event_view.render_event_details(record, alerts))
            else:
                self.say("Unknown row.")

    # ----- security modules -----

    def _security_overview(self) -> dict[str, dict[str, Any]]:
        if self.state is not None:
            return self.state.security.overview()
        overview: dict[str, dict[str, Any]] = {}
        for module in MODULES:  # historical: last stored scan and findings per module
            body = self.database.baseline(module, "last-scan")
            findings = self._security_findings(module)
            overview[module] = {
                "enabled": "enabled" if body else "no stored scan",
                "status": body.get("status") if body else None,
                "last_scan": body.get("started_at") if body else None,
                "scans": 1 if body else 0,
                "findings": len(findings),
                "promoted": sum(1 for f in findings if f.promoted),
                "by_severity": dict(Counter(f.severity.value for f in findings)),
            }
        return overview

    def _security_findings(self, module: str) -> list[Finding]:
        if self.state is not None:
            return self.state.security.recent(module)
        fields = Finding.model_fields
        return [
            Finding.model_validate({k: v for k, v in row.items() if k in fields})
            for row in self.database.findings(module)
        ]

    def show_finding(self, finding: Finding) -> None:
        # The stored row adds first/last seen and occurrences across scans.
        self.console.print(finding_detail(self.database.finding(finding.finding_id) or finding))

    def _security_report(self, module: str) -> ScanReport | None:
        if self.state is not None:
            return self.state.security.report(module)
        body = self.database.baseline(module, "last-scan")
        return ScanReport.from_dict(body) if body else None

    def security_page(self) -> None:
        """Menu of the six security modules; cached results only, never triggers a scan."""
        while True:
            self.console.print(security_view.render_security_menu(self._security_overview()))
            answer = self.ask("Module # or name, or a finding ID (blank to return): ")
            if not answer or answer.lower() in ("b", "q"):
                return
            module = security_view.resolve_module(answer)
            if module is not None:
                self.security_module_page(module)
                continue
            everything = [f for m in MODULES for f in self._security_findings(m)]
            finding = security_view.find_finding(everything, answer)
            if finding is None:
                self.say(f"No module or finding matches {clean(answer)!r}.")
            else:
                self.show_finding(finding)

    def security_module_page(self, module: str) -> None:
        minimum: Severity | None = None
        rule: str | None = None
        while True:
            findings = self._security_findings(module)
            self.console.print(
                security_view.render_module_page(
                    module,
                    self._security_overview().get(module, {}),
                    self._security_report(module),
                    findings,
                    minimum=minimum,
                    rule=rule,
                )
            )
            answer = self.ask(
                "Finding ID for details, 'sev LEVEL' or 'rule ID' to filter, 'c' to clear, "
                "Enter to refresh, 'b' to go back: "
            )
            words = answer.split()
            if answer.lower() in ("b", "q"):
                return
            if not words:
                continue
            if answer.lower() == "c":
                minimum = rule = None
            elif words[0].lower() in ("sev", "severity") and len(words) == 2:
                try:
                    minimum = Severity(words[1].upper())
                except ValueError:
                    self.say("Severity must be LOW, MEDIUM, HIGH or CRITICAL.")
            elif words[0].lower() == "rule" and len(words) == 2:
                rule = words[1].upper()
            else:
                finding = security_view.find_finding(findings, answer)
                if finding is None:
                    self.say(f"No {module} finding matches {clean(answer)!r}.")
                    continue
                self.show_finding(finding)
                self.ask("Press Enter to return to the module page ")

    # ----- live logs -----

    def live_logs_page(self, read_key: Callable[[float], str | None]) -> str | None:
        """Open the live event log view. Monitoring continues in the background.

        Returns "user_quit" if the user pressed q, otherwise None (back to dashboard).
        """
        assert self.state is not None
        result = LiveLogRenderer(self.console, self.state, read_key=read_key).run()
        return "user_quit" if result == "user_quit" else None


class StopMonitoring(Exception):
    """Raised when the user presses q to stop monitoring."""

    def __init__(self, reason: str):
        self.reason = reason


class InteractiveMonitor:
    """Live dashboard with single-key commands. Rendering never blocks the pipeline."""

    def __init__(
        self,
        session: MonitorSession,
        console: Console,
        keys: KeyReader,
        inspector: Inspector,
        *,
        refresh: float,
        live_factory: Callable[..., Live] = Live,
        max_render_failures: int = 3,
        fallback: PlainLogRenderer | None = None,
    ) -> None:
        self.session = session
        self.state = session.state
        self.console = console
        self.keys = keys
        self.inspector = inspector
        self.refresh = refresh
        self.live_factory = live_factory
        self.max_render_failures = max_render_failures
        self.renderer = DashboardRenderer(self.state, interactive=True)
        self.fallback = fallback or PlainLogRenderer(self.state, console, self.state.info.verbosity)
        self.fell_back = False

    def _live(self) -> Live:
        return self.live_factory(
            console=self.console,
            screen=True,
            auto_refresh=False,
            redirect_stdout=False,
            redirect_stderr=False,
            transient=True,
        )

    def _draw(self, live: Live, failures: int) -> int:
        try:
            live.update(self.renderer.build(self.console.width, self.console.height), refresh=True)
            return 0
        except Exception as exc:
            self.state.record_render_error(type(exc).__name__)
            if failures + 1 >= self.max_render_failures:
                raise RenderingUnavailable from exc
            return failures + 1

    def _dashboard(self) -> str:
        """Render until a command or a stop; returns a page key or a stop reason."""
        failures = 0
        with self._live() as live:
            while True:
                if self.session.stopping:
                    return self.session.reason or "error"
                failures = self._draw(live, failures)
                key = self.keys.read_key(self.refresh)
                if key is None:
                    continue
                key = key.lower()
                if key == "q":
                    return "user_quit"
                if key in PAGES or key == "h":
                    return key

    def run(self) -> str:
        """Returns the stop reason. Ctrl+C anywhere (dashboard or page) stops gracefully."""
        try:
            with self.keys:
                while True:
                    outcome = self._dashboard()
                    if outcome not in PAGES and outcome != "h":
                        return outcome
                    if outcome == "l":
                        # Live logs keep single-key input, so the keys stay in cbreak mode.
                        if self.inspector.live_logs_page(self.keys.read_key) == "user_quit":
                            return "user_quit"
                        continue
                    with self.keys.suspend():
                        try:
                            self.inspector.dispatch(outcome)
                        except StopMonitoring as stop:
                            return stop.reason
        except KeyboardInterrupt:
            return self.session.reason or "keyboard_interrupt"
        except RenderingUnavailable:
            self.fell_back = True
            self.console.print(
                Text(
                    "Dashboard output failed repeatedly; continuing with line output.",
                    style="bold yellow",
                )
            )
            return run_plain(self.session, self.fallback)

    def drain(self, reason: str) -> None:
        """Show the STOPPING screen while accepted events finish; Ctrl+C again forces."""
        self.session.begin_stop(reason)
        try:
            with self._live() as live:
                while not self.session.processor_done.wait(0.1):
                    with contextlib.suppress(Exception):
                        live.update(
                            self.renderer.build(self.console.width, self.console.height),
                            refresh=True,
                        )
        except KeyboardInterrupt:
            self.session.force()
        except Exception as exc:
            self.state.record_render_error(type(exc).__name__)


def run_plain(session: MonitorSession, renderer: PlainLogRenderer, interval: float = 0.25) -> str:
    """Non-interactive loop: print new log lines until a stop is requested."""
    try:
        while not session.wait(interval):
            renderer.flush()
    except KeyboardInterrupt:
        return session.reason or "keyboard_interrupt"
    renderer.flush()
    return session.reason or "error"
