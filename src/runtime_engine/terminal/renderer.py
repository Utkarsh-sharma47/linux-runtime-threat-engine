"""Renderers that cannot take monitoring down: failures are counted and replaced by fallbacks."""

import os
import sys
import time
from collections.abc import Callable

from rich.console import Console, RenderableType
from rich.panel import Panel
from rich.text import Text

from runtime_engine.monitor.state import DashboardSnapshot, DashboardState, Verbosity
from runtime_engine.terminal.dashboard import render_dashboard
from runtime_engine.terminal.live_logs import plain_line

Builder = Callable[..., RenderableType]


class SafeConsole(Console):
    """On a closed pipe, go quiet and raise BrokenPipeError instead of Rich's SystemExit.

    Rich's default handler exits the interpreter, which would skip the coordinated
    shutdown and the session persistence that must still happen.
    """

    def on_broken_pipe(self) -> None:
        self.quiet = True
        if self.file in (sys.stdout, sys.__stdout__):
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())  # silence the interpreter's final flush
            os.close(devnull)
        raise BrokenPipeError


class DashboardRenderer:
    def __init__(
        self, state: DashboardState, *, interactive: bool, builder: Builder = render_dashboard
    ) -> None:
        self.state = state
        self.interactive = interactive
        self.builder = builder

    def build(self, width: int, height: int) -> RenderableType:
        try:
            snap: DashboardSnapshot = self.state.snapshot(log_limit=max(10, height))
            return self.builder(snap, width, height, interactive=self.interactive)
        except Exception as exc:
            self.state.record_render_error(type(exc).__name__)
            return Panel(
                Text(
                    f"Dashboard rendering failed ({type(exc).__name__}). Monitoring continues; "
                    "press q to stop and print the session report.",
                    style="bold yellow",
                ),
                title="RENDER ERROR (display only - not a security finding)",
                border_style="yellow",
            )


class PlainLogRenderer:
    """Line-oriented output for pipes, CI, `--no-dashboard` and dashboard fallback."""

    def __init__(
        self,
        state: DashboardState,
        console: Console,
        verbosity: Verbosity,
        *,
        heartbeat_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.state = state
        self.console = console
        self.verbosity = verbosity
        self.cursor = 0
        self.heartbeat_seconds = heartbeat_seconds
        self.clock = clock
        self.last_heartbeat = clock()
        self.broken = False

    def _write(self, text: Text | str) -> None:
        self.console.print(text, soft_wrap=True, markup=False, highlight=False)

    def flush(self) -> int:
        """Print entries newer than the cursor; returns how many were printed."""
        if self.broken:
            return 0
        entries = self.state.visible_entries(self.verbosity, after=self.cursor)
        evicted = self.state.last_evicted(self.verbosity)
        try:
            if evicted > self.cursor:
                self._write(
                    Text(
                        "[display] some log entries were evicted from the bounded view buffer "
                        "before they could be printed; they remain in SQLite.",
                        style="yellow",
                    )
                )
            for entry in entries:
                style = {"WARNING": "bold yellow", "ALERT": "bold red", "ERROR": "bold red"}
                self._write(Text(plain_line(entry), style=style.get(entry.level, "")))
            if entries:
                self.cursor = entries[-1].seq
            self.cursor = max(self.cursor, evicted)
            if self.clock() - self.last_heartbeat >= self.heartbeat_seconds:
                self.last_heartbeat = self.clock()
                self._write(self.heartbeat())
        except OSError:
            # Closed pipe or terminal: stop writing; monitoring and persistence continue.
            self.broken = True
        return len(entries)

    def heartbeat(self) -> str:
        snap = self.state.snapshot(log_limit=0)
        c = snap.counters
        return (
            f"[status] {snap.status} observed={c.observed} processed={c.processed} "
            f"queue={c.queue_depth} matches={c.rule_matches} alerts={snap.unique_alerts} "
            f"incidents={len(snap.incidents)} dropped={c.dropped} errors={c.collector_errors}"
        )
