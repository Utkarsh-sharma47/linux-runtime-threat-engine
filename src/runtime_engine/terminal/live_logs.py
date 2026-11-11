"""Live event stream formatting for the dashboard panel and for line-oriented output.
# type: ignore

Also provides LiveLogRenderer for the dedicated live-logs inspection page.
"""

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from runtime_engine.monitor.state import DashboardState, EntryKind, LogEntry, Verbosity
from runtime_engine.terminal.formatting import (
    LEVEL_STYLES,
    clean,
    clock_ms,
    level_text,
    severity_style,
)

# Long free-text values are shortened in the stream; inspection views show them in full.
FIELD_LIMITS = {"CMD": 60, "EXE": 48, "REASON": 90, "NAME": 40, "NOTE": 70, "MESSAGE": 100}
KIND_TAGS = {
    EntryKind.RULE_MATCH: "[RULE MATCH]",
    EntryKind.DUPLICATE_MATCH: "[REPEAT - deduplicated]",
    EntryKind.INCIDENT: "[CORRELATED INCIDENT]",
    EntryKind.ERROR: "[MONITORING ERROR - not a security finding]",
    EntryKind.TELEMETRY: "[TELEMETRY GAP]",
    EntryKind.DIAGNOSTIC: "[internal diagnostic]",
    EntryKind.OBSERVED: "[OBSERVED]",
}


def visible(entry: LogEntry, verbosity: Verbosity) -> bool:
    return entry.min_verbosity <= verbosity


def _fields(entry: LogEntry, limit_scale: float = 1.0) -> str:
    parts = []
    for key, value in entry.fields:
        limit = FIELD_LIMITS.get(key)
        parts.append(f"{key}={clean(value, int((limit or 120) * limit_scale))}")
    return " ".join(parts)


def _title_style(entry: LogEntry) -> str:
    if entry.kind in (EntryKind.RULE_MATCH, EntryKind.INCIDENT):
        return severity_style(entry.severity) or "bold"
    if entry.kind == EntryKind.ERROR:
        return LEVEL_STYLES["ERROR"]
    if entry.kind == EntryKind.OBSERVED:
        return "bold" if entry.severity else ""
    return LEVEL_STYLES.get(entry.level, "")


def entry_lines(entry: LogEntry) -> tuple[Text, Text]:
    """Two single lines that are truncated, never wrapped, so panel sizing stays exact."""
    header = Text(no_wrap=True, overflow="ellipsis")
    header.append(f"[{clock_ms(entry.at)}] ", style="dim")
    header.append_text(level_text(entry.level))
    header.append(" ")
    header.append(clean(entry.title), style=_title_style(entry))
    tag = KIND_TAGS.get(entry.kind)
    if tag:
        header.append(f" {tag}", style=_title_style(entry))
    if entry.severity is not None and entry.kind != EntryKind.OBSERVED:
        header.append("  SEVERITY=")
        header.append(entry.severity.value, style=severity_style(entry.severity))
    body = Text("    " + _fields(entry), no_wrap=True, overflow="ellipsis")
    body.stylize("dim" if entry.kind == EntryKind.OBSERVED and not entry.severity else "")
    return header, body


def entry_text(entry: LogEntry) -> Group:
    return Group(*entry_lines(entry))


def plain_line(entry: LogEntry) -> str:
    """One self-contained line for pipes, CI logs and other non-interactive output."""
    tag = KIND_TAGS.get(entry.kind, "")
    severity = (
        f" SEVERITY={entry.severity.value}"
        if entry.severity is not None and entry.kind != EntryKind.OBSERVED
        else ""
    )
    fields = _fields(entry, limit_scale=2.0)
    return (
        f"[{clock_ms(entry.at)}] {entry.level:<8} {clean(entry.title)}"
        f"{' ' + tag if tag else ''}{severity} {fields}".rstrip()
    )


def log_panel(entries: list[LogEntry], height: int, verbosity: Verbosity) -> RenderableType:
    body: RenderableType
    """Newest entries at the bottom, sized to the panel so the layout never scrolls."""
    capacity = max(0, (height - 2) // 2)
    shown = entries[-capacity:] if capacity else []
    title = f"LIVE SECURITY EVENTS (verbosity: {verbosity.name.lower()})"
    if not shown:
        body = Text("No new events yet. Monitoring continues.", style="dim")
    else:
        # type: ignore[assignment]
            body = Group(*(line for e in shown for line in entry_lines(e)))
    return Panel(body, title=title, title_align="left", border_style="blue", height=height)


class LiveLogRenderer:
    """Live event log view that runs in a dedicated Rich Live context.

    - Shows incoming events continuously.
    - Distinguishes normal observations from rule matches and incidents.
    - Pause/resume only renders, never stops event collection.
    - Filter support via verbosity toggle.
    - User can return to dashboard with [b].
    - Bounded display buffer; events are never lost from the pipeline.
    """

    TOGGLE_VERBOSITY = "f"
    PAUSE_DISPLAY = "p"
    BACK_TO_DASHBOARD = "b"
    QUIT = "q"

    def __init__(
        self,
        console: Console,
        state: DashboardState,
        *,
        pause_shortcut: str = "p",
        filter_shortcut: str = "f",
    ) -> None:
        self.console = console
        self.state = state
        self.paused = False
        self.filter_verbosity = Verbosity.NORMAL
        self.pause_shortcut = pause_shortcut
        self.filter_shortcut = filter_shortcut

    def _format_entry(self, entry: LogEntry) -> tuple[Text, Text]:
        """Format a single log entry for display."""
        return entry_lines(entry)

    def _get_entries(self) -> list[LogEntry]:
        """Get entries to display based on current filter verbosity."""
        verbosity = self.filter_verbosity
        entries = self.state.visible_entries(verbosity)
        return entries

    def _draw(self, live: Live) -> None:
        """Render the current log state."""
        entries = self._get_entries()
        capacity = max(0, (self.console.height - 4) // 2)
        shown = entries[-capacity:] if capacity else []

        # Build display Group from entry lines
        lines: list[RenderableType] = []
        for e in shown:
            header, body = self._format_entry(e)
            lines.append(header)
            lines.append(body)

        title = f"LIVE SECURITY EVENTS (verbosity: {self.filter_verbosity.name.lower()})"
        if self.paused:
            title += "  [PAUSED]"

        if not shown and not self.paused:
            # Show waiting message only when not paused and no entries
            panel_body = Text("No new events yet. Monitoring continues.", style="dim")
        else:
            if lines:
                panel_body = Group(*lines)
            else:
                panel_body = Text("No new events yet. Monitoring continues.", style="dim")

        panel = Panel(
            panel_body,
            title=title,
            title_align="left",
            border_style="blue",
            height=self.console.height,
        )

        live.update(panel, refresh=False)

    def run(self) -> str:
        """Run the live logs inspection page.

        Returns the reason for leaving the page (reason to pass to monitor.shutdown).
        """
        failures = 0
        with Live(
            self.console,
            screen=True,
            auto_refresh=False,
            redirect_stdout=False,
            redirect_stderr=False,
            transient=True,
        ) as live:
            # Initial draw
            self._draw(live)
            live.refresh()

            while True:
                # Read key press (non-blocking with short timeout)
                key = self._read_key(timeout=0.1)
                if key is not None:
                    key = key.lower()
                    result = self._handle_key(key)
                    if result is not None:
                        return result

                # Periodic draw
                try:
                    self._draw(live)
                    live.refresh()
                except Exception:
                    failures += 1
                    if failures >= 5:
                        raise

    def _read_key(self, timeout: float) -> str | None:
        """Read a single key from the terminal stdin."""
        import os
        import select

        try:
            fd = self.console.file.fileno()
        except (AttributeError, OSError):
            return None

        try:
            ready, _, _ = select.select([fd], [], [], timeout)
            if not ready:
                return None
            data = os.read(fd, 32)
            if not data:
                return None
            return data[:1].decode("ascii", errors="ignore") or None
        except (OSError, ValueError):
            return None

    def _handle_key(self, key: str) -> str | None:
        """Handle a key press. Returns a stop reason string, or None to continue."""
        if key == self.QUIT:
            return "user_quit"
        elif key == self.BACK_TO_DASHBOARD:
            # Return to dashboard - signal to the caller
            return "return_to_dashboard"
        elif key == self.PAUSE_DISPLAY:
            self.paused = not self.paused
            return None
        elif key == self.TOGGLE_VERBOSITY:
            # Cycle through verbosity levels
            if self.filter_verbosity == Verbosity.DEBUG:
                self.filter_verbosity = Verbosity.NORMAL
            elif self.filter_verbosity == Verbosity.VERBOSE:
                self.filter_verbosity = Verbosity.NORMAL
            else:
                self.filter_verbosity = Verbosity.VERBOSE
            return None
        else:
            # Unknown key - ignore but don't crash
            return None