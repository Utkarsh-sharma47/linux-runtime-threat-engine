"""Live event stream formatting for the dashboard panel and for line-oriented output."""

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from runtime_engine.monitor.state import EntryKind, LogEntry, Verbosity
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
    """Newest entries at the bottom, sized to the panel so the layout never scrolls."""
    capacity = max(0, (height - 2) // 2)
    shown = entries[-capacity:] if capacity else []
    title = f"LIVE SECURITY EVENTS (verbosity: {verbosity.name.lower()})"
    if not shown:
        body: RenderableType = Text(
            "No events to display yet at this verbosity. Waiting for the collector...",
            style="dim",
        )
    else:
        body = Group(*(line for e in shown for line in entry_lines(e)))
    return Panel(body, title=title, title_align="left", border_style="blue", height=height)
