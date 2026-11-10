"""Event inspection that keeps raw observations, rule matches and incidents distinct."""

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.events.schema import Alert, Event
from runtime_engine.incidents.reporter import export_json
from runtime_engine.monitor.investigation import EventFilter
from runtime_engine.monitor.state import EventRecord
from runtime_engine.terminal.formatting import (
    clean,
    clock_ms,
    command_line,
    severity_text,
    timestamp,
)

FILTER_HELP = (
    "Filters (space separated key=value, all must match):\n"
    "  pid=1234  name=bash  type=PROCESS_START|FILE_ACCESS|NETWORK_CONNECTION|...\n"
    "  severity=MEDIUM (at least)  since=10m|30s|2h|14:05|ISO  until=...  incident=INC-0001\n"
    "  kind=observed (no rule match) | match (rule matched) | incident (correlated)"
)


def detail(event: Event, limit: int | None = 48) -> str:
    if event.file_path:
        return clean(event.file_path, limit)
    if event.network_destination:
        return clean(event.network_destination, limit)
    if event.previous_uid is not None:
        return f"uid {event.previous_uid} -> {clean(event.uid)}"
    if event.command_line:
        return command_line(event.command_line, limit)
    return clean(event.executable_path, limit)


def kind(record: EventRecord) -> Text:
    if record.incident_ids:
        return Text("INCIDENT EVIDENCE", style="bold red")
    if record.rule_ids:
        return Text("RULE MATCH", style="bold yellow")
    return Text("OBSERVED", style="dim")


def render_event_table(
    records: list[EventRecord],
    spec: EventFilter,
    total: int,
    limit: int = 40,
    width: int = 140,
) -> RenderableType:
    """Narrow terminals drop the free-text DETAIL column instead of crushing identifiers."""
    shown = records[-limit:]
    caption = (
        f"{len(records)} matching of {total} event(s) searched; showing the newest "
        f"{len(shown)}. Filter: {clean(spec.describe())}"
    )
    if not shown:
        return Panel(
            Text("No events match this filter.\n" + caption, style="dim"),
            title="RECENT EVENTS",
            title_align="left",
        )
    wide = width >= 120
    table = Table(title="RECENT EVENTS", title_justify="left", caption=caption, box=box.SIMPLE_HEAD)
    for name in ("#", "TIME", "CATEGORY", "TYPE", "PID", "PROCESS", "SEVERITY", "RULES"):
        table.add_column(name, no_wrap=True, justify="right" if name in ("#", "PID") else "left")
    table.add_column("INCIDENT", no_wrap=True)
    if wide:
        table.add_column("DETAIL", overflow="ellipsis", no_wrap=True, max_width=50)
    for index, record in enumerate(shown, 1):
        event = record.event
        row: list[RenderableType] = [
            str(index),
            clock_ms(event.timestamp),
            kind(record),
            event.event_type.value + (" [baseline]" if record.baseline and wide else ""),
            clean(event.pid),
            clean(event.process_name, 16),
            severity_text(record.severity, normal="-"),
            ", ".join(record.rule_ids) or "-",
            ", ".join(record.incident_ids) or "-",
        ]
        if wide:
            row.append(detail(event))
        table.add_row(*row)
    return table


def render_event_details(record: EventRecord, alerts: list[Alert]) -> RenderableType:
    event = record.event
    raw = Panel(
        Text(export_json(event.model_dump(mode="json"))),
        title="RAW OBSERVED EVENT (normalized telemetry; not a finding by itself)",
        title_align="left",
    )
    if alerts:
        matches = Table(title="RULE MATCHES ON THIS EVENT", title_justify="left")
        matches.add_column("RULE")
        matches.add_column("NAME")
        matches.add_column("SEVERITY")
        matches.add_column("MATCHED CONDITIONS", overflow="fold")
        for alert in alerts:
            matches.add_row(
                alert.rule_id,
                clean(alert.rule_name),
                severity_text(alert.severity),
                clean(alert.reason),
            )
        rule_part: RenderableType = matches
    else:
        rule_part = Text("RULE MATCHES ON THIS EVENT: none", style="dim")
    incidents = Text(
        "CORRELATED INCIDENTS: "
        + (", ".join(record.incident_ids) if record.incident_ids else "none"),
        style="bold" if record.incident_ids else "dim",
    )
    received = Text(
        f"Event time: {timestamp(event.timestamp)}   Engine processed: "
        f"{timestamp(record.received_at)}",
        style="dim",
    )
    return Group(raw, rule_part, incidents, received)
