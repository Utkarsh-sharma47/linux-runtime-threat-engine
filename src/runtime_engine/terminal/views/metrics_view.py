"""Live metrics, the session alert list and the help page."""

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.events.schema import Alert
from runtime_engine.monitor.investigation import identity
from runtime_engine.monitor.state import DashboardSnapshot, ProcessRecord
from runtime_engine.terminal.formatting import (
    clean,
    duration,
    memory,
    milliseconds,
    number,
    severity_text,
    timestamp,
)


def render_metrics(snap: DashboardSnapshot) -> RenderableType:
    c, latency = snap.counters, snap.latency
    elapsed = (snap.now - snap.info.started_at).total_seconds()
    table = Table(title="LIVE METRICS (this session)", title_justify="left")
    table.add_column("GROUP", style="bold")
    table.add_column("METRIC")
    table.add_column("VALUE", justify="right")
    rows = [
        ("Session", "Session ID", snap.info.session_id),
        ("Session", "Duration", duration(elapsed)),
        ("Session", "Polls", number(c.polls)),
        ("Events", "Processed", number(c.processed)),
        ("Events", "Dropped", number(c.dropped)),
        ("Queue", "Depth / capacity", f"{c.queue_depth} / {number(snap.info.queue_capacity)}"),
        ("Queue", "Peak depth", number(c.queue_peak)),
        ("Detection", "Rule matches", number(c.rule_matches)),
        ("Detection", "Unique alerts", number(snap.unique_alerts)),
        (
            "Detection",
            "Incidents (active)",
            f"{len(snap.incidents)} ({len(snap.active_incident_ids)})",
        ),
        ("Health", "Collector errors", number(c.collector_errors)),
        ("Health", "Read failures", number(c.read_failures)),
        ("Health", "Avg latency / event", milliseconds(latency.average_ms)),
        ("Health", "P95 latency / event", milliseconds(latency.p95_ms)),
        ("Health", "Memory (peak RSS)", memory(snap.peak_rss_kb)),
        ("Health", "Render errors", number(c.render_errors)),
    ]
    for group, metric, value in rows:
        table.add_row(group, metric, value)
    note = Text(
        "Metrics cover the current monitoring session only. "
        "Historical session summaries remain available via the session CLI.",
        style="dim",
    )
    return Group(table, note)


def render_alert_list(
    alerts: list[tuple[Alert, str | None]], processes: dict[str, ProcessRecord]
) -> RenderableType:
    if not alerts:
        return Panel(
            Text("No rule has matched in this session.", style="dim"),
            title="RECENT ALERTS",
            title_align="left",
        )
    table = Table(
        title="RECENT ALERTS (deduplicated; newest last)",
        title_justify="left",
        caption="COUNT = matched events folded into this alert by deduplication.",
    )
    table.add_column("LAST SEEN", no_wrap=True)
    table.add_column("RULE")
    table.add_column("NAME")
    table.add_column("SEVERITY")
    table.add_column("PID", justify="right")
    table.add_column("PROCESS")
    table.add_column("COUNT", justify="right")
    table.add_column("INCIDENT")
    for alert, incident_id in sorted(alerts, key=lambda pair: pair[0].last_seen):
        parsed = identity(alert.process_key) if alert.process_key else None
        record = processes.get(alert.process_key or "")
        table.add_row(
            timestamp(alert.last_seen),
            alert.rule_id,
            clean(alert.rule_name, 40),
            severity_text(alert.severity),
            str(parsed[1]) if parsed else "-",
            clean(record.event.process_name if record else None, 16),
            str(len(alert.event_ids)),
            incident_id or "-",
        )
    return table


def render_help(telemetry: str) -> RenderableType:
    commands = Table(title="COMMANDS", title_justify="left", show_header=False)
    commands.add_column(style="bold")
    commands.add_column()
    for key, text in (
        ("1 / h", "Help"),
        ("2 / l", "Live event log (b returns)"),
        ("3 / p", "Suspicious processes (details on selection)"),
        ("4 / t", "Suspicious activity / process ancestry"),
        ("5 / n", "Network destinations, ports, attribution, indicators"),
        ("6 / s", "Security modules (status + details on open)"),
        ("7 / i", "Incidents (summary; evidence on selection)"),
        ("8 / a", "Atomic / lab execution sessions"),
        ("9 / m", "Session metrics / health"),
        ("e", "Event filters (blank returns; 'all' shows newest)"),
        ("r", "Alerts (clears pinned notifications)"),
        ("q", "Stop monitoring gracefully and print the session report"),
        ("Ctrl+C", "Same as q. A second Ctrl+C during shutdown forces the stop."),
    ):
        commands.add_row(key, text)
    legend = Text.assemble(
        ("Categories\n", "bold"),
        ("  OBSERVED     ", "dim"),
        "raw telemetry; not a finding\n",
        ("  RULE MATCH   ", "bold yellow"),
        "a detection rule matched (indicator for review)\n",
        ("  INCIDENT     ", "bold red"),
        "rule matches correlated by process identity/ancestry in a time window\n",
        ("  ERROR        ", "bold"),
        "monitoring failure, never a security finding\n",
        ("  TELEMETRY GAP", "cyan"),
        " a field or entry could not be read\n\n",
        ("Telemetry: ", "bold"),
        clean(telemetry),
        "\nMonitoring continues in the background while any page is open.",
    )
    return Group(commands, legend)
