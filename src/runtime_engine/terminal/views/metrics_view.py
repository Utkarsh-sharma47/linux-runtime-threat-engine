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
    pipeline_rate = (
        c.processed / ((latency.average_ms or 0) * latency.samples / 1000)
        if latency.samples and latency.average_ms
        else None
    )
    table = Table(title="LIVE METRICS (measured in this session)", title_justify="left")
    table.add_column("GROUP", style="bold")
    table.add_column("METRIC")
    table.add_column("VALUE", justify="right")
    rows = [
        ("Session", "Duration", duration(elapsed)),
        ("Session", "Polls completed", number(c.polls)),
        ("Session", "Baseline processes (first poll)", number(c.baseline_processes)),
        ("Events", "Observed by collector", number(c.observed)),
        ("Events", "Accepted into queue", number(c.accepted)),
        ("Events", "Processed by pipeline", number(c.processed)),
        ("Events", "Duplicate events ignored", number(c.duplicate_events)),
        ("Events", "Rejected", number(c.rejected)),
        ("Events", "Dropped", number(c.dropped)),
        ("Queue", "Depth / capacity", f"{c.queue_depth} / {number(snap.info.queue_capacity)}"),
        ("Queue", "Peak depth", number(c.queue_peak)),
        ("Queue", "Backpressure waits (collector blocked)", number(c.backpressure_waits)),
        ("Detection", "Rule matches", number(c.rule_matches)),
        ("Detection", "Unique alerts", number(snap.unique_alerts)),
        ("Detection", "Duplicate matches suppressed", number(c.duplicate_matches)),
        (
            "Detection",
            "Incidents (active)",
            f"{len(snap.incidents)} ({len(snap.active_incident_ids)})",
        ),
        ("Collector", "Errors (total)", number(c.collector_errors)),
        ("Collector", "Unreadable optional fields", number(c.missing_telemetry)),
        ("Collector", "Entries skipped (read failed)", number(c.read_failures)),
        ("Latency", "Average per event", milliseconds(latency.average_ms)),
        ("Latency", "P95 per event", milliseconds(latency.p95_ms)),
        ("Latency", "Maximum per event", milliseconds(latency.max_ms)),
        ("Throughput", "Pipeline events/s (busy time)", number(pipeline_rate)),
        (
            "Throughput",
            "Session events/s (wall time)",
            number(c.processed / elapsed if elapsed > 0 else None),
        ),
        ("Resources", "Memory", memory(snap.peak_rss_kb)),
        ("Display", "Render errors", number(c.render_errors)),
        ("Display", "Log entries evicted from view buffer", number(c.logs_evicted)),
        ("Display", "Event records evicted from view buffer", number(c.events_evicted)),
    ]
    for group, metric, value in rows:
        table.add_row(group, metric, value)
    note = Text(
        "Latency covers the pipeline (rules, correlation, SQLite) per event, not /proc reads.\n"
        "Evicted view-buffer entries remain in SQLite; rule matches and incidents are never "
        "evicted.",
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
        ("h", "This help page"),
        ("p", "Inspect a process by PID: identity, rules, events, ancestry, children"),
        ("i", "Inspect a correlated incident: evidence timeline, tree, why it was flagged"),
        ("e", "Inspect recent events with filters (pid, name, type, severity, time, incident)"),
        ("m", "Live metrics: queue, latency, throughput, collector errors, memory"),
        ("r", "All alerts of this session (also clears pinned alert notifications)"),
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
