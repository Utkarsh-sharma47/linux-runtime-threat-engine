"""Final session report and session history, rendered from the persisted summary dict.

The same renderer serves the live shutdown report, `replay --summary` and `session --id`,
so a historical session reads exactly like the report printed when it ended.
"""

import shlex
from datetime import datetime
from typing import Any

from rich import box
from rich.console import Group, RenderableType
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from runtime_engine.events.schema import Severity
from runtime_engine.terminal.formatting import (
    clean,
    duration,
    local,
    memory,
    milliseconds,
    number,
    severity_text,
    timestamp,
)

STATUS_LABELS = {
    "STOPPED_GRACEFULLY": ("STOPPED GRACEFULLY", "bold green"),
    "FORCED_STOP": ("FORCED STOP (some accepted events were not processed)", "bold yellow"),
    "FAILED": ("FAILED (monitoring error; see below)", "bold red"),
    "RUNNING": ("RUNNING or INCOMPLETE (no clean shutdown was recorded)", "bold yellow"),
}
REASONS = {
    "user_quit": "q command",
    "keyboard_interrupt": "Ctrl+C",
    "sigterm": "SIGTERM",
    "sighup": "SIGHUP (terminal or SSH session closed)",
    "duration_elapsed": "--duration elapsed",
    "replay_complete": "replay input exhausted",
    "error": "monitoring failure",
}


def _section(title: str) -> RenderableType:
    return Rule(Text(title, style="bold"), align="left", style="dim")


def _grid(rows: list[tuple[str, object]]) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", min_width=30, no_wrap=True)
    grid.add_column(overflow="fold")
    for label, value in rows:
        grid.add_row(label, value if isinstance(value, Text) else str(value))
    return grid


def next_commands(summary: dict[str, Any]) -> list[str]:
    db = shlex.quote(summary["persistence"]["database"])
    commands = [
        f"runtime-engine --db {db} sessions",
        f"runtime-engine --db {db} session --id {summary['session_id']}",
        f"runtime-engine --db {db} incidents",
    ]
    first = summary["incident_ids"][0] if summary["incident_ids"] else None
    if first:
        commands += [
            f"runtime-engine --db {db} incident --id {first}",
            f"runtime-engine --db {db} export --id {first} --format json",
        ]
    commands += [f"runtime-engine --db {db} events --limit 50", f"runtime-engine --db {db} metrics"]
    return commands


def render_session_report(summary: dict[str, Any], *, title: str | None = None) -> RenderableType:
    events, security = summary["events"], summary["security"]
    performance, persistence = summary["performance"], summary["persistence"]
    collector = summary["collector"]
    label, style = STATUS_LABELS.get(summary["status"], (summary["status"], "bold"))
    heading = title or (
        "MONITORING SESSION COMPLETED" if summary["mode"] == "LIVE" else "REPLAY SESSION COMPLETED"
    )
    parts: list[RenderableType] = [
        Rule(Text(heading, style="bold"), style="bold blue"),
        Text.assemble("STATUS: ", (label, style)),
    ]
    if summary.get("error"):
        parts.append(
            Text(
                f"MONITORING ERROR: {clean(summary['error'])} (an engine failure, "
                "not a security finding)",
                style="bold red",
            )
        )
    parts += [
        _section("SESSION INFORMATION"),
        _grid(
            [
                ("Session ID", summary["session_id"]),
                ("Started At", timestamp(summary["started_at"])),
                ("Stopped At", timestamp(summary["stopped_at"])),
                ("Duration", duration(summary["duration_seconds"])),
                ("Monitoring Mode", summary["mode"]),
                ("Stop Reason", REASONS.get(summary["stop_reason"] or "", "N/A")),
                ("Host", clean(summary["host"]["hostname"])),
                ("Telemetry", clean(summary["configuration"]["telemetry"])),
            ]
        ),
        _section("EVENT STATISTICS"),
        _grid(
            [
                ("Total Events Observed", number(events["observed"])),
                ("Events Processed", number(events["processed"])),
                ("Duplicate Events Ignored", number(events["duplicates_ignored"])),
                ("Events Rejected", number(events["rejected"])),
                ("Events Dropped", number(events["dropped"])),
                ("Unprocessed at Shutdown", number(events["unprocessed_at_shutdown"])),
                (
                    "Polls Completed",
                    number(events["polls"]) if summary["mode"] == "LIVE" else "N/A",
                ),
                (
                    "Collector Read Errors",
                    f"{number(collector['errors'])} cumulative over all polls: "
                    f"{number(collector['missing_telemetry'])} optional fields unreadable "
                    f"(e.g. other users' executable paths), "
                    f"{number(collector['read_failures'])} entries skipped",
                ),
            ]
        ),
        _section("SECURITY STATISTICS"),
        _grid(
            [
                ("Total Detections (rule matches)", number(security["rule_matches"])),
                ("Unique Alerts", number(security["unique_alerts"])),
                ("Duplicate Alerts Suppressed", number(security["duplicate_matches_suppressed"])),
                ("Incidents Generated", number(security["incidents_generated"])),
            ]
        ),
        _section("SEVERITY BREAKDOWN"),
    ]
    severity = Table(box=None, padding=(0, 2), show_edge=False)
    severity.add_column("SEVERITY")
    severity.add_column("RULE MATCHES", justify="right")
    severity.add_column("UNIQUE ALERTS", justify="right")
    for level in reversed(Severity):
        severity.add_row(
            severity_text(level),
            str(security["matches_by_severity"].get(level.value, 0)),
            str(security["alerts_by_severity"].get(level.value, 0)),
        )
    parts += [severity, _section("TOP SUSPICIOUS PROCESSES")]
    if summary["top_processes"]:
        top = Table(box=None, padding=(0, 2), show_edge=False)
        for column in ("PID", "PROCESS", "ALERTS", "MATCHES", "SEVERITY", "INCIDENTS"):
            top.add_column(column)
        for item in summary["top_processes"]:
            top.add_row(
                clean(item["pid"]),
                clean(item["process_name"], 24),
                str(item["alerts"]),
                str(item["matches"]),
                severity_text(item["severity"]),
                ", ".join(item["incident_ids"]) or "-",
            )
        parts.append(top)
    else:
        parts.append(Text("No process matched a detection rule.", style="dim"))
    parts.append(_section("INCIDENTS GENERATED"))
    if summary["incidents"]:
        incidents = Table(box=None, padding=(0, 2), show_edge=False)
        for column in ("ID", "SEVERITY", "ALERTS", "EVENTS", "RULES", "TITLE"):
            incidents.add_column(column)
        for item in summary["incidents"]:
            incidents.add_row(
                item["incident_id"],
                severity_text(item["severity"]),
                str(item["alerts"]),
                str(item["events"]),
                ", ".join(item["rule_ids"]),
                clean(item["title"]),
            )
        parts.append(incidents)
        parts.append(
            Text("Incidents are indicators for review, not confirmed compromises.", style="dim")
        )
    else:
        parts.append(
            Text(
                "No security incidents were generated during this monitoring session.\n"
                "This does not prove that the machine was completely safe.",
                style="bold",
            )
        )
    parts += [
        _section("PERFORMANCE"),
        _grid(
            [
                ("Average Processing Latency", milliseconds(performance["average_latency_ms"])),
                (
                    "P95 Processing Latency",
                    milliseconds(performance["p95_latency_ms"])
                    + (
                        f" (over {number(performance['latency_samples'])} events)"
                        if performance["latency_samples"]
                        else ""
                    ),
                ),
                ("Maximum Processing Latency", milliseconds(performance["max_latency_ms"])),
                (
                    "Events Per Second (wall time)",
                    number(performance["session_events_per_second"]),
                ),
                (
                    "Pipeline Events Per Second",
                    number(performance["pipeline_events_per_second"]),
                ),
                ("Peak Memory", memory(performance["peak_rss_kb"])),
                (
                    "Queue Peak / Backpressure Waits",
                    f"{performance['queue_peak']} / {performance['backpressure_waits']}",
                ),
                ("Render Errors", number(performance["render_errors"])),
            ]
        ),
        _section("PERSISTENCE"),
        _grid(
            [
                ("Database Location", clean(persistence["database"])),
                ("Incident Reports", clean(persistence["reports_directory"])),
                (
                    "Reports Exported This Session",
                    "\n".join(clean(p) for p in persistence["exported_reports"]) or "none",
                ),
            ]
        ),
        _section("NEXT COMMANDS"),
        Text("\n".join(next_commands(summary))),
        Rule(style="bold blue"),
    ]
    return Group(*parts)


SHORT_STATUS = {
    "STOPPED_GRACEFULLY": "GRACEFUL",
    "FORCED_STOP": "FORCED",
    "FAILED": "FAILED",
    "RUNNING": "INCOMPLETE",
}


def render_session_list(sessions: list[dict[str, Any]]) -> RenderableType:
    if not sessions:
        return Text("No monitoring sessions are recorded in this database.", style="dim")
    table = Table(
        title="MONITORING SESSIONS",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        padding=(0, 1, 0, 0),
        show_edge=False,
        caption="INCOMPLETE = no clean shutdown recorded (running, killed or crashed).\n"
        "Details: session --id ID",
        caption_justify="left",
    )
    for column in ("SESSION ID", "MODE", "STARTED", "DURATION", "STATUS"):
        table.add_column(column, no_wrap=True)
    for column in ("EVENTS", "ALERTS", "INCIDENTS"):
        table.add_column(column, no_wrap=True, justify="right")
    for item in sessions:
        _, style = STATUS_LABELS.get(item["status"], (item["status"], ""))
        started = local(datetime.fromisoformat(item["started_at"]))
        table.add_row(
            item["session_id"],
            item["mode"],
            started.strftime("%m-%d %H:%M"),
            duration(item["duration_seconds"]),
            Text(SHORT_STATUS.get(item["status"], item["status"]), style=style),
            number(item["events"]["processed"]),
            number(item["security"]["unique_alerts"]),
            number(len(item["incident_ids"])),
        )
    return table
