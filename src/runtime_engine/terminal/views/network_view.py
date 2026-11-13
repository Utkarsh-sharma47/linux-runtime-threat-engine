"""Network Monitor page: connections by process, frequency, repeats and beacon indicators."""

from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.security.findings import Finding, ScanReport
from runtime_engine.terminal.formatting import clean, timestamp
from runtime_engine.terminal.views.security_common import (
    as_dict,
    coverage_panel,
    findings_table,
    report_header,
)


def connections_table(
    connections: list[dict[str, Any]],
    title: str,
    incidents: dict[str, list[str]] | None = None,
    limit: int = 30,
) -> RenderableType:
    if not connections:
        return Panel(
            Text("No connections in the last snapshot.", style="dim"),
            title=title,
            title_align="left",
        )
    table = Table(title=title, title_justify="left", expand=True)
    for column in ("PROCESS", "PID", "PROTO", "LOCAL", "REMOTE", "STATE", "ATTRIBUTION"):
        table.add_column(column, no_wrap=True, overflow="ellipsis")
    table.add_column("INCIDENTS", no_wrap=True)
    for item in connections[:limit]:
        owners = item.get("processes", [])
        owner = owners[0] if len(owners) == 1 else None
        keys = [o["process_key"] for o in owners]
        related = sorted({i for k in keys for i in (incidents or {}).get(k, [])})
        table.add_row(
            clean(owner["name"] if owner else ("shared" if owners else "unattributed"), 18),
            str(owner["pid"]) if owner else "-",
            item["protocol"],
            clean(item["local"], 26),
            clean(item["remote"], 30),
            item["state"],
            clean(item["attribution"], 40),
            ", ".join(related) or "-",
        )
    if len(connections) > limit:
        table.caption = f"{len(connections) - limit} more not shown"
    return table


def render_network(
    report: ScanReport | None,
    findings: list[Finding] | list[dict[str, Any]],
    *,
    pid: int | None = None,
    incidents: dict[str, list[str]] | None = None,
) -> RenderableType:
    summary = report.summary if report else {}
    rows = [as_dict(f) for f in findings]
    connections = summary.get("connections", [])
    if pid is not None:
        connections = [c for c in connections if any(o["pid"] == pid for o in c["processes"])]
        rows = [r for r in rows if r.get("pid") == pid]
    header = report_header(
        "NETWORK MONITOR",
        report,
        [
            (
                "SNAPSHOT",
                f"{summary.get('sockets', 0)} sockets, {summary.get('connected', 0)} connected, "
                f"{summary.get('listening', 0)} listening/unconnected at "
                f"{timestamp(summary.get('taken_at'))}",
            ),
            (
                "NEW CONNECTIONS",
                f"{summary.get('new_total', 0)} observed since start "
                f"({summary.get('new_this_scan', 0)} in the last scan)",
            ),
            ("FILTER", f"PID {pid}" if pid is not None else "all processes"),
        ],
    )
    frequency = Table(title="CONNECTION FREQUENCY BY PROCESS", title_justify="left", expand=True)
    for column in ("PROCESS", "PID", "NEW CONNECTIONS", "PER MIN (10 MIN)", "DESTINATIONS"):
        frequency.add_column(column, no_wrap=True)
    for item in summary.get("processes", []):
        if pid is not None and item["pid"] != pid:
            continue
        frequency.add_row(
            clean(item["process"] or "unattributed", 20),
            str(item["pid"] or "-"),
            str(item["new_connections"]),
            f"{item['per_minute_10m']:.1f}",
            str(item["destinations"]),
        )
    repeated = Table(
        title="REPEATED DESTINATIONS (inter-arrival statistics of newly observed connections)",
        title_justify="left",
        expand=True,
    )
    for column in ("PROCESS", "PID", "DESTINATION", "CONNECTIONS", "MEAN Δt (s)", "CV"):
        repeated.add_column(column, no_wrap=True)
    for item in summary.get("repeated", []):
        if pid is not None and item["pid"] != pid:
            continue
        stats = item.get("periodicity") or {}
        repeated.add_row(
            clean(item["process"], 20),
            str(item["pid"] or "-"),
            clean(item["destination"], 32),
            str(item["connections"]),
            f"{stats['mean_interval_seconds']:.1f}" if stats else "-",
            f"{stats['cv']:.3f}" if stats and stats.get("cv") is not None else "-",
        )
    beacons = [r for r in rows if r["rule_id"] == "NB001"]
    other = [r for r in rows if r["rule_id"] != "NB001"]
    return Panel(
        Group(
            header,
            coverage_panel(report),
            connections_table(connections, "ACTIVE CONNECTIONS (last snapshot)", incidents),
            frequency,
            repeated,
            findings_table(
                beacons,
                "POTENTIAL BEACONING INDICATORS (low CV is not proof of C2)",
                empty="No periodic connection pattern met the thresholds.",
            ),
            findings_table(other, "OTHER NETWORK FINDINGS", empty="No other network findings."),
            Text(
                "Snapshot polling: connections that open and close between scans are not "
                "seen, and connect times are first-observed times.",
                style="dim italic",
            ),
        ),
        title="NETWORK MONITOR",
        title_align="left",
        border_style="cyan",
    )
