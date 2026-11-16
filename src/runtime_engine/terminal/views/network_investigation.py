"""Dedicated network investigation view for live monitoring.

Network-focused: destinations, ports, protocol, connection counts, attribution,
and related indicators. Distinguishes observed connections, suspicious findings,
and potential beaconing indicators — never labeled as confirmed attacks.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.atomic.live import session_for_process_key
from runtime_engine.events.schema import Alert, Event, EventType, Incident
from runtime_engine.monitor.state import EventRecord, ProcessRecord
from runtime_engine.security.findings import Finding, ScanReport
from runtime_engine.terminal.formatting import clean, timestamp


def _exe(process: ProcessRecord | None, owners: list[dict[str, Any]]) -> str:
    if process is not None and process.event.executable_path:
        return process.event.executable_path
    if owners:
        return owners[0].get("name") or "-"
    return "-"


def _confidence(attribution: str) -> str:
    value = (attribution or "unattributed").lower()
    if value.startswith("unique") or value == "unique":
        return "unique"
    if "ambiguous" in value or "shared" in value:
        return "ambiguous"
    if "unattributed" in value or not value:
        return "unattributed"
    return value


def _split_endpoint(remote: object) -> tuple[str, str]:
    text = str(remote or "-")
    if text in {"-", ""}:
        return "-", "-"
    if "://" in text:
        parsed = urlsplit(text)
        host = parsed.hostname or parsed.netloc or text
        if parsed.port:
            port = str(parsed.port)
        elif ":" in parsed.path:
            port = parsed.path.split(":")[-1]
        else:
            port = "-"
        return host, port
    if text.startswith("[") and "]:" in text:
        host, _, port = text.rpartition("]:")
        return host + "]", port or "-"
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host or "-", port or "-"
    return text, "-"


def classify_row(row: dict[str, Any]) -> str:
    """observed | suspicious | beacon_indicator — never 'confirmed attack'."""
    detections = [str(d).upper() for d in (row.get("detections") or [])]
    findings = [str(f).upper() for f in (row.get("finding_rules") or [])]
    combined = detections + findings
    if any("BEACON" in d or d.startswith("NM") for d in combined) or row.get("beacon"):
        return "beacon_indicator"
    if combined or row.get("incidents"):
        return "suspicious"
    return "observed"


def build_rows(
    *,
    connections: Sequence[dict[str, Any]],
    network_events: Sequence[Event | EventRecord],
    processes: dict[str, ProcessRecord],
    alerts: Sequence[Alert],
    incidents: Sequence[Incident],
    findings: Sequence[Finding] | Sequence[dict[str, Any]],
    atomic_sessions: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge snapshot sockets with NETWORK_CONNECTION events for first/last seen."""
    events: list[Event] = []
    for record in network_events:
        event = record.event if isinstance(record, EventRecord) else record
        if event.event_type == EventType.NETWORK_CONNECTION:
            events.append(event)

    by_flow: dict[tuple[Any, ...], dict[str, Any]] = {}
    for event in events:
        meta = event.metadata or {}
        local = meta.get("local") or "-"
        remote = event.network_destination or meta.get("remote") or "-"
        if remote and ":" not in str(remote) and meta.get("remote_port") is not None:
            remote = f"{remote}:{meta['remote_port']}"
        key = (event.pid, meta.get("protocol"), local, remote)
        row = by_flow.get(key)
        if row is None:
            row = {
                "pid": event.pid,
                "process_key": event.process_key,
                "process_name": event.process_name,
                "executable": event.executable_path,
                "protocol": meta.get("protocol") or "-",
                "local": local,
                "remote": remote,
                "state": meta.get("state") or "-",
                "attribution": meta.get("attribution")
                or ("unique" if event.pid else "unattributed"),
                "first_seen": event.timestamp,
                "last_seen": event.timestamp,
                "synthetic": bool(meta.get("synthetic")),
                "event_ids": [event.event_id],
                "connection_count": 1,
            }
            by_flow[key] = row
        else:
            row["first_seen"] = min(row["first_seen"], event.timestamp)
            row["last_seen"] = max(row["last_seen"], event.timestamp)
            row["event_ids"].append(event.event_id)
            row["connection_count"] = len(row["event_ids"])
            row["synthetic"] = row["synthetic"] or bool(meta.get("synthetic"))

    rows: list[dict[str, Any]] = list(by_flow.values())
    seen_flows = {(r["pid"], r["protocol"], r["local"], r["remote"]) for r in rows}
    for connection in connections:
        owners = connection.get("processes") or []
        owner = owners[0] if len(owners) == 1 else None
        key = (
            owner["pid"] if owner else None,
            connection.get("protocol"),
            connection.get("local"),
            connection.get("remote"),
        )
        if key in seen_flows:
            continue
        process_key = owner.get("process_key") if owner else None
        process = processes.get(process_key) if process_key else None
        rows.append(
            {
                "pid": owner["pid"] if owner else None,
                "process_key": process_key,
                "process_name": (owner.get("name") if owner else None)
                or ("shared" if owners else None),
                "executable": _exe(process, owners),
                "protocol": connection.get("protocol") or "-",
                "local": connection.get("local") or "-",
                "remote": connection.get("remote") or "-",
                "state": connection.get("state") or "-",
                "attribution": connection.get("attribution") or "unattributed",
                "first_seen": None,
                "last_seen": None,
                "synthetic": False,
                "event_ids": [],
                "snapshot_only": True,
                "connection_count": 1,
            }
        )

    finding_rows = [f.model_dump(mode="json") if isinstance(f, Finding) else f for f in findings]
    for row in rows:
        process_key = row.get("process_key")
        related_alerts = [
            a
            for a in alerts
            if (a.process_key and a.process_key == process_key)
            or set(a.event_ids).intersection(row.get("event_ids") or [])
        ]
        related_incidents = [
            i
            for i in incidents
            if (process_key and process_key in i.process_keys)
            or set(i.event_ids).intersection(row.get("event_ids") or [])
        ]
        related_findings = [
            f
            for f in finding_rows
            if f.get("process_key") == process_key
            or (row.get("pid") is not None and f.get("pid") == row.get("pid"))
        ]
        atomic = session_for_process_key(atomic_sessions, process_key)
        destination, port = _split_endpoint(row.get("remote"))
        row["destination"] = destination
        row["port"] = port
        row["confidence"] = _confidence(str(row.get("attribution") or ""))
        row["detections"] = sorted(
            {a.rule_id for a in related_alerts}
            | {f.get("rule_id") for f in related_findings if f.get("rule_id")}
        )
        row["finding_rules"] = sorted(
            {f.get("rule_id") for f in related_findings if f.get("rule_id")}
        )
        row["finding_titles"] = [
            clean(f.get("title") or f.get("rule_id") or "finding", 48) for f in related_findings[:5]
        ]
        row["beacon"] = any(
            "beacon" in str(f.get("title") or "").lower()
            or "beacon" in str(f.get("rule_id") or "").lower()
            for f in related_findings
        )
        row["incidents"] = sorted({i.incident_id for i in related_incidents})
        row["atomic_run_id"] = atomic["run_id"] if atomic else None
        row["atomic_synthetic"] = bool(atomic and atomic.get("synthetic"))
        row["category"] = classify_row(row)
        if process_key and process_key in processes:
            proc = processes[process_key]
            row["executable"] = proc.event.executable_path or row.get("executable")
            row["process_name"] = proc.event.process_name or row.get("process_name")
    order = {"beacon_indicator": 0, "suspicious": 1, "observed": 2}

    def _sort_key(row: dict[str, Any]) -> tuple[int, str]:
        category = str(row.get("category") or "observed")
        return order.get(category, 9), str(row.get("destination") or "")

    rows.sort(key=_sort_key)
    return rows


def render_network_investigation(
    report: ScanReport | None,
    rows: list[dict[str, Any]],
    *,
    atomic_sessions: list[dict[str, Any]] | None = None,
    interface_summary: str | None = None,
    limit: int = 40,
) -> RenderableType:
    summary = report.summary if report else {}
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold", no_wrap=True)
    header.add_column(overflow="fold")
    header.add_row(
        "SCOPE",
        Text(
            "Socket snapshots (/proc/net). Not system-wide continuous capture; "
            "short-lived flows between scans may be missed.",
            style="yellow",
        ),
    )
    if interface_summary:
        header.add_row("INTERFACES", interface_summary)
    header.add_row(
        "SNAPSHOT",
        f"{summary.get('sockets', 0)} sockets, {summary.get('connected', 0)} connected "
        f"at {timestamp(summary.get('taken_at'))}"
        if report
        else "no network module scan yet",
    )
    active = [r for r in atomic_sessions or [] if r.get("status") not in ("COMPLETED",)]
    header.add_row(
        "ATOMIC",
        ", ".join(
            f"{s['run_id']}{' [SYNTHETIC]' if s.get('synthetic') else ''}" for s in active
        )
        or "none active",
    )
    counts = {
        "observed": sum(1 for r in rows if r.get("category") == "observed"),
        "suspicious": sum(1 for r in rows if r.get("category") == "suspicious"),
        "beacon_indicator": sum(1 for r in rows if r.get("category") == "beacon_indicator"),
    }
    header.add_row(
        "CATEGORIES",
        f"observed={counts['observed']}  suspicious={counts['suspicious']}  "
        f"beacon indicators={counts['beacon_indicator']} (indicators only, not confirmed attacks)",
    )

    table = Table(
        title="NETWORK ACTIVITY (this session)",
        title_justify="left",
        expand=True,
        show_lines=False,
    )
    for column in (
        "#",
        "DESTINATION",
        "PORT",
        "PROTO",
        "COUNT",
        "PROCESS",
        "PID",
        "CONFIDENCE",
        "CATEGORY",
        "LAST SEEN",
        "FINDINGS",
    ):
        table.add_column(column, no_wrap=True, overflow="ellipsis")

    shown = rows[:limit]
    for index, row in enumerate(shown, 1):
        category = row.get("category") or "observed"
        style = (
            "yellow"
            if category == "suspicious"
            else "bold yellow"
            if category == "beacon_indicator"
            else ("cyan" if row.get("synthetic") else None)
        )
        table.add_row(
            str(index),
            clean(str(row.get("destination") or "-"), 28),
            clean(str(row.get("port") or "-"), 6),
            str(row.get("protocol") or "-"),
            str(row.get("connection_count") or 1),
            clean(row.get("process_name") or "-", 16),
            str(row.get("pid") or "-"),
            clean(str(row.get("confidence") or "-"), 12),
            category.replace("_", " "),
            _ts(row.get("last_seen")),
            clean(", ".join(row.get("detections") or []) or "-", 20),
            style=style,
        )
    if len(rows) > limit:
        table.caption = f"{len(rows) - limit} more not shown; select a row number for details"

    note = Text(
        "Categories are review indicators only. Beacon indicators are behavioural signals, "
        "not confirmed C2. Press a row # for details, or Enter to return.",
        style="dim",
    )
    return Panel(
        Group(header, table, note),
        title="NETWORK INVESTIGATION [n]",
        title_align="left",
        border_style="cyan",
    )


def render_connection_detail(row: dict[str, Any]) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    category = str(row.get("category") or "observed").replace("_", " ")
    for label, value in (
        ("DESTINATION", clean(str(row.get("destination") or "-"))),
        ("PORT", clean(str(row.get("port") or "-"))),
        ("PROTOCOL", clean(str(row.get("protocol") or "-"))),
        ("LOCAL", clean(str(row.get("local") or "-"))),
        ("STATE", clean(str(row.get("state") or "-"))),
        ("CONNECTIONS", str(row.get("connection_count") or 1)),
        ("PROCESS", f"{clean(row.get('process_name') or '-')} (PID {row.get('pid') or '-'})"),
        ("EXECUTABLE", clean(str(row.get("executable") or "-"), 60)),
        ("ATTRIBUTION", clean(f"{row.get('confidence')} ({row.get('attribution') or '-'})")),
        ("CATEGORY", category),
        ("FIRST SEEN", _ts(row.get("first_seen"))),
        ("LAST SEEN", _ts(row.get("last_seen"))),
        ("DETECTIONS", ", ".join(row.get("detections") or []) or "none"),
        ("INCIDENTS", ", ".join(row.get("incidents") or []) or "none"),
        ("ATOMIC", row.get("atomic_run_id") or "none"),
    ):
        grid.add_row(label, value)
    findings = row.get("finding_titles") or []
    finding_block: RenderableType = (
        Text("\n".join(f"- {f}" for f in findings))
        if findings
        else Text("No network-module findings for this destination/process.", style="dim")
    )
    caveat = Text(
        "Findings and detections are indicators for review, not confirmed attacks.",
        style="italic dim",
    )
    return Panel(
        Group(grid, Text("\nRELATED FINDINGS", style="bold underline"), finding_block, caveat),
        title="CONNECTION DETAILS",
        title_align="left",
        border_style="cyan",
    )


def _ts(value: datetime | str | None) -> str:
    if value is None:
        return "snapshot"
    if isinstance(value, str):
        return timestamp(value)
    return timestamp(value.isoformat())


__all__ = [
    "build_rows",
    "classify_row",
    "render_connection_detail",
    "render_network_investigation",
]
