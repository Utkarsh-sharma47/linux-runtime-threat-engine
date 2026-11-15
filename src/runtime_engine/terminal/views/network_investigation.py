"""Dedicated network investigation view for live monitoring.

Shows process identity, endpoints, attribution confidence, related detections /
incidents, and any Atomic execution session linked by process_key. Ambiguous and
unattributed connections are called out. Snapshot collection limits are disclosed —
this is not system-wide continuous network visibility.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

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
            }
            by_flow[key] = row
        else:
            row["first_seen"] = min(row["first_seen"], event.timestamp)
            row["last_seen"] = max(row["last_seen"], event.timestamp)
            row["event_ids"].append(event.event_id)
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
        row["confidence"] = _confidence(str(row.get("attribution") or ""))
        row["detections"] = sorted(
            {a.rule_id for a in related_alerts}
            | {f.get("rule_id") for f in related_findings if f.get("rule_id")}
        )
        row["incidents"] = sorted({i.incident_id for i in related_incidents})
        row["atomic_run_id"] = atomic["run_id"] if atomic else None
        row["atomic_synthetic"] = bool(atomic and atomic.get("synthetic"))
        if process_key and process_key in processes:
            proc = processes[process_key]
            row["executable"] = proc.event.executable_path or row.get("executable")
            row["process_name"] = proc.event.process_name or row.get("process_name")
    return rows


def render_network_investigation(
    report: ScanReport | None,
    rows: list[dict[str, Any]],
    *,
    atomic_sessions: list[dict[str, Any]] | None = None,
) -> RenderableType:
    summary = report.summary if report else {}
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold", no_wrap=True)
    header.add_column(overflow="fold")
    header.add_row(
        "SCOPE",
        Text(
            "Snapshot polling of /proc/net (+ synthetic NETWORK_CONNECTION events). "
            "Not system-wide continuous capture; connections that open and close "
            "between scans are missed.",
            style="yellow",
        ),
    )
    header.add_row(
        "SNAPSHOT",
        f"{summary.get('sockets', 0)} sockets, {summary.get('connected', 0)} connected "
        f"at {timestamp(summary.get('taken_at'))}"
        if report
        else "no network module scan yet",
    )
    active = [r for r in atomic_sessions or [] if r.get("status") not in ("COMPLETED",)]
    header.add_row(
        "ATOMIC SESSIONS",
        ", ".join(f"{s['run_id']}{' [SYNTHETIC]' if s.get('synthetic') else ''}" for s in active)
        or "none active",
    )

    table = Table(
        title="NETWORK INVESTIGATION",
        title_justify="left",
        expand=True,
        show_lines=False,
    )
    for column in (
        "PID",
        "PROCESS",
        "EXECUTABLE",
        "PROTO",
        "LOCAL",
        "REMOTE",
        "STATE",
        "FIRST",
        "LAST",
        "ATTRIBUTION",
        "DETECTIONS",
        "INCIDENTS",
        "ATOMIC SESSION",
    ):
        table.add_column(column, no_wrap=True, overflow="ellipsis")

    ambiguous = 0
    unattributed = 0
    for row in rows:
        confidence = row.get("confidence") or "unattributed"
        if confidence == "ambiguous":
            ambiguous += 1
        elif confidence == "unattributed":
            unattributed += 1
        style = (
            "yellow"
            if confidence == "ambiguous"
            else "dim"
            if confidence == "unattributed"
            else ("cyan" if row.get("synthetic") or row.get("atomic_synthetic") else None)
        )
        atomic_label = row.get("atomic_run_id") or "-"
        if row.get("atomic_synthetic") and atomic_label != "-":
            atomic_label = f"{atomic_label} [SYNTHETIC]"
        table.add_row(
            str(row.get("pid") or "-"),
            clean(row.get("process_name") or "-", 16),
            clean(row.get("executable") or "-", 24),
            str(row.get("protocol") or "-"),
            clean(str(row.get("local") or "-"), 22),
            clean(str(row.get("remote") or "-"), 26),
            str(row.get("state") or "-"),
            _ts(row.get("first_seen")),
            _ts(row.get("last_seen")),
            clean(f"{confidence} ({row.get('attribution') or '-'})", 28),
            clean(", ".join(row.get("detections") or []) or "-", 20),
            clean(", ".join(row.get("incidents") or []) or "-", 16),
            clean(str(atomic_label), 28),
            style=style,
        )

    callouts = Text()
    callouts.append(
        f"{ambiguous} ambiguous, {unattributed} unattributed connection(s). ",
        style="bold yellow" if ambiguous or unattributed else "dim",
    )
    callouts.append(
        "Ambiguous = multiple PIDs share the socket inode; unattributed = no readable "
        "owner (often other-user processes without root). SYNTHETIC rows are acceptance "
        "evidence, not real host activity.",
        style="dim",
    )
    return Panel(
        Group(header, table, callouts),
        title="NETWORK INVESTIGATION [n]",
        title_align="left",
        border_style="cyan",
    )


def _ts(value: datetime | str | None) -> str:
    if value is None:
        return "snapshot"
    if isinstance(value, str):
        return timestamp(value)
    return timestamp(value.isoformat())


__all__ = ["build_rows", "render_network_investigation"]
