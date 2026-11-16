"""Dashboard layout: a pure function of one state snapshot and the terminal size."""

from typing import Any

from rich.console import Group, RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.events.schema import Severity
from runtime_engine.monitor.state import (
    DashboardSnapshot,
    DashboardState,
    ProcessLifecycle,
    Verbosity,
)
from runtime_engine.terminal.formatting import (
    STATUS_STYLES,
    clean,
    clock,
    duration,
    number,
    severity_style,
    severity_text,
)
from runtime_engine.terminal.live_logs import entry_text, log_panel
from runtime_engine.terminal.views.security_view import any_enabled, status_line

COMMANDS = (
    ("1", "Help"),
    ("2", "Events"),
    ("3", "Process"),
    ("4", "Tree"),
    ("5", "Network"),
    ("6", "Security"),
    ("7", "Incident"),
    ("8", "Atomic"),
    ("9", "Metrics"),
    ("q", "Quit"),
)
SEVERITIES = list(reversed(Severity))  # CRITICAL first


def header(snap: DashboardSnapshot) -> RenderableType:
    info, counters = snap.info, snap.counters
    elapsed = (snap.now - info.started_at).total_seconds()
    line = Text(no_wrap=True, overflow="ellipsis")
    line.append("STATUS: ")
    line.append(snap.status, style=STATUS_STYLES.get(snap.status, "bold"))
    line.append(f"   SESSION: {info.session_id}")
    line.append(f"   DURATION: {duration(elapsed)}")
    line.append(f"   HOST: {clean(info.hostname, 24)}")
    meta = Text(no_wrap=True, overflow="ellipsis", style="dim")
    meta.append(f"Mode {info.mode}   Started {clock(info.started_at)}")
    if counters.last_poll_at is not None and counters.last_poll_seconds is not None:
        meta.append(
            f"   Poll #{counters.polls} {clock(counters.last_poll_at)}"
            f" ({counters.last_poll_seconds * 1000:.0f} ms)"
        )
    lines: list[RenderableType] = [line, meta]
    if any_enabled(snap.security):
        lines.append(status_line(snap.security))
    if snap.atomic_sessions:
        atomic = Text(no_wrap=True, overflow="ellipsis")
        atomic.append("ATOMIC SESSIONS [a]: ", style="bold")
        parts = []
        for item in snap.atomic_sessions[:2]:
            label = item.get("run_id") or "?"
            if item.get("synthetic"):
                label += " [SYNTHETIC]"
            parts.append(f"{label} ({item.get('status')})")
        atomic.append(", ".join(parts), style="cyan")
        if len(snap.atomic_sessions) > 2:
            atomic.append(f" +{len(snap.atomic_sessions) - 2} more", style="dim")
        lines.append(atomic)
    if snap.lab_status:
        lines.append(lab_status_line(snap.lab_status, snap.counters, len(snap.incidents)))
    return Panel(
        Group(*lines),
        title="LINUX RUNTIME THREAT DETECTION ENGINE (read-only)",
        border_style="bold blue",
    )


def lab_status_line(lab: dict[str, object], counters: object, incidents: int) -> Text:
    """Compact security-lab demonstration panel (provenance-aware)."""
    line = Text(no_wrap=True, overflow="ellipsis")
    line.append("SECURITY LAB: ", style="bold magenta")
    line.append(str(lab.get("session_id") or "?"), style="magenta")
    line.append(f"  phase={lab.get('phase') or 'idle'}")
    current = lab.get("current_scenario")
    if current:
        line.append(f"  scenario={current}", style="bold")
        started = lab.get("scenario_started_at")
        if started:
            line.append(f"@{str(started)[11:19]}")
    raw_scenarios = lab.get("scenarios")
    done: dict[str, object] = raw_scenarios if isinstance(raw_scenarios, dict) else {}
    if done:
        finished = sum(
            1 for s in done.values() if isinstance(s, dict) and s.get("status") == "completed"
        )
        line.append(f"  done={finished}/{len(done)}")
    observed = getattr(counters, "observed", 0)
    matches = getattr(counters, "rule_matches", 0)
    line.append(f"  events={observed} matches={matches} incidents={incidents}")
    raw_procs = lab.get("active_processes")
    raw_conns = lab.get("active_connections")
    procs: list[object] = raw_procs if isinstance(raw_procs, list) else []
    conns: list[object] = raw_conns if isinstance(raw_conns, list) else []
    if procs:
        line.append(f"  procs={len(procs)}")
    if conns:
        line.append(f"  conns={len(conns)}")
    raw_health = lab.get("collector_health")
    health: dict[str, object] = raw_health if isinstance(raw_health, dict) else {}
    if health:
        line.append("  collectors=", style="dim")
        line.append(
            ",".join(f"{k}:{v}" for k, v in list(health.items())[:2]),
            style="dim",
        )
    line.append("  [REAL|SYNTHETIC|ATOMIC]", style="dim")
    return line


def overview(snap: DashboardSnapshot, inline_severity: bool = False) -> RenderableType:
    c = snap.counters
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(justify="right", no_wrap=True, overflow="ellipsis")
    rows = [
        ("Events Processed", number(c.processed)),
        ("Detections", number(c.rule_matches)),
        ("Alerts", number(snap.unique_alerts)),
        ("Active Incidents", f"{len(snap.active_incident_ids)} of {len(snap.incidents)}"),
    ]
    if c.dropped:
        rows.append(("Events Dropped", number(c.dropped)))
    if inline_severity:
        rows.append(
            (
                "Severity C/H/M/L",
                "/".join(str(snap.match_severity.get(s.value, 0)) for s in SEVERITIES),
            )
        )
    for label, value in rows:
        style = "bold red" if label == "Events Dropped" else ""
        grid.add_row(label, Text(value, style=style))
    return Panel(grid, title="SESSION STATUS", title_align="left", border_style="cyan")


def severity_panel(snap: DashboardSnapshot) -> RenderableType:
    table = Table(box=None, padding=(0, 1), show_edge=False)
    table.add_column("SEVERITY")
    table.add_column("MATCHES", justify="right")
    table.add_column("ALERTS", justify="right")
    for severity in SEVERITIES:
        table.add_row(
            severity_text(severity),
            str(snap.match_severity.get(severity.value, 0)),
            str(snap.alert_severity.get(severity.value, 0)),
        )
    note = Text("matches = every rule hit\nalerts = after deduplication", style="dim")
    return Panel(
        Group(table, note), title="DETECTION SEVERITY", title_align="left", border_style="cyan"
    )


def incidents_panel(snap: DashboardSnapshot, rows: int) -> RenderableType:
    if not snap.incidents:
        body: RenderableType = Text(
            "No incidents correlated in this session.\n"
            "(Absence of incidents does not prove the host is safe.)",
            style="dim",
        )
    else:
        table = Table(box=None, padding=(0, 1), show_edge=False, expand=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("SEVERITY", no_wrap=True)
        table.add_column("ALERTS", justify="right")
        table.add_column("WINDOW", no_wrap=True)
        table.add_column("RULES", overflow="ellipsis", no_wrap=True)
        for incident in snap.incidents[: max(1, rows)]:
            active = incident.incident_id in snap.active_incident_ids
            table.add_row(
                incident.incident_id,
                severity_text(incident.severity),
                str(len(incident.alert_ids)),
                Text("ACTIVE", style="bold") if active else Text("CLOSED", style="dim"),
                ",".join(incident.rule_ids),
            )
        if len(snap.incidents) > rows:
            table.add_row(Text(f"+{len(snap.incidents) - rows} more (press i)", style="dim"))
        body = table
    return Panel(body, title="RECENT INCIDENTS", title_align="left", border_style="red")


def processes_panel(snap: DashboardSnapshot, height: int) -> RenderableType:
    rows = max(0, height - 3)
    suspicious = [p for p in snap.processes if p.severity is not None]
    if not suspicious:
        body: RenderableType = Text(
            "No suspicious processes in this session.\nPress [3] to inspect a PID.",
            style="dim",
        )
    else:
        table = Table(box=None, padding=(0, 1), show_edge=False, expand=True)
        table.add_column("PID", justify="right", no_wrap=True, min_width=7)
        table.add_column("PROCESS", overflow="ellipsis", no_wrap=True, ratio=1)
        table.add_column("SEVERITY", no_wrap=True, min_width=10)
        table.add_column("INCIDENTS", no_wrap=True, overflow="ellipsis")
        for record in suspicious[:rows]:
            event = record.event
            table.add_row(
                clean(event.pid),
                clean(event.process_name, 24),
                severity_text(record.severity),
                ", ".join(record.incident_ids) or "-",
            )
        body = table
    return Panel(
        body,
        title="SUSPICIOUS PROCESSES (this session)",
        title_align="left",
        border_style="green",
        height=height,
    )


def alert_banner(snap: DashboardSnapshot, lines: int) -> RenderableType | None:
    if not snap.notifications:
        return None
    shown = snap.notifications[: max(1, lines - 3)]
    body = Text()
    for index, note in enumerate(shown):
        if index:
            body.append("\n")
        body.append(f"[{note.severity.value}] ", style=severity_style(note.severity))
        body.append(clean(", ".join(note.rule_names), 48), style="bold")
        body.append(f"  rule {', '.join(note.rule_ids)}")
        body.append(f"  PID {clean(note.pid)} {clean(note.process_name, 16)}")
        body.append(f"  incident {', '.join(note.incident_ids[:3])}")
        if len(note.incident_ids) > 3:
            body.append(f" +{len(note.incident_ids) - 3}")
        if note.matches > 1:
            body.append(f"  ({note.matches} matches coalesced)", style="dim")
    extra = len(snap.notifications) - len(shown)
    body.append("\n")
    if extra > 0:
        body.append(f"+{extra} more notifications. ", style="bold")
    body.append("Press [i] to inspect the associated incident, [r] for all alerts.", style="dim")
    worst = snap.notifications[0].severity
    return Panel(
        body,
        title="SECURITY ALERT (rule match - an indicator for review, not proof)",
        title_align="left",
        border_style=severity_style(worst) or "red",
    )


def footer(snap: DashboardSnapshot, interactive: bool) -> RenderableType:
    text = Text(no_wrap=True, overflow="ellipsis")
    if snap.status == "STOPPING":
        text.append(
            "Stopping: finishing accepted events, then printing the session report...",
            style="bold yellow",
        )
        return text
    if not interactive:
        text.append("Ctrl+C stops monitoring.", style="dim")
        return text
    for key, label in COMMANDS:
        text.append(f"[{key}]", style="bold reverse")
        text.append(f" {label}  ")
    text.append("Ctrl+C: graceful stop", style="dim")
    return text


def error_banner(snap: DashboardSnapshot) -> RenderableType | None:
    if not snap.error:
        return None
    return Panel(
        Text(
            f"MONITORING FAILURE: {clean(snap.error)} - this is an engine error, "
            "not a security finding. Monitoring is stopping.",
            style="bold",
        ),
        border_style="bold red",
    )


def diagnostics_panel(snap: DashboardSnapshot, height: int) -> RenderableType:
    entries = snap.diagnostics[-max(0, (height - 2) // 2) :] if height > 2 else []
    body: RenderableType = (
        Group(*(entry_text(e) for e in entries))
        if entries
        else Text("No diagnostics.", style="dim")
    )
    return Panel(
        body,
        title="INTERNAL DIAGNOSTICS (debug; not security events)",
        title_align="left",
        border_style="magenta",
        height=height,
    )


def render_dashboard(
    snap: DashboardSnapshot, width: int, height: int, *, interactive: bool = True
) -> RenderableType:
    """Size every section from the terminal so the screen updates in place without scrolling."""
    width, height = max(width, 20), max(height, 6)
    if height < 24 or width < 70:
        return compact(snap, height, interactive)
    layout = Layout(name="root")
    header_size = 4
    if any_enabled(snap.security):
        header_size += 1
    if snap.atomic_sessions:
        header_size += 1
    if snap.lab_status:
        header_size += 1
    sections: list[Layout] = [Layout(header(snap), name="header", size=header_size)]
    used = header_size + 1
    error = error_banner(snap)
    if error is not None:
        sections.append(Layout(error, name="error", size=3))
        used += 3
    top_size = 10
    top = Layout(name="top", size=top_size)
    if width >= 110:
        top.split_row(
            Layout(overview(snap), name="overview", ratio=2),
            Layout(severity_panel(snap), name="severity", ratio=2),
            Layout(incidents_panel(snap, 5), name="incidents", ratio=3),
        )
    else:
        top.split_row(
            Layout(overview(snap, inline_severity=True), name="overview", ratio=1),
            Layout(incidents_panel(snap, 5), name="incidents", ratio=1),
        )
    sections.append(top)
    used += top_size
    banner_lines = min(5, 3 + min(2, len(snap.notifications)))
    banner = alert_banner(snap, banner_lines) if height - used > 14 else None
    if banner is not None:
        sections.append(Layout(banner, name="alerts", size=banner_lines))
        used += banner_lines
    debug = snap.info.verbosity >= Verbosity.DEBUG and height - used > 18
    remaining = height - used - (6 if debug else 0)
    body = Layout(name="body")
    if width >= 140:
        body.split_row(
            Layout(processes_panel(snap, remaining), name="processes", ratio=2),
            Layout(log_panel(snap.logs, remaining, snap.info.verbosity), name="logs", ratio=3),
        )
    else:
        process_height = min(8, max(4, remaining // 3))
        body.split_column(
            Layout(processes_panel(snap, process_height), name="processes", size=process_height),
            Layout(
                log_panel(snap.logs, remaining - process_height, snap.info.verbosity),
                name="logs",
            ),
        )
    sections.append(body)
    if debug:
        sections.append(Layout(diagnostics_panel(snap, 6), name="diagnostics", size=6))
    sections.append(Layout(footer(snap, interactive), name="footer", size=1))
    layout.split_column(*sections)
    return layout


def compact(snap: DashboardSnapshot, height: int, interactive: bool) -> RenderableType:
    """Small terminals: key counters, the newest entries and the command line only."""
    c = snap.counters
    status = Text(no_wrap=True, overflow="ellipsis")
    status.append(f"{snap.status} ", style=STATUS_STYLES.get(snap.status, "bold"))
    status.append(
        f"session={snap.info.session_id} proc={c.processed} matches={c.rule_matches} "
        f"alerts={snap.unique_alerts} incidents={len(snap.incidents)}"
    )
    if c.dropped:
        status.append(f" dropped={c.dropped}", style="bold red")
    parts: list[RenderableType] = [status]
    if any_enabled(snap.security):
        parts.append(status_line(snap.security))
    if snap.notifications:
        note = snap.notifications[0]
        alert = Text(no_wrap=True, overflow="ellipsis")
        alert.append(f"ALERT [{note.severity.value}] ", style=severity_style(note.severity))
        alert.append(f"{', '.join(note.rule_ids)} PID {clean(note.pid)} {note.incident_ids[0]}")
        parts.append(alert)
    room = max(0, (height - len(parts) - 1) // 2)
    parts.extend(entry_text(e) for e in (snap.logs[-room:] if room else []))
    parts.append(footer(snap, interactive))
    return Group(*parts)


def render_process_tree(
    state: DashboardState | None,
    width: int,
    height: int,
    *,
    process_tree: dict[str, Any] | None = None,
    selected_key: str | None = None,
    show_suspicious_only: bool = False,
) -> RenderableType:
    """Render a process ancestry tree using Rich Tree.

    Shows observed parent-child relationships from the monitoring session.
    Handles PID reuse, missing parents, and historical processes.
    Uses Rich Tree for clear hierarchical visualization.

    Args:
        state: The DashboardState containing process records.
        width: Terminal width in characters.
        height: Terminal height in characters.
        process_tree: Pre-built process tree dict. If None, builds from state.
        selected_key: Key of the process to root the tree at.
        show_suspicious_only: If True, only show processes with severity matches.

    Returns:
        A Rich Renderable representing the process tree.
    """
    from rich.panel import Panel
    from rich.text import Text
    from rich.tree import Tree

    if state is None:
        return Panel(
            Text("No processes observed yet.", style="dim"),
            title="PROCESS TREE",
            title_align="left",
        )
    if process_tree is None:
        process_tree = state.build_process_tree()

    def severity_of(key: str) -> Severity | None:
        # Rule-match severity lives on the state's process record, not on the event.
        record = state.processes.get(key)
        return record.severity if record is not None else None

    # Select root if specified
    if selected_key is None:
        # Show tree rooted at first suspicious process
        suspicious_keys = [k for k in process_tree if severity_of(k) is not None]
        if suspicious_keys:
            selected_key = suspicious_keys[0]
        else:
            # Show all processes
            selected_key = next(iter(process_tree)) if process_tree else None

    if selected_key is None or selected_key not in process_tree:
        return Panel(
            Text("No processes observed yet.", style="dim"),
            title="PROCESS TREE",
            title_align="left",
        )

    # Build the tree recursively
    def add_node(parent_tree: Tree, key: str, depth: int = 0) -> None:
        if key not in process_tree:
            return

        node_data = process_tree[key]
        event = node_data["event"]
        lifecycle = node_data["lifecycle"]

        # Create node label
        pid = event.pid if event.pid else "?"
        pname = (event.process_name or "unknown")[:20]
        suffix = ""
        if lifecycle == ProcessLifecycle.EXITED:
            suffix = " [EXITED]"
        elif lifecycle == ProcessLifecycle.GONE:
            suffix = " [GONE]"

        severity = severity_of(key)
        if show_suspicious_only and severity is None:
            return  # Skip processes without a rule match

        label = Text(f"PID {pid} {pname}{suffix}")
        if severity is not None:
            label.append(f" {severity.value}", style=severity_style(severity))
            label.stylize("bold")
        node = Tree(label, guide_style="dim")

        for child_key in node_data["children"]:
            add_node(node, child_key, depth + 1)

        parent_tree.add(node)

    # Create the tree
    root_key = selected_key
    root_data = process_tree.get(root_key, {})
    root_event = root_data.get("event")

    if root_event is None:
        return Panel(
            Text("No process data available.", style="dim"),
            title="PROCESS TREE",
            title_align="left",
        )

    # Create root label
    pid = root_event.pid if root_event.pid else "?"
    pname = (root_event.process_name or "unknown")[:25]
    suffix = ""
    root_lifecycle = root_data.get("lifecycle", ProcessLifecycle.RUNNING)
    if root_lifecycle == ProcessLifecycle.EXITED:
        suffix = " [EXITED]"
    elif root_lifecycle == ProcessLifecycle.GONE:
        suffix = " [GONE]"

    root_label = Text(f"PID {pid} {pname}{suffix}")
    root_severity = severity_of(root_key)
    if root_severity is not None:
        root_label.append(f" {root_severity.value}", style=severity_style(root_severity))
        root_label.stylize("bold")

    root_tree = Tree(root_label, guide_style="bold")

    # Add children recursively
    for child_key in root_data.get("children", []):
        add_node(root_tree, child_key)

    return Panel(
        root_tree,
        title=f"PROCESS TREE {'- SUSPICIOUS ONLY' if show_suspicious_only else ''}",
        title_align="left",
        border_style="green",
    )
