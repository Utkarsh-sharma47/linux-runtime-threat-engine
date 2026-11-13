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

COMMANDS = (
    ("h", "Help"),
    ("p", "Inspect process"),
    ("i", "Inspect incident"),
    ("e", "Inspect events"),
    ("m", "Metrics"),
    ("r", "Recent alerts"),
    ("q", "Stop monitoring"),
)
SEVERITIES = list(reversed(Severity))  # CRITICAL first


def header(snap: DashboardSnapshot) -> RenderableType:
    info, counters = snap.info, snap.counters
    elapsed = (snap.now - info.started_at).total_seconds()
    line = Text(no_wrap=True, overflow="ellipsis")
    line.append("STATUS: ")
    line.append(snap.status, style=STATUS_STYLES.get(snap.status, "bold"))
    line.append(f"   MODE: {info.mode}   DURATION: {duration(elapsed)}")
    line.append(f"   STARTED: {clock(info.started_at)}")
    line.append(f"   VERBOSITY: {info.verbosity.name.lower()}")
    host = Text(no_wrap=True, overflow="ellipsis")
    host.append(f"HOST: {clean(info.hostname, 32)}   ENGINE PID: {info.engine_pid}")
    host.append(f"   SESSION: {info.session_id}")
    poll = Text(no_wrap=True, overflow="ellipsis", style="dim")
    poll.append(f"Telemetry: {info.telemetry}")
    if counters.last_poll_at is not None and counters.last_poll_seconds is not None:
        poll.append(
            f"   Last poll #{counters.polls}: {clock(counters.last_poll_at)}"
            f" ({counters.last_poll_seconds * 1000:.0f} ms)"
        )
    return Panel(
        Group(line, host, poll),
        title="LINUX RUNTIME THREAT DETECTION ENGINE (read-only)",
        border_style="bold blue",
    )


def overview(snap: DashboardSnapshot, inline_severity: bool = False) -> RenderableType:
    c = snap.counters
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(justify="right", no_wrap=True, overflow="ellipsis")
    queue = f"{number(c.queue_depth)}/{number(snap.info.queue_capacity)} (peak {c.queue_peak})"
    rows = [
        ("Events Observed", number(c.observed)),
        ("Events Processed", number(c.processed)),
        ("Event Queue", queue if snap.info.queue_capacity else "N/A"),
        ("Suspicious Detections", number(c.rule_matches)),
        ("Unique Alerts", number(snap.unique_alerts)),
        ("Active Incidents", f"{len(snap.active_incident_ids)} of {len(snap.incidents)}"),
        ("Suppressed Duplicates", number(c.duplicate_matches)),
        ("Events Dropped", number(c.dropped)),
        (
            "Telemetry Gaps/Poll",
            f"{number(c.last_poll_missing)} fields, {c.last_poll_failures} skipped",
        ),
    ]
    if inline_severity:
        rows.append(
            (
                "Matches C/H/M/L",
                "/".join(str(snap.match_severity.get(s.value, 0)) for s in SEVERITIES),
            )
        )
    for label, value in rows:
        style = "bold red" if label == "Events Dropped" and c.dropped else ""
        grid.add_row(label, Text(value, style=style))
    return Panel(grid, title="SYSTEM OVERVIEW", title_align="left", border_style="cyan")


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
    if not snap.processes:
        body: RenderableType = Text("No processes observed yet.", style="dim")
    else:
        table = Table(box=None, padding=(0, 1), show_edge=False, expand=True)
        table.add_column("PID", justify="right", no_wrap=True, min_width=7)
        table.add_column("PPID", justify="right", no_wrap=True, min_width=7)
        table.add_column("PROCESS", overflow="ellipsis", no_wrap=True, ratio=1)
        table.add_column("UID", no_wrap=True, min_width=5)
        table.add_column("STATUS", no_wrap=True, min_width=19)
        for record in snap.processes[:rows]:
            event = record.event
            if record.severity is not None:
                status = Text(f"SUSPICIOUS ({record.severity.value})")
                status.stylize(severity_style(record.severity))
            elif record.baseline:
                status = Text("NORMAL (baseline)", style="green dim")
            else:
                status = Text("NORMAL", style="green")
            table.add_row(
                clean(event.pid),
                clean(event.ppid),
                clean(event.process_name, 24),
                clean(event.uid),
                status,
            )
        body = table
    return Panel(
        body,
        title="RECENT PROCESSES (NORMAL = no rule matched)",
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
    sections: list[Layout] = [Layout(header(snap), name="header", size=5)]
    used = 5 + 1
    error = error_banner(snap)
    if error is not None:
        sections.append(Layout(error, name="error", size=3))
        used += 3
    top = Layout(name="top", size=13)
    if width >= 110:
        top.split_row(
            Layout(overview(snap), name="overview", ratio=3),
            Layout(severity_panel(snap), name="severity", ratio=2),
            Layout(incidents_panel(snap, 8), name="incidents", ratio=4),
        )
    else:
        top.split_row(
            Layout(overview(snap, inline_severity=True), name="overview", ratio=1),
            Layout(incidents_panel(snap, 8), name="incidents", ratio=1),
        )
    sections.append(top)
    used += 13
    banner_lines = min(6, 3 + len(snap.notifications))
    banner = alert_banner(snap, banner_lines) if height - used > 16 else None
    if banner is not None:
        sections.append(Layout(banner, name="alerts", size=banner_lines))
        used += banner_lines
    debug = snap.info.verbosity >= Verbosity.DEBUG and height - used > 18
    remaining = height - used - (8 if debug else 0)
    body = Layout(name="body")
    if width >= 140:
        body.split_row(
            Layout(processes_panel(snap, remaining), name="processes", ratio=2),
            Layout(log_panel(snap.logs, remaining, snap.info.verbosity), name="logs", ratio=3),
        )
    else:
        process_height = min(10, max(5, remaining // 3))
        body.split_column(
            Layout(processes_panel(snap, process_height), name="processes", size=process_height),
            Layout(
                log_panel(snap.logs, remaining - process_height, snap.info.verbosity),
                name="logs",
            ),
        )
    sections.append(body)
    if debug:
        sections.append(Layout(diagnostics_panel(snap, 8), name="diagnostics", size=8))
    sections.append(Layout(footer(snap, interactive), name="footer", size=1))
    layout.split_column(*sections)
    return layout


def compact(snap: DashboardSnapshot, height: int, interactive: bool) -> RenderableType:
    """Small terminals: key counters, the newest entries and the command line only."""
    c = snap.counters
    status = Text(no_wrap=True, overflow="ellipsis")
    status.append(f"{snap.status} ", style=STATUS_STYLES.get(snap.status, "bold"))
    status.append(
        f"obs={c.observed} proc={c.processed} matches={c.rule_matches} "
        f"alerts={snap.unique_alerts} incidents={len(snap.incidents)} dropped={c.dropped}"
    )
    parts: list[RenderableType] = [status]
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


def render_process_tree(state: DashboardState | None, width: int, height: int, *,
    process_tree: dict[str, Any] | None = None,
    selected_key: str | None = None,
    show_suspicious_only: bool = False) -> RenderableType:
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

    # Select root if specified
    if selected_key is None:
        # Show tree rooted at first suspicious process
        suspicious_keys = [k for k, v in process_tree.items()
                          if v["lifecycle"] == ProcessLifecycle.EXITED
                          or (getattr(v["event"], "severity", None) 
                              and v["event"].severity.rank < 3)]
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
        elif lifecycle == ProcessLifecycle.RUNNING:
            suffix = " [RUNNING]"

        if show_suspicious_only and not (
    getattr(event, "severity", None)
    and getattr(event.severity, "rank", -1) < 3
):
            return  # Skip non-suspicious processes

        # Create rich label
        label_text = f"PID {pid} {pname}{suffix}"
        if getattr(event, "severity", None):
            label_text += f" {severity_text(event.severity)}"

        node = Tree(label_text, guide_style="dim")

        # Add children
        for child_key in node_data["children"]:
            add_node(node, child_key, depth + 1)

        # Add parent info if available
        if node_data["parent"]:
            parent_record = state.processes.get(node_data["parent"])
            if parent_record is not None and parent_record.event is not None:
                node.add(f"  (parent PID {parent_record.event.pid})")

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

    root_label = f"PID {pid} {pname}{suffix}"
    if getattr(root_event, "severity", None):
        root_label += f" {severity_text(root_event.severity)}"

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
