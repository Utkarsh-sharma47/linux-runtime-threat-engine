"""Process inspection: identity, live/historical status, rules, events, ancestry, children."""

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from runtime_engine.events.schema import Event
from runtime_engine.monitor.investigation import LineageNode, ProcessDetails
from runtime_engine.monitor.state import ProcessRecord
from runtime_engine.terminal.formatting import (
    clean,
    severity_text,
    timestamp,
    user,
)

ACTIONS = (
    ("1", "View parent process"),
    ("2", "View child processes"),
    ("3", "View complete ancestry"),
    ("4", "View associated alerts"),
    ("5", "View associated incidents"),
    ("6", "View related events"),
    ("7", "Back to dashboard"),
)


def _reason(record: ProcessRecord) -> str:
    if record.incident_ids:
        return f"incident {', '.join(record.incident_ids[:2])}"
    if record.alert_ids:
        return f"{len(record.alert_ids)} alert(s)"
    return "rule match"


def render_process_list(records: list[ProcessRecord], title: str) -> RenderableType:
    if not records:
        return Panel(
            Text(
                "No suspicious processes in this session.\n"
                "Enter a PID to inspect any observed process, or press Enter to return.",
                style="dim",
            ),
            title=title,
            title_align="left",
        )
    table = Table(title=title, title_justify="left", expand=False)
    table.add_column("PID", justify="right")
    table.add_column("PROCESS")
    table.add_column("SEVERITY")
    table.add_column("REASON", overflow="fold")
    table.add_column("INCIDENTS")
    for record in records:
        table.add_row(
            clean(record.event.pid),
            clean(record.event.process_name, 24),
            severity_text(record.severity),
            clean(_reason(record), 40),
            ", ".join(record.incident_ids) or "-",
        )
    return table


def render_identity_choices(events: list[Event]) -> RenderableType:
    """Several identities shared one PID (PID reuse); the user must pick one explicitly."""
    table = Table(
        title="This PID was used by more than one process identity",
        title_justify="left",
        caption="Identity = boot ID + PID + kernel start ticks. Choose by row number.",
    )
    table.add_column("#", justify="right")
    table.add_column("PROCESS")
    table.add_column("START TOKEN")
    table.add_column("FIRST OBSERVED")
    table.add_column("HOST/BOOT")
    for index, event in enumerate(events, 1):
        table.add_row(
            str(index),
            clean(event.process_name, 24),
            clean(event.process_start_time),
            timestamp(event.timestamp),
            clean(event.host_id, 12),
        )
    return table


def _node_label(node: LineageNode, details: ProcessDetails) -> Text:
    if node.event is None:
        return Text(
            f"[not observed] PID {clean(node.pid)} start={clean(node.start)}", style="dim italic"
        )
    label = Text(f"{clean(node.event.process_name, 32)} (PID {node.event.pid})")
    severity = details.severities.get(node.key)
    if severity is not None:
        label.append("  ")
        label.append_text(severity_text(severity))
    if node.key == details.key:
        label.append("  <- selected", style="bold")
        label.stylize("bold")
    return label


def ancestry_tree(details: ProcessDetails, *, verbose: bool = False) -> Tree:
    """Root-to-selected chain from explicit parent identities, then observed children."""
    tree: Tree | None = None
    branch: Tree | None = None
    for node in details.lineage:
        label = _node_label(node, details)
        if verbose and node.event is not None:
            label.append(
                f"\n  start={clean(node.event.process_start_time)}"
                f" exe={clean(node.event.executable_path, 60)}",
                style="dim",
            )
        branch = Tree(label, guide_style="dim") if branch is None else branch.add(label)
        tree = tree or branch
    assert tree is not None and branch is not None
    for child in details.children:
        label = Text(f"{clean(child.process_name, 32)} (PID {child.pid})")
        severity = details.severities.get(child.process_key or "")
        if severity is not None:
            label.append("  ")
            label.append_text(severity_text(severity))
        branch.add(label)
    return tree


def render_process_details(details: ProcessDetails, *, full: bool = False) -> RenderableType:
    """Compact summary by default. ``full=True`` includes ancestry/events (CLI)."""
    event = details.event
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    live = details.liveness
    status = Text(live.label, style="bold green" if live.running else "bold yellow")
    status.append(f" - {live.detail}", style="")
    detection = (
        severity_text(details.severity).append("  SUSPICIOUS")
        if details.severity
        else Text("NO RULE MATCHED (not proof of benign behaviour)", style="green")
    )
    top_reason = details.alerts[0].reason if details.alerts else "-"
    for label, value in (
        ("PID", clean(event.pid)),
        ("PROCESS NAME", clean(event.process_name)),
        ("EXECUTABLE", clean(event.executable_path, missing="unknown")),
        ("USER ID", user(event.uid, event.source == "proc")),
        ("FIRST OBSERVED", timestamp(details.first_observed)),
        ("LIVE STATUS", status),
        ("DETECTION", detection),
        ("REASON", clean(top_reason, 80)),
        ("ALERTS", str(len(details.alerts))),
        ("INCIDENTS", ", ".join(i.incident_id for i in details.incidents) or "-"),
    ):
        grid.add_row(label, value)
    sections: list[RenderableType] = [grid]
    if not details.liveness.running:
        sections.append(
            Text(
                "Showing HISTORICAL information recorded by the engine. The PID was not used "
                "to read data about any other process.",
                style="yellow",
            )
        )
    if details.alerts:
        sections.append(Text("\nTOP RULE MATCHES", style="bold underline"))
        for alert in details.alerts[: 3 if not full else None]:
            line = Text("- ")
            line.append(f"{alert.rule_id}: {clean(alert.rule_name)} ")
            line.append_text(severity_text(alert.severity))
            line.append(f"\n    matched: {clean(alert.reason)}", style="dim")
            sections.append(line)
        if not full and len(details.alerts) > 3:
            sections.append(Text(f"  +{len(details.alerts) - 3} more (action 4)", style="dim"))
    if full:
        sections.append(
            Text("\nRELATED EVENTS (stored telemetry for this identity)", style="bold underline")
        )
        sections.append(
            event_table(details.events) if details.events else Text("- none", style="dim")
        )
        sections.append(
            Text("\nPROCESS ANCESTRY (explicit parent identities only)", style="bold underline")
        )
        sections.append(ancestry_tree(details))
        sections.append(Text("\nRELATED INCIDENTS", style="bold underline"))
        if details.incidents:
            for incident in details.incidents:
                role = (
                    "rule match on this process"
                    if details.key in incident.process_keys
                    else "context: ancestor of a matched process"
                )
                line = Text(f"- {incident.incident_id} ")
                line.append_text(severity_text(incident.severity))
                line.append(f"  {role}", style="dim")
                sections.append(line)
        else:
            sections.append(Text("- none", style="dim"))
    else:
        sections.append(
            Text("\nSelect an action for ancestry, events, alerts, or incidents.", style="dim")
        )
    return Panel(Group(*sections), title="PROCESS DETAILS", title_align="left")


def render_process_events(details: ProcessDetails) -> RenderableType:
    if not details.events:
        return Text("No related events for this process in the current session.", style="dim")
    return Panel(
        event_table(details.events),
        title="RELATED EVENTS (this session)",
        title_align="left",
    )


def event_table(events: list[Event]) -> Table:
    table = Table(box=None, padding=(0, 1), show_edge=False)
    table.add_column("TIME", no_wrap=True)
    table.add_column("TYPE", no_wrap=True)
    table.add_column("DETAIL", overflow="fold")
    for event in events:
        detail = (
            event.file_path
            or event.network_destination
            or (
                f"uid {event.previous_uid} -> {event.uid}"
                if event.previous_uid is not None
                else None
            )
            or event.executable_path
        )
        table.add_row(timestamp(event.timestamp), event.event_type.value, clean(detail))
    return table


def render_children(details: ProcessDetails) -> RenderableType:
    if not details.children:
        return Text(
            "No child processes with this process as their explicit parent were observed.",
            style="dim",
        )
    table = Table(title="CHILD PROCESSES (observed)", title_justify="left")
    table.add_column("#", justify="right")
    table.add_column("PID", justify="right")
    table.add_column("PROCESS")
    table.add_column("SEVERITY")
    table.add_column("FIRST OBSERVED")
    for index, child in enumerate(details.children, 1):
        table.add_row(
            str(index),
            clean(child.pid),
            clean(child.process_name, 24),
            severity_text(details.severities.get(child.process_key or "")),
            timestamp(child.timestamp),
        )
    return table


def render_full_ancestry(details: ProcessDetails) -> RenderableType:
    note = Text(
        "Edges require the child's reported parent PID and parent start ticks. "
        "A PID match alone never links processes.",
        style="dim",
    )
    return Panel(
        Group(ancestry_tree(details, verbose=True), Text(""), note),
        title="COMPLETE ANCESTRY",
        title_align="left",
    )


def render_alerts(details: ProcessDetails) -> RenderableType:
    if not details.alerts:
        return Text("No alerts are associated with this process.", style="dim")
    table = Table(title="ASSOCIATED ALERTS", title_justify="left")
    table.add_column("RULE")
    table.add_column("NAME")
    table.add_column("SEVERITY")
    table.add_column("FIRST SEEN")
    table.add_column("LAST SEEN")
    table.add_column("COUNT", justify="right")
    table.add_column("MATCHED CONDITIONS", overflow="fold")
    for alert in details.alerts:
        table.add_row(
            alert.rule_id,
            clean(alert.rule_name),
            severity_text(alert.severity),
            timestamp(alert.first_seen),
            timestamp(alert.last_seen),
            str(len(alert.event_ids)),
            clean(alert.reason),
        )
    return table


def render_actions(actions: tuple[tuple[str, str], ...] = ACTIONS) -> Text:
    text = Text("Available actions:\n", style="bold")
    for key, label in actions:
        text.append(f"  [{key}] {label}\n")
    return text
