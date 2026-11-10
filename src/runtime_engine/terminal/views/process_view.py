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
    command_line,
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
    ("6", "Back to dashboard"),
)


def render_process_list(records: list[ProcessRecord], title: str) -> RenderableType:
    if not records:
        return Panel(
            Text(
                "No process has a rule match in this session.\n"
                "You can still enter the PID of any observed process.",
                style="dim",
            ),
            title=title,
            title_align="left",
        )
    table = Table(title=title, title_justify="left", expand=False)
    table.add_column("PID", justify="right")
    table.add_column("PPID", justify="right")
    table.add_column("PROCESS")
    table.add_column("SEVERITY")
    table.add_column("ALERTS", justify="right")
    table.add_column("INCIDENTS")
    for record in records:
        table.add_row(
            clean(record.event.pid),
            clean(record.event.ppid),
            clean(record.event.process_name, 24),
            severity_text(record.severity),
            str(len(record.alert_ids)),
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


def render_process_details(details: ProcessDetails) -> RenderableType:
    event = details.event
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    cmd = (
        command_line(event.command_line)
        if event.command_line
        else "not collected (enable with monitor --include-cmdline, if authorized)"
    )
    live = details.liveness
    status = Text(live.label, style="bold green" if live.running else "bold yellow")
    status.append(f" - {live.detail}", style="")
    started = (
        f"{timestamp(details.started_at)} (derived from boot time + start ticks)"
        if details.started_at
        else "N/A (only kernel start ticks are known)"
    )
    first = timestamp(details.first_observed)
    if details.baseline:
        first += "  [baseline snapshot: already running when monitoring started]"
    detection = (
        severity_text(details.severity).append("  SUSPICIOUS - rule match(es) below")
        if details.severity
        else Text("NO RULE MATCHED (not proof of benign behaviour)", style="green")
    )
    for label, value in (
        ("PID", clean(event.pid)),
        ("PPID", clean(event.ppid)),
        ("PROCESS NAME", clean(event.process_name)),
        ("PARENT NAME", clean(event.parent_process_name)),
        ("EXECUTABLE", clean(event.executable_path, missing="unknown (unreadable or absent)")),
        ("COMMAND LINE", cmd),
        ("USER ID", user(event.uid, event.source == "proc")),
        ("START TIME", started),
        ("START TOKEN", f"{clean(event.process_start_time)} (kernel start ticks)"),
        ("FIRST OBSERVED", first),
        ("SOURCE", clean(event.source)),
        ("IDENTITY", clean(details.key)),
    ):
        grid.add_row(label, value)
    grid.add_row("LIVE STATUS", status)
    grid.add_row("DETECTION STATUS", detection)
    sections: list[RenderableType] = [grid, Text("")]
    if not details.liveness.running:
        sections.append(
            Text(
                "Showing HISTORICAL information recorded by the engine. The PID was not used "
                "to read data about any other process.",
                style="yellow",
            )
        )
    sections.append(Text("TRIGGERED RULES", style="bold underline"))
    if details.alerts:
        for alert in details.alerts:
            line = Text("- ")
            line.append(f"{alert.rule_id}: {clean(alert.rule_name)} ")
            line.append_text(severity_text(alert.severity))
            line.append(f"  occurrences={len(alert.event_ids)}")
            line.append(f"\n    matched: {clean(alert.reason)}", style="dim")
            sections.append(line)
    else:
        sections.append(Text("- none", style="dim"))
    sections.append(
        Text("\nRELATED EVENTS (stored telemetry for this identity)", style="bold underline")
    )
    sections.append(event_table(details.events) if details.events else Text("- none", style="dim"))
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
                else ("context: ancestor of a matched process")
            )
            line = Text(f"- {incident.incident_id} ")
            line.append_text(severity_text(incident.severity))
            line.append(f"  {role}", style="dim")
            sections.append(line)
    else:
        sections.append(Text("- none", style="dim"))
    return Panel(Group(*sections), title="PROCESS DETAILS", title_align="left")


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
