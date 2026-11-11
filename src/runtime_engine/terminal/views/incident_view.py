"""Incident inspection built from persisted evidence and the loaded rule definitions."""

from collections.abc import Iterable
from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from runtime_engine.events.schema import Event, Incident
from runtime_engine.incidents.reporter import export_json
from runtime_engine.monitor.investigation import IncidentDetails, identity
from runtime_engine.process.ancestry import parent_key
from runtime_engine.terminal.formatting import clean, severity_text, timestamp

ACTIONS = (
    ("1", "View all related events"),
    ("2", "View process details"),
    ("3", "View complete evidence"),
    ("4", "Export JSON report"),
    ("5", "Return to dashboard"),
)
NOT_CONFIRMED = (
    "An incident groups rule matches for human review. It does not confirm that a "
    "compromise or attack took place."
)


def render_incident_list(incidents: list[Incident], active: Iterable[str]) -> RenderableType:
    active_ids = set(active)
    if not incidents:
        return Panel(
            Text(
                "No security incidents were generated during this session.\n"
                "This does not prove that the machine is safe.",
                style="dim",
            ),
            title="INCIDENTS",
            title_align="left",
        )
    table = Table(title="INCIDENTS", title_justify="left")
    table.add_column("ID")
    table.add_column("SEVERITY")
    table.add_column("ALERTS", justify="right")
    table.add_column("EVENTS", justify="right")
    table.add_column("STATUS")
    table.add_column("LAST OBSERVED")
    table.add_column("RULES")
    for incident in incidents:
        window = "ACTIVE" if incident.incident_id in active_ids else "WINDOW CLOSED"
        table.add_row(
            incident.incident_id,
            severity_text(incident.severity),
            str(len(incident.alert_ids)),
            str(incident.event_count),
            f"{incident.status} / {window}",
            timestamp(incident.last_seen),
            ", ".join(incident.rule_ids),
        )
    return table


def _process_label(event: Event | None, key: str, matched: bool) -> Text:
    if event is None:
        parsed = identity(key)
        return Text(f"[not observed] PID {parsed[1] if parsed else '?'}", style="dim italic")
    label = Text(f"{clean(event.process_name, 32)} (PID {event.pid})")
    label.append("  [rule match]" if matched else "  [context]", style="bold" if matched else "dim")
    return label


def process_tree(details: IncidentDetails) -> RenderableType:
    """Tree of the incident's matched processes and their observed ancestors."""
    incident = details.incident
    nodes = {e.process_key: e for e in details.processes if e.process_key}
    keys = list(dict.fromkeys([*incident.context_process_keys, *nodes]))
    parent: dict[str, str] = {}
    for key in keys:
        event = nodes.get(key)
        candidate = parent_key(event) if event else None
        if candidate is not None and candidate in keys:
            parent[key] = candidate
    children: dict[str, list[str]] = {}
    for key, value in parent.items():
        children.setdefault(value, []).append(key)
    roots = [k for k in keys if k not in parent]
    if not roots:
        return Text("No process identity was recorded for this incident.", style="dim")
    trees: list[RenderableType] = []
    visited: set[str] = set()

    def grow(branch: Tree, key: str) -> None:
        for child in children.get(key, []):
            if child in visited:
                continue
            visited.add(child)
            grow(
                branch.add(_process_label(nodes.get(child), child, child in incident.process_keys)),
                child,
            )

    for root in roots:
        visited.add(root)
        tree = Tree(
            _process_label(nodes.get(root), root, root in incident.process_keys),
            guide_style="dim",
        )
        grow(tree, root)
        trees.append(tree)
    return Group(*trees)


def _rules_for_event(details: IncidentDetails, event_id: str) -> str:
    return ", ".join(a.rule_id for a in details.detections if event_id in a.event_ids)


def why_flagged(details: IncidentDetails) -> RenderableType:
    parts: list[RenderableType] = []
    for alert in details.detections:
        rule = details.rules.get(alert.rule_id)
        heading = Text(f"{alert.rule_id} - {clean(alert.rule_name)}  ", style="bold")
        heading.append_text(severity_text(alert.severity))
        parts.append(heading)
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column(overflow="fold")
        if rule is not None:
            grid.add_row("Rule description", clean(rule.description))
            grid.add_row("Applies to", rule.event_type.value)
            grid.add_row(
                "Conditions (all)",
                "\n".join(f"{c.field} {c.op} {clean(c.value)}" for c in rule.conditions),
            )
        else:
            grid.add_row("Rule description", "rule not loaded in this session (stored alert only)")
        grid.add_row("Matched evidence", clean(alert.reason))
        grid.add_row("Occurrences", f"{len(alert.event_ids)} event(s)")
        grid.add_row("Resource", clean(alert.resource))
        if alert.mitre_reference:
            grid.add_row("Reference", clean(alert.mitre_reference))
        parts.append(grid)
    parts.append(Text(""))
    parts.append(Text("Correlation: " + clean(details.incident.explanation)))
    severity = Text("Severity: ")
    severity.append_text(severity_text(details.incident.severity))
    severity.append(" = highest severity among this incident's rule matches.")
    parts.append(severity)
    parts.append(Text(NOT_CONFIRMED, style="italic"))
    return Group(*parts)


def render_incident_details(details: IncidentDetails) -> RenderableType:
    incident, report = details.incident, details.report
    window = (
        "unknown (historical view)"
        if details.active is None
        else "ACTIVE (related evidence can still join)"
        if details.active
        else "CLOSED (correlation window elapsed or session ended)"
    )
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("TITLE", clean(incident.title))
    grid.add_row("SEVERITY", severity_text(incident.severity))
    grid.add_row("STATUS", f"{incident.status} (awaiting review); correlation window {window}")
    grid.add_row("FIRST OBSERVED", timestamp(incident.first_seen))
    grid.add_row("LAST OBSERVED", timestamp(incident.last_seen))
    grid.add_row(
        "EVIDENCE",
        f"{incident.event_count} matched event(s), {len(incident.alert_ids)} alert(s), "
        f"{len(report['context_events'])} context event(s)",
    )
    processes = Text()
    matched = set(incident.process_keys)
    for event in details.processes:
        processes.append(
            f"- {clean(event.process_name, 32)} PID {event.pid}"
            f"{'  [rule match]' if event.process_key in matched else '  [context]'}\n"
        )
    rules = Text()
    for rule_id in incident.rule_ids:
        rule = details.rules.get(rule_id)
        rules.append(f"- {rule_id}{': ' + clean(rule.name) if rule else ''}\n")
    timeline = Table(box=None, padding=(0, 1), show_edge=False)
    timeline.add_column("TIME", no_wrap=True)
    timeline.add_column("EVENT TYPE", no_wrap=True)
    timeline.add_column("PID", justify="right")
    timeline.add_column("RULES MATCHED")
    for item in report["evidence_timeline"]:
        timeline.add_row(
            timestamp(item["timestamp"]),
            clean(item["event_type"]),
            clean(item["pid"]),
            _rules_for_event(details, item["event_id"]),
        )
    return Panel(
        Group(
            grid,
            Text("\nRELATED PROCESSES", style="bold underline"),
            processes if details.processes else Text("- none recorded", style="dim"),
            Text("DETECTION RULES", style="bold underline"),
            rules,
            Text("EVIDENCE TIMELINE (rule-matched events)", style="bold underline"),
            timeline,
            Text("\nPROCESS TREE", style="bold underline"),
            process_tree(details),
            Text("\nWHY WAS THIS FLAGGED?", style="bold underline"),
            why_flagged(details),
        ),
        title=f"SECURITY INCIDENT: {incident.incident_id}",
        title_align="left",
        border_style="red",
    )


def _events_table(title: str, events: list[dict[str, Any]], details: IncidentDetails) -> Table:
    table = Table(title=title, title_justify="left")
    table.add_column("TIME", no_wrap=True)
    table.add_column("TYPE")
    table.add_column("PID", justify="right")
    table.add_column("PROCESS")
    table.add_column("DETAIL", overflow="fold")
    table.add_column("RULES")
    for event in events:
        detail = (
            event.get("file_path")
            or event.get("network_destination")
            or event.get("executable_path")
        )
        table.add_row(
            timestamp(event["timestamp"]),
            clean(event["event_type"]),
            clean(event.get("pid")),
            clean(event.get("process_name"), 24),
            clean(detail),
            _rules_for_event(details, event["event_id"]) or "-",
        )
    return table


def render_related_events(details: IncidentDetails) -> RenderableType:
    report = details.report
    parts: list[RenderableType] = [
        _events_table("SUPPORTING EVENTS (matched a rule)", report["supporting_events"], details)
    ]
    if report["context_events"]:
        parts.append(
            _events_table(
                "CONTEXT EVENTS (ancestor observations; no rule match)",
                report["context_events"],
                details,
            )
        )
    else:
        parts.append(Text("No separate ancestor context events were stored.", style="dim"))
    return Group(*parts)


def render_evidence(details: IncidentDetails) -> RenderableType:
    """Full normalized evidence; JSON escaping keeps control characters inert."""
    return Panel(
        Text(export_json(details.report)),
        title=f"COMPLETE EVIDENCE: {details.incident.incident_id}",
        title_align="left",
    )
