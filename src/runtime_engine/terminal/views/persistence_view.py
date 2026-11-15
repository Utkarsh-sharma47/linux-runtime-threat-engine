"""Persistence Monitor page: baseline, monitored locations, persistence and privilege changes."""

from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.security.findings import Finding, ScanReport
from runtime_engine.terminal.formatting import clean
from runtime_engine.terminal.views.security_common import (
    as_dict,
    coverage_panel,
    findings_table,
    report_header,
)

PRIVILEGE_RULES = {"PM004", "PM005", "PM006", "PM008"}


def render_persistence(
    report: ScanReport | None, findings: list[Finding] | list[dict[str, Any]]
) -> RenderableType:
    rows = [as_dict(f) for f in findings]
    summary = report.summary if report else {}
    header = report_header(
        "PERSISTENCE MONITOR",
        report,
        [
            ("BASELINE", clean(summary.get("baseline", "none"))),
            (
                "ITEMS",
                ", ".join(f"{k} {v}" for k, v in summary.get("items", {}).items()) or "-",
            ),
        ],
    )
    locations = Table(title="MONITORED LOCATIONS", title_justify="left", show_header=False)
    locations.add_column(style="bold", no_wrap=True)
    locations.add_column(overflow="fold")
    for name, paths in summary.get("monitored", {}).items():
        locations.add_row(name, clean(", ".join(paths)))
    privileged = summary.get("privileged_items", [])
    privileged_view: RenderableType = Text(
        "Privileged executables now: "
        + (", ".join(clean(p, 80) for p in privileged[:12]) or "none")
        + (f" (+{len(privileged) - 12} more)" if len(privileged) > 12 else ""),
        style="dim",
    )
    persistence = [r for r in rows if r["rule_id"] not in PRIVILEGE_RULES]
    privilege = [r for r in rows if r["rule_id"] in PRIVILEGE_RULES]
    return Panel(
        Group(
            header,
            Text(""),
            locations,
            privileged_view,
            coverage_panel(report),
            findings_table(
                persistence,
                "NEW OR MODIFIED PERSISTENCE MECHANISMS (systemd, cron, SSH keys, executables)",
                empty="No persistence changes relative to the baseline.",
            ),
            findings_table(
                privilege,
                "PRIVILEGE-RELATED CHANGES (sudoers, SUID/SGID, capabilities, permissions)",
                empty="No privilege-related changes relative to the baseline.",
            ),
            Text(
                "Changes are evidence for review, not verdicts. The writing process is not "
                "known: polling cannot attribute file changes.",
                style="dim italic",
            ),
        ),
        title="PERSISTENCE MONITOR",
        title_align="left",
        border_style="cyan",
    )
