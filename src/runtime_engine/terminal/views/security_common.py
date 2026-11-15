"""Shared Rich components for the security module pages (findings, coverage, status)."""

import json
from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.security.findings import Finding, ScanReport
from runtime_engine.terminal.formatting import clean, severity_text, timestamp

STATUS_STYLES = {
    "ok": "bold green",
    "degraded": "bold yellow",
    "baseline-created": "bold cyan",
    "no-baseline": "bold yellow",
    "not-baselined": "bold yellow",
    "no-model": "bold yellow",
    "untrained": "bold yellow",
    "disabled": "dim",
    "error": "bold white on dark_red",
    "unavailable": "bold yellow",
}
STATUS_MEANING = {
    "ok": "scan complete",
    "degraded": "scan complete, but some locations could not be read (see coverage)",
    "baseline-created": "first scan recorded the baseline; changes are reported from now on",
    "no-baseline": "NOT BASELINED: nothing can be compared yet",
    "not-baselined": "NOT BASELINED: nothing can be compared yet",
    "no-model": "UNTRAINED: no trained model; nothing is scored",
    "untrained": "UNTRAINED: no trained model; nothing is scored",
    "disabled": "DISABLED in configuration",
    "error": "the scan failed; this is NOT a clean result",
    "unavailable": "UNAVAILABLE: required telemetry is not available on this host",
}
STATUS_DISPLAY = {
    "no-baseline": "NOT BASELINED",
    "not-baselined": "NOT BASELINED",
    "no-model": "UNTRAINED",
    "untrained": "UNTRAINED",
    "disabled": "DISABLED",
    "unavailable": "UNAVAILABLE",
}


def as_dict(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    return finding.model_dump(mode="json") if isinstance(finding, Finding) else finding


def status_text(status: str | None) -> Text:
    key = status or "not run"
    label = STATUS_DISPLAY.get(key, key.upper())
    return Text(label, style=STATUS_STYLES.get(status or "", "dim"))


def report_header(
    title: str, report: ScanReport | None, extra: list[tuple[str, RenderableType]]
) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    status = report.status if report else None
    line = status_text(status)
    if status in STATUS_MEANING:
        line.append(f"  {STATUS_MEANING[status]}", style="")
    grid.add_row("STATUS", line)
    if report is not None:
        grid.add_row(
            "LAST SCAN",
            f"{timestamp(report.started_at)} ({report.duration_seconds * 1000:.0f} ms)",
        )
        if report.error:
            grid.add_row("ERROR", Text(clean(report.error), style="bold red"))
    else:
        grid.add_row("LAST SCAN", "not run yet")
    for label, value in extra:
        grid.add_row(label, value)
    return grid


def coverage_panel(report: ScanReport | None) -> RenderableType:
    if report is None:
        return Text("Coverage: no scan yet.", style="dim")
    cov = report.coverage
    text = Text()
    text.append(f"Checked {cov.checked:,} item(s). ")
    if cov.denied_count:
        text.append(f"{cov.denied_count} unreadable (permission denied)", style="yellow")
        if cov.denied:
            text.append(": " + ", ".join(clean(p, 60) for p in cov.denied[:5]))
            if len(cov.denied) > 5:
                text.append(", ...")
        text.append(". ")
    else:
        text.append("No permission errors. ", style="green")
    for note in cov.unavailable:
        text.append(f"\nNot observable: {clean(note)}", style="yellow")
    if report.suppressed:
        text.append(f"\n{report.suppressed} finding(s) suppressed by the allowlist.", style="dim")
    return Panel(text, title="COVERAGE (what this scan could not see)", title_align="left")


def findings_table(
    findings: list[Finding] | list[dict[str, Any]],
    title: str,
    *,
    empty: str = "No findings.",
    limit: int = 40,
) -> RenderableType:
    rows = [as_dict(f) for f in findings]
    if not rows:
        return Panel(Text(empty, style="dim"), title=title, title_align="left")
    table = Table(title=title, title_justify="left", expand=True)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("FINDING", no_wrap=True)
    table.add_column("RULE", no_wrap=True)
    table.add_column("SEVERITY", no_wrap=True)
    table.add_column("RESOURCE", overflow="ellipsis", no_wrap=True, ratio=2)
    table.add_column("EVIDENCE", overflow="ellipsis", no_wrap=True, ratio=3)
    table.add_column("INCIDENT?", no_wrap=True)
    for index, item in enumerate(rows[:limit], 1):
        evidence = item.get("evidence", {})
        summary = evidence.get("change") or evidence.get("summary") or item.get("title", "")
        table.add_row(
            str(index),
            item["finding_id"],
            item["rule_id"],
            severity_text(item["severity"]),
            clean(item["resource"], 60),
            clean(summary, 90),
            "promoted" if item.get("promoted") else "stored only",
        )
    if len(rows) > limit:
        table.caption = f"{len(rows) - limit} more not shown"
    return table


def finding_detail(finding: Finding | dict[str, Any]) -> RenderableType:
    item = as_dict(finding)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("FINDING", item["finding_id"])
    grid.add_row("MODULE / RULE", f"{item['module']} / {item['rule_id']}: {clean(item['title'])}")
    grid.add_row("SEVERITY", severity_text(item["severity"]))
    if item.get("risk_score") is not None:
        grid.add_row("RISK SCORE", f"{item['risk_score']:.1f}")
    grid.add_row("RESOURCE", clean(item["resource"]))
    grid.add_row("DETECTED", timestamp(item.get("detected_at")))
    if item.get("first_seen"):
        grid.add_row(
            "HISTORY",
            f"first {timestamp(item['first_seen'])}, last {timestamp(item['last_seen'])}, "
            f"{item.get('occurrences', 1)} scan(s)",
        )
    process = (
        f"{clean(item.get('process_name'))} PID {item.get('pid')}"
        if item.get("pid") is not None
        else "none"
    )
    grid.add_row("PROCESS", f"{process}  (attribution: {clean(item.get('attribution'))})")
    grid.add_row(
        "INCIDENT",
        "promoted into incident correlation"
        if item.get("promoted")
        else "stored only (below the promotion threshold)",
    )
    if item.get("mitre_reference"):
        grid.add_row("REFERENCE", clean(item["mitre_reference"]))
    grid.add_row("EXPLANATION", clean(item.get("explanation")))
    if item.get("remediation"):
        grid.add_row("REMEDIATION", clean(item["remediation"]))
    evidence = Text(json.dumps(item.get("evidence", {}), indent=2, ensure_ascii=True, default=str))
    return Panel(
        Group(grid, Text(""), Text("EVIDENCE", style="bold underline"), evidence),
        title=f"FINDING {item['finding_id']}",
        title_align="left",
    )
