"""Security Investigation menu, dashboard status line and session-summary section."""

from typing import Any

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import MODULES, Finding, ScanReport
from runtime_engine.terminal.formatting import clean, severity_style, severity_text
from runtime_engine.terminal.views.anomaly_view import render_anomaly
from runtime_engine.terminal.views.exposure_view import render_exposure
from runtime_engine.terminal.views.integrity_view import render_integrity
from runtime_engine.terminal.views.network_view import render_network
from runtime_engine.terminal.views.persistence_view import render_persistence
from runtime_engine.terminal.views.ransomware_view import render_ransomware
from runtime_engine.terminal.views.security_common import (
    STATUS_DISPLAY,
    STATUS_STYLES,
    status_text,
)

TITLES = {
    "persistence": ("Persistence & privilege", "cron, systemd, shell profiles, sudoers, SUID"),
    "network": ("Network behaviour", "sockets with process attribution, beaconing"),
    "anomaly": ("Process anomalies", "Isolation Forest / robust-z behaviour scoring"),
    "integrity": ("File integrity (Merkle)", "signed SHA-256 Merkle baseline of key files"),
    "exposure": ("Attack surface", "listeners, SUID/capabilities, writable paths, keys"),
    "ransomware": ("Ransomware early warning", "file behaviour in configured directories"),
}
SEVERITIES = list(reversed(Severity))  # CRITICAL first
RENDERERS = {
    "persistence": render_persistence,
    "network": render_network,
    "anomaly": render_anomaly,
    "integrity": render_integrity,
    "exposure": render_exposure,
    "ransomware": render_ransomware,
}


def resolve_module(answer: str) -> str | None:
    """Accept a menu number, a module name or an unambiguous prefix of one."""
    text = answer.strip().lower()
    if text.isdigit() and 1 <= int(text) <= len(MODULES):
        return MODULES[int(text) - 1]
    matches = [m for m in MODULES if m.startswith(text)] if text else []
    return matches[0] if len(matches) == 1 else None


def counts_text(by_severity: dict[str, int]) -> Text:
    text = Text()
    for index, level in enumerate(SEVERITIES):
        if index:
            text.append("/", style="dim")
        count = by_severity.get(level.value, 0)
        text.append(str(count), style=severity_style(level) if count else "dim")
    return text


def state_text(entry: dict[str, Any]) -> Text:
    enabled = entry.get("enabled", "not configured")
    if enabled == "enabled":
        if entry.get("status") is None:
            return Text("PENDING (first scan not finished)", style="dim")
        return status_text(entry.get("status"))
    return Text(f"OFF: {clean(enabled, 60)}", style="dim")


def _latest_finding_label(entry: dict[str, Any]) -> tuple[str, Text]:
    """Return (title, severity text) for the module's most severe recent finding."""
    latest = entry.get("latest_finding")
    if isinstance(latest, dict):
        title = clean(latest.get("title") or latest.get("rule_id") or "finding", 40)
        severity = latest.get("severity")
        try:
            level = Severity(severity) if isinstance(severity, str) else severity
        except ValueError:
            level = None
        return title, severity_text(level) if level else Text("-", style="dim")
    count = entry.get("findings") or 0
    if count:
        return f"{count} finding(s)", counts_text(entry.get("by_severity", {}))
    status = entry.get("status")
    if entry.get("enabled") != "enabled":
        return "not running", Text("-", style="dim")
    if status in ("untrained", "no-model"):
        return "model untrained", Text("UNTRAINED", style="bold yellow")
    if status in ("no-baseline", "not-baselined"):
        return "not baselined", Text("NOT BASELINED", style="bold yellow")
    if status == "degraded":
        return "scan degraded", Text("DEGRADED", style="bold yellow")
    if status is None:
        return "awaiting first scan", Text("-", style="dim")
    return "no findings yet", Text("OK", style="green")


def render_security_menu(overview: dict[str, dict[str, Any]]) -> RenderableType:
    table = Table(title="SECURITY MODULES", title_justify="left", expand=True)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("MODULE", no_wrap=True)
    table.add_column("STATUS", overflow="fold", ratio=1)
    table.add_column("LATEST / NOTES", overflow="ellipsis", no_wrap=True, ratio=2)
    table.add_column("SEVERITY", no_wrap=True)
    for index, module in enumerate(MODULES, 1):
        entry = overview.get(module, {})
        title, _ = TITLES[module]
        latest, severity = _latest_finding_label(entry)
        table.add_row(
            str(index),
            title,
            state_text(entry),
            latest,
            severity,
        )
    note = Text(
        "Open a module for findings and coverage. OFF / UNTRAINED / NOT BASELINED / DEGRADED "
        "are honest states — empty findings there do not mean the host is clean. "
        "Enter / b returns to the dashboard.",
        style="dim",
    )
    return Group(table, note)


def status_line(overview: dict[str, dict[str, Any]]) -> Text:
    """One-line module status for the dashboard header (no scans are triggered)."""
    line = Text(no_wrap=True, overflow="ellipsis")
    line.append("SECURITY MODULES [s]: ", style="bold")
    for index, module in enumerate(MODULES):
        entry = overview.get(module, {})
        if index:
            line.append("  ")
        line.append(f"{module} ")
        if entry.get("enabled") != "enabled":
            line.append("off", style="dim")
            continue
        status = entry.get("status")
        label = STATUS_DISPLAY.get(status or "", (status or "pending").upper())
        line.append(label, style=STATUS_STYLES.get(status or "", "dim"))
        if entry.get("findings"):
            worst = entry.get("worst")
            line.append(f" {entry['findings']}", style=severity_style(worst) if worst else "")
    return line


def any_enabled(overview: dict[str, dict[str, Any]]) -> bool:
    return any(entry.get("enabled") == "enabled" for entry in overview.values())


def filter_findings(
    findings: list[Finding], minimum: Severity | None = None, rule: str | None = None
) -> list[Finding]:
    return [
        f
        for f in findings
        if (minimum is None or f.severity.rank >= minimum.rank)
        and (rule is None or f.rule_id.upper() == rule.upper())
    ]


def find_finding(findings: list[Finding], answer: str) -> Finding | None:
    """Full finding ID or a unique prefix of one."""
    text = answer.strip()
    exact = [f for f in findings if f.finding_id == text]
    if exact:
        return exact[0]
    prefixed = [f for f in findings if text and f.finding_id.startswith(text)]
    return prefixed[0] if len(prefixed) == 1 else None


def render_module_page(
    module: str,
    entry: dict[str, Any],
    report: ScanReport | None,
    findings: list[Finding],
    *,
    minimum: Severity | None = None,
    rule: str | None = None,
) -> RenderableType:
    parts: list[RenderableType] = []
    if entry.get("enabled", "enabled") != "enabled":
        parts.append(
            Text(
                f"{TITLES[module][0]} is not running in this session: {clean(entry['enabled'])}. "
                f"The standalone command `runtime-engine {module} --help` works without it.",
                style="bold yellow",
            )
        )
    shown = filter_findings(findings, minimum, rule)
    parts.append(RENDERERS[module](report, shown))
    active = []
    if minimum is not None:
        active.append(f"severity >= {minimum.value}")
    if rule is not None:
        active.append(f"rule {rule.upper()}")
    if active:
        parts.append(
            Text(
                f"Filter: {', '.join(active)} ({len(shown)} of {len(findings)} findings shown)",
                style="bold cyan",
            )
        )
    return Group(*parts)


def render_summary_section(modules: dict[str, dict[str, Any]]) -> RenderableType:
    table = Table(box=None, padding=(0, 2), show_edge=False)
    table.add_column("MODULE", no_wrap=True)
    table.add_column("STATE", overflow="fold")
    table.add_column("SCANS", justify="right")
    table.add_column("FINDINGS C/H/M/L", no_wrap=True)
    table.add_column("PROMOTED", justify="right")
    for module in MODULES:
        entry = modules.get(module)
        if entry is None:
            continue
        table.add_row(
            TITLES[module][0],
            state_text(entry),
            str(entry.get("scans", 0)),
            counts_text(entry.get("by_severity", {})),
            str(entry.get("promoted", 0)),
        )
    return table
