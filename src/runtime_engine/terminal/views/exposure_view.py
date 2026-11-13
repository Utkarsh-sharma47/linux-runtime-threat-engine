"""Attack Surface Analyzer page: posture, findings by category, remediation guidance."""

from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import Finding, ScanReport
from runtime_engine.terminal.formatting import clean, severity_style, severity_text
from runtime_engine.terminal.views.security_common import (
    as_dict,
    coverage_panel,
    findings_table,
    report_header,
)

POSTURE_STYLES = {"GOOD": "bold green", "FAIR": "bold yellow", "POOR": "bold red",
                  "CRITICAL": "bold white on red"}  # fmt: skip
SECTIONS = [
    ("SUID/SGID FINDINGS", {"EX001"}),
    ("CAPABILITY FINDINGS", {"EX002"}),
    ("WEAK PERMISSION FINDINGS (PATH, sensitive files)", {"EX003", "EX004"}),
    ("PRIVILEGED SERVICE FINDINGS", {"EX005", "EX006"}),
    ("SUSPICIOUS LOCATIONS AND SUDO", {"EX007", "EX008"}),
]


def render_exposure(
    report: ScanReport | None,
    findings: list[Finding] | list[dict[str, Any]],
    *,
    severity: Severity | None = None,
    rule: str | None = None,
) -> RenderableType:
    summary = report.summary if report else {}
    rows = [as_dict(f) for f in findings]
    if severity is not None:
        rows = [r for r in rows if Severity(r["severity"]).rank >= severity.rank]
    if rule is not None:
        rows = [r for r in rows if r["rule_id"] == rule]
    posture = summary.get("posture")
    counts = summary.get("counts", {})
    count_text = Text()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count_text.append(f"{level} {counts.get(level, 0)}  ", style=severity_style(level))
    header = report_header(
        "ATTACK SURFACE ANALYZER",
        report,
        [
            (
                "OVERALL POSTURE",
                Text(
                    f"{posture or 'NOT ASSESSED'}  (score {summary.get('score', '-')}; "
                    f"new findings {summary.get('new', '-')}, "
                    f"accepted in baseline {summary.get('accepted', '-')})",
                    style=POSTURE_STYLES.get(posture or "", "dim"),
                ),
            ),
            ("FINDINGS", count_text),
            ("SCAN TYPE", str(summary.get("scan_type", "-"))),
            (
                "FILTER",
                ", ".join(x for x in (f">= {severity.value}" if severity else "", rule or "") if x)
                or "none",
            ),
        ],
    )
    parts: list[RenderableType] = [header, coverage_panel(report) if report else Text("")]
    for title, rules in SECTIONS:
        section = [r for r in rows if r["rule_id"] in rules]
        section.sort(key=lambda r: Severity(r["severity"]).rank, reverse=True)
        parts.append(findings_table(section, title, empty=f"{title.split(' (')[0].title()}: none."))
    guidance = Table(title="REMEDIATION GUIDANCE (highest risk first)", title_justify="left",
                     expand=True)  # fmt: skip
    guidance.add_column("SEVERITY", no_wrap=True)
    guidance.add_column("RESOURCE", overflow="ellipsis", no_wrap=True, ratio=2)
    guidance.add_column("WEAKNESS", overflow="fold", ratio=2)
    guidance.add_column("REMEDIATION", overflow="fold", ratio=3)
    ranked = sorted(rows, key=lambda r: (r.get("risk_score") or 0), reverse=True)
    for item in [r for r in ranked if Severity(r["severity"]).rank >= Severity.MEDIUM.rank][:10]:
        guidance.add_row(
            severity_text(item["severity"]),
            clean(item["resource"], 60),
            clean(item["evidence"].get("weakness")),
            clean(item.get("remediation")),
        )
    if not guidance.rows:
        guidance.caption = "No MEDIUM or higher findings."
    parts.append(guidance)
    parts.append(
        Text(
            "Posture findings describe configuration, not intrusions. Nothing was changed; "
            "remediation is for a human to review and apply.",
            style="dim italic",
        )
    )
    return Panel(Group(*parts), title="ATTACK SURFACE ANALYZER", title_align="left",
                 border_style="cyan")  # fmt: skip
