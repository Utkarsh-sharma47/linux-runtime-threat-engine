"""Ransomware Early Warning page: monitored directories, rates, entropy, indicators, score."""

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


def score_text(result: dict[str, Any], alert_score: float) -> Text:
    score = result.get("score", 0)
    style = (
        "bold red"
        if result.get("alert")
        else "bold yellow"
        if score >= alert_score / 2
        else "green"
    )
    label = "ALERT" if result.get("alert") else "below alert" if score else "quiet"
    return Text(f"{score:.1f} / 100 ({label})", style=style)


def render_ransomware(
    report: ScanReport | None, findings: list[Finding] | list[dict[str, Any]]
) -> RenderableType:
    summary = report.summary if report else {}
    directories: dict[str, dict[str, Any]] = summary.get("directories", {})
    alert_score = float(summary.get("alert_score", 50))
    header = report_header(
        "RANSOMWARE EARLY WARNING",
        report,
        [
            ("MECHANISM", clean(summary.get("mechanism", "not running"))),
            (
                "MONITORED",
                clean(
                    ", ".join(directories)
                    or "no directories configured (security.ransomware.directories)"
                ),
            ),
            (
                "TOTAL EVENTS",
                ", ".join(f"{k} {v}" for k, v in summary.get("totals", {}).items()) or "-",
            ),
            (
                "RULE",
                f"alert at score >= {alert_score:g} with >= "
                f"{summary.get('min_indicators', 2)} full indicators",
            ),
        ],
    )
    table = Table(
        title="BEHAVIOURAL INDICATORS (current window)", title_justify="left", expand=True
    )
    for column in ("DIRECTORY", "SCORE", "WRITES/MIN", "RENAMES/MIN", "FILES", "DIRS",
                   "ENTROPY RISES", "EXTENSION", "TRIGGERED"):  # fmt: skip
        table.add_column(column, no_wrap=column != "TRIGGERED", overflow="ellipsis")
    for directory, result in directories.items():
        table.add_row(
            clean(directory, 40),
            score_text(result, alert_score),
            f"{result['modification_rate_per_min']:.0f} ({result['modifications']})",
            f"{result['rename_rate_per_min']:.0f} ({result['renames']})",
            str(result["files"]),
            str(result["directories"]),
            f"{result['entropy_increases']}/{result['entropy_samples']}",
            f"{clean(result['extension_change'])} ({result['extension_change_ratio']:.0%})"
            if result.get("extension_change")
            else "-",
            ", ".join(result["triggered"]) or "-",
        )
    weights = Text(
        "Score = 100 x sum(weight x indicator): "
        + ", ".join(f"{k} {v:.2f}" for k, v in summary.get("weights", {}).items())
        + ". Entropy alone can add at most 20 points, so high entropy never alerts by itself.",
        style="dim",
    )
    examples = Table(title="ENTROPY CHANGES (bits per byte, sampled)", title_justify="left")
    examples.add_column("FILE", overflow="fold")
    examples.add_column("BEFORE")
    examples.add_column("AFTER")
    for result in directories.values():
        for item in result.get("entropy_examples", []):
            before = "unknown" if item["before"] is None else str(item["before"])
            examples.add_row(clean(item["path"]), before, str(item["after"]))
    candidates = Table(title="PER-PROCESS ACTIVITY (heuristic attribution)", title_justify="left")
    for column in ("PID", "PROCESS", "WHY"):
        candidates.add_column(column)
    for item in summary.get("candidates", []):
        candidates.add_row(str(item["pid"]), clean(item["name"]), ", ".join(item["reasons"]))
    if not summary.get("candidates"):
        candidates.caption = (
            "No candidates recorded (inotify does not report which process wrote a file)."
        )
    return Panel(
        Group(
            header,
            coverage_panel(report),
            table,
            weights,
            examples,
            candidates,
            findings_table(
                [as_dict(f) for f in findings],
                "TRIGGERED FINDINGS (RW001)",
                empty="No ransomware-like activity detected.",
            ),  # fmt: skip
            Text("An early warning to investigate, not a confirmed infection.", style="dim italic"),
        ),
        title="RANSOMWARE EARLY WARNING",
        title_align="left",
        border_style="cyan",
    )
