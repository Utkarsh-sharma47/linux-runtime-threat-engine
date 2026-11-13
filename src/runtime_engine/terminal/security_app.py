"""CLI handlers for the security modules (non-interactive alternatives to the pages)."""

import json
import sys
from typing import Any

from rich.console import Console

from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.pipeline import Pipeline
from runtime_engine.security.findings import ScanReport
from runtime_engine.security.modules import persistence_monitor
from runtime_engine.security.persistence import PersistenceMonitor, entries_to_body
from runtime_engine.storage.database import Database
from runtime_engine.terminal.views.persistence_view import render_persistence
from runtime_engine.terminal.views.security_common import finding_detail

BASELINE_WARNING = (
    "The baseline is stored in this engine database on this host. Anyone who can write "
    "that file (or is root) can replace it; for tamper evidence, keep a copy elsewhere."
)


def emit_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=True, default=str))


def record_report(
    database: Database, report: ScanReport, rules: list[Rule], settings: Settings
) -> int:
    """Store findings through the normal pipeline (promotion, correlation) and the report."""
    pipeline = Pipeline(database, rules, settings.correlation_window_seconds)
    promoted = 0
    for finding in report.findings:
        if pipeline.process_finding(finding) is not None:
            promoted += 1
    body = report.as_dict()
    body["created_at"] = report.started_at.isoformat()
    database.save_baseline(report.module, "last-scan", body)
    return promoted


def last_report(database: Database, module: str) -> ScanReport | None:
    body = database.baseline(module, "last-scan")
    return ScanReport.from_dict(body) if body else None


def show_finding(database: Database, console: Console, finding_id: str, as_json: bool) -> int:
    finding = database.finding(finding_id)
    if finding is None:
        raise KeyError(finding_id)
    if as_json:
        emit_json(finding)
    else:
        console.print(finding_detail(finding))
    return 0


def persistence_command(
    database: Database,
    settings: Settings,
    rules: list[Rule],
    console: Console,
    action: str,
    *,
    as_json: bool = False,
    finding_id: str | None = None,
) -> int:
    if action == "baseline":
        monitor = PersistenceMonitor(settings.security.persistence)
        entries, coverage = monitor.collect()
        body = entries_to_body(entries, coverage)
        database.save_baseline("persistence", "default", body)
        result = {
            "baseline_created_at": body["created_at"],
            "items": len(entries),
            "coverage": coverage.as_dict(),
            "warning": BASELINE_WARNING,
        }
        if as_json:
            emit_json(result)
        else:
            console.print(
                f"Persistence baseline recorded: {len(entries)} item(s), "
                f"{coverage.denied_count} unreadable location(s)."
            )
            for note in coverage.unavailable:
                console.print(f"Not observable: {note}", style="yellow")
            console.print(BASELINE_WARNING, style="dim")
        return 0
    if action == "scan":
        monitor = persistence_monitor(settings, database)
        if monitor.baseline is None:
            print(
                "error: no persistence baseline in this database; run: persistence baseline",
                file=sys.stderr,
            )
            return 3
        report = monitor.scan()
        promoted = record_report(database, report, rules, settings)
        if as_json:
            emit_json(report.as_dict() | {"promoted_to_incidents": promoted})
        else:
            console.print(render_persistence(report, report.findings))
            console.print(f"{len(report.findings)} finding(s); {promoted} promoted to incidents.")
        return 0
    if finding_id:
        return show_finding(database, console, finding_id, as_json)
    findings = database.findings("persistence")
    if as_json:
        emit_json(findings)
    else:
        console.print(render_persistence(last_report(database, "persistence"), findings))
    return 0
