"""CLI handlers for the security modules (non-interactive alternatives to the pages)."""

import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Event
from runtime_engine.pipeline import Pipeline
from runtime_engine.security.findings import ScanReport
from runtime_engine.security.modules import persistence_monitor
from runtime_engine.security.network import NetworkMonitor, analyze_series, demo_series
from runtime_engine.security.persistence import PersistenceMonitor, entries_to_body
from runtime_engine.storage.database import Database
from runtime_engine.terminal.views.network_view import render_network
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


def incidents_by_process(database: Database) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for incident in database.incidents():
        for key in incident.process_keys:
            result.setdefault(key, []).append(incident.incident_id)
    return result


def network_command(
    database: Database,
    settings: Settings,
    console: Console,
    action: str,
    *,
    as_json: bool = False,
    pid: int | None = None,
    finding_id: str | None = None,
    input_path: Path | None = None,
    demo: bool = False,
) -> int:
    config = settings.security.network
    if action == "analyze":
        if demo:
            records = demo_series()
        elif input_path is not None:
            records = [
                json.loads(line) for line in input_path.read_text().splitlines() if line.strip()
            ]
        else:
            raise ValueError("network analyze needs --input FILE or --demo")
        results = analyze_series(records, config)
        if as_json:
            emit_json(results)
        else:
            console.print(render_analysis(results, config, synthetic=demo))
        return 0
    if action == "show":
        if finding_id:
            return show_finding(database, console, finding_id, as_json)
        findings = database.findings("network")
        if as_json:
            emit_json(findings)
        else:
            console.print(render_network(last_report(database, "network"), findings))
        return 0
    if action == "process" and pid is None:
        raise ValueError("network process needs --pid")
    report = NetworkMonitor(config).scan()  # one snapshot of current sockets
    if as_json:
        connections = report.summary["connections"]
        if pid is not None:
            connections = [c for c in connections if any(o["pid"] == pid for o in c["processes"])]
        data: dict[str, Any] = {
            "taken_at": report.summary["taken_at"],
            "connections": connections,
            "coverage": report.coverage.as_dict(),
        }
        if action == "process":
            data["stored_events"] = [
                e.model_dump(mode="json")
                for e in database.recent_events(200, pid=pid, event_type="NETWORK_CONNECTION")
            ]
        emit_json(data)
        return 0
    findings = [f for f in database.findings("network") if pid is None or f.get("pid") == pid]
    console.print(
        render_network(report, findings, pid=pid, incidents=incidents_by_process(database))
    )
    if action == "process":
        stored = database.recent_events(50, pid=pid, event_type="NETWORK_CONNECTION")
        console.print(render_stored_connections(stored, pid))
    return 0


def render_analysis(results: list[dict[str, Any]], config: Any, *, synthetic: bool) -> Table:
    table = Table(
        title="CONNECTION PERIODICITY ANALYSIS" + (" (synthetic timelines)" if synthetic else ""),
        title_justify="left",
        caption=(
            f"NB001 when >= {config.beacon_min_connections} connections, CV <= "
            f"{config.beacon_cv_threshold} and {config.beacon_min_interval_seconds:g} s <= mean "
            f"<= {config.beacon_max_interval_seconds:g} s. Regular timing is not proof of C2."
        ),
    )
    for column in ("PROCESS", "DESTINATION", "N", "MEAN Δt (s)", "STDEV (s)", "CV", "RULES"):
        table.add_column(column, no_wrap=True)
    for item in results:
        stats = item["periodicity"] or {}
        table.add_row(
            item["process"],
            item["destination"],
            str(stats.get("connections", "-")),
            f"{stats['mean_interval_seconds']:.1f}" if stats else "-",
            f"{stats['stdev_seconds']:.1f}" if stats else "-",
            f"{stats['cv']:.3f}" if stats and stats.get("cv") is not None else "-",
            ", ".join(item["rules"]) or "-",
        )
    return table


def render_stored_connections(events: list[Event], pid: int | None) -> Table:
    table = Table(
        title=f"STORED NETWORK_CONNECTION EVENTS FOR PID {pid} (newest first)",
        title_justify="left",
    )
    for column in ("FIRST OBSERVED", "DESTINATION", "PORT", "PROTOCOL", "ATTRIBUTION"):
        table.add_column(column, no_wrap=True)
    for event in events:
        table.add_row(
            event.timestamp.isoformat(timespec="seconds"),
            event.network_destination or "-",
            str(event.metadata.get("remote_port", "-")),
            str(event.metadata.get("protocol", "-")),
            str(event.metadata.get("attribution", "-")),
        )
    if not events:
        table.caption = "No stored connection events for this PID (run monitor to collect)."
    return table
