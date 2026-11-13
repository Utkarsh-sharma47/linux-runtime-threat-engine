"""CLI handlers for the security modules (non-interactive alternatives to the pages)."""

import json
import os
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from runtime_engine.collector.net_collector import NetCollector
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Event
from runtime_engine.pipeline import Pipeline
from runtime_engine.security.anomaly import (
    ProcessSampler,
    load_model,
    load_rows,
    public_metadata,
    rank,
    save_model,
    synthetic_rows,
    train,
)
from runtime_engine.security.findings import ScanReport
from runtime_engine.security.modules import persistence_monitor
from runtime_engine.security.network import NetworkMonitor, analyze_series, demo_series
from runtime_engine.security.persistence import PersistenceMonitor, entries_to_body
from runtime_engine.storage.database import Database
from runtime_engine.terminal.views.anomaly_view import model_panel, render_anomaly
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


def known_incident_keys(database: Database) -> set[str]:
    """Process identities with alerts or incidents; never used as 'normal' training data."""
    keys = {a.process_key for a in database.all_alerts() if a.process_key}
    for incident in database.incidents():
        keys.update(incident.process_keys)
        keys.update(incident.context_process_keys)
    return keys


def live_rows(
    sampler: ProcessSampler,
) -> tuple[dict[str, dict[str, float | None]], dict[str, tuple[int, str]]]:
    snapshot = NetCollector().snapshot()
    resources = {
        key: {"fds": snapshot.fd_counts[key], "sockets": snapshot.socket_counts.get(key, 0)}
        for key in snapshot.fd_counts
    }
    samples, _ = sampler.samples()
    return sampler.features(samples, resources), {s.key: (s.pid, s.name) for s in samples}


def anomaly_command(
    database: Database,
    settings: Settings,
    console: Console,
    action: str,
    *,
    as_json: bool = False,
    dataset: Path | None = None,
    algorithm: str | None = None,
    reviewed: bool = False,
    model_dir: Path | None = None,
    pid: int | None = None,
    top: int = 15,
    duration: float = 60,
    interval: float = 10,
    output: Path | None = None,
) -> int:
    config = settings.security.anomaly
    directory = model_dir or Path(config.model_directory)
    if action == "demo":
        return anomaly_demo(console, config, model_dir, as_json, output)
    if action == "collect":
        if output is None:
            raise ValueError("anomaly collect needs --output FILE")
        return anomaly_collect(console, output, duration, interval)
    if action == "train":
        if dataset is None:
            raise ValueError("anomaly train needs --dataset FILE")
        rows = load_rows(dataset)
        unverified = [r for r in rows if r.get("source") != "synthetic"]
        if unverified and not reviewed:
            print(
                f"error: {len(unverified)} row(s) were collected from a live host. Active "
                "processes are not a verified clean baseline: review the dataset, then rerun "
                "with --i-reviewed-baseline.",
                file=sys.stderr,
            )
            return 2
        assertion = (
            "synthetic demonstration data"
            if not unverified
            else "host-collected; operator asserted it was reviewed (not independently verified)"
        )
        trained = train(
            rows,
            config,
            dataset=str(dataset),
            excluded_keys=known_incident_keys(database),
            algorithm=algorithm,
            assertion=assertion,
        )
        path = save_model(trained, directory)
        database.save_baseline(
            "anomaly",
            "model",
            public_metadata(trained.metadata) | {"created_at": trained.metadata["trained_at"]},
        )
        if as_json:
            emit_json(public_metadata(trained.metadata) | {"metadata_path": str(path)})
        else:
            console.print(model_panel(public_metadata(trained.metadata)))
            console.print(f"Model saved to {directory} (metadata {path.name}).")
        return 0
    trained_model = load_model(directory)
    if trained_model is None:
        if action == "status":
            if as_json:
                emit_json({"model": None, "model_directory": str(directory)})
            else:
                console.print(model_panel(None))
            return 0
        print("error: no trained model; run anomaly train or anomaly demo", file=sys.stderr)
        return 3
    meta = public_metadata(trained_model.metadata)
    if action == "status":
        if as_json:
            emit_json(meta | {"model_directory": str(directory)})
        else:
            console.print(model_panel(meta))
        return 0
    if action == "score":
        if dataset is None:
            raise ValueError("anomaly score needs --dataset FILE")
        rows_in = load_rows(dataset)
        features = {str(i): r["features"] for i, r in enumerate(rows_in)}
        names = {
            str(i): (int(r.get("pid") or 0), str(r.get("process", f"row-{i}")))
            for i, r in enumerate(rows_in)
        }
    else:  # inspect: score the live host now
        features, names = live_rows(ProcessSampler())
        if pid is not None:
            keep = [k for k, (p, _) in names.items() if p == pid]
            if not keep:
                raise KeyError(pid)
            features = {k: features[k] for k in keep}
    ranking = rank(trained_model, features, names, config.deviation_z)
    if as_json:
        emit_json({"model": meta, "ranking": ranking[:top]})
    else:
        console.print(
            render_anomaly(None, [], model=meta, ranking=ranking[:top], sampled=len(ranking))
        )
    return 0


def anomaly_demo(
    console: Console, config: Any, model_dir: Path | None, as_json: bool, output: Path | None
) -> int:
    """Train on synthetic baseline rows and rank synthetic observed rows (no host data)."""
    baseline, observed = synthetic_rows()
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        for name, rows in (("baseline.jsonl", baseline), ("observed.jsonl", observed)):
            (output / name).write_text("".join(json.dumps(r) + "\n" for r in rows))
    trained = train(
        baseline,
        config,
        dataset="synthetic demonstration baseline (600 rows)",
        assertion="synthetic demonstration data",
    )
    with tempfile.TemporaryDirectory() as scratch:
        save_model(trained, model_dir or Path(scratch))
        reloaded = load_model(model_dir or Path(scratch))
    assert reloaded is not None
    features = {str(i): r["features"] for i, r in enumerate(observed)}
    names = {str(i): (r["pid"], r["process"]) for i, r in enumerate(observed)}
    ranking = rank(reloaded, features, names, config.deviation_z)
    injected = {r["process"] for r in observed if r["label"] == "anomaly"}
    flagged = {r["process"] for r in ranking if r["above_threshold"]}
    model = public_metadata(reloaded.metadata)
    result: dict[str, Any] = {
        "model": model,
        "injected_outliers": sorted(injected),
        "flagged": sorted(flagged),
        "injected_found": sorted(injected & flagged),
        "normal_rows_flagged": sorted(flagged - injected),
        "ranking": ranking[:10],
    }
    if as_json:
        emit_json(result)
        return 0
    console.print(render_anomaly(None, [], model=model, ranking=ranking[:12], sampled=len(ranking)))
    console.print(
        f"Synthetic check: {len(result['injected_found'])}/{len(injected)} injected outliers "
        f"flagged; {len(result['normal_rows_flagged'])} normal row(s) flagged."
    )
    return 0


def anomaly_collect(console: Console, output: Path, duration: float, interval: float) -> int:
    """Write host feature rows for later review; they are NOT a verified clean baseline."""
    sampler = ProcessSampler()
    rows: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + duration
    while True:
        features, names = live_rows(sampler)
        stamp = datetime.now(UTC).isoformat()
        for key, values in features.items():
            pid, name = names[key]
            rows[key] = {
                "process": name,
                "pid": pid,
                "process_key": key,
                "source": "host-collected",
                "collected_at": stamp,
                "features": values,
            }
        if time.monotonic() + interval > deadline:
            break
        time.sleep(interval)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        for row in rows.values():
            stream.write(json.dumps(row) + "\n")
    console.print(
        f"Wrote {len(rows)} process rows to {output}. Review them (remove anything "
        "unexpected) before training with --i-reviewed-baseline."
    )
    return 0
