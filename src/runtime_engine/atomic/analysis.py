"""Stages D and E: offline analysis of captured Atomic evidence and its evaluation.

Captured events go through the engine's own replay collector and pipeline
(normalization, ancestry, rules, correlation, SQLite) into a database inside the run
directory; module evidence is evaluated with the modules' own code. Nothing is executed
and the live monitor is not involved, so analysis can be repeated, for example after
rules change, to compare results on identical evidence.

Grades, per component and overall:

  DETECTED            a relevant expected detection matched, supported by captured evidence
  PARTIALLY DETECTED  some, not all, expected detections matched
  NOT DETECTED        the behaviour was observed with the required telemetry, nothing matched
  INCONCLUSIVE        telemetry missing or the expected behaviour was not observed
  EXECUTION FAILED    the Atomic test itself did not complete (overall only)
  NOT APPLICABLE      the reviewed profile does not expect this component to apply

Missing telemetry never becomes NOT DETECTED, and an exit code of 0 is never a detection.
"""

import os
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtime_engine.atomic.evidence import read_json, write_private
from runtime_engine.atomic.profiles import COMPONENTS, ModuleExpectation, Profile
from runtime_engine.collector.replay_collector import ReplayCollector
from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Event, EventType
from runtime_engine.pipeline import Pipeline
from runtime_engine.security.anomaly import load_model, rank
from runtime_engine.security.network import analyze_records
from runtime_engine.storage.database import Database

DETECTED = "DETECTED"
PARTIAL = "PARTIALLY DETECTED"
NOT_DETECTED = "NOT DETECTED"
INCONCLUSIVE = "INCONCLUSIVE"
EXECUTION_FAILED = "EXECUTION FAILED"
NOT_APPLICABLE = "NOT APPLICABLE"
LABELS = {
    "rules": "Detection rules (RT001-RT006)",
    "persistence": "Persistence monitor",
    "network": "Network monitor",
    "anomaly": "Anomaly detector",
    "integrity": "File integrity (Merkle)",
    "exposure": "Exposure analyzer",
    "ransomware": "Ransomware detector",
}
TRACED_TYPES = {"PROCESS_START", "PROCESS_EXIT", "FILE_ACCESS", "NETWORK_CONNECTION",
                "PRIVILEGE_CHANGE"}  # fmt: skip
POLLED_TYPES = {"PROCESS_START"}


@dataclass
class Component:
    name: str
    label: str
    grade: str
    reasons: list[str]
    expected: list[str] | None
    observed: list[str]
    telemetry: bool
    behaviour: bool
    evidence: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def grade_component(
    expectation: ModuleExpectation | None,
    observed: set[str],
    *,
    telemetry: bool,
    behaviour: bool,
    gaps: list[str],
) -> tuple[str, list[str]]:
    if expectation is None:
        reasons = ["not expected to apply by the reviewed profile"]
        if observed:
            reasons.append(f"unreviewed detections: {', '.join(sorted(observed))}")
        return NOT_APPLICABLE, reasons
    if not telemetry:
        return INCONCLUSIVE, ["required telemetry unavailable: " + "; ".join(gaps or ["unknown"])]
    expected = set(expectation.rules)
    hits = expected & observed
    if expected and hits == expected:
        return DETECTED, [f"expected detection(s) matched: {', '.join(sorted(hits))}"]
    if hits:
        return PARTIAL, [
            f"matched: {', '.join(sorted(hits))}",
            f"missing: {', '.join(sorted(expected - hits))}",
        ]
    if not behaviour:
        return INCONCLUSIVE, [
            "the expected behaviour was not observed in the captured evidence, so a miss "
            "cannot be told apart from a test that did not do what was expected"
        ]
    if expected:
        return NOT_DETECTED, [
            "behaviour observed with the required telemetry; expected "
            f"{', '.join(sorted(expected))} did not match"
        ]
    return NOT_DETECTED, ["behaviour observed but no current rule covers it (coverage gap)"]


def overall(
    components: list[Component], execution: str, profile: Profile | None
) -> tuple[str, list[str]]:
    if execution != "COMPLETED":
        return EXECUTION_FAILED, [
            f"Atomic execution status is {execution}; module results below describe whatever "
            "was captured and are not a detection verdict"
        ]
    if profile is None:
        return INCONCLUSIVE, ["no reviewed expectation profile for this test"]
    applicable = [c for c in components if c.grade != NOT_APPLICABLE]
    if not applicable:
        return INCONCLUSIVE, ["the profile marks no component as applicable"]
    summary = [f"{c.label}: {c.grade}" for c in applicable]
    evaluated = {c.grade for c in applicable if c.grade != INCONCLUSIVE}
    if evaluated == {DETECTED}:
        unknown = [c.label for c in applicable if c.grade == INCONCLUSIVE]
        if unknown:
            summary.append(f"not evaluated (telemetry or behaviour missing): {', '.join(unknown)}")
        return DETECTED, summary
    if evaluated & {DETECTED, PARTIAL}:
        return PARTIAL, summary
    if INCONCLUSIVE in {c.grade for c in applicable}:
        return INCONCLUSIVE, summary
    return NOT_DETECTED, summary


def label(event: Event) -> str:
    return f"{event.process_name or '?'} PID {event.pid}"


def replay(run: Path, rules: list[Rule], settings: Settings) -> dict[str, Any]:
    """Feed events.jsonl through the existing pipeline into <run>/analysis.db."""
    database_path = run / "analysis.db"
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(str(database_path) + suffix).unlink(missing_ok=True)
    database = Database(database_path)
    try:
        pipeline = Pipeline(database, rules, settings.correlation_window_seconds)
        collector = ReplayCollector(run / "events.jsonl", sort=True)
        events: list[Event] = []
        detections: list[dict[str, Any]] = []
        for event in collector.collect() if (run / "events.jsonl").is_file() else iter(()):
            result = pipeline.process(event)
            events.append(event)
            for detection in result.detections:
                alert = detection.alert
                detections.append(
                    {
                        "rule_id": alert.rule_id,
                        "rule_name": alert.rule_name,
                        "severity": alert.severity.value,
                        "event_id": event.event_id,
                        "event_type": event.event_type.value,
                        "process": label(event),
                        "process_key": event.process_key,
                        "resource": event.file_path or event.network_destination
                        or event.executable_path,
                        "incident_id": detection.incident_id,
                        "reason": alert.reason,
                        "duplicate": detection.duplicate,
                        "context": bool(event.metadata.get("role")),
                    }
                )  # fmt: skip
        incidents = [
            {
                "incident_id": i.incident_id,
                "severity": i.severity.value,
                "rule_ids": list(i.rule_ids),
                "alerts": len(i.alert_ids),
                "events": i.event_count,
                "ancestry": list(i.ancestry),
            }
            for i in pipeline.correlation.incidents
        ]
        processes = []
        for key, node in list(pipeline.ancestry.nodes.items())[:60]:
            lineage = [
                pipeline.ancestry.nodes[k].process_name or "?"
                for k in pipeline.ancestry.lineage(key)
                if k in pipeline.ancestry.nodes
            ]
            processes.append(
                {
                    "process_key": key,
                    "pid": node.pid,
                    "ppid": node.ppid,
                    "process": node.process_name,
                    "executable": node.executable_path,
                    "command_line": node.command_line,
                    "lineage": " > ".join(reversed(lineage)),
                    "context": bool(node.metadata.get("role")),
                }
            )
        return {
            "events": events,
            "rejected": collector.rejected,
            "detections": detections,
            "incidents": incidents,
            "processes": processes,
            "metrics": {
                "events_processed": pipeline.metrics.total_events_processed,
                "rule_matches": pipeline.metrics.total_alerts_generated,
                "incidents": pipeline.metrics.total_incidents_created,
            },
        }
    finally:
        database.close()


def under(path: str | None, roots: list[str]) -> bool:
    if not path:
        return False
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def expand(paths: list[str]) -> list[str]:
    return [os.path.realpath(os.path.expanduser(p)) for p in paths]


def finding_rules(report: dict[str, Any] | None, key: str = "findings") -> set[str]:
    return {f["rule_id"] for f in (report or {}).get(key) or []}


def analyze(
    run: Path,
    rules: list[Rule],
    settings: Settings,
    profiles: dict[str, Profile],
) -> dict[str, Any]:
    record = read_json(run / "record.json")
    if record is None:
        raise KeyError(str(run))
    test = record["test"]
    profile = profiles.get(test["guid"])
    expectations = profile.expectations() if profile else {}
    collection = record.get("collection", {})
    collector = collection.get("collector", "none")
    replayed = replay(run, rules, settings)
    events: list[Event] = replayed["events"]
    test_events = [e for e in events if not e.metadata.get("role")]
    by_type = Counter(e.event_type.value for e in test_events)
    names = {e.process_name for e in test_events if e.event_type == EventType.PROCESS_START}
    available = TRACED_TYPES if collector == "strace" else POLLED_TYPES
    if collector == "none":
        available = set()
    state = read_json(run / "state" / "state-after.json") or {}
    readability: dict[str, bool] = collection.get("readability", {})
    files = [e for e in test_events if e.event_type == EventType.FILE_ACCESS]
    detections = [d for d in replayed["detections"] if not d["context"]]
    components: list[Component] = []

    def add(
        name: str,
        observed: set[str],
        *,
        telemetry: bool,
        behaviour: bool,
        gaps: list[str],
        evidence: list[dict[str, Any]],
    ) -> None:
        expectation = expectations.get(name)
        if expectation is not None:
            for path in expectation.requires_readable:
                if not readability.get(path, False):
                    telemetry = False
                    gaps.append(f"{path} is not readable by the collector (run as this user)")
        grade, reasons = grade_component(
            expectation, observed, telemetry=telemetry, behaviour=behaviour, gaps=gaps
        )
        components.append(
            Component(
                name,
                LABELS[name],
                grade,
                reasons,
                None if expectation is None else expectation.rules,
                sorted(observed),
                telemetry,
                behaviour,
                evidence,
                gaps,
            )
        )

    # Rule engine on events captured during execution.
    required = set(profile.telemetry) if profile else {"PROCESS_START"}
    missing_types = sorted(required - available)
    key = set(profile.key_processes) if profile else set()
    rule_gaps = []
    if missing_types:
        rule_gaps.append(f"collector '{collector}' does not provide {', '.join(missing_types)}")
    if not test_events:
        rule_gaps.append("no events from the test's process tree were captured")
    add(
        "rules",
        {d["rule_id"] for d in detections},
        telemetry=not missing_types and bool(test_events),
        behaviour=bool(names & key) if key else bool(test_events),
        gaps=rule_gaps,
        evidence=[
            {"key_processes_observed": sorted(names & key), "missing": sorted(key - names)}
        ] if key else [],
    )  # fmt: skip

    # Network: connect() calls from the trace, rules on them, beacon analysis, listeners.
    connections = [e for e in test_events if e.event_type == EventType.NETWORK_CONNECTION]
    records = [
        {
            "time": e.timestamp.timestamp(),
            "destination": f"{e.network_destination}:{e.metadata.get('port')}",
            "process": e.process_name or "?",
            "pid": e.pid,
        }
        for e in connections
    ]
    beacons = analyze_records(records, settings.security.network) if records else []
    network_rules = {d["rule_id"] for d in detections if d["event_type"] == "NETWORK_CONNECTION"}
    network_rules |= {i for b in beacons for i in b["indicators"]}
    listeners = state.get("listeners", {})
    add(
        "network",
        network_rules,
        telemetry="NETWORK_CONNECTION" in available,
        behaviour=bool(connections) or bool(listeners.get("new")),
        gaps=[] if "NETWORK_CONNECTION" in available else [f"collector '{collector}' has no "
              "connection telemetry"],
        evidence=[
            {
                "process": label(e),
                "destination": e.network_destination,
                "port": e.metadata.get("port"),
                "protocol": e.metadata.get("protocol"),
                "result": e.metadata.get("result"),
                "attribution": "direct: connect() system call of this process (traced)",
                "time": e.timestamp.isoformat(),
            }
            for e in connections[:20]
        ]
        + [{"beacon_analysis": b} for b in beacons[:5]]
        + [{"new_listener": item} for item in listeners.get("new", [])],
    )  # fmt: skip

    # Anomaly: features sampled during execution, scored offline with a reviewed model.
    samples = read_json(run / "anomaly-samples.json") or []
    model_dir = Path(settings.security.anomaly.model_directory)
    try:
        trained = load_model(model_dir)
        model_error = None if trained else f"no trained model in {model_dir}"
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        trained, model_error = None, f"{type(exc).__name__}: {exc}"
    ranking: list[dict[str, Any]] = []
    if trained is not None and samples:
        rows = {s["process_key"]: s["features"] for s in samples}
        names_by_key = {s["process_key"]: (s["pid"], s["process"]) for s in samples}
        ranking = rank(trained, rows, names_by_key, settings.security.anomaly.deviation_z)
    anomaly_gaps = [model_error] if model_error else []
    if not samples:
        anomaly_gaps.append("no process of the test lived long enough to be sampled")
    add(
        "anomaly",
        {"AN001"} if any(r["above_threshold"] for r in ranking) else set(),
        telemetry=trained is not None and bool(samples),
        behaviour=bool(samples),
        gaps=anomaly_gaps,
        evidence=[
            {
                "process": f"{r['process']} PID {r['pid']}",
                "score": r["score"],
                "threshold": round(trained.threshold, 4) if trained else None,
                "above_threshold": r["above_threshold"],
                "top_deviations": r["deviations"][:3],
            }
            for r in ranking[:10]
        ],
    )

    # State differences from module scans before and after the run.
    persistence = state.get("persistence")
    watched = expand(
        settings.security.persistence.systemd_paths
        + settings.security.persistence.cron_paths
        + settings.security.persistence.ssh_paths
        + settings.security.persistence.sudoers_paths
        + settings.security.persistence.privileged_dirs
    )
    touched = [e for e in files if under(e.file_path, watched)]
    add(
        "persistence",
        finding_rules(persistence),
        telemetry=persistence is not None and persistence.get("status") != "error",
        behaviour=bool(touched) or bool(finding_rules(persistence)),
        gaps=[] if persistence else ["no before/after persistence scan in this run"],
        evidence=[
            {"finding": f["finding_id"], "rule": f["rule_id"], "severity": f["severity"],
             "resource": f["resource"], "change": f.get("evidence", {}).get("change")}
            for f in (persistence or {}).get("findings", [])[:20]
        ] + [{"traced_write": e.file_path, "process": label(e),
              "operation": e.metadata.get("operation")} for e in touched[:10]],
    )  # fmt: skip

    integrity = state.get("integrity")
    integrity_roots = expand((integrity or {}).get("summary", {}).get("paths", []))
    in_tree = [e for e in files if under(e.file_path, integrity_roots)]
    add(
        "integrity",
        finding_rules(integrity),
        telemetry=integrity is not None and integrity.get("status") in ("ok", "degraded"),
        behaviour=bool(in_tree) or bool(finding_rules(integrity)),
        gaps=[] if integrity else ["no integrity baseline was taken for this run"],
        evidence=(
            [{"merkle_root_before": integrity["summary"].get("baseline_root"),
              "merkle_root_after": integrity["summary"].get("current_root"),
              "root_matches": integrity["summary"].get("root_matches"),
              "changes": integrity.get("changes")}]
            + [{"proof": p} for p in integrity.get("proofs", [])]
        ) if integrity else [],
    )  # fmt: skip

    exposure = state.get("exposure")
    permission_changes = [e for e in files if e.metadata.get("operation") in ("chmod", "chown")]
    add(
        "exposure",
        finding_rules(exposure, "new_findings"),
        telemetry=exposure is not None and exposure.get("status") != "error",
        behaviour=bool(permission_changes) or bool(finding_rules(exposure, "new_findings")),
        gaps=[] if exposure else ["no before/after exposure scan in this run"],
        evidence=[
            {"finding": f["finding_id"], "rule": f["rule_id"], "severity": f["severity"],
             "resource": f["resource"], "title": f["title"]}
            for f in (exposure or {}).get("new_findings", [])[:20]
        ] + [{"traced_permission_change": e.file_path, "process": label(e),
              "operation": e.metadata.get("operation"), "mode": e.metadata.get("mode")}
             for e in permission_changes[:10]],
    )  # fmt: skip

    ransomware = read_json(run / "ransomware.json")
    watch = expand(collection.get("ransomware_watch", []))
    in_watch = [e for e in files if under(e.file_path, watch)]
    add(
        "ransomware",
        finding_rules(ransomware),
        telemetry=bool(watch) and ransomware is not None,
        behaviour=bool(in_watch) or bool(finding_rules(ransomware)),
        gaps=[] if watch else ["no directory was watched (profile watch_ransomware)"],
        evidence=(
            [{"directories": (ransomware or {}).get("summary", {}).get("directories")}]
            if ransomware else []
        ),
    )  # fmt: skip

    execution = record.get("execution", {}).get("status", "NOT_EXECUTED")
    result, reasons = overall(components, execution, profile)
    unexpected = [
        {"component": c.label, "rules": c.observed}
        for c in components
        if c.observed and (c.grade == NOT_APPLICABLE or (profile is not None and profile.benign))
    ]
    context_hits = [d for d in replayed["detections"] if d["context"]]
    evaluation = {
        "schema": "rte-atomic-evaluation/1",
        "run_id": record["run_id"],
        "analyzed_at": datetime.now(UTC).isoformat(),
        "rules_evaluated": len([r for r in rules if r.enabled]),
        "result": result,
        "reasons": reasons,
        "execution": record.get("execution", {}),
        "test": test,
        "profile": profile.model_dump() if profile else None,
        "components": [asdict(c) for c in components],
        "detections": detections,
        "context_detections": context_hits,
        "incidents": replayed["incidents"],
        "processes": [p for p in replayed["processes"] if not p["context"]][:40],
        "runner_context": [p for p in replayed["processes"] if p["context"]],
        "pipeline": replayed["metrics"] | {"rejected_records": replayed["rejected"]},
        "coverage": {
            "collector": collector,
            "captured_during_execution": {
                "process_events": by_type.get("PROCESS_START", 0),
                "exit_events": by_type.get("PROCESS_EXIT", 0),
                "file_events": by_type.get("FILE_ACCESS", 0),
                "network_events": by_type.get("NETWORK_CONNECTION", 0),
                "privilege_events": by_type.get("PRIVILEGE_CHANGE", 0),
                "anomaly_samples": len(samples),
            },
            "state_differences": {
                "persistence_changes": len((persistence or {}).get("findings", [])),
                "integrity_changes": sum(
                    len(v) for v in ((integrity or {}).get("changes") or {}).values()
                ),
                "new_exposure_findings": len((exposure or {}).get("new_findings", [])),
                "new_listeners": len(listeners.get("new", [])),
            },
            "telemetry_types_available": sorted(available),
            "unavailable": collection.get("unavailable", []),
        },
        "false_positive_observations": {
            "unexpected_detections": unexpected,
            "detections_on_runner_context": len(context_hits),
            "measurable": profile is not None,
        },
        "cleanup": record.get("cleanup", {}),
    }
    write_private(run / "evaluation.json", evaluation)
    return evaluation


__all__ = ["COMPONENTS", "analyze", "grade_component", "overall"]
