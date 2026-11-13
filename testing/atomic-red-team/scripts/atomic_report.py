#!/usr/bin/env python3
"""Correlate one Atomic test execution window with the engine's stored observations.

This is an integration layer outside the engine. It opens the engine database READ-ONLY
and never writes detections, alerts or incidents. It only associates a recorded test
window with what the engine actually stored:

  * attributed events: processes whose recorded parent chain reaches the runner's
    PowerShell process (identity = boot ID + PID + start ticks, never PID alone), or
    whose parent PID is the executor PID logged by Invoke-AtomicTest within the window
  * rule matches and incidents that cite those events
  * concurrent events in the same window that are NOT attributed (reported, never used)

Subcommands:
  identity --pid PID                 print the process identity of PID (JSON)
  engine-status --db DB              is a monitor session writing to DB right now?
  report --record RECORD.json --db DB [--expectations FILE] [--out DIR]
"""

import argparse
import csv
import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from runtime_engine.events.schema import Alert, Event, Incident

HERE = Path(__file__).resolve().parent
DEFAULT_EXPECTATIONS = HERE.parent / "expectations.yaml"
LIVE_TELEMETRY = {"PROCESS_START"}  # what the /proc collector actually emits
RESULTS = ("DETECTED", "PARTIALLY DETECTED", "NOT DETECTED", "INCONCLUSIVE")


# ----- process identity -----


def boot_id(proc: Path = Path("/proc")) -> str:
    return (proc / "sys/kernel/random/boot_id").read_text().strip()


def start_ticks(pid: int, proc: Path = Path("/proc")) -> str:
    stat = (proc / str(pid) / "stat").read_text()
    return stat[stat.rindex(")") + 2 :].split()[19]


def process_key(host: str, pid: int, start: str) -> str:
    """Same encoding as Event.process_key in the engine."""
    return json.dumps([host, pid, start], separators=(",", ":"))


def identity(pid: int, proc: Path = Path("/proc")) -> dict[str, Any]:
    host, start = boot_id(proc), start_ticks(pid, proc)
    return {"pid": pid, "start_ticks": start, "boot_id": host, "key": process_key(host, pid, start)}


# ----- engine database (read-only) -----


def connect(db: Path) -> sqlite3.Connection:
    if not db.is_file():
        raise FileNotFoundError(db)
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def engine_status(db: Path, proc: Path = Path("/proc")) -> dict[str, Any]:
    """A RUNNING session row whose engine PID is alive and is really this engine."""
    status: dict[str, Any] = {"running": False, "db": str(db.resolve())}
    try:
        with connect(db) as connection:
            rows = connection.execute(
                "SELECT body FROM monitor_sessions ORDER BY started_at DESC"
            ).fetchall()
    except (FileNotFoundError, sqlite3.Error) as exc:
        status["reason"] = f"cannot read engine database: {type(exc).__name__}"
        return status
    for (body,) in rows:
        session = json.loads(body)
        if session.get("status") != "RUNNING" or session.get("mode") != "LIVE":
            continue
        pid = int(session["engine_pid"])
        try:
            cmdline = (proc / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except OSError:
            continue  # stale row from a killed session
        if "runtime_engine" not in cmdline or "monitor" not in cmdline:
            continue  # PID reused by another program
        status.update(
            running=True,
            session_id=session["session_id"],
            engine_pid=pid,
            started_at=session["started_at"],
            poll_interval_seconds=session["configuration"].get("poll_interval_seconds"),
        )
        return status
    status["reason"] = "no live monitor session is writing to this database"
    return status


@dataclass
class Observation:
    event: Event
    attribution: str  # "runner identity" or "executor PID"
    chain: list[str] = field(default_factory=list)


def load_window(connection: sqlite3.Connection, start: datetime, end: datetime) -> list[Event]:
    lower = (start - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
    rows = connection.execute(
        "SELECT body FROM events WHERE json_extract(body, '$.timestamp') >= ?", (lower,)
    ).fetchall()
    events = [Event.model_validate_json(row[0]) for row in rows]
    return sorted((e for e in events if start <= e.timestamp <= end), key=lambda e: e.timestamp)


def lookup(connection: sqlite3.Connection, key: str) -> Event | None:
    row = connection.execute(
        "SELECT body FROM events WHERE process_key = ? ORDER BY rowid LIMIT 1", (key,)
    ).fetchone()
    return Event.model_validate_json(row[0]) if row else None


def parent_key(event: Event) -> str | None:
    if not event.ppid or not event.parent_start_time:
        return None
    return process_key(event.host_id, event.ppid, event.parent_start_time)


def chain_to(
    connection: sqlite3.Connection, event: Event, target: str, depth: int = 12
) -> list[str] | None:
    """Labels from the event up to the target identity, or None if it is not an ancestor."""
    labels = [f"{event.process_name}({event.pid})"]
    current: Event | None = event
    seen: set[str] = set()
    for _ in range(depth):
        if current is None:
            return None
        key = parent_key(current)
        if key is None or key in seen:
            return None
        if key == target:
            return list(reversed(labels + ["runner pwsh"]))
        seen.add(key)
        current = lookup(connection, key)
        if current is not None:
            labels.append(f"{current.process_name}({current.pid})")
    return None


def attribute(
    connection: sqlite3.Connection,
    events: list[Event],
    runner_key: str,
    executor_pid: int | None,
) -> tuple[list[Observation], list[Event]]:
    attributed: list[Observation] = []
    other: list[Event] = []
    for event in events:
        if event.process_key == runner_key:
            other.append(event)  # the runner itself is not test activity
            continue
        chain = chain_to(connection, event, runner_key)
        if chain is not None:
            attributed.append(Observation(event, "runner identity", chain))
        elif executor_pid is not None and executor_pid in (event.pid, event.ppid):
            label = f"{event.process_name}({event.pid})"
            attributed.append(Observation(event, "executor PID (weaker)", [label]))
        else:
            other.append(event)
    return attributed, other


def related_findings(
    connection: sqlite3.Connection, event_ids: set[str]
) -> tuple[list[Alert], list[Incident]]:
    alerts = [
        a
        for a in (
            Alert.model_validate_json(r[0]) for r in connection.execute("SELECT body FROM alerts")
        )
        if event_ids.intersection(a.event_ids)
    ]
    incidents = [
        i
        for i in (
            Incident.model_validate_json(r[0])
            for r in connection.execute("SELECT body FROM incidents")
        )
        if event_ids.intersection(i.event_ids)
    ]
    return alerts, incidents


# ----- grading -----


def grade(
    record: dict[str, Any],
    profile: dict[str, Any] | None,
    observed: list[Observation],
    alerts: list[Alert],
) -> tuple[str, list[str]]:
    """Apply the documented result definitions. Returns (result, reasons)."""
    execution = record["execution"]["status"]
    if execution != "COMPLETED":
        return "INCONCLUSIVE", [f"test execution status is {execution}"]
    if not record["engine"].get("active_for_window"):
        return "INCONCLUSIVE", ["the monitoring engine was not running for the whole test window"]
    if profile is None:
        return "INCONCLUSIVE", [
            "no reviewed expectation profile for this test in expectations.yaml"
        ]
    missing = set(profile.get("telemetry", [])) - LIVE_TELEMETRY
    if missing:
        return "INCONCLUSIVE", [
            "required telemetry is not collected live: " + ", ".join(sorted(missing))
        ]
    if not observed:
        return "INCONCLUSIVE", [
            "no process attributable to the test was stored; /proc polling may have "
            "missed short-lived processes"
        ]
    names = {o.event.process_name for o in observed}
    keys = set(profile.get("key_processes", []))
    expected = set(profile.get("expected_rules", []))
    matched = {a.rule_id for a in alerts}
    seen_keys = keys & names
    if expected and expected <= matched:
        return "DETECTED", [f"expected rule(s) matched: {', '.join(sorted(expected))}"]
    if matched:
        reasons = [f"rule(s) matched: {', '.join(sorted(matched))}"]
        if expected - matched:
            reasons.append(f"expected rule(s) missing: {', '.join(sorted(expected - matched))}")
        if not expected:
            reasons.append("the expectation profile lists no rule for this behaviour; review it")
        return "PARTIALLY DETECTED", reasons
    if keys and not seen_keys:
        return "INCONCLUSIVE", [
            "attributed processes were stored, but none of the key processes "
            f"({', '.join(sorted(keys))}) was observed"
        ]
    if not expected:
        return "NOT DETECTED", [
            "key behaviour was observed but no current engine rule covers it (rule coverage gap)"
        ]
    return "NOT DETECTED", [
        f"key behaviour observed ({', '.join(sorted(seen_keys))}) but expected rule(s) "
        f"{', '.join(sorted(expected))} did not match"
    ]


# ----- report -----


def executor_from_log(path: str | None) -> tuple[int | None, int | None]:
    if not path or not Path(path).is_file():
        return None, None
    with open(path, newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        return None, None
    row = rows[-1]
    pid = int(row["ProcessId"]) if row.get("ProcessId", "").isdigit() else None
    code = row.get("ExitCode", "")
    exit_code = int(code) if code.lstrip("-").isdigit() else None
    return pid, exit_code


def build_report(record: dict[str, Any], db: Path, expectations: dict[str, Any]) -> dict[str, Any]:
    start = parse_time(record["start_utc"])
    end = parse_time(record["end_utc"])
    poll = float(record["engine"].get("poll_interval_seconds") or 2.0)
    # Events carry poll discovery time, which is never earlier than the process start, so
    # the window opens at the test start and extends one poll interval (plus margin) past
    # the end.
    window = (start, end + timedelta(seconds=poll + 1.5))
    executor_pid = record["execution"].get("executor_pid")
    observed: list[Observation] = []
    other: list[Event] = []
    alerts: list[Alert] = []
    incidents: list[Incident] = []
    if record["execution"]["status"] == "COMPLETED" or record["execution"]["status"] == "FAILED":
        with connect(db) as connection:
            events = load_window(connection, *window)
            observed, other = attribute(connection, events, record["runner"]["key"], executor_pid)
            alerts, incidents = related_findings(connection, {o.event.event_id for o in observed})
    profile = expectations.get(record["guid"])
    result, reasons = grade(record, profile, observed, alerts)
    return {
        "run_id": record["run_id"],
        "test": {
            "guid": record["guid"],
            "name": record["test_name"],
            "technique": record["technique"],
            "technique_name": record.get("technique_name"),
            "number": record.get("test_number"),
            "risk_class": record.get("risk_class"),
            "executor": record.get("executor"),
            "command": record.get("command"),
        },
        "window": {
            "start_utc": record["start_utc"],
            "end_utc": record["end_utc"],
            "correlation_from": window[0].isoformat(),
            "correlation_to": window[1].isoformat(),
        },
        "execution": record["execution"],
        "cleanup": record["cleanup"],
        "engine": record["engine"],
        "counts": {
            "attributed_events": len(observed),
            "unattributed_events_in_window": len(other),
            "rule_matches": sum(len(a.event_ids) for a in alerts),
            "alerts": len(alerts),
            "incidents": len(incidents),
        },
        "result": result,
        "result_reasons": reasons,
        "expectation": profile,
        "evidence": {
            "processes": [
                {
                    "time": o.event.timestamp.isoformat(),
                    "pid": o.event.pid,
                    "ppid": o.event.ppid,
                    "name": o.event.process_name,
                    "executable": o.event.executable_path,
                    "attribution": o.attribution,
                    "ancestry": " > ".join(o.chain),
                    "event_id": o.event.event_id,
                }
                for o in observed
            ],
            "alerts": [
                {
                    "rule_id": a.rule_id,
                    "rule_name": a.rule_name,
                    "severity": a.severity.value,
                    "reason": a.reason,
                    "first_seen": a.first_seen.isoformat(),
                }
                for a in alerts
            ],
            "incident_ids": [i.incident_id for i in incidents],
            "incidents": [
                {"incident_id": i.incident_id, "severity": i.severity.value, "rules": i.rule_ids}
                for i in incidents
            ],
        },
        "limitations": [
            "Live telemetry is /proc process discovery only (poll interval "
            f"{poll:g} s); processes that start and exit between polls are never seen.",
            "File access, network connections and privilege changes are not collected live; "
            "rules RT003, RT004 and RT006 cannot fire during live tests.",
            "Event timestamps are discovery times, not exec times.",
            "Attribution needs the parent identity chain recorded by the collector; "
            "processes reparented before discovery cannot be attributed.",
        ],
    }


def text(report: dict[str, Any]) -> str:
    bar = "=" * 64
    test, counts, evidence = report["test"], report["counts"], report["evidence"]
    lines = [
        bar,
        "ATOMIC RED TEAM TEST REPORT",
        bar,
        "",
        f"TEST:              {test['name']}",
        f"GUID:              {test['guid']}",
        f"TECHNIQUE:         {test['technique']} {test.get('technique_name') or ''}".rstrip(),
        f"RISK CLASS:        {test.get('risk_class') or 'unknown'}",
        f"RUN ID:            {report['run_id']}",
        f"WINDOW (UTC):      {report['window']['start_utc']} -> {report['window']['end_utc']}",
        "",
        f"EXECUTION STATUS:  {report['execution']['status']}"
        + (
            f" (exit code {report['execution'].get('exit_code')})"
            if report["execution"].get("exit_code") is not None
            else ""
        ),
        "MONITORING STATUS: "
        + ("ACTIVE" if report["engine"].get("active_for_window") else "NOT ACTIVE")
        + (
            f" (session {report['engine'].get('session_id')})"
            if report["engine"].get("session_id")
            else ""
        ),
        "",
        f"EVENTS OBSERVED:   {counts['attributed_events']} attributed to the test "
        f"({counts['unattributed_events_in_window']} unrelated events in the same window)",
        f"RULE MATCHES:      {counts['rule_matches']} ({counts['alerts']} alert(s))",
        f"INCIDENTS:         {counts['incidents']}",
        "",
        f"DETECTION RESULT:  {report['result']}",
    ]
    lines += [f"  - {reason}" for reason in report["result_reasons"]]
    lines += ["", "EVIDENCE:"]
    if not evidence["processes"]:
        lines.append("  - no attributed process observations")
    for item in evidence["processes"]:
        lines.append(
            f"  - {item['time']}  {item['name']} PID {item['pid']} exe={item['executable'] or '-'}"
        )
        lines.append(f"      ancestry: {item['ancestry']}  [{item['attribution']}]")
    for alert in evidence["alerts"]:
        lines.append(
            f"  - RULE {alert['rule_id']} {alert['severity']} {alert['rule_name']}: "
            f"{alert['reason']}"
        )
    for incident in evidence["incidents"]:
        rules = ",".join(incident["rules"])
        lines.append(f"  - INCIDENT {incident['incident_id']} {incident['severity']} rules={rules}")
    cleanup = report["cleanup"]
    lines += [
        "",
        f"CLEANUP STATUS:    {cleanup['status']}"
        + (
            f" (verification: {cleanup.get('verification')})" if cleanup.get("verification") else ""
        ),
        "",
        "LIMITATIONS:",
    ]
    lines += [f"  - {item}" for item in report["limitations"]]
    lines += ["", "A successful test execution is never counted as a detection by itself.", bar]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    ident = sub.add_parser("identity")
    ident.add_argument("--pid", type=int, required=True)
    status = sub.add_parser("engine-status")
    status.add_argument("--db", type=Path, required=True)
    report = sub.add_parser("report")
    report.add_argument("--record", type=Path, required=True)
    report.add_argument("--db", type=Path, required=True)
    report.add_argument("--expectations", type=Path, default=DEFAULT_EXPECTATIONS)
    report.add_argument("--out", type=Path, help="Directory for report.txt and report.json")
    args = parser.parse_args(argv)
    if args.command == "identity":
        print(json.dumps(identity(args.pid)))
        return 0
    if args.command == "engine-status":
        result = engine_status(args.db)
        print(json.dumps(result))
        return 0 if result["running"] else 4
    record = json.loads(args.record.read_text(encoding="utf-8-sig"))
    pid, code = executor_from_log(record["execution"].get("log_path"))
    record["execution"].setdefault("executor_pid", pid)
    if record["execution"].get("exit_code") is None:
        record["execution"]["exit_code"] = code
    expectations = yaml.safe_load(args.expectations.read_text(encoding="utf-8")) or {}
    try:
        result = build_report(record, args.db, expectations)
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(
            f"error: cannot read engine database {args.db}: {type(exc).__name__}", file=sys.stderr
        )
        return 1
    rendered = text(result)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (args.out / "report.txt").write_text(rendered, encoding="utf-8")
        os.chmod(args.out / "report.json", 0o600)
        os.chmod(args.out / "report.txt", 0o600)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
