"""Read-only lookups for process, incident and event inspection.

Two sources share one interface: the live session (dashboard state plus SQLite) and a
stored database alone (historical CLI commands). Process identity is always the full
`[host_id, pid, start]` key; a PID only selects candidate identities.
"""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Alert, Event, EventType, Incident, Severity
from runtime_engine.incidents.generator import generate
from runtime_engine.monitor.state import DashboardState, EventRecord
from runtime_engine.process.ancestry import parent_key
from runtime_engine.process.liveness import Liveness, check, start_time
from runtime_engine.storage.database import Database


def identity(key: str) -> tuple[str, int, str] | None:
    try:
        host, pid, start = json.loads(key)
    except (ValueError, TypeError):
        return None
    if isinstance(host, str) and isinstance(pid, int) and isinstance(start, str):
        return host, pid, start
    return None


def _first(events: list[Event]) -> Event | None:
    starts = [e for e in events if e.event_type == EventType.PROCESS_START]
    candidates = starts or events
    return candidates[0] if candidates else None


class InvestigationSource(Protocol):
    def identities(self, pid: int) -> list[Event]: ...
    def lookup(self, key: str) -> Event | None: ...
    def children(self, key: str) -> list[Event]: ...
    def events(self, key: str) -> list[Event]: ...
    def alerts(self, key: str) -> list[Alert]: ...
    def incidents(self, key: str) -> list[Incident]: ...
    def first_observed(self, key: str) -> tuple[datetime | None, bool | None]: ...


class DatabaseSource:
    """Stored evidence only. Used by `process --pid` and other historical commands."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def identities(self, pid: int) -> list[Event]:
        grouped: dict[str, list[Event]] = {}
        for event in reversed(self.database.recent_events(1_000_000, pid=pid)):
            if event.process_key:
                grouped.setdefault(event.process_key, []).append(event)
        found = [e for e in (_first(g) for g in grouped.values()) if e is not None]
        return sorted(found, key=lambda e: e.timestamp)

    def lookup(self, key: str) -> Event | None:
        return _first(self.database.process_events([key]))

    def children(self, key: str) -> list[Event]:
        parsed = identity(key)
        if parsed is None:
            return []
        found: dict[str, Event] = {}
        for event in self.database.child_events(*parsed):
            if event.process_key:
                found.setdefault(event.process_key, event)
        return list(found.values())

    def events(self, key: str) -> list[Event]:
        return self.database.process_events([key])

    def alerts(self, key: str) -> list[Alert]:
        return self.database.alerts_for_process(key)

    def incidents(self, key: str) -> list[Incident]:
        return [
            i
            for i in self.database.incidents()
            if key in i.process_keys or key in i.context_process_keys
        ]

    def first_observed(self, key: str) -> tuple[datetime | None, bool | None]:
        # Baseline status is session-local and is not stored per event.
        event = self.lookup(key)
        return (event.timestamp if event else None), None


class LiveSource:
    """The running session's state, falling back to SQLite for stored event history."""

    def __init__(self, state: DashboardState, database: Database) -> None:
        self.state = state
        self.database = database
        self.stored = DatabaseSource(database)

    def identities(self, pid: int) -> list[Event]:
        return [p.event for p in self.state.processes_for_pid(pid)]

    def lookup(self, key: str) -> Event | None:
        record = self.state.process(key)
        return record.event if record else self.stored.lookup(key)

    def children(self, key: str) -> list[Event]:
        return [p.event for p in self.state.child_processes(key)]

    def events(self, key: str) -> list[Event]:
        return self.database.process_events([key])

    def alerts(self, key: str) -> list[Alert]:
        record = self.state.process(key)
        return self.state.alerts_by_id(record.alert_ids) if record else []

    def incidents(self, key: str) -> list[Incident]:
        """Incidents with a rule match on this process, then incidents using it as context."""
        record = self.state.process(key)
        own = record.incident_ids if record else []
        matched = [i for i in (self.state.incident(n) for n in own) if i is not None]
        context = [
            i
            for i in self.state.incident_list()
            if key in i.context_process_keys and i.incident_id not in own
        ]
        return matched + context

    def first_observed(self, key: str) -> tuple[datetime | None, bool | None]:
        record = self.state.process(key)
        if record is None:
            return self.stored.first_observed(key)
        return record.first_observed, record.baseline


@dataclass(frozen=True)
class LineageNode:
    key: str
    pid: int | None
    start: str | None
    event: Event | None  # None: identity referenced by a child but never observed


@dataclass
class ProcessDetails:
    key: str
    event: Event
    first_observed: datetime | None
    baseline: bool | None
    liveness: Liveness
    alerts: list[Alert]
    incidents: list[Incident]
    events: list[Event]
    lineage: list[LineageNode]
    children: list[Event]
    started_at: datetime | None = None
    severities: dict[str, Severity] = field(default_factory=dict)

    @property
    def severity(self) -> Severity | None:
        return max((a.severity for a in self.alerts), key=lambda s: s.rank, default=None)


def lineage(source: InvestigationSource, key: str, event: Event | None) -> list[LineageNode]:
    """Root-to-leaf chain; an unobserved parent ends the chain with an explicit marker."""
    chain: list[LineageNode] = []
    visited: set[str] = set()
    current: str | None = key
    while current is not None and current not in visited:
        visited.add(current)
        node = event if current == key else source.lookup(current)
        parsed = identity(current)
        chain.append(
            LineageNode(
                current,
                node.pid if node else (parsed[1] if parsed else None),
                node.process_start_time if node else (parsed[2] if parsed else None),
                node,
            )
        )
        current = parent_key(node) if node else None
    return list(reversed(chain))


def process_details(
    source: InvestigationSource,
    key: str,
    liveness: Callable[[Event], Liveness] = check,
    started: Callable[[Event], datetime | None] = start_time,
) -> ProcessDetails | None:
    event = source.lookup(key)
    if event is None:
        return None
    first, baseline = source.first_observed(key)
    chain = lineage(source, key, event)
    children = source.children(key)
    severities: dict[str, Severity] = {}
    for other in [n.key for n in chain if n.event] + [c.process_key for c in children]:
        worst = max(
            (a.severity for a in source.alerts(other or "")), key=lambda s: s.rank, default=None
        )
        if other and worst:
            severities[other] = worst
    return ProcessDetails(
        key=key,
        event=event,
        first_observed=first,
        baseline=baseline,
        liveness=liveness(event),
        alerts=source.alerts(key),
        incidents=source.incidents(key),
        events=source.events(key),
        lineage=chain,
        children=children,
        started_at=started(event),
        severities=severities,
    )


@dataclass
class IncidentDetails:
    incident: Incident
    report: dict[str, Any]
    detections: list[Alert]
    rules: dict[str, Rule]
    processes: list[Event]
    active: bool | None


def incident_details(
    database: Database,
    incident_id: str,
    rules: list[Rule],
    active: bool | None = None,
) -> IncidentDetails | None:
    incident = database.incident(incident_id)
    if incident is None:
        return None
    report = generate(database, incident_id)
    observed: dict[str, Event] = {}
    for event in database.process_events(incident.context_process_keys):
        if event.process_key and (
            event.process_key not in observed or event.event_type == EventType.PROCESS_START
        ):
            observed.setdefault(event.process_key, event)
    return IncidentDetails(
        incident,
        report,
        database.alerts(incident.alert_ids),
        {r.rule_id: r for r in rules},
        list(observed.values()),
        active,
    )


# ----- event filtering -----

KINDS = ("observed", "match", "incident")
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)([smhd])$")


@dataclass
class EventFilter:
    pid: int | None = None
    name: str | None = None
    event_type: str | None = None
    severity: Severity | None = None
    since: datetime | None = None
    until: datetime | None = None
    incident: str | None = None
    kind: str | None = None
    terms: list[str] = field(default_factory=list)

    def describe(self) -> str:
        return " ".join(self.terms) or "none"


def parse_time(text: str, now: datetime) -> datetime:
    """`10m`/`30s`/`2h`/`1d` ago, local `HH:MM[:SS]` today, or ISO-8601 with timezone."""
    match = _DURATION.match(text)
    if match:
        unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
        return now - timedelta(seconds=float(match.group(1)) * unit)
    if re.match(r"^\d{1,2}:\d{2}(:\d{2})?$", text):
        parts = [int(p) for p in text.split(":")] + [0]
        local = now.astimezone().replace(
            hour=parts[0], minute=parts[1], second=parts[2], microsecond=0
        )
        return local.astimezone(UTC)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("ISO time must include a timezone")
    return parsed.astimezone(UTC)


def parse_filter(text: str, now: datetime | None = None) -> EventFilter:
    """Parse `key=value` terms, e.g. `pid=42 type=PROCESS_START severity=HIGH since=5m`."""
    now = now or datetime.now(UTC)
    result = EventFilter()
    for term in text.split():
        if "=" not in term:
            raise ValueError(f"expected key=value, got {term!r}")
        key, value = term.split("=", 1)
        key = key.lower()
        if not value:
            raise ValueError(f"empty value for {key}")
        if key == "pid":
            result.pid = int(value)
        elif key in ("name", "process"):
            result.name = value
        elif key == "type":
            result.event_type = EventType(value.upper()).value
        elif key == "severity":
            result.severity = Severity(value.upper())
        elif key == "since":
            result.since = parse_time(value, now)
        elif key == "until":
            result.until = parse_time(value, now)
        elif key == "incident":
            result.incident = value.upper()
        elif key == "kind":
            if value.lower() not in KINDS:
                raise ValueError(f"kind must be one of {', '.join(KINDS)}")
            result.kind = value.lower()
        else:
            raise ValueError(f"unknown filter {key!r}")
        result.terms.append(term)
    return result


def filter_records(records: list[EventRecord], spec: EventFilter) -> list[EventRecord]:
    result: list[EventRecord] = []
    for record in records:
        event = record.event
        if spec.pid is not None and event.pid != spec.pid:
            continue
        if spec.name is not None and event.process_name != spec.name:
            continue
        if spec.event_type is not None and event.event_type != spec.event_type:
            continue
        if spec.severity is not None and (
            record.severity is None or record.severity.rank < spec.severity.rank
        ):
            continue
        if spec.since is not None and event.timestamp < spec.since:
            continue
        if spec.until is not None and event.timestamp > spec.until:
            continue
        if spec.incident is not None and spec.incident not in record.incident_ids:
            continue
        if spec.kind == "observed" and record.rule_ids:
            continue
        if spec.kind in ("match", "incident") and not record.rule_ids:
            continue
        if spec.kind == "incident" and not record.incident_ids:
            continue
        result.append(record)
    return result


def records_from_database(database: Database, events: list[Event]) -> list[EventRecord]:
    """Attach stored rule matches and incidents to stored events, oldest first."""
    by_event: dict[str, list[Alert]] = {}
    for alert in database.all_alerts():
        for event_id in alert.event_ids:
            by_event.setdefault(event_id, []).append(alert)
    incidents: dict[str, list[str]] = {}
    for incident in database.incidents():
        for event_id in incident.event_ids:
            incidents.setdefault(event_id, []).append(incident.incident_id)
    records = []
    for event in sorted(events, key=lambda e: e.timestamp):
        alerts = by_event.get(event.event_id, [])
        records.append(
            EventRecord(
                event,
                False,
                tuple(a.alert_id for a in alerts),
                tuple(dict.fromkeys(a.rule_id for a in alerts)),
                tuple(incidents.get(event.event_id, [])),
                max((a.severity for a in alerts), key=lambda s: s.rank, default=None),
                event.timestamp,
            )
        )
    return records
