"""Thread-safe display state written by the pipeline thread and read by the terminal.

The state only mirrors pipeline results: it never evaluates rules or changes incidents.
Alerts and incidents are deep-copied on arrival, so the terminal never touches objects
that the correlation engine is still mutating. Display buffers are bounded; evictions are
counted. Rule matches and incidents are held separately and never evicted by routine
process observations (they are also persisted in SQLite by the pipeline).
"""

import logging
import math
import resource
import sys
import threading
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Any

from runtime_engine.events.schema import Alert, Event, EventType, Incident, Severity
from runtime_engine.monitor.notifications import Notification, NotificationCenter
from runtime_engine.pipeline import ProcessResult
from runtime_engine.process.ancestry import parent_key


class Verbosity(IntEnum):
    QUIET = 0
    NORMAL = 1
    VERBOSE = 2
    DEBUG = 3

    @classmethod
    def parse(cls, name: str) -> "Verbosity":
        return cls[name.upper()]


class EntryKind(StrEnum):
    OBSERVED = "OBSERVED"  # raw, normalized telemetry; not a finding
    RULE_MATCH = "RULE_MATCH"  # a detection rule matched an event
    DUPLICATE_MATCH = "DUPLICATE_MATCH"  # repeat folded into an existing alert
    INCIDENT = "INCIDENT"  # correlated incident created or updated
    TELEMETRY = "TELEMETRY"  # partial or missing telemetry
    ERROR = "ERROR"  # monitoring failure, not a security finding
    LIFECYCLE = "LIFECYCLE"  # session start, baseline, stop
    DIAGNOSTIC = "DIAGNOSTIC"  # internal debug information


LEVELS = {
    EntryKind.OBSERVED: "INFO",
    EntryKind.RULE_MATCH: "WARNING",
    EntryKind.DUPLICATE_MATCH: "NOTICE",
    EntryKind.INCIDENT: "ALERT",
    EntryKind.TELEMETRY: "NOTICE",
    EntryKind.ERROR: "ERROR",
    EntryKind.LIFECYCLE: "NOTICE",
    EntryKind.DIAGNOSTIC: "DEBUG",
}
SECURITY_KINDS = {EntryKind.RULE_MATCH, EntryKind.INCIDENT, EntryKind.ERROR}


@dataclass(frozen=True)
class LogEntry:
    seq: int
    at: datetime
    kind: EntryKind
    title: str
    fields: tuple[tuple[str, str], ...]
    min_verbosity: Verbosity
    severity: Severity | None = None
    incident_id: str | None = None
    event_id: str | None = None

    @property
    def level(self) -> str:
        return LEVELS[self.kind]


@dataclass(frozen=True)
class EventRecord:
    """One event as the pipeline saw it, with the rule matches it produced."""

    event: Event
    baseline: bool
    alert_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    incident_ids: tuple[str, ...]
    severity: Severity | None
    received_at: datetime


@dataclass
class ProcessRecord:
    key: str
    event: Event
    first_observed: datetime
    baseline: bool
    parent: str | None
    alert_ids: list[str] = field(default_factory=list)
    incident_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    matches: int = 0
    severity: Severity | None = None

    def copy(self) -> "ProcessRecord":
        return replace(
            self,
            alert_ids=list(self.alert_ids),
            incident_ids=list(self.incident_ids),
            event_ids=list(self.event_ids),
        )


@dataclass
class Counters:
    observed: int = 0
    accepted: int = 0
    processed: int = 0
    duplicate_events: int = 0
    rejected: int = 0  # by the pipeline (conflicting event ID reuse)
    collector_rejected: int = 0  # invalid input records (replay)
    dropped: int = 0
    unprocessed_at_shutdown: int = 0
    backpressure_waits: int = 0
    queue_depth: int = 0
    queue_peak: int = 0
    polls: int = 0
    baseline_processes: int = 0
    collector_errors: int = 0
    missing_telemetry: int = 0
    read_failures: int = 0
    rule_matches: int = 0
    duplicate_matches: int = 0
    render_errors: int = 0
    logs_evicted: int = 0
    events_evicted: int = 0
    last_poll_at: datetime | None = None
    last_poll_seconds: float | None = None
    last_poll_missing: int = 0
    last_poll_failures: int = 0


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    mode: str
    hostname: str
    kernel: str
    engine_pid: int
    started_at: datetime
    verbosity: Verbosity
    poll_interval: float | None
    queue_capacity: int | None
    window_seconds: float
    telemetry: str
    database_path: str
    reports_directory: str
    include_cmdline: bool = False
    dashboard: bool = False


@dataclass(frozen=True)
class LatencySummary:
    samples: int
    average_ms: float | None
    p95_ms: float | None
    max_ms: float | None


@dataclass(frozen=True)
class DashboardSnapshot:
    info: SessionInfo
    status: str
    now: datetime
    counters: Counters
    match_severity: dict[str, int]
    alert_severity: dict[str, int]
    unique_alerts: int
    incidents: list[Incident]
    active_incident_ids: frozenset[str]
    processes: list[ProcessRecord]
    logs: list[LogEntry]
    diagnostics: list[LogEntry]
    notifications: list[Notification]
    latency: LatencySummary
    peak_rss_kb: int | None
    error: str | None


def peak_rss_kb() -> int | None:
    """Peak resident set size of this process; Linux reports kilobytes."""
    if not sys.platform.startswith("linux"):
        return None
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def percentile(values: Iterable[float], fraction: float) -> float | None:
    """Nearest-rank percentile; no interpolation of values that were never measured."""
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


class DashboardState:
    def __init__(
        self,
        info: SessionInfo,
        *,
        log_capacity: int = 2000,
        security_log_capacity: int = 5000,
        event_capacity: int = 5000,
        latency_samples: int = 100_000,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        notifications: NotificationCenter | None = None,
    ) -> None:
        self.info = info
        self.lock = threading.RLock()
        self.clock = clock
        self.status = "STARTING"
        self.error: str | None = None
        self.stop_reason: str | None = None
        self.stopped_at: datetime | None = None
        self.counters = Counters()
        self.logs: deque[LogEntry] = deque(maxlen=log_capacity)
        self.security_logs: deque[LogEntry] = deque(maxlen=security_log_capacity)
        self.diagnostics: deque[LogEntry] = deque(maxlen=500)
        self.events: deque[EventRecord] = deque(maxlen=event_capacity)
        self.processes: dict[str, ProcessRecord] = {}
        self.children: dict[str, list[str]] = {}
        self.recent_processes: deque[str] = deque(maxlen=200)
        self.alerts: dict[str, Alert] = {}
        self.alert_incident: dict[str, str] = {}
        self.incidents: dict[str, Incident] = {}
        self.match_severity: Counter[str] = Counter()
        self.latencies: deque[float] = deque(maxlen=latency_samples)
        self.latency_count = 0
        self.latency_total = 0.0
        self.latency_max = 0.0
        self.latest_event_time: datetime | None = None
        self.exported_reports: list[str] = []
        self.notifications = notifications or NotificationCenter()
        self.evicted_marks: dict[Verbosity, int] = {}  # newest evicted seq per verbosity
        self._seq = 0

    # ----- producer side (collector / pipeline threads) -----

    def _entry(
        self,
        kind: EntryKind,
        title: str,
        fields: Iterable[tuple[str, object]],
        verbosity: Verbosity,
        *,
        at: datetime | None = None,
        severity: Severity | None = None,
        incident_id: str | None = None,
        event_id: str | None = None,
    ) -> None:
        self._seq += 1
        entry = LogEntry(
            self._seq,
            at or self.clock(),
            kind,
            title,
            tuple((k, str(v)) for k, v in fields if v is not None),
            verbosity,
            severity,
            incident_id,
            event_id,
        )
        target = (
            self.diagnostics
            if kind == EntryKind.DIAGNOSTIC
            else self.security_logs
            if kind in SECURITY_KINDS
            else self.logs
        )
        if target.maxlen is not None and len(target) == target.maxlen:
            self.counters.logs_evicted += 1
            oldest = target[0]
            mark = self.evicted_marks.get(oldest.min_verbosity, 0)
            self.evicted_marks[oldest.min_verbosity] = max(mark, oldest.seq)
        target.append(entry)

    def set_status(self, status: str) -> None:
        with self.lock:
            self.status = status
            if status in ("STOPPED", "FAILED") and self.stopped_at is None:
                self.stopped_at = self.clock()

    def record_lifecycle(
        self,
        title: str,
        fields: Iterable[tuple[str, object]] = (),
        *,
        verbosity: Verbosity = Verbosity.QUIET,
    ) -> None:
        with self.lock:
            self._entry(EntryKind.LIFECYCLE, title, fields, verbosity)

    def record_error(
        self, title: str, fields: Iterable[tuple[str, object]] = (), *, fatal: bool = False
    ) -> None:
        fields = list(fields)
        with self.lock:
            if fatal:
                self.error = next((str(v) for k, v in fields if k == "ERROR"), title)
            self._entry(EntryKind.ERROR, title, fields, Verbosity.QUIET)

    def record_diagnostic(self, message: str, fields: Iterable[tuple[str, object]] = ()) -> None:
        with self.lock:
            self._entry(EntryKind.DIAGNOSTIC, message, fields, Verbosity.DEBUG)

    def record_observed(self) -> None:
        with self.lock:
            self.counters.observed += 1

    def record_accepted(self, depth: int) -> None:
        with self.lock:
            self.counters.accepted += 1
            self.counters.queue_depth = depth
            self.counters.queue_peak = max(self.counters.queue_peak, depth)

    def record_dropped(self) -> None:
        with self.lock:
            self.counters.dropped += 1

    def record_backpressure(self) -> None:
        with self.lock:
            self.counters.backpressure_waits += 1

    def record_queue_depth(self, depth: int) -> None:
        with self.lock:
            self.counters.queue_depth = depth

    def record_unprocessed(self, count: int) -> None:
        with self.lock:
            self.counters.unprocessed_at_shutdown = count

    def record_render_error(self, error: str) -> None:
        with self.lock:
            self.counters.render_errors += 1
            self._entry(EntryKind.DIAGNOSTIC, "RENDER_ERROR", [("ERROR", error)], Verbosity.DEBUG)

    def record_export(self, path: str) -> None:
        with self.lock:
            self.exported_reports.append(path)

    def update_collector(
        self, errors: int, missing: int, read_failures: int, rejected: int = 0
    ) -> None:
        """Collector counters are cumulative totals owned by the collector thread."""
        with self.lock:
            self.counters.collector_errors = errors
            self.counters.missing_telemetry = missing
            self.counters.read_failures = read_failures
            self.counters.collector_rejected = rejected

    def record_poll(
        self,
        poll: int,
        seconds: float,
        discovered: int,
        missing_delta: int,
        failure_delta: int,
    ) -> None:
        with self.lock:
            counters = self.counters
            counters.polls = poll
            counters.last_poll_at = self.clock()
            counters.last_poll_seconds = seconds
            counters.last_poll_missing = missing_delta
            counters.last_poll_failures = failure_delta
            if poll == 1:
                counters.baseline_processes = discovered
                self._entry(
                    EntryKind.LIFECYCLE,
                    "BASELINE_SNAPSHOT",
                    [
                        ("PROCESSES_VISIBLE", discovered),
                        ("NOTE", "pre-existing processes; first observation, not new starts"),
                    ],
                    Verbosity.NORMAL,
                )
            if missing_delta or failure_delta:
                self._entry(
                    EntryKind.TELEMETRY,
                    "PARTIAL_TELEMETRY",
                    [
                        ("POLL", poll),
                        ("FIELDS_UNREADABLE", missing_delta),
                        ("ENTRIES_SKIPPED", failure_delta),
                        ("CAUSE", "permission denied or process exited during read"),
                    ],
                    Verbosity.NORMAL if poll == 1 else Verbosity.VERBOSE,
                )
            self._entry(
                EntryKind.DIAGNOSTIC,
                "POLL_COMPLETE",
                [
                    ("POLL", poll),
                    ("NEW", discovered),
                    ("MS", f"{seconds * 1000:.1f}"),
                    ("QUEUE", counters.queue_depth),
                ],
                Verbosity.DEBUG,
            )

    def apply(self, result: ProcessResult, baseline: bool = False) -> None:
        """Mirror one pipeline result. Called only from the pipeline thread."""
        now = self.clock()
        with self.lock:
            event = result.event
            if result.status == "duplicate":
                self.counters.duplicate_events += 1
                self._entry(
                    EntryKind.DIAGNOSTIC,
                    "DUPLICATE_EVENT_IGNORED",
                    [("EVENT_ID", event.event_id)],
                    Verbosity.DEBUG,
                    event_id=event.event_id,
                )
                return
            if result.status == "rejected":
                self.counters.rejected += 1
                self._entry(
                    EntryKind.ERROR,
                    "EVENT_REJECTED",
                    [("EVENT_ID", event.event_id), ("CAUSE", "event ID reused with new content")],
                    Verbosity.QUIET,
                    event_id=event.event_id,
                )
                return
            self.counters.processed += 1
            self._observe_latency(result.latency_seconds)
            if self.latest_event_time is None or event.timestamp > self.latest_event_time:
                self.latest_event_time = event.timestamp
            for alert in result.alerts:
                self.alerts[alert.alert_id] = alert.model_copy(deep=True)
            for incident in result.incidents:
                copy = incident.model_copy(deep=True)
                self.incidents[incident.incident_id] = copy
                for alert_id in copy.alert_ids:
                    self.alert_incident[alert_id] = incident.incident_id
            process = self._register_process(event, baseline, now)
            matched: list[tuple[Alert, str, bool]] = []
            for detection in result.detections:
                alert = (
                    self._prior_alert(detection.alert, detection.incident_id)
                    if detection.duplicate
                    else self.alerts.get(detection.alert.alert_id)
                ) or detection.alert
                matched.append((alert, detection.incident_id, detection.duplicate))
            severity = max((a.severity for a, _, _ in matched), key=lambda s: s.rank, default=None)
            self._log_observation(event, baseline, matched, severity)
            for alert, incident_id, duplicate in matched:
                self._log_match(event, alert, incident_id, duplicate)
                if process is None:  # alerts carry the event's own identity, if any
                    continue
                process.matches += 1
                if alert.alert_id not in process.alert_ids:
                    process.alert_ids.append(alert.alert_id)
                if incident_id not in process.incident_ids:
                    process.incident_ids.append(incident_id)
                if process.severity is None or alert.severity.rank > process.severity.rank:
                    process.severity = alert.severity
            for incident in result.incidents:
                created = incident.incident_id in result.created_incident_ids
                novel = any(not d and i == incident.incident_id for _, i, d in matched)
                self._entry(
                    EntryKind.INCIDENT,
                    "INCIDENT_CREATED" if created else "INCIDENT_UPDATED",
                    [
                        ("INCIDENT", incident.incident_id),
                        ("SEVERITY", incident.severity.value),
                        ("RELATED_ALERTS", len(incident.alert_ids)),
                        ("EVENTS", incident.event_count),
                        ("RULES", ",".join(incident.rule_ids)),
                    ],
                    Verbosity.QUIET if created or novel else Verbosity.VERBOSE,
                    at=event.timestamp,
                    severity=incident.severity,
                    incident_id=incident.incident_id,
                )
            if len(self.events) == self.events.maxlen:
                self.counters.events_evicted += 1
            self.events.append(
                EventRecord(
                    event,
                    baseline,
                    tuple(dict.fromkeys(a.alert_id for a, _, _ in matched)),
                    tuple(dict.fromkeys(a.rule_id for a, _, _ in matched)),
                    tuple(dict.fromkeys(i for _, i, _ in matched)),
                    severity,
                    now,
                )
            )

    def _observe_latency(self, seconds: float) -> None:
        milliseconds = seconds * 1000
        self.latencies.append(milliseconds)
        self.latency_count += 1
        self.latency_total += milliseconds
        self.latency_max = max(self.latency_max, milliseconds)

    def _prior_alert(self, alert: Alert, incident_id: str) -> Alert | None:
        incident = self.incidents.get(incident_id)
        for alert_id in incident.alert_ids if incident else []:
            prior = self.alerts.get(alert_id)
            if (
                prior is not None
                and prior.rule_id == alert.rule_id
                and prior.process_key == alert.process_key
                and prior.resource == alert.resource
            ):
                return prior
        return None

    def _register_process(
        self, event: Event, baseline: bool, now: datetime
    ) -> ProcessRecord | None:
        key = event.process_key
        if key is None:
            return None
        record = self.processes.get(key)
        if record is None:
            record = ProcessRecord(key, event, now, baseline, parent_key(event))
            self.processes[key] = record
            if record.parent is not None:
                self.children.setdefault(record.parent, []).append(key)
            self.recent_processes.append(key)
        elif (
            event.event_type == EventType.PROCESS_START
            and record.event.event_type != EventType.PROCESS_START
        ):
            record.event = event
            if record.parent is None and parent_key(event) is not None:
                record.parent = parent_key(event)
                assert record.parent is not None
                self.children.setdefault(record.parent, []).append(key)
        record.event_ids.append(event.event_id)
        return record

    def _log_observation(
        self,
        event: Event,
        baseline: bool,
        matched: list[tuple[Alert, str, bool]],
        severity: Severity | None,
    ) -> None:
        status = f"RULE MATCH ({len(matched)})" if matched else "NO RULE MATCH"
        fields: list[tuple[str, object]] = [
            ("PID", event.pid),
            ("PPID", event.ppid),
            ("PROCESS", event.process_name),
            ("UID", event.uid),
            ("EXE", event.executable_path),
            ("CMD", " ".join(event.command_line) if event.command_line else None),
            ("FILE", event.file_path),
            ("DEST", event.network_destination),
            ("SOURCE", event.source),
            ("STATUS", status),
        ]
        title = event.event_type.value + (" [baseline]" if baseline else "")
        verbosity = Verbosity.VERBOSE if baseline and not matched else Verbosity.NORMAL
        self._entry(
            EntryKind.OBSERVED,
            title,
            fields,
            verbosity,
            at=event.timestamp,
            severity=severity,
            event_id=event.event_id,
        )

    def _log_match(self, event: Event, alert: Alert, incident_id: str, duplicate: bool) -> None:
        fields: list[tuple[str, object]] = [
            ("PID", event.pid),
            ("PROCESS", event.process_name),
            ("RULE", alert.rule_id),
            ("NAME", alert.rule_name),
            ("SEVERITY", alert.severity.value),
            ("INCIDENT", incident_id),
        ]
        if duplicate:
            fields.append(("REPEATS", len(alert.event_ids)))
            self.counters.duplicate_matches += 1
        else:
            fields.append(("REASON", alert.reason))
            self.notifications.push(alert, incident_id, event.pid, event.process_name)
        self.counters.rule_matches += 1
        self.match_severity[alert.severity.value] += 1
        self._entry(
            EntryKind.DUPLICATE_MATCH if duplicate else EntryKind.RULE_MATCH,
            "RULE_MATCH_REPEATED" if duplicate else "RULE_MATCH",
            fields,
            Verbosity.VERBOSE if duplicate else Verbosity.QUIET,
            at=event.timestamp,
            severity=alert.severity,
            incident_id=incident_id,
            event_id=event.event_id,
        )

    # ----- consumer side (terminal thread) -----

    def visible_entries(self, verbosity: Verbosity, after: int = 0) -> list[LogEntry]:
        with self.lock:
            entries = [e for e in self.logs if e.seq > after]
            entries += [e for e in self.security_logs if e.seq > after]
            if verbosity >= Verbosity.DEBUG:
                entries += [e for e in self.diagnostics if e.seq > after]
        return sorted((e for e in entries if e.min_verbosity <= verbosity), key=lambda e: e.seq)

    def last_evicted(self, verbosity: Verbosity) -> int:
        """Sequence number of the newest evicted entry that this verbosity would show."""
        with self.lock:
            return max(
                (seq for level, seq in self.evicted_marks.items() if level <= verbosity),
                default=0,
            )

    def latency(self) -> LatencySummary:
        with self.lock:
            if not self.latency_count:
                return LatencySummary(0, None, None, None)
            return LatencySummary(
                self.latency_count,
                self.latency_total / self.latency_count,
                percentile(self.latencies, 0.95),
                self.latency_max,
            )

    def active_incident_ids(self, now: datetime | None = None) -> frozenset[str]:
        """Incidents that new related evidence can still join under the correlation window."""
        with self.lock:
            reference = (
                (now or self.clock()) if self.info.mode == "LIVE" else self.latest_event_time
            )
            if reference is None or self.status in ("STOPPED", "FAILED"):
                return frozenset()
            window = timedelta(seconds=self.info.window_seconds)
            return frozenset(
                i.incident_id for i in self.incidents.values() if reference - i.first_seen <= window
            )

    def snapshot(
        self, verbosity: Verbosity | None = None, log_limit: int = 200
    ) -> DashboardSnapshot:
        verbosity = self.info.verbosity if verbosity is None else verbosity
        now = self.clock()
        with self.lock:
            recent = [self.processes[k] for k in reversed(self.recent_processes)]
            suspicious = sorted(
                (p for p in self.processes.values() if p.severity is not None),
                key=lambda p: (p.severity.rank if p.severity else -1, p.matches),
                reverse=True,
            )
            new = [p for p in recent if not p.baseline]
            baseline = [p for p in recent if p.baseline]
            ordered = list({p.key: p for p in suspicious + new + baseline}.values())[:50]
            return DashboardSnapshot(
                info=self.info,
                status=self.status,
                now=now,
                counters=replace(self.counters),
                match_severity=dict(self.match_severity),
                alert_severity=dict(Counter(a.severity.value for a in self.alerts.values())),
                unique_alerts=len(self.alerts),
                incidents=sorted(self.incidents.values(), key=lambda i: i.last_seen, reverse=True),
                active_incident_ids=self.active_incident_ids(now),
                processes=[p.copy() for p in ordered],
                logs=self.visible_entries(verbosity)[-log_limit:],
                diagnostics=list(self.diagnostics)[-50:],
                notifications=self.notifications.active(),
                latency=self.latency(),
                peak_rss_kb=peak_rss_kb(),
                error=self.error,
            )

    def process(self, key: str) -> ProcessRecord | None:
        with self.lock:
            record = self.processes.get(key)
            return record.copy() if record else None

    def processes_for_pid(self, pid: int) -> list[ProcessRecord]:
        with self.lock:
            return [p.copy() for p in self.processes.values() if p.event.pid == pid]

    def child_processes(self, key: str) -> list[ProcessRecord]:
        with self.lock:
            return [self.processes[k].copy() for k in self.children.get(key, [])]

    def suspicious_processes(self) -> list[ProcessRecord]:
        with self.lock:
            return [
                p.copy()
                for p in sorted(
                    (p for p in self.processes.values() if p.severity is not None),
                    key=lambda p: (p.severity.rank if p.severity else -1, p.matches),
                    reverse=True,
                )
            ]

    def incident_list(self) -> list[Incident]:
        with self.lock:
            return sorted(self.incidents.values(), key=lambda i: i.incident_id)

    def incident(self, incident_id: str) -> Incident | None:
        with self.lock:
            return self.incidents.get(incident_id)

    def alert_list(self) -> list[tuple[Alert, str | None]]:
        with self.lock:
            return [(a, self.alert_incident.get(a.alert_id)) for a in self.alerts.values()]

    def alerts_by_id(self, ids: Iterable[str]) -> list[Alert]:
        with self.lock:
            return [self.alerts[a] for a in ids if a in self.alerts]

    def event_records(self) -> list[EventRecord]:
        with self.lock:
            return list(self.events)

    def acknowledge_notifications(self) -> None:
        with self.lock:
            self.notifications.acknowledge()

    # ----- session summary -----

    def summary(self, status: str | None = None) -> dict[str, Any]:
        """JSON-serializable record of what was measured. Unmeasured values are None."""
        with self.lock:
            info, counters = self.info, self.counters
            end = self.stopped_at or self.clock()
            duration = max(0.0, (end - info.started_at).total_seconds())
            latency = self.latency()
            per_process = sorted(
                (p for p in self.processes.values() if p.severity is not None),
                key=lambda p: (p.severity.rank if p.severity else -1, len(p.alert_ids)),
                reverse=True,
            )[:10]
            return {
                "schema": 1,
                "session_id": info.session_id,
                "mode": info.mode,
                "status": status or self.status,
                "stop_reason": self.stop_reason,
                "error": self.error,
                "started_at": info.started_at.isoformat(),
                "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
                "duration_seconds": round(duration, 3),
                "host": {"hostname": info.hostname, "kernel": info.kernel},
                "engine_pid": info.engine_pid,
                "configuration": {
                    "verbosity": info.verbosity.name.lower(),
                    "poll_interval_seconds": info.poll_interval,
                    "queue_capacity": info.queue_capacity,
                    "correlation_window_seconds": info.window_seconds,
                    "include_cmdline": info.include_cmdline,
                    "dashboard": info.dashboard,
                    "telemetry": info.telemetry,
                },
                "events": {
                    "observed": counters.observed,
                    "accepted": counters.accepted,
                    "processed": counters.processed,
                    "duplicates_ignored": counters.duplicate_events,
                    "rejected": counters.rejected + counters.collector_rejected,
                    "dropped": counters.dropped,
                    "unprocessed_at_shutdown": counters.unprocessed_at_shutdown,
                    "polls": counters.polls,
                    "baseline_processes": counters.baseline_processes,
                },
                "collector": {
                    "errors": counters.collector_errors,
                    "missing_telemetry": counters.missing_telemetry,
                    "read_failures": counters.read_failures,
                },
                "security": {
                    "rule_matches": counters.rule_matches,
                    "unique_alerts": len(self.alerts),
                    "duplicate_matches_suppressed": counters.duplicate_matches,
                    "incidents_generated": len(self.incidents),
                    "matches_by_severity": {
                        s.value: self.match_severity[s.value] for s in Severity
                    },
                    "alerts_by_severity": {
                        s.value: sum(1 for a in self.alerts.values() if a.severity == s)
                        for s in Severity
                    },
                },
                "incident_ids": sorted(self.incidents),
                "incidents": [
                    {
                        "incident_id": i.incident_id,
                        "severity": i.severity.value,
                        "title": i.title,
                        "alerts": len(i.alert_ids),
                        "events": i.event_count,
                        "rule_ids": list(i.rule_ids),
                        "first_seen": i.first_seen.isoformat(),
                        "last_seen": i.last_seen.isoformat(),
                    }
                    for i in sorted(self.incidents.values(), key=lambda i: i.incident_id)
                ],
                "top_processes": [
                    {
                        "pid": p.event.pid,
                        "process_name": p.event.process_name,
                        "start_token": p.event.process_start_time,
                        "alerts": len(p.alert_ids),
                        "matches": p.matches,
                        "severity": p.severity.value if p.severity else None,
                        "incident_ids": list(p.incident_ids),
                    }
                    for p in per_process
                ],
                "performance": {
                    "latency_samples": latency.samples,
                    "average_latency_ms": latency.average_ms,
                    "p95_latency_ms": latency.p95_ms,
                    "max_latency_ms": latency.max_ms,
                    "pipeline_events_per_second": (
                        counters.processed / (self.latency_total / 1000)
                        if self.latency_total
                        else None
                    ),
                    "session_events_per_second": (
                        counters.processed / duration if duration > 0 else None
                    ),
                    "peak_rss_kb": peak_rss_kb(),
                    "backpressure_waits": counters.backpressure_waits,
                    "queue_peak": counters.queue_peak,
                    "render_errors": counters.render_errors,
                    "log_entries_evicted": counters.logs_evicted,
                    "event_records_evicted": counters.events_evicted,
                    "notifications_coalesced": self.notifications.coalesced,
                },
                "persistence": {
                    "database": info.database_path,
                    "reports_directory": info.reports_directory,
                    "exported_reports": list(self.exported_reports),
                },
            }


class StateLogHandler(logging.Handler):
    """Route engine logging into the diagnostics buffer while the dashboard owns the screen."""

    def __init__(self, state: DashboardState) -> None:
        super().__init__(logging.DEBUG)
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.state.record_diagnostic(
                f"{record.levelname} {record.name}", [("MESSAGE", record.getMessage())]
            )
        except Exception:  # pragma: no cover - logging must never break monitoring
            self.handleError(record)
