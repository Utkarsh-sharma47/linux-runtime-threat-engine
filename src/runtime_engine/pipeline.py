"""Compose normalization, ancestry, detection, correlation and transactional storage."""

import json
from dataclasses import dataclass, field
from time import perf_counter
from typing import TYPE_CHECKING, Literal

from runtime_engine.correlation.engine import CorrelationEngine
from runtime_engine.detection.engine import DetectionEngine
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Alert, Event, EventType, Incident
from runtime_engine.metrics.collector import Metrics
from runtime_engine.process.ancestry import AncestryTracker
from runtime_engine.storage.database import Database

if TYPE_CHECKING:
    from runtime_engine.security.findings import Finding


@dataclass(frozen=True)
class Detection:
    """One rule match. A duplicate was folded into an existing alert of the same incident."""

    alert: Alert
    incident_id: str
    duplicate: bool


@dataclass
class ProcessResult:
    """What one `Pipeline.process` call did. Alerts/incidents are live engine objects."""

    event: Event
    status: Literal["processed", "duplicate", "rejected"]
    latency_seconds: float = 0
    detections: list[Detection] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    created_incident_ids: list[str] = field(default_factory=list)


class Pipeline:
    def __init__(self, database: Database, rules: list[Rule], window_seconds: float = 120) -> None:
        self.database = database
        self.ancestry = AncestryTracker()
        self.detection = DetectionEngine(rules)
        self.correlation = CorrelationEngine(
            self.ancestry, window_seconds, database.next_incident_number()
        )
        self.metrics = Metrics()

    def process(self, event: Event) -> ProcessResult:
        """Process one already-validated event. Storage failure aborts the run."""
        start = perf_counter()
        existing = self.database.event(event.event_id)
        if existing:
            if existing == event:
                self.metrics.duplicate_events_suppressed += 1
                return ProcessResult(event, "duplicate")
            self.metrics.events_rejected += 1  # ID collision must not replace evidence
            return ProcessResult(event, "rejected")
        self.ancestry.observe(event)
        detections = self.detection.evaluate(event, self.ancestry)
        return self._correlate(event, detections, start)

    def _correlate(
        self,
        event: Event,
        detections: list[Alert],
        start: float,
        finding: "Finding | None" = None,
    ) -> ProcessResult:
        affected: dict[str, Incident] = {}
        outcomes: list[Detection] = []
        created: list[str] = []
        for alert in detections:
            known = {i.incident_id for i in self.correlation.incidents}
            incident = self.correlation.add(alert, event)
            if incident.incident_id not in known:
                created.append(incident.incident_id)
            affected[incident.incident_id] = incident
            outcomes.append(
                Detection(
                    alert, incident.incident_id, alert.alert_id not in self.correlation.alerts
                )
            )
        alerts = [self.correlation.alerts[a] for i in affected.values() for a in i.alert_ids]
        self.database.save(event, list(affected.values()), alerts, finding)
        self.metrics.total_events_processed += 1
        self.metrics.total_alerts_generated += len(detections)
        self.metrics.total_incidents_created = len(self.correlation.incidents)
        self.metrics.duplicate_alerts_suppressed = self.correlation.duplicates
        elapsed = perf_counter() - start
        self.metrics.observe(elapsed)
        return ProcessResult(
            event, "processed", elapsed, outcomes, list(affected.values()), alerts, created
        )

    def process_finding(self, finding: "Finding") -> ProcessResult | None:
        """Store a security-module finding; promote new revisions into correlation.

        Findings below the promotion threshold are stored only. A promoted finding becomes
        one SECURITY_FINDING event and one alert per revision, so an unchanged finding that
        a module reports on every scan refreshes its record without re-alerting. The
        finding carries the process identity when the module could attribute it, which
        links it to that process's incidents through the existing ancestry correlation.
        """
        start = perf_counter()
        self.metrics.security_findings_received += 1
        event = finding_event(finding)
        if not finding.promoted or self.database.event(event.event_id) is not None:
            self.database.save_finding(finding)
            return None
        alert = Alert(
            rule_id=finding.rule_id,
            rule_name=finding.title,
            mitre_reference=finding.mitre_reference,
            severity=finding.severity,
            reason=finding.explanation,
            event_ids=[event.event_id],
            process_key=event.process_key,
            resource=finding.resource,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
        )
        self.ancestry.observe(event)
        self.metrics.security_findings_promoted += 1
        return self._correlate(event, [alert], start, finding)


def finding_event(finding: "Finding") -> Event:
    """The event that represents a promoted finding inside the existing pipeline."""
    host, pid, start = "local", None, None
    if finding.process_key:
        try:
            host, pid, start = json.loads(finding.process_key)
        except (ValueError, TypeError):
            host, pid, start = "local", None, None
    remote = finding.evidence.get("remote")
    return Event(
        event_id=f"finding:{finding.finding_id}:{finding.revision}",
        timestamp=finding.detected_at,
        event_type=EventType.SECURITY_FINDING,
        pid=pid,
        process_name=finding.process_name,
        process_start_time=start,
        host_id=host,
        file_path=finding.resource if finding.resource.startswith("/") else None,
        network_destination=remote if isinstance(remote, str) else None,
        source=f"security:{finding.module}",
        metadata={
            "finding_id": finding.finding_id,
            "module": finding.module,
            "rule_id": finding.rule_id,
            "revision": finding.revision,
            "attribution": finding.attribution,
        },
    )
