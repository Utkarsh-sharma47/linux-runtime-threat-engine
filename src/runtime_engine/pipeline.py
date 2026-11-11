"""Compose normalization, ancestry, detection, correlation and transactional storage."""

from dataclasses import dataclass, field
from time import perf_counter
from typing import Literal

from runtime_engine.correlation.engine import CorrelationEngine
from runtime_engine.detection.engine import DetectionEngine
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Alert, Event, Incident
from runtime_engine.metrics.collector import Metrics
from runtime_engine.process.ancestry import AncestryTracker
from runtime_engine.storage.database import Database


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
        self.database.save(event, list(affected.values()), alerts)
        self.metrics.total_events_processed += 1
        self.metrics.total_alerts_generated += len(detections)
        self.metrics.total_incidents_created = len(self.correlation.incidents)
        self.metrics.duplicate_alerts_suppressed = self.correlation.duplicates
        elapsed = perf_counter() - start
        self.metrics.observe(elapsed)
        return ProcessResult(
            event, "processed", elapsed, outcomes, list(affected.values()), alerts, created
        )
