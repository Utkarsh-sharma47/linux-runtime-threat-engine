"""Compose normalization, ancestry, detection, correlation and transactional storage."""

from time import perf_counter

from runtime_engine.correlation.engine import CorrelationEngine
from runtime_engine.detection.engine import DetectionEngine
from runtime_engine.detection.rule_loader import Rule
from runtime_engine.events.schema import Event
from runtime_engine.metrics.collector import Metrics
from runtime_engine.process.ancestry import AncestryTracker
from runtime_engine.storage.database import Database


class Pipeline:
    def __init__(self, database: Database, rules: list[Rule], window_seconds: float = 120) -> None:
        self.database = database
        self.ancestry = AncestryTracker()
        self.detection = DetectionEngine(rules)
        self.correlation = CorrelationEngine(
            self.ancestry, window_seconds, database.next_incident_number()
        )
        self.metrics = Metrics()

    def process(self, event: Event) -> None:
        """Process one already-validated event. Storage failure aborts the run."""
        start = perf_counter()
        existing = self.database.event(event.event_id)
        if existing:
            if existing == event:
                self.metrics.duplicate_events_suppressed += 1
            else:
                self.metrics.events_rejected += 1  # ID collision must not replace evidence
            return
        self.ancestry.observe(event)
        detections = self.detection.evaluate(event, self.ancestry)
        affected = {}
        for alert in detections:
            incident = self.correlation.add(alert, event)
            affected[incident.incident_id] = incident
        self.database.save(
            event,
            list(affected.values()),
            [self.correlation.alerts[a] for i in affected.values() for a in i.alert_ids],
        )
        self.metrics.total_events_processed += 1
        self.metrics.total_alerts_generated += len(detections)
        self.metrics.total_incidents_created = len(self.correlation.incidents)
        self.metrics.duplicate_alerts_suppressed = self.correlation.duplicates
        self.metrics.observe(perf_counter() - start)
