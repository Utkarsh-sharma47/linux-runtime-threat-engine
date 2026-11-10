"""Conservative event-time correlation and per-rule/process/resource deduplication."""

from datetime import timedelta

from runtime_engine.events.schema import Alert, Event, Incident
from runtime_engine.process.ancestry import AncestryTracker


class CorrelationEngine:
    """Correlation is per engine session. Prior persisted incidents remain immutable.

    Incidents have a bounded total event-time span, not a sliding window that can grow
    forever. No identity means no cross-event merge. Resource and rule IDs key alert
    deduplication; temporal proximity or a shared file alone never links processes.
    """

    def __init__(
        self, ancestry: AncestryTracker, window_seconds: float = 120, first_number: int = 1
    ) -> None:
        self.ancestry = ancestry
        self.window = timedelta(seconds=window_seconds)
        self.incidents: list[Incident] = []
        self.alerts: dict[str, Alert] = {}
        self.next_number = first_number
        self.duplicates = 0

    def add(self, alert: Alert, event: Event) -> Incident:
        candidates: list[Incident] = []
        for incident in self.incidents:
            # Multiple rules on the exact same event are related even without process identity.
            if event.event_id in incident.event_ids:
                candidates.append(incident)
                continue
            span = max(incident.last_seen, event.timestamp) - min(
                incident.first_seen, event.timestamp
            )
            if span > self.window or alert.process_key is None:
                continue
            if any(self.ancestry.related(alert.process_key, key) for key in incident.process_keys):
                candidates.append(incident)
        # Stable earliest-created choice if late evidence links two existing incidents.
        # We do not silently merge already-created incidents.
        incident = (
            candidates[0]
            if candidates
            else Incident(
                incident_id=f"INC-{self.next_number:04d}",
                severity=alert.severity,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
        )
        if not candidates:
            self.incidents.append(incident)
            self.next_number += 1
        prior = next(
            (
                self.alerts[a]
                for a in incident.alert_ids
                if self.alerts[a].rule_id == alert.rule_id
                and self.alerts[a].process_key is not None
                and self.alerts[a].process_key == alert.process_key
                and self.alerts[a].resource == alert.resource
            ),
            None,
        )
        if prior:
            self.duplicates += 1
            if event.event_id not in prior.event_ids:
                prior.event_ids.append(event.event_id)
            prior.first_seen = min(prior.first_seen, event.timestamp)
            prior.last_seen = max(prior.last_seen, event.timestamp)
        else:
            self.alerts[alert.alert_id] = alert
            incident.alert_ids.append(alert.alert_id)
        incident.first_seen = min(incident.first_seen, event.timestamp)
        incident.last_seen = max(incident.last_seen, event.timestamp)
        if alert.severity.rank > incident.severity.rank:
            incident.severity = alert.severity
        if event.event_id not in incident.event_ids:
            incident.event_ids.append(event.event_id)
        if alert.rule_id not in incident.rule_ids:
            incident.rule_ids.append(alert.rule_id)
        if alert.process_key and alert.process_key not in incident.process_keys:
            incident.process_keys.append(alert.process_key)
        incident.context_process_keys = list(
            dict.fromkeys(
                ancestor for key in incident.process_keys for ancestor in self.ancestry.lineage(key)
            )
        )
        incident.ancestry = [self.ancestry.tree(key) for key in incident.process_keys]
        return incident
