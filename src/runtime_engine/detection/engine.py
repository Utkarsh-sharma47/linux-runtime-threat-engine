"""Evaluate AND conditions and produce evidence-linked, explainable alerts."""

from runtime_engine.detection.rule_loader import Rule
from runtime_engine.detection.rules import matches
from runtime_engine.events.schema import Alert, Event
from runtime_engine.process.ancestry import AncestryTracker


class DetectionEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def evaluate(self, event: Event, ancestry: AncestryTracker) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if not rule.enabled or rule.event_type != event.event_type:
                continue
            evidence: list[str] = []
            for condition in rule.conditions:
                value = (
                    ancestry.parent_name(event)
                    if condition.field == "parent_process_name"
                    else getattr(event, condition.field)
                )
                if not matches(value, condition):
                    break
                evidence.append(f"{condition.field}={value!r} {condition.op} {condition.value!r}")
            else:
                alerts.append(
                    Alert(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        mitre_reference=rule.mitre_reference,
                        severity=rule.severity,
                        reason="; ".join(evidence),
                        event_ids=[event.event_id],
                        process_key=event.process_key,
                        resource=event.file_path
                        or event.network_destination
                        or event.executable_path,
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                    )
                )
        return alerts
