"""Build a report directly from persisted evidence, including full rule reasons."""

from typing import Any

from runtime_engine.storage.database import Database


def generate(database: Database, incident_id: str) -> dict[str, Any]:
    incident = database.incident(incident_id)
    if incident is None:
        raise KeyError(incident_id)
    events = database.evidence(incident_id)
    result = incident.model_dump(mode="json")
    result["event_count"] = incident.event_count
    result["supporting_events"] = [event.model_dump(mode="json") for event in events]
    result["context_events"] = [
        e.model_dump(mode="json")
        for e in database.process_events(incident.context_process_keys)
        if e.timestamp <= incident.last_seen and e.event_id not in incident.event_ids
    ]
    result["related_processes"] = [
        {
            "process_key": e.process_key,
            "pid": e.pid,
            "ppid": e.ppid,
            "process_name": e.process_name,
            "process_start_time": e.process_start_time,
        }
        for e in database.process_events(incident.context_process_keys)
        if e.event_type == "PROCESS_START" and e.timestamp <= incident.last_seen
    ]
    result["detections"] = [
        alert.model_dump(mode="json") for alert in database.alerts(incident.alert_ids)
    ]
    result["evidence_timeline"] = [
        {
            "timestamp": event.timestamp.isoformat(),
            "event_id": event.event_id,
            "event_type": event.event_type,
            "pid": event.pid,
            "source": event.source,
        }
        for event in events
    ]
    return result
