"""Human and JSON renderers. Escape untrusted text to prevent ANSI control injection."""

import json
from typing import Any


def safe(value: object) -> str:
    """Represent external text without emitting terminal control characters."""
    return json.dumps(value, ensure_ascii=True)


def terminal(report: dict[str, Any]) -> str:
    """Summarize the incident, followed by full original normalized evidence."""
    lines = [
        f"INCIDENT: {report['incident_id']}",
        f"SEVERITY: {report['severity']}",
        f"STATUS: {report['status']}",
        f"SUMMARY: {report['title']}",
        f"OBSERVED: {report['first_seen']} to {report['last_seen']}",
        f"EVENTS: {report['event_count']}",
        "",
        "WHY:",
        report["explanation"],
        "",
        "TIMELINE:",
    ]
    for event in report["evidence_timeline"]:
        lines.append(
            f"  {event['timestamp']} {safe(event['event_type'])} "
            f"PID {safe(event['pid'])} source={safe(event['source'])}"
        )
    lines += ["", "DETECTIONS:"]
    for alert in report["detections"]:
        lines.append(
            f"  {safe(alert['rule_id'])} {safe(alert['rule_name'])}: {safe(alert['reason'])}"
        )
    lines += ["", "ANCESTRY (root to leaf):"]
    for tree in report["ancestry"]:
        # Keep formatting newlines we generated, while escaping each external-text line.
        lines.extend("  " + safe(line) for line in tree.split("\n"))
    lines += ["", "FULL NORMALIZED EVIDENCE:", export_json(report)]
    # Fields above are constrained internal IDs/enums/static summaries except title/explanation;
    # generator uses fixed internal defaults for those values.
    return "\n".join(lines)


def export_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"
