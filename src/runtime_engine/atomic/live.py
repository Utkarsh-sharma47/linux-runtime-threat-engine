"""Live Atomic execution sessions: feed evidence into a running MonitorSession.

This is the bridge the offline runner deliberately omitted. Events are normalized into
the existing Event schema, submitted through MonitorSession.submit_event, and processed
by the shared Pipeline (rules, correlation, SQLite). Security modules continue via the
existing SecurityScheduler; they are not reimplemented here.

Attribution is by stable process_key (and explicit event_id membership). Wall-clock
overlap alone never associates an unrelated event with an Atomic session.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from runtime_engine.atomic.analysis import (
    EXECUTION_FAILED,
    LABELS,
    Component,
    grade_component,
    overall,
)
from runtime_engine.atomic.profiles import COMPONENTS, ModuleExpectation, Profile
from runtime_engine.events.normalizer import normalize
from runtime_engine.events.schema import Alert, Event, EventType, Incident
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.security.findings import Finding
from runtime_engine.storage.database import Database

SCHEMA = "rte-atomic-live-session/1"


@dataclass
class AtomicExecutionSession:
    """Persistent record of one Atomic (or synthetic) execution observed by the monitor."""

    run_id: str
    technique: str
    test_number: int
    guid: str
    name: str
    status: str  # REGISTERED, RUNNING, COMPLETED, FAILED, SYNTHETIC
    synthetic: bool
    started_at: datetime
    ended_at: datetime | None = None
    process_keys: set[str] = field(default_factory=set)
    event_ids: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    incident_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    collectors: dict[str, str] = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "technique": self.technique,
            "test_number": self.test_number,
            "guid": self.guid,
            "name": self.name,
            "status": self.status,
            "synthetic": self.synthetic,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "process_keys": sorted(self.process_keys),
            "event_ids": list(self.event_ids),
            "alert_ids": list(self.alert_ids),
            "incident_ids": list(self.incident_ids),
            "finding_ids": list(self.finding_ids),
            "metadata": self.metadata,
            "collectors": self.collectors,
            "note": self.note,
            "live_monitor_used": True,
        }


class LiveAtomicBridge:
    """Register Atomic sessions and ingest evidence into a live MonitorSession."""

    def __init__(self, session: MonitorSession, database: Database) -> None:
        self.session = session
        self.database = database
        self.state = session.state
        self._lock = threading.Lock()
        self._sessions: dict[str, AtomicExecutionSession] = {}

    def sessions(self) -> list[AtomicExecutionSession]:
        with self._lock:
            return list(self._sessions.values())

    def get(self, run_id: str) -> AtomicExecutionSession | None:
        with self._lock:
            return self._sessions.get(run_id)

    def verify_collectors(self) -> dict[str, str]:
        """Report which live collectors / modules are available (do not start a second engine)."""
        status: dict[str, str] = {
            "proc_collector": "active" if self.session.collector is not None else "missing",
            "pipeline": "active",
            "security_scheduler": "active" if self.session.scheduler is not None else "disabled",
        }
        overview = self.state.security.overview()
        for module, entry in overview.items():
            enabled = entry.get("enabled", "not configured")
            status[f"module:{module}"] = (
                "enabled" if enabled == "enabled" else f"off ({enabled})"
            )
        return status

    def register(
        self,
        *,
        technique: str,
        test_number: int,
        guid: str,
        name: str,
        synthetic: bool = False,
        run_id: str | None = None,
        note: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AtomicExecutionSession:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        label = "synthetic" if synthetic else "atomic"
        run_id = run_id or f"{label}-{stamp}-{technique}-{test_number}-{guid[:8]}"
        collectors = self.verify_collectors()
        record = AtomicExecutionSession(
            run_id=run_id,
            technique=technique,
            test_number=test_number,
            guid=guid,
            name=name,
            status="SYNTHETIC" if synthetic else "REGISTERED",
            synthetic=synthetic,
            started_at=datetime.now(UTC),
            collectors=collectors,
            note=note
            or (
                "SYNTHETIC evidence: not real host Atomic activity"
                if synthetic
                else "Live Atomic execution session"
            ),
            metadata=dict(metadata or {}),
        )
        with self._lock:
            if run_id in self._sessions:
                raise ValueError(f"Atomic session {run_id} already registered")
            self._sessions[run_id] = record
        self.database.save_atomic_session(record.as_dict())
        self.state.upsert_atomic_session(record.as_dict())
        self.state.record_lifecycle(
            "ATOMIC_SESSION_REGISTERED",
            [
                ("RUN", run_id),
                ("TECHNIQUE", technique),
                ("SYNTHETIC", synthetic),
                ("COLLECTORS", ",".join(f"{k}={v}" for k, v in collectors.items() if ":" not in k)),
            ],
        )
        return record

    def mark_running(self, run_id: str) -> AtomicExecutionSession:
        record = self._require(run_id)
        if record.synthetic:
            record.status = "SYNTHETIC"
        else:
            record.status = "RUNNING"
        self._persist(record)
        return record

    def ingest(
        self,
        run_id: str,
        raw_events: Sequence[dict[str, Any] | Event],
        *,
        wait: bool = True,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Normalize and submit events to the live pipeline. Tags Atomic + synthetic metadata."""
        record = self._require(run_id)
        if record.status == "REGISTERED":
            self.mark_running(run_id)
        before = self.state.counters.processed
        accepted = 0
        rejected = 0
        for item in raw_events:
            event = item if isinstance(item, Event) else normalize(dict(item))
            meta = dict(event.metadata)
            meta["atomic_run_id"] = run_id
            meta["atomic_technique"] = record.technique
            meta["atomic_guid"] = record.guid
            if record.synthetic:
                meta["synthetic"] = True
                meta["evidence_label"] = "SYNTHETIC"
                meta.setdefault(
                    "synthetic_note",
                    "Synthetic acceptance evidence; not real host Atomic activity",
                )
            event = event.model_copy(update={"metadata": meta})
            if not self.session.submit_event(event):
                rejected += 1
                continue
            accepted += 1
            with self._lock:
                record.event_ids.append(event.event_id)
                if event.process_key:
                    record.process_keys.add(event.process_key)
        if wait and accepted:
            self._wait_processed(before + accepted, timeout=timeout)
        self.correlate(run_id)
        self._persist(record)
        return {
            "run_id": run_id,
            "accepted": accepted,
            "rejected": rejected,
            "process_keys": sorted(record.process_keys),
            "processed": self.state.counters.processed,
        }

    def correlate(self, run_id: str) -> dict[str, Any]:
        """Link alerts, incidents and findings that share process_key or event_id with the session.

        Time-window-only matches are never used.
        """
        record = self._require(run_id)
        keys = set(record.process_keys)
        event_ids = set(record.event_ids)
        alerts: list[Alert] = []
        incidents: list[Incident] = []
        findings: list[Finding] = []
        with self.state.lock:
            for alert in self.state.alerts.values():
                if (alert.process_key and alert.process_key in keys) or event_ids.intersection(
                    alert.event_ids
                ):
                    alerts.append(alert)
            for incident in self.state.incidents.values():
                shared_keys = keys.intersection(incident.process_keys)
                shared_events = event_ids.intersection(incident.event_ids)
                if shared_keys or shared_events:
                    incidents.append(incident)
        for finding in self.state.security.recent():
            if finding.process_key and finding.process_key in keys:
                findings.append(finding)
            elif finding.evidence.get("atomic_run_id") == run_id:
                findings.append(finding)
        with self._lock:
            record.alert_ids = [a.alert_id for a in alerts]
            record.incident_ids = [i.incident_id for i in incidents]
            record.finding_ids = [f.finding_id for f in findings]
        self._persist(record)
        return {
            "alerts": [a.model_dump(mode="json") for a in alerts],
            "incidents": [i.model_dump(mode="json") for i in incidents],
            "findings": [f.model_dump(mode="json") for f in findings],
            "process_keys": sorted(keys),
            "event_ids": list(record.event_ids),
        }

    def finish(self, run_id: str, status: str = "COMPLETED") -> AtomicExecutionSession:
        record = self._require(run_id)
        self.correlate(run_id)
        record.status = status if not record.synthetic else "SYNTHETIC"
        record.ended_at = datetime.now(UTC)
        self._persist(record)
        self.state.record_lifecycle(
            "ATOMIC_SESSION_FINISHED",
            [
                ("RUN", run_id),
                ("STATUS", record.status),
                ("EVENTS", len(record.event_ids)),
                ("ALERTS", len(record.alert_ids)),
                ("INCIDENTS", len(record.incident_ids)),
            ],
        )
        return record

    def evaluate(
        self,
        run_id: str,
        profile: Profile | None,
        *,
        execution_status: str = "COMPLETED",
    ) -> dict[str, Any]:
        """Grade using the same component grades as offline analysis, from live correlations."""
        record = self._require(run_id)
        correlated = self.correlate(run_id)
        observed_rules = {
            a["rule_id"] for a in correlated["alerts"] if a.get("rule_id")
        }
        observed_findings = {
            f["rule_id"] for f in correlated["findings"] if f.get("rule_id")
        }
        event_types = {
            e.event.event_type.value
            for e in self.state.events
            if e.event.event_id in set(record.event_ids)
        }
        components: list[Component] = []
        for name in COMPONENTS:
            expectation: ModuleExpectation | None = None
            if profile is not None:
                expectation = profile.modules.get(name)
            if name == "rules":
                expected_set = set(profile.expected_rules) if profile else set()
                if profile is not None and "rules" not in profile.modules:
                    expectation = ModuleExpectation(rules=list(expected_set))
                observed = observed_rules
                telemetry = bool(event_types)
                behaviour = bool(event_types & {"PROCESS_START", "PROCESS_EXIT", "FILE_ACCESS",
                                                "NETWORK_CONNECTION", "PRIVILEGE_CHANGE"})
                gaps = [] if telemetry else ["no events attributed to this Atomic session"]
            else:
                observed = {r for r in observed_findings if r.startswith(_PREFIX.get(name, ""))}
                # Also accept exact rule ids listed in the profile for that module.
                if expectation is not None:
                    observed |= observed_findings.intersection(expectation.rules)
                telemetry = self._module_telemetry(name, event_types, record)
                behaviour = bool(observed) or self._module_behaviour(name, event_types, record)
                gaps = [] if telemetry else [f"{name} telemetry unavailable for this session"]
            grade, reasons = grade_component(
                expectation,
                observed,
                telemetry=telemetry,
                behaviour=behaviour,
                gaps=gaps,
            )
            components.append(
                Component(
                    name=name,
                    label=LABELS[name],
                    grade=grade,
                    reasons=reasons,
                    expected=list(expectation.rules) if expectation else None,
                    observed=sorted(observed),
                    telemetry=telemetry,
                    behaviour=behaviour,
                    gaps=gaps,
                    evidence=[
                        {"alert_id": a["alert_id"], "rule_id": a["rule_id"]}
                        for a in correlated["alerts"]
                        if a.get("rule_id") in observed
                    ]
                    + [
                        {"finding_id": f["finding_id"], "rule_id": f["rule_id"]}
                        for f in correlated["findings"]
                        if f.get("rule_id") in observed
                    ],
                )
            )
        if execution_status in ("COMPLETED", "SYNTHETIC"):
            execution = "COMPLETED"
        else:
            execution = execution_status
        if execution_status in ("FAILED", "TIMEOUT", "EXECUTION FAILED"):
            summary_grade, summary_reasons = EXECUTION_FAILED, [
                f"execution status was {execution_status}"
            ]
        else:
            summary_grade, summary_reasons = overall(components, execution, profile)
        evaluation = {
            "schema": "rte-atomic-evaluation/1",
            "run_id": run_id,
            "created_at": datetime.now(UTC).isoformat(),
            "live_monitor_used": True,
            "synthetic": record.synthetic,
            "evidence_label": "SYNTHETIC" if record.synthetic else "LIVE",
            "overall": {"grade": summary_grade, "reasons": summary_reasons},
            "components": [
                {
                    "name": c.name,
                    "label": c.label,
                    "grade": c.grade,
                    "reasons": c.reasons,
                    "expected": c.expected,
                    "observed": c.observed,
                    "telemetry": c.telemetry,
                    "behaviour": c.behaviour,
                    "evidence": c.evidence,
                    "gaps": c.gaps,
                }
                for c in components
            ],
            "session": record.as_dict(),
            "correlated": {
                "alerts": len(correlated["alerts"]),
                "incidents": len(correlated["incidents"]),
                "findings": len(correlated["findings"]),
            },
        }
        self.database.save_atomic_session(record.as_dict(), evaluation=evaluation)
        return evaluation

    def _module_telemetry(
        self, name: str, event_types: set[str], record: AtomicExecutionSession
    ) -> bool:
        overview = self.state.security.overview().get(name, {})
        if overview.get("enabled") != "enabled":
            return False
        if name == "network":
            return "NETWORK_CONNECTION" in event_types or bool(overview.get("scans"))
        if name == "anomaly":
            return "PROCESS_START" in event_types
        if name in ("persistence", "integrity", "exposure", "ransomware"):
            # Modules may scan host state independently; live path reports telemetry only
            # when the module is enabled and has scanned or relevant events exist.
            return bool(overview.get("scans")) or bool(event_types)
        return bool(event_types)

    def _module_behaviour(
        self, name: str, event_types: set[str], record: AtomicExecutionSession
    ) -> bool:
        if name == "network":
            return "NETWORK_CONNECTION" in event_types
        return bool(event_types)

    def _require(self, run_id: str) -> AtomicExecutionSession:
        with self._lock:
            record = self._sessions.get(run_id)
        if record is None:
            raise KeyError(f"unknown Atomic session {run_id}")
        return record

    def _persist(self, record: AtomicExecutionSession) -> None:
        self.database.save_atomic_session(record.as_dict())
        self.state.upsert_atomic_session(record.as_dict())

    def _wait_processed(self, target: int, *, timeout: float) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.session.stopping and self.session.abort.is_set():
                return False
            if self.state.counters.processed >= target and self.session.events.empty():
                return True
            time.sleep(0.01)
        return self.state.counters.processed >= target


_PREFIX = {
    "persistence": "PM",
    "network": "NB",
    "anomaly": "AN",
    "integrity": "FI",
    "exposure": "EX",
    "ransomware": "RW",
}


def synthetic_process_event(
    *,
    pid: int,
    name: str,
    exe: str,
    start: str,
    host_id: str = "synthetic-host",
    ppid: int | None = None,
    parent_name: str | None = None,
    parent_start: str | None = None,
    uid: int = 1000,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build a clearly labeled synthetic PROCESS_START observation."""
    return {
        "event_id": event_id or f"synthetic-proc-{uuid4()}",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": EventType.PROCESS_START.value,
        "pid": pid,
        "ppid": ppid,
        "process_name": name,
        "executable_path": exe,
        "command_line": [exe],
        "uid": uid,
        "process_start_time": start,
        "parent_start_time": parent_start,
        "parent_process_name": parent_name,
        "host_id": host_id,
        "source": "synthetic",
        "metadata": {
            "synthetic": True,
            "evidence_label": "SYNTHETIC",
            "synthetic_note": "Synthetic acceptance evidence; not real host Atomic activity",
        },
    }


def synthetic_network_event(
    *,
    pid: int,
    name: str,
    start: str,
    destination: str,
    local: str = "127.0.0.1:40000",
    protocol: str = "tcp",
    state: str = "ESTABLISHED",
    host_id: str = "synthetic-host",
    attribution: str = "unique",
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build a clearly labeled synthetic NETWORK_CONNECTION observation."""
    return {
        "event_id": event_id or f"synthetic-net-{uuid4()}",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": EventType.NETWORK_CONNECTION.value,
        "pid": pid,
        "process_name": name,
        "executable_path": f"/tmp/{name}",
        "uid": 1000,
        "process_start_time": start,
        "host_id": host_id,
        "network_destination": destination,
        "source": "synthetic",
        "metadata": {
            "synthetic": True,
            "evidence_label": "SYNTHETIC",
            "synthetic_note": "Synthetic acceptance evidence; not real host Atomic activity",
            "protocol": protocol,
            "local": local,
            "state": state,
            "attribution": attribution,
            "observation": "synthetic: not a /proc snapshot",
            "remote_port": int(destination.rsplit(":", 1)[-1]) if ":" in destination else None,
        },
    }


def session_for_process_key(
    sessions: Sequence[dict[str, Any]], process_key: str | None
) -> dict[str, Any] | None:
    if not process_key:
        return None
    for item in sessions:
        if process_key in item.get("process_keys", []):
            return item
    return None


__all__ = [
    "AtomicExecutionSession",
    "LiveAtomicBridge",
    "session_for_process_key",
    "synthetic_network_event",
    "synthetic_process_event",
]
