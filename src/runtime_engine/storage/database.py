"""Parameterized SQLite persistence. Every processed event is one atomic transaction.

One connection is shared by the pipeline thread and the terminal thread; every access is
serialized through `lock`, so the connection is opened without the same-thread check.
"""

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from runtime_engine.events.schema import Alert, Event, Incident

if TYPE_CHECKING:
    from runtime_engine.security.findings import Finding


class Database:
    def __init__(self, path: str | Path) -> None:
        if str(path) != ":memory:":
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
            except FileExistsError:
                pass  # preserve existing evidence and its permissions
        self.path = str(path)
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, body TEXT NOT NULL, process_key TEXT);
            CREATE INDEX IF NOT EXISTS events_process ON events(process_key);
            CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incident_events (
                incident_id TEXT REFERENCES incidents(id),
                event_id TEXT REFERENCES events(id),
                PRIMARY KEY (incident_id, event_id));
            CREATE TABLE IF NOT EXISTS metric_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS monitor_sessions (
                id TEXT PRIMARY KEY, started_at TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_findings (
                id TEXT PRIMARY KEY, module TEXT NOT NULL, rule_id TEXT NOT NULL,
                severity TEXT NOT NULL, resource TEXT NOT NULL, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, revision TEXT NOT NULL,
                occurrences INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS security_findings_module
                ON security_findings(module, last_seen);
            CREATE TABLE IF NOT EXISTS security_baselines (
                module TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL,
                body TEXT NOT NULL, PRIMARY KEY (module, name));
            CREATE TABLE IF NOT EXISTS atomic_sessions (
                id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT,
                status TEXT NOT NULL, synthetic INTEGER NOT NULL, body TEXT NOT NULL,
                evaluation TEXT);
        """)

    def event(self, event_id: str) -> Event | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body FROM events WHERE id=?", (event_id,)
            ).fetchone()
        return Event.model_validate_json(row[0]) if row else None

    def next_incident_number(self) -> int:
        with self.lock:
            ids = self.connection.execute("SELECT id FROM incidents").fetchall()
        return max((int(row[0].removeprefix("INC-")) for row in ids), default=0) + 1

    def save(
        self,
        event: Event,
        incidents: list[Incident],
        alerts: list[Alert],
        finding: "Finding | None" = None,
    ) -> None:
        """Save the event, affected reports and evidence relationships atomically."""
        with self.lock, self.connection:
            if finding is not None:
                self._upsert_finding(finding)
            self.connection.execute(
                "INSERT INTO events VALUES (?, ?, ?)",
                (event.event_id, event.model_dump_json(), event.process_key),
            )
            for alert in alerts:
                self.connection.execute(
                    "INSERT INTO alerts VALUES (?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                    (alert.alert_id, alert.model_dump_json()),
                )
            for incident in incidents:
                self.connection.execute(
                    "INSERT INTO incidents VALUES (?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                    (incident.incident_id, incident.model_dump_json()),
                )
                self.connection.executemany(
                    "INSERT OR IGNORE INTO incident_events VALUES (?, ?)",
                    [(incident.incident_id, e) for e in incident.event_ids],
                )

    def incidents(self) -> list[Incident]:
        with self.lock:
            rows = self.connection.execute("SELECT body FROM incidents ORDER BY id").fetchall()
        return [Incident.model_validate_json(row[0]) for row in rows]

    def incident(self, incident_id: str) -> Incident | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body FROM incidents WHERE id=?", (incident_id,)
            ).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def evidence(self, incident_id: str) -> list[Event]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT e.body FROM events e JOIN incident_events ie ON e.id=ie.event_id "
                "WHERE ie.incident_id=?",
                (incident_id,),
            ).fetchall()
        return sorted(
            (Event.model_validate_json(row[0]) for row in rows), key=lambda e: e.timestamp
        )

    def process_events(self, keys: list[str]) -> list[Event]:
        """Fetch observed lineage context, with identifiers passed only as parameters."""
        result: dict[str, Event] = {}
        with self.lock:
            for key in keys:
                for row in self.connection.execute(
                    "SELECT body FROM events WHERE process_key=?", (key,)
                ).fetchall():
                    event = Event.model_validate_json(row[0])
                    result[event.event_id] = event
        return sorted(result.values(), key=lambda e: e.timestamp)

    def alerts(self, ids: list[str]) -> list[Alert]:
        result: list[Alert] = []
        with self.lock:
            for alert_id in ids:
                row = self.connection.execute(
                    "SELECT body FROM alerts WHERE id=?", (alert_id,)
                ).fetchone()
                if row:
                    result.append(Alert.model_validate_json(row[0]))
        return result

    def all_alerts(self) -> list[Alert]:
        with self.lock:
            rows = self.connection.execute("SELECT body FROM alerts ORDER BY rowid").fetchall()
        return [Alert.model_validate_json(row[0]) for row in rows]

    def recent_events(
        self,
        limit: int,
        *,
        pid: int | None = None,
        event_type: str | None = None,
        process_name: str | None = None,
    ) -> list[Event]:
        """Most recently stored events first (insertion order), filtered in SQL."""
        clauses: list[str] = []
        params: list[object] = []
        for path, value in (
            ("$.pid", pid),
            ("$.event_type", event_type),
            ("$.process_name", process_name),
        ):
            if value is not None:
                clauses.append(f"json_extract(body, '{path}') = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self.lock:
            rows = self.connection.execute(
                f"SELECT body FROM events {where}ORDER BY rowid DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [Event.model_validate_json(row[0]) for row in rows]

    def child_events(self, host_id: str, pid: int, start_time: str) -> list[Event]:
        """Events whose explicit parent identity is the given process identity."""
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM events WHERE json_extract(body, '$.host_id') = ? "
                "AND json_extract(body, '$.ppid') = ? "
                "AND json_extract(body, '$.parent_start_time') = ?",
                (host_id, pid, start_time),
            ).fetchall()
        return sorted(
            (Event.model_validate_json(row[0]) for row in rows), key=lambda e: e.timestamp
        )

    def alerts_for_process(self, key: str) -> list[Alert]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM alerts WHERE json_extract(body, '$.process_key') = ? "
                "ORDER BY rowid",
                (key,),
            ).fetchall()
        return [Alert.model_validate_json(row[0]) for row in rows]

    def save_metrics(self, metrics: dict[str, int | float]) -> None:
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT INTO metric_sessions(body) VALUES (?)", (json.dumps(metrics),)
            )

    def metrics(self) -> list[dict[str, Any]]:
        """Return recorded sessions, oldest first, without misleadingly averaging averages."""
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM metric_sessions ORDER BY id"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_session(self, summary: dict[str, Any]) -> None:
        """Insert or replace one monitoring session summary (written at start and at stop)."""
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT INTO monitor_sessions VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                (summary["session_id"], summary["started_at"], json.dumps(summary)),
            )

    def sessions(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT body FROM monitor_sessions ORDER BY started_at, rowid"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def session(self, session_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body FROM monitor_sessions WHERE id=?", (session_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    # ----- security module findings and baselines -----

    def _upsert_finding(self, finding: "Finding") -> bool:
        """Insert or refresh; True when the finding is new or its evidence changed."""
        row = self.connection.execute(
            "SELECT revision FROM security_findings WHERE id=?", (finding.finding_id,)
        ).fetchone()
        seen = finding.detected_at.isoformat()
        if row is None:
            self.connection.execute(
                "INSERT INTO security_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                (
                    finding.finding_id,
                    finding.module,
                    finding.rule_id,
                    finding.severity.value,
                    finding.resource,
                    seen,
                    seen,
                    finding.revision,
                    finding.model_dump_json(),
                ),
            )
            return True
        self.connection.execute(
            "UPDATE security_findings SET severity=?, last_seen=?, revision=?, "
            "occurrences=occurrences+1, body=? WHERE id=?",
            (
                finding.severity.value,
                seen,
                finding.revision,
                finding.model_dump_json(),
                finding.finding_id,
            ),
        )
        return bool(row[0] != finding.revision)

    def save_finding(self, finding: "Finding") -> bool:
        with self.lock, self.connection:
            return self._upsert_finding(finding)

    def findings(
        self,
        module: str | None = None,
        *,
        rule_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Newest first. Each dict is the finding plus first_seen/last_seen/occurrences."""
        clauses, params = [], []
        if module:
            clauses.append("module = ?")
            params.append(module)
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self.lock:
            rows = self.connection.execute(
                "SELECT body, first_seen, last_seen, occurrences FROM security_findings "
                f"{where}ORDER BY last_seen DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [
            json.loads(body) | {"first_seen": first, "last_seen": last, "occurrences": count}
            for body, first, last, count in rows
        ]

    def finding(self, finding_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body, first_seen, last_seen, occurrences FROM security_findings WHERE id=?",
                (finding_id,),
            ).fetchone()
        if row is None:
            return None
        body: dict[str, Any] = json.loads(row[0])
        return body | {"first_seen": row[1], "last_seen": row[2], "occurrences": row[3]}

    def save_baseline(self, module: str, name: str, body: dict[str, Any]) -> None:
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT INTO security_baselines VALUES (?, ?, ?, ?) "
                "ON CONFLICT(module, name) DO UPDATE SET created_at=excluded.created_at, "
                "body=excluded.body",
                (module, name, body.get("created_at", ""), json.dumps(body)),
            )

    def baseline(self, module: str, name: str = "default") -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body FROM security_baselines WHERE module=? AND name=?", (module, name)
            ).fetchone()
        if row is None:
            return None
        body: dict[str, Any] = json.loads(row[0])
        return body

    def save_atomic_session(
        self, body: dict[str, Any], *, evaluation: dict[str, Any] | None = None
    ) -> None:
        """Upsert a live Atomic execution session (and optional evaluation report)."""
        with self.lock, self.connection:
            existing = self.connection.execute(
                "SELECT evaluation FROM atomic_sessions WHERE id=?", (body["run_id"],)
            ).fetchone()
            kept = evaluation
            if kept is None and existing is not None and existing[0]:
                kept = json.loads(existing[0])
            self.connection.execute(
                "INSERT INTO atomic_sessions VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET ended_at=excluded.ended_at, "
                "status=excluded.status, synthetic=excluded.synthetic, body=excluded.body, "
                "evaluation=COALESCE(excluded.evaluation, atomic_sessions.evaluation)",
                (
                    body["run_id"],
                    body.get("started_at") or "",
                    body.get("ended_at"),
                    body.get("status") or "REGISTERED",
                    1 if body.get("synthetic") else 0,
                    json.dumps(body),
                    json.dumps(kept) if kept is not None else None,
                ),
            )

    def atomic_session(self, run_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT body, evaluation FROM atomic_sessions WHERE id=?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        body: dict[str, Any] = json.loads(row[0])
        if row[1]:
            body["evaluation"] = json.loads(row[1])
        return body

    def atomic_sessions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT body, evaluation FROM atomic_sessions "
                "ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for body, evaluation in rows:
            item: dict[str, Any] = json.loads(body)
            if evaluation:
                item["evaluation"] = json.loads(evaluation)
            result.append(item)
        return result

    def close(self) -> None:
        with self.lock:
            self.connection.close()
