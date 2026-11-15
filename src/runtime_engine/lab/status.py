"""Lab simulation status written by the orchestrator and read by the live dashboard."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from runtime_engine.lab.paths import status_path, validate_under_lab_root

Provenance = Literal["REAL_HOST_TELEMETRY", "SYNTHETIC_LAB_FIXTURE", "ATOMIC_EXECUTION_EVIDENCE"]


@dataclass
class ScenarioResult:
    name: str
    status: str  # pending, running, completed, failed, skipped, dry-run
    started_at: str | None = None
    ended_at: str | None = None
    provenance: list[str] = field(default_factory=list)
    behavior: list[str] = field(default_factory=list)
    collectors: list[str] = field(default_factory=list)
    expected_rules: list[str] = field(default_factory=list)
    expected_modules: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    grade_hint: str | None = None  # NOT a forced detection — advisory only

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LabStatus:
    schema: str = "rte-security-lab-status/1"
    session_id: str = ""
    lab_dir: str = ""
    database: str = ""
    started_at: str = ""
    updated_at: str = ""
    current_scenario: str | None = None
    scenario_started_at: str | None = None
    phase: str = "idle"  # idle, running, completed, failed, interrupted
    scenarios: dict[str, dict[str, Any]] = field(default_factory=dict)
    events_hint: int = 0
    findings_hint: int = 0
    incidents_hint: int = 0
    active_processes: list[str] = field(default_factory=list)
    active_connections: list[str] = field(default_factory=list)
    collector_health: dict[str, str] = field(default_factory=dict)
    message: str = ""
    provenance_legend: dict[str, str] = field(
        default_factory=lambda: {
            "REAL_HOST_TELEMETRY": "Observed on this host by live collectors",
            "SYNTHETIC_LAB_FIXTURE": "Isolated under the lab temp root; not real persistence",
            "ATOMIC_EXECUTION_EVIDENCE": "From an approved Atomic Red Team execution session",
        }
    )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LabStatus:
        known = {item.name for item in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def write_status(status: LabStatus, path: Path | None = None) -> Path:
    target = path or status_path(Path(status.lab_dir) if status.lab_dir else None)
    if status.lab_dir:
        validate_under_lab_root(Path(status.lab_dir))
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(status.as_dict(), indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(prefix=".status-", dir=str(target.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def read_status(path: Path | None = None) -> LabStatus | None:
    target = path
    if target is None:
        env = os.environ.get("RTE_LAB_STATUS")
        if env:
            target = Path(env)
        else:
            try:
                target = status_path()
            except Exception:
                return None
    if target is None or not target.is_file():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return LabStatus.from_dict(data)


__all__ = [
    "LabStatus",
    "Provenance",
    "ScenarioResult",
    "now_iso",
    "read_status",
    "write_status",
]
