"""Validated telemetry and detection data. Missing evidence stays missing."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(StrEnum):
    PROCESS_START = "PROCESS_START"
    PROCESS_EXIT = "PROCESS_EXIT"
    FILE_ACCESS = "FILE_ACCESS"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Event(BaseModel):
    """Normalized event. Start identity is opaque and source-scoped, not a guessed time."""

    model_config = ConfigDict(extra="forbid", strict=False)
    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    timestamp: datetime
    event_type: EventType
    pid: int | None = Field(default=None, ge=1, strict=True)
    ppid: int | None = Field(default=None, ge=0, strict=True)
    process_name: str | None = None
    executable_path: str | None = None
    command_line: list[str] | None = None
    uid: int | None = Field(default=None, ge=0, strict=True)
    process_start_time: str | None = Field(default=None, min_length=1)
    parent_start_time: str | None = Field(default=None, min_length=1)
    host_id: str = Field(default="replay", min_length=1)
    parent_process_name: str | None = None
    file_path: str | None = None
    network_destination: str | None = None
    previous_uid: int | None = Field(default=None, ge=0, strict=True)
    source: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include an explicit timezone")
        return value.astimezone(UTC)

    @property
    def process_key(self) -> str | None:
        if self.pid is None or self.process_start_time is None:
            return None
        # JSON encoding avoids ambiguous separator collisions in source-provided tokens.
        import json

        return json.dumps([self.host_id, self.pid, self.process_start_time], separators=(",", ":"))


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    rule_name: str
    mitre_reference: str | None = None
    severity: Severity
    reason: str
    event_ids: list[str]
    process_key: str | None
    resource: str | None = None
    first_seen: datetime
    last_seen: datetime


class Incident(BaseModel):
    incident_id: str
    title: str = "Suspicious runtime activity requires review"
    severity: Severity
    status: str = "OPEN"
    first_seen: datetime
    last_seen: datetime
    process_keys: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    context_process_keys: list[str] = Field(default_factory=list)
    ancestry: list[str] = Field(default_factory=list)
    explanation: str = (
        "Rule matches linked by process identity or verified ancestor relationships within "
        "the configured time window. Matches are indicators, not proof of compromise."
    )

    @property
    def event_count(self) -> int:
        return len(self.event_ids)
