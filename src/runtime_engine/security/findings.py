"""Findings, scan reports and the severity/allowlist policy shared by all security modules.

A finding is evidence that something changed or looks risky. It is not a verdict: the
severity policy decides which findings are promoted into incident correlation, and the
allowlist suppresses expected resources. Coverage records what a scan could NOT see, so
missing telemetry is never reported as a clean result.
"""

import fnmatch
import hashlib
import json
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from runtime_engine.events.schema import Severity

MODULES = ("persistence", "network", "anomaly", "integrity", "exposure", "ransomware")
RULE_PREFIX = re.compile(r"^([A-Z]{2,3}\d{3}):")


def stable_id(module: str, rule_id: str, resource: str) -> str:
    """Same module, rule and resource always map to the same finding ID."""
    digest = hashlib.sha256(json.dumps([module, rule_id, resource]).encode()).hexdigest()
    return f"{module[:3].upper()}-{digest[:12]}"


def revision_of(evidence: dict[str, Any]) -> str:
    """Fingerprint of the evidence; a new revision means the finding changed."""
    text = json.dumps(evidence, sort_keys=True, default=str)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    module: str
    rule_id: str
    title: str
    severity: Severity
    resource: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    remediation: str | None = None
    risk_score: float | None = None
    mitre_reference: str | None = None
    attribution: str = "unavailable"
    process_key: str | None = None
    pid: int | None = None
    process_name: str | None = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    revision: str = ""
    promoted: bool = False

    @classmethod
    def create(cls, module: str, rule_id: str, resource: str, **values: Any) -> "Finding":
        finding = cls(
            finding_id=stable_id(module, rule_id, resource),
            module=module,
            rule_id=rule_id,
            resource=resource,
            **values,
        )
        finding.revision = revision_of(finding.evidence)
        return finding


class SeverityPolicy:
    """Per-rule severity overrides, resource allowlist and the promotion threshold."""

    def __init__(
        self,
        promote_min: Severity = Severity.MEDIUM,
        overrides: dict[str, Severity] | None = None,
        allow: list[str] | None = None,
    ) -> None:
        self.promote_min = promote_min
        self.overrides = overrides or {}
        self.allow = allow or []

    def allowed(self, finding: Finding) -> bool:
        """Allowlist entries are `glob` (any rule) or `RULE:glob`, e.g. `PM001:/etc/x/*`."""
        for entry in self.allow:
            match = RULE_PREFIX.match(entry)
            rule, pattern = (match.group(1), entry[match.end() :]) if match else ("", entry)
            if (not rule or rule == finding.rule_id) and fnmatch.fnmatch(finding.resource, pattern):
                return True
        return False

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Returns (kept findings with policy applied, number suppressed by the allowlist)."""
        kept: list[Finding] = []
        suppressed = 0
        for finding in findings:
            if self.allowed(finding):
                suppressed += 1
                continue
            finding.severity = self.overrides.get(finding.rule_id, finding.severity)
            finding.promoted = finding.severity.rank >= self.promote_min.rank
            kept.append(finding)
        return kept, suppressed


@dataclass
class Coverage:
    """What a scan looked at, and what it could not see (never reported as 'clean')."""

    checked: int = 0
    denied: list[str] = field(default_factory=list)
    denied_count: int = 0
    unavailable: list[str] = field(default_factory=list)

    def deny(self, path: str, limit: int = 50) -> None:
        self.denied_count += 1
        if len(self.denied) < limit:
            self.denied.append(path)

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "denied_count": self.denied_count,
            "denied_examples": list(self.denied),
            "unavailable": list(self.unavailable),
        }


@dataclass
class ScanReport:
    module: str
    status: str  # ok, degraded, baseline-created, no-baseline, disabled, error
    started_at: datetime
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    summary: dict[str, Any] = field(default_factory=dict)
    suppressed: int = 0
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanReport":
        cov = data.get("coverage", {})
        return cls(
            data["module"],
            data["status"],
            datetime.fromisoformat(data["started_at"]),
            float(data.get("duration_seconds", 0)),
            [Finding.model_validate(f) for f in data.get("findings", [])],
            Coverage(
                cov.get("checked", 0),
                list(cov.get("denied_examples", [])),
                cov.get("denied_count", 0),
                list(cov.get("unavailable", [])),
            ),
            dict(data.get("summary", {})),
            int(data.get("suppressed_by_allowlist", 0)),
            data.get("error"),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 4),
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "coverage": self.coverage.as_dict(),
            "summary": self.summary,
            "suppressed_by_allowlist": self.suppressed,
            "error": self.error,
        }


class SecurityState:
    """Latest report per module plus a bounded list of recent findings, for display.

    Written by module threads and the pipeline thread, read by the terminal; the
    dashboard reads cached reports and never triggers a scan.
    """

    def __init__(self, finding_capacity: int = 2000) -> None:
        self.lock = threading.Lock()
        self.reports: dict[str, ScanReport] = {}
        self.enabled: dict[str, str] = {}  # module -> "enabled" or reason it is off
        self.findings: deque[Finding] = deque(maxlen=finding_capacity)
        self.scans: dict[str, int] = {}
        self.extra: dict[str, Any] = {}  # module-specific cached views (e.g. connections)

    def set_enabled(self, module: str, status: str) -> None:
        with self.lock:
            self.enabled[module] = status

    def record_report(self, report: ScanReport) -> None:
        with self.lock:
            self.reports[report.module] = report
            self.scans[report.module] = self.scans.get(report.module, 0) + 1

    def record_finding(self, finding: Finding) -> None:
        with self.lock:
            self.findings.append(finding)

    def put_extra(self, key: str, value: Any) -> None:
        with self.lock:
            self.extra[key] = value

    def get_extra(self, key: str) -> Any:
        with self.lock:
            return self.extra.get(key)

    def report(self, module: str) -> ScanReport | None:
        with self.lock:
            return self.reports.get(module)

    def recent(self, module: str | None = None, limit: int = 200) -> list[Finding]:
        with self.lock:
            items = [f for f in self.findings if module is None or f.module == module]
        latest: dict[str, Finding] = {}
        for finding in items:
            latest[finding.finding_id] = finding
        return list(latest.values())[-limit:]

    def overview(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            result: dict[str, dict[str, Any]] = {}
            for module in MODULES:
                report = self.reports.get(module)
                result[module] = {
                    "enabled": self.enabled.get(module, "not configured"),
                    "status": report.status if report else None,
                    "last_scan": report.started_at if report else None,
                    "findings": len({f.finding_id for f in self.findings if f.module == module}),
                    "scans": self.scans.get(module, 0),
                }
            return result
