"""Persistence and privilege-escalation monitoring by metadata and content comparison.

The module records a baseline of security-sensitive locations and compares later scans:

  * systemd units, cron jobs, SSH authorized_keys and sudoers: added, removed, content
    changed (SHA-256), ownership/permission changed
  * SUID/SGID executables and file capabilities in privileged directories: newly
    privileged, privilege changed, binary changed
  * new executables in sensitive directories

Only metadata and digests are stored: never key material, password hashes or file
contents. authorized_keys is summarized as a digest and a key count. Polling cannot tell
which process made a change, so findings carry `attribution: unavailable` unless audit
or eBPF telemetry is added. A change is evidence for review, not proof of compromise.
"""

import fnmatch
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from runtime_engine.config.settings import PersistenceSettings
from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import Coverage, Finding, ScanReport, SeverityPolicy
from runtime_engine.security.fsutil import (
    FileHasher,
    FileMeta,
    dangerous,
    expand,
    file_capabilities,
    lstat,
    walk,
)

MODULE = "persistence"
UNIT_PATTERNS = ("*.service", "*.timer", "*.socket", "*.path", "*.target")

# rule id: (title, default severity, MITRE ATT&CK reference)
RULES: dict[str, tuple[str, Severity, str]] = {
    "PM001": ("systemd unit added or modified", Severity.MEDIUM, "T1543.002"),
    "PM002": ("Scheduled task (cron) added or modified", Severity.MEDIUM, "T1053.003"),
    "PM003": ("SSH authorized_keys changed", Severity.HIGH, "T1098.004"),
    "PM004": ("sudoers configuration changed", Severity.HIGH, "T1548.003"),
    "PM005": ("New or changed SUID/SGID executable", Severity.HIGH, "T1548.001"),
    "PM006": ("File capability added or changed", Severity.HIGH, "T1548"),
    "PM007": ("New executable in a sensitive directory", Severity.LOW, "T1036"),
    "PM008": ("Ownership or permissions weakened", Severity.HIGH, "T1222.002"),
    "PM009": ("Persistence or privileged item removed", Severity.LOW, "T1070"),
}
CATEGORY_RULE = {"systemd": "PM001", "cron": "PM002", "ssh": "PM003", "sudoers": "PM004"}


@dataclass(frozen=True)
class Entry:
    """One monitored item: metadata plus digest/summary, never contents."""

    path: str
    category: str  # systemd, cron, ssh, sudoers, privileged, executable
    meta: FileMeta
    sha256: str | None
    hash_status: str
    capabilities: str | None = None
    key_count: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "category": self.category,
            "meta": self.meta.public() | {"ctime_ns": self.meta.ctime_ns},
            "sha256": self.sha256,
            "hash_status": self.hash_status,
            "capabilities": self.capabilities,
            "key_count": self.key_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Entry":
        meta = dict(data["meta"])
        meta.pop("permissions", None)
        return cls(
            data["path"],
            data["category"],
            FileMeta(**meta),
            data.get("sha256"),
            data.get("hash_status", "unknown"),
            data.get("capabilities"),
            data.get("key_count"),
        )


def count_keys(path: str) -> int | None:
    """Number of public key lines; the keys themselves are never stored or shown."""
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            return sum(1 for line in stream if line.strip() and not line.lstrip().startswith("#"))
    except OSError:
        return None


class PersistenceMonitor:
    name = MODULE

    def __init__(
        self,
        settings: PersistenceSettings,
        policy: SeverityPolicy | None = None,
        baseline: dict[str, Entry] | None = None,
        baseline_source: str = "none",
    ) -> None:
        self.settings = settings
        self.interval = settings.interval_seconds
        self.policy = policy or SeverityPolicy(
            overrides=settings.severity_overrides, allow=settings.allow
        )
        self.hasher = FileHasher(settings.max_hash_bytes)
        self.baseline = baseline
        self.baseline_source = baseline_source if baseline is not None else "none"

    # ----- collection -----

    def _entry(self, meta: FileMeta, category: str, coverage: Coverage) -> Entry:
        digest, status = (None, "not-hashed")
        if category in ("systemd", "cron", "ssh", "sudoers", "privileged") or (
            category == "executable"
        ):
            digest, status = self.hasher.digest(meta)
            if status == "denied":
                coverage.deny(meta.path)
        caps = file_capabilities(meta.path) if meta.kind == "file" else None
        keys = count_keys(meta.path) if category == "ssh" and meta.kind == "file" else None
        return Entry(meta.path, category, meta, digest, status, caps, keys)

    def _collect_paths(
        self, roots: list[str], category: str, coverage: Coverage, patterns: tuple[str, ...]
    ) -> dict[str, Entry]:
        found: dict[str, Entry] = {}
        seen_roots: set[str] = set()
        for raw in roots:
            root = expand(raw)
            real = os.path.realpath(root)
            if real in seen_roots:
                continue  # e.g. /lib/systemd/system -> /usr/lib/systemd/system
            seen_roots.add(real)
            meta = lstat(root)
            if meta.kind == "missing":
                continue
            if meta.kind == "denied":
                coverage.deny(root)
                continue
            if meta.kind != "dir":
                found[root] = self._entry(meta, category, coverage)
                coverage.checked += 1
                continue
            errors: list[str] = []
            for item in walk(root, max_depth=2, errors=errors):
                if item.kind == "dir":
                    continue
                if patterns and not any(
                    fnmatch.fnmatch(os.path.basename(item.path), p) for p in patterns
                ):
                    continue
                found[item.path] = self._entry(item, category, coverage)
                coverage.checked += 1
            for path in errors:
                coverage.deny(path)
        return found

    def collect(self) -> tuple[dict[str, Entry], Coverage]:
        coverage = Coverage()
        s = self.settings
        entries: dict[str, Entry] = {}
        entries.update(self._collect_paths(s.systemd_paths, "systemd", coverage, UNIT_PATTERNS))
        entries.update(self._collect_paths(s.cron_paths, "cron", coverage, ()))
        entries.update(self._collect_paths(s.ssh_paths, "ssh", coverage, ()))
        entries.update(self._collect_paths(s.sudoers_paths, "sudoers", coverage, ()))
        seen: set[str] = set()
        for raw in s.privileged_dirs + s.sensitive_exec_dirs:
            root = expand(raw)
            real = os.path.realpath(root)
            if real in seen:
                continue
            seen.add(real)
            sensitive = raw in s.sensitive_exec_dirs
            errors: list[str] = []
            for meta in walk(root, max_depth=1, errors=errors):
                coverage.checked += 1
                if meta.kind != "file":
                    continue
                caps = file_capabilities(meta.path)
                if meta.setuid or meta.setgid or (caps and caps != "none"):
                    entries[meta.path] = self._entry(meta, "privileged", coverage)
                elif sensitive and meta.executable:
                    entries[meta.path] = self._entry(meta, "executable", coverage)
            for path in errors:
                coverage.deny(path)
        if any(e.category == "sudoers" and e.hash_status == "denied" for e in entries.values()):
            coverage.unavailable.append(
                "sudoers contents unreadable without root: only metadata is compared"
            )
        return entries, coverage

    # ----- comparison -----

    def _finding(
        self, rule: str, entry: Entry, change: str, before: Entry | None, severity: Severity
    ) -> Finding:
        title, _, mitre = RULES[rule]
        evidence: dict[str, Any] = {
            "change": change,
            "category": entry.category,
            "previous": before.as_dict() if before else None,
            "current": entry.as_dict() if entry.meta.kind != "missing" else None,
            "baseline": self.baseline_source,
        }
        explanation = (
            f"{title}: {change}. Detected by comparing {entry.category} metadata and SHA-256 "
            "digests with the baseline. A change can be legitimate administration or package "
            "updates; review who made it. The writing process is not known: polling cannot "
            "attribute file changes (requires audit or eBPF telemetry)."
        )
        return Finding.create(
            MODULE,
            rule,
            entry.path,
            title=title,
            severity=severity,
            evidence=evidence,
            explanation=explanation,
            mitre_reference=f"https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/",
            attribution="unavailable: metadata polling cannot identify the writer",
        )

    @staticmethod
    def _weakened(before: FileMeta, after: FileMeta) -> list[str]:
        reasons = []
        if after.world_writable and not before.world_writable:
            reasons.append("became world-writable")
        if after.group_writable and not before.group_writable:
            reasons.append("became group-writable")
        if before.uid == 0 and after.uid not in (0, None):
            reasons.append(f"owner changed from root to uid {after.uid}")
        return reasons

    def compare(self, baseline: dict[str, Entry], current: dict[str, Entry]) -> list[Finding]:
        findings: list[Finding] = []
        for path, entry in current.items():
            before = baseline.get(path)
            rule = CATEGORY_RULE.get(entry.category)
            default = RULES[rule][1] if rule else Severity.LOW
            if entry.category == "systemd" and path.startswith("/usr/lib/"):
                default = Severity.LOW  # package-managed vendor units change on upgrades
            if before is None:
                if entry.category == "privileged":
                    bits = [
                        b
                        for b, on in (("SUID", entry.meta.setuid), ("SGID", entry.meta.setgid))
                        if on
                    ]
                    if bits:
                        findings.append(
                            self._finding(
                                "PM005",
                                entry,
                                f"new {'/'.join(bits)} executable",
                                None,
                                RULES["PM005"][1],
                            )
                        )
                    if entry.capabilities and entry.capabilities != "none":
                        severity = (
                            Severity.HIGH if dangerous(entry.capabilities) else Severity.MEDIUM
                        )
                        findings.append(
                            self._finding(
                                "PM006", entry, f"capabilities {entry.capabilities}", None, severity
                            )
                        )
                elif entry.category == "executable":
                    findings.append(
                        self._finding("PM007", entry, "new executable", None, Severity.LOW)
                    )
                elif rule:
                    findings.append(
                        self._finding(rule, entry, f"new {entry.category} item", None, default)
                    )
                continue
            changes: list[str] = []
            if entry.sha256 and before.sha256 and entry.sha256 != before.sha256:
                changes.append("content changed (SHA-256 differs)")
            elif (
                entry.sha256 is None and entry.meta.signature()[2:4] != before.meta.signature()[2:4]
            ):
                changes.append("size or modification time changed (content unreadable)")
            if entry.meta.link_target != before.meta.link_target:
                changes.append(
                    f"symlink target {before.meta.link_target} -> {entry.meta.link_target}"
                )
            if entry.category == "ssh" and entry.key_count != before.key_count:
                changes.append(f"key count {before.key_count} -> {entry.key_count}")
            weakened = self._weakened(before.meta, entry.meta)
            if weakened:
                findings.append(
                    self._finding("PM008", entry, "; ".join(weakened), before, Severity.HIGH)
                )
            elif (entry.meta.mode, entry.meta.uid, entry.meta.gid) != (
                before.meta.mode,
                before.meta.uid,
                before.meta.gid,
            ):
                changes.append(
                    f"mode/owner {before.meta.permissions} {before.meta.uid}:{before.meta.gid} -> "
                    f"{entry.meta.permissions} {entry.meta.uid}:{entry.meta.gid}"
                )
            if entry.category == "privileged":
                if (entry.meta.setuid and not before.meta.setuid) or (
                    entry.meta.setgid and not before.meta.setgid
                ):
                    findings.append(
                        self._finding("PM005", entry, "SUID/SGID bit added", before, Severity.HIGH)
                    )
                elif changes:
                    findings.append(
                        self._finding("PM005", entry, "; ".join(changes), before, Severity.MEDIUM)
                    )
                if entry.capabilities != before.capabilities and entry.capabilities not in (
                    None,
                    "none",
                ):
                    severity = Severity.HIGH if dangerous(entry.capabilities) else Severity.MEDIUM
                    change = f"capabilities {before.capabilities} -> {entry.capabilities}"
                    findings.append(self._finding("PM006", entry, change, before, severity))
            elif changes:
                rule_id = rule or "PM007"
                findings.append(self._finding(rule_id, entry, "; ".join(changes), before, default))
        for path, before in baseline.items():
            if path not in current:
                gone = Entry(path, before.category, FileMeta(path, "missing"), None, "missing")
                findings.append(
                    self._finding(
                        "PM009", gone, f"{before.category} item removed", before, Severity.LOW
                    )
                )
        return findings

    # ----- module interface -----

    def set_baseline(self, entries: dict[str, Entry], source: str) -> None:
        self.baseline, self.baseline_source = entries, source

    def scan(self) -> ScanReport:
        started = datetime.now(UTC)
        clock = time.perf_counter()
        current, coverage = self.collect()
        summary: dict[str, Any] = {
            "monitored": {
                "systemd": self.settings.systemd_paths,
                "cron": self.settings.cron_paths,
                "ssh": self.settings.ssh_paths,
                "sudoers": self.settings.sudoers_paths,
                "privileged_dirs": self.settings.privileged_dirs,
                "sensitive_exec_dirs": self.settings.sensitive_exec_dirs,
            },
            "items": {
                c: sum(1 for e in current.values() if e.category == c)
                for c in ("systemd", "cron", "ssh", "sudoers", "privileged", "executable")
            },
            "privileged_items": sorted(
                f"{e.path} {e.meta.permissions} caps={e.capabilities}"
                for e in current.values()
                if e.category == "privileged"
            ),
            "hash_reads": self.hasher.reads,
        }
        if self.baseline is None:
            self.set_baseline(current, "session start (not persisted)")
            summary["baseline"] = self.baseline_source
            return ScanReport(
                MODULE,
                "baseline-created",
                started,
                time.perf_counter() - clock,
                coverage=coverage,
                summary=summary,
            )
        raw = self.compare(self.baseline, current)
        findings, suppressed = self.policy.apply(raw)
        summary["baseline"] = self.baseline_source
        status = "degraded" if coverage.denied_count or coverage.unavailable else "ok"
        return ScanReport(
            MODULE,
            status,
            started,
            time.perf_counter() - clock,
            findings,
            coverage,
            summary,
            suppressed,
        )


def entries_to_body(entries: dict[str, Entry], coverage: Coverage) -> dict[str, Any]:
    return {
        "created_at": datetime.now(UTC).isoformat(),
        "entries": [e.as_dict() for e in entries.values()],
        "coverage": coverage.as_dict(),
    }


def entries_from_body(body: dict[str, Any]) -> dict[str, Entry]:
    return {item["path"]: Entry.from_dict(item) for item in body.get("entries", [])}
