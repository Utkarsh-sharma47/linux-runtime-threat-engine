"""Attack surface and exposure analysis: static posture of the host, read-only.

Checks SUID/SGID executables, file capabilities, writable directories on PATH, weak
permissions on selected sensitive files, root-owned listening services, admin-installed
services that run as root, processes running from suspicious locations and dangerous
sudoers patterns (when readable). Nothing is changed: every finding carries a
remediation for a human to apply.

Risk model (documented, configurable `weights`):

* finding risk = weight[severity] x exposure multiplier (1.5 for network services
  listening on all interfaces, 1.0 otherwise);
* posture score = sum of risks of findings that are not accepted in the exposure
  baseline; grade GOOD < 10 <= FAIR < 30 <= POOR < 70 <= CRITICAL, and any CRITICAL
  finding makes the grade at least POOR.

An expected SUID helper or a root service is not "malicious": expected items are
informational (LOW) and an accepted baseline separates new exposure from known posture.

Full and incremental scans: a full scan walks every SUID path. An incremental scan
re-lists only directories whose mtime changed and re-checks files already known to be
privileged; every `full_scan_every`-th scan is full, so a privilege bit added to an
existing file in an unchanged directory is found at the next full scan.
"""

import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtime_engine.collector.net_collector import NetCollector
from runtime_engine.config.settings import ExposureSettings
from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import Coverage, Finding, ScanReport, SeverityPolicy
from runtime_engine.security.fsutil import FileMeta, dangerous, file_capabilities, lstat, walk

MODULE = "exposure"
SHELL_ESCAPES = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "fish", "python", "python2", "python3",
    "perl", "ruby", "php", "lua", "node", "find", "vim", "vi", "nano", "less", "more",
    "env", "awk", "gawk", "mawk", "cp", "mv", "tar", "zip", "nmap", "tee", "dd", "chmod",
    "chown", "systemctl", "docker", "busybox", "strace", "gdb", "socat", "nc", "openssl",
    "rsync", "wget", "curl", "git", "ed", "man", "xxd", "base64", "install",
}  # fmt: skip
SUSPICIOUS_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
SHELL_ESCAPE_RULE = r"\b(" + "|".join(sorted(SHELL_ESCAPES)) + r")\b"
SUDO_PATTERNS = [
    (
        r"env_keep\s*\+?=.*\bLD_(PRELOAD|LIBRARY_PATH)\b",
        Severity.CRITICAL,
        "env_keep preserves LD_PRELOAD/LD_LIBRARY_PATH (library injection into sudo commands)",
    ),
    (r"NOPASSWD\s*:\s*ALL\b", Severity.HIGH, "passwordless sudo for ALL commands"),
    (r"!authenticate", Severity.HIGH, "authentication disabled for sudo"),
    (SHELL_ESCAPE_RULE, Severity.HIGH, "allows a program that can spawn a shell (shell escape)"),
    (r"/\S*\*", Severity.MEDIUM, "wildcard in an allowed command path or argument"),
]
NETWORK_ONLY = {"cap_net_raw", "cap_net_bind_service"}
SSH_NOT_KEYS = {"config", "authorized_keys", "authorized_keys2", "environment"}


@dataclass
class Check:
    rule: str
    title: str
    severity: Severity
    resource: str
    weakness: str
    evidence: dict[str, Any]
    explanation: str
    remediation: str
    multiplier: float = 1.0


def grade(score: float, critical: bool) -> str:
    level = "GOOD" if score < 10 else "FAIR" if score < 30 else "POOR" if score < 70 else "CRITICAL"
    if critical and level in ("GOOD", "FAIR"):
        level = "POOR"
    return level


def suid_check(meta: FileMeta, expected: set[str], writable: bool) -> Check:
    name = os.path.basename(meta.path)
    base = name.split(".")[0].rstrip("0123456789")
    bits = "/".join(b for b, on in (("SUID", meta.setuid), ("SGID", meta.setgid)) if on)
    if writable:
        severity, weakness = Severity.CRITICAL, f"{bits} executable that others can modify"
    elif meta.setuid and (name in SHELL_ESCAPES or base in SHELL_ESCAPES):
        severity, weakness = Severity.CRITICAL, f"{bits} program with a known shell escape"
    elif name in expected:
        severity, weakness = Severity.LOW, f"expected {bits} helper (informational)"
    elif meta.setuid and meta.uid not in (0, None):
        severity, weakness = Severity.MEDIUM, f"SUID to non-root uid {meta.uid}"
    else:
        severity, weakness = Severity.HIGH, f"unexpected {bits} executable"
    return Check(
        "EX001",
        "SUID/SGID executable",
        severity,
        meta.path,
        weakness,
        {"metadata": meta.public()},
        f"{weakness}. A {bits} binary runs with its owner's or group's privileges; a flaw or "
        "shell escape in it can lead to privilege escalation. Expected helpers are reported "
        "as LOW so they stay visible without alarm.",
        "Remove the bit if not needed (chmod u-s/g-s), uninstall the package, or add it to "
        "expected_suid after review.",
    )


def capability_check(meta: FileMeta, caps: str, expected: set[str]) -> Check:
    risky = dangerous(caps)
    names = set(caps.split("=")[0].split(","))
    if os.path.basename(meta.path) in expected:
        severity, label = Severity.LOW, "expected helper (informational)"
    elif names <= NETWORK_ONLY:
        severity, label = Severity.LOW, "network capability only"
    elif risky:
        severity, label = Severity.HIGH, "dangerous: " + ", ".join(risky)
    else:
        severity, label = Severity.MEDIUM, "review"
    return Check(
        "EX002",
        "File capabilities",
        severity,
        meta.path,
        f"capabilities {caps} ({label})",
        {"capabilities": caps, "dangerous": risky, "metadata": meta.public()},
        "File capabilities grant part of root's power to anyone who runs the file. "
        "cap_net_raw (ping) is common and low risk; capabilities such as cap_setuid or "
        "cap_sys_admin are equivalent to root.",
        "Remove unneeded capabilities (setcap -r FILE) or restrict who can execute the file.",
    )


class ExposureAnalyzer:
    name = MODULE

    def __init__(
        self,
        settings: ExposureSettings,
        policy: SeverityPolicy | None = None,
        accepted: set[str] | None = None,
        *,
        proc: Path = Path("/proc"),
        home: str | None = None,
        sudoers: list[str] | None = None,
        sensitive: list[tuple[str, str]] | None = None,
        path_env: str | None = None,
        unit_dir: str = "/etc/systemd/system",
    ) -> None:
        self.settings = settings
        self.interval = settings.interval_seconds
        self.policy = policy or SeverityPolicy(
            overrides=settings.severity_overrides, allow=settings.allow
        )
        self.accepted = accepted or set()
        self.proc = proc
        self.home = home or os.path.expanduser("~")
        self.sudoers = sudoers or ["/etc/sudoers", "/etc/sudoers.d"]
        self.sensitive = sensitive
        self.path_env = path_env
        self.unit_dir = unit_dir
        self.cap_cache: dict[tuple[str, int | None, int | None], str | None] = {}
        self.known_dirs: dict[str, int | None] = {}
        self.known_privileged: set[str] = set()
        self.scans = 0

    # ----- SUID/SGID and capabilities -----

    def _caps(self, meta: FileMeta, full: bool) -> str | None:
        key = (meta.path, meta.inode, meta.ctime_ns)  # setcap changes ctime
        if full or key not in self.cap_cache:
            self.cap_cache[key] = file_capabilities(meta.path)
        return self.cap_cache[key]

    def _candidates(self, coverage: Coverage, full: bool) -> list[FileMeta]:
        if full:
            self.known_dirs = {}
            found: list[FileMeta] = []
            for root in self.settings.suid_paths:
                meta = lstat(root)
                if meta.kind != "dir":
                    continue
                self.known_dirs[root] = meta.mtime_ns
                errors: list[str] = []
                for item in walk(root, max_depth=self.settings.suid_max_depth, errors=errors):
                    if item.kind == "dir":
                        self.known_dirs[item.path] = item.mtime_ns
                    elif item.kind == "file":
                        found.append(item)
                for path in errors:
                    coverage.deny(path)
            return found
        candidates = {path: lstat(path) for path in self.known_privileged}
        for directory, mtime in list(self.known_dirs.items()):
            meta = lstat(directory)
            if meta.kind != "dir":
                del self.known_dirs[directory]
                continue
            if meta.mtime_ns == mtime:
                continue
            self.known_dirs[directory] = meta.mtime_ns
            try:
                with os.scandir(directory) as entries:
                    paths = [entry.path for entry in entries]
            except PermissionError:
                coverage.deny(directory)
                continue
            for path in paths:
                item = lstat(path)
                if item.kind == "file":
                    candidates[path] = item
                elif item.kind == "dir":
                    self.known_dirs.setdefault(path, item.mtime_ns)
        coverage.unavailable.append(
            "incremental scan: unchanged directories were not re-listed; the next full scan "
            "re-checks every file"
        )
        return [m for m in candidates.values() if m.kind == "file"]

    def privileged_files(self, coverage: Coverage, full: bool) -> list[Check]:
        checks: list[Check] = []
        expected = set(self.settings.expected_suid)
        privileged: set[str] = set()
        for meta in self._candidates(coverage, full):
            coverage.checked += 1
            caps = self._caps(meta, full)
            has_caps = bool(caps and caps != "none")
            if not (meta.setuid or meta.setgid or has_caps):
                continue
            privileged.add(meta.path)
            parent = lstat(os.path.dirname(meta.path))
            sticky = bool(parent.mode and parent.mode & stat.S_ISVTX)
            writable = meta.world_writable or (parent.world_writable and not sticky)
            if meta.setuid or meta.setgid:
                checks.append(suid_check(meta, expected, writable))
            if caps and has_caps:
                checks.append(capability_check(meta, caps, expected))
        self.known_privileged = privileged
        return checks

    # ----- PATH and sensitive files -----

    def path_dirs(self) -> list[Check]:
        checks: list[Check] = []
        raw = self.path_env if self.path_env is not None else os.environ.get("PATH", "")
        for entry in dict.fromkeys(raw.split(":")):
            if entry in ("", "."):
                checks.append(
                    Check(
                        "EX003",
                        "Writable or relative PATH entry",
                        Severity.MEDIUM,
                        entry or "(empty)",
                        "current directory is on PATH",
                        {"entry": entry},
                        "A relative PATH entry lets a file in the current directory shadow "
                        "system commands.",
                        "Remove '.' and empty entries from PATH.",
                    )
                )
                continue
            meta = lstat(entry)
            if meta.kind != "dir":
                continue
            sticky = bool(meta.mode and meta.mode & stat.S_ISVTX)
            if meta.world_writable:
                weakness = "world-writable directory on PATH" + (" (sticky)" if sticky else "")
                severity = Severity.MEDIUM if sticky else Severity.HIGH
            elif meta.group_writable and meta.gid not in (0, os.getgid()):
                weakness = f"group-writable directory on PATH (gid {meta.gid})"
                severity = Severity.MEDIUM
            else:
                continue
            checks.append(
                Check(
                    "EX003",
                    "Writable or relative PATH entry",
                    severity,
                    entry,
                    weakness,
                    {"metadata": meta.public()},
                    "Others can place an executable here that shadows a command run by this "
                    "user or by scripts using this PATH.",
                    "Remove the directory from PATH or remove the write access (chmod o-w/g-w).",
                )
            )
        return checks

    def _sensitive_items(self) -> list[tuple[str, str]]:
        if self.sensitive is not None:
            return self.sensitive
        items = [
            ("/etc/passwd", "no-world-write"),
            ("/etc/group", "no-world-write"),
            ("/etc/shadow", "private"),
            ("/etc/gshadow", "private"),
            ("/etc/sudoers", "no-world-read"),
            ("/etc/ssh/sshd_config", "no-world-write"),
            ("/etc/crontab", "no-world-write"),
        ]
        items += [(str(p), "private") for p in Path("/etc/ssh").glob("ssh_host_*_key")]
        items += [(str(p), "no-world-write") for p in Path("/etc/cron.d").glob("*")]
        ssh = Path(self.home, ".ssh")
        items += [(str(ssh), "private-dir"), (str(ssh / "authorized_keys"), "no-group-write")]
        if ssh.is_dir():
            # Private keys are recognized by name only: their contents are never read.
            items += [
                (str(p), "private")
                for p in sorted(ssh.iterdir())
                if p.is_file()
                and p.suffix != ".pub"
                and p.name not in SSH_NOT_KEYS
                and "known_hosts" not in p.name
            ]
        return items

    def sensitive_files(self, coverage: Coverage) -> list[Check]:
        checks: list[Check] = []
        for path, rule in self._sensitive_items():
            meta = lstat(path)
            if meta.kind in ("missing", "symlink"):
                continue
            if meta.kind == "denied":
                coverage.deny(path)
                continue
            coverage.checked += 1
            mode = meta.mode or 0
            problems: list[tuple[Severity, str]] = []
            if mode & stat.S_IWOTH:
                critical = rule == "no-world-write" and path.endswith("passwd")
                problems.append(
                    (Severity.CRITICAL if critical else Severity.HIGH, "world-writable")
                )
            if rule in ("private", "no-world-read") and mode & stat.S_IROTH:
                severity = Severity.CRITICAL if "shadow" in path else Severity.HIGH
                problems.append((severity, "world-readable"))
            if rule == "private" and mode & stat.S_IRGRP and meta.gid != 0 and "shadow" not in path:
                problems.append((Severity.HIGH, "group-readable"))
            if rule in ("private-dir", "no-group-write") and mode & stat.S_IWGRP:
                problems.append((Severity.HIGH, "group-writable"))
            if rule == "private-dir" and mode & stat.S_IRWXO:
                problems.append((Severity.HIGH, "accessible by others"))
            if not problems:
                continue
            severity = max((p[0] for p in problems), key=lambda s: s.rank)
            weakness = ", ".join(p[1] for p in problems)
            checks.append(
                Check(
                    "EX004",
                    "Weak permissions on a sensitive file",
                    severity,
                    path,
                    f"{weakness} ({meta.permissions}, owner {meta.uid}:{meta.gid})",
                    {"metadata": meta.public(), "policy": rule},
                    "The permissions allow other users to read secrets or modify security "
                    "configuration. Only metadata was inspected; contents were not read.",
                    "Restore the expected mode, e.g. chmod 600 for private keys, 640 root:shadow "
                    "for /etc/shadow, 644 for /etc/passwd, 700 for ~/.ssh.",
                )
            )
        return checks

    # ----- services and processes -----

    def services(self, coverage: Coverage) -> list[Check]:
        checks: list[Check] = []
        expected = set(self.settings.expected_listen_ports)
        groups: dict[tuple[str, int, bool], list[Any]] = {}
        for item in NetCollector(self.proc).snapshot().sockets:
            udp_bound = item.protocol.startswith("udp") and item.state == "UNCONNECTED"
            if not (item.state == "LISTEN" or udp_bound) or item.uid != 0:
                continue
            if item.local_port in expected:
                continue
            exposed = item.local_ip in ("0.0.0.0", "::")
            # IPv4 and IPv6 sockets of one service are one finding.
            groups.setdefault((item.protocol.rstrip("6"), item.local_port, exposed), []).append(
                item
            )
        for (protocol, port, exposed), items in sorted(groups.items()):
            owners = sorted({o.name for item in items for o in item.owners})
            addresses = sorted({item.local_ip for item in items})
            checks.append(
                Check(
                    "EX005",
                    "Root-owned listening service",
                    Severity.MEDIUM if exposed else Severity.LOW,
                    f"{protocol}/{port} on {', '.join(addresses)}",
                    "root service listening on all interfaces"
                    if exposed
                    else "root service on a local address",
                    {
                        "protocol": protocol,
                        "addresses": addresses,
                        "port": port,
                        "processes": owners or None,
                        "attribution": items[0].attribution,
                    },
                    "A network service running as root turns any exploitable bug into full "
                    "compromise; on all interfaces it is reachable from the network.",
                    "Bind it to localhost, run it as a dedicated user, firewall the port, or add "
                    "the port to expected_listen_ports after review.",
                    1.5 if exposed else 1.0,
                )
            )
        unit_dir = Path(self.unit_dir)
        units = sorted(unit_dir.glob("*.service")) if unit_dir.is_dir() else []
        for unit in units:
            if unit.is_symlink() or not unit.is_file():
                continue
            try:
                text = unit.read_text(errors="replace")
            except OSError:
                coverage.deny(str(unit))
                continue
            coverage.checked += 1
            flags = re.MULTILINE | re.IGNORECASE
            if re.search(r"^\s*User\s*=", text, flags) or re.search(
                r"^\s*DynamicUser\s*=\s*(yes|true)", text, flags
            ):
                continue
            start = next(
                (
                    ln.split("=", 1)[1].strip()
                    for ln in text.splitlines()
                    if ln.strip().startswith("ExecStart=")
                ),
                None,
            )
            checks.append(
                Check(
                    "EX006",
                    "Admin-installed service runs as root",
                    Severity.LOW,
                    str(unit),
                    "no User= or DynamicUser= in the unit (runs as root)",
                    {"unit": str(unit), "exec_start": start},
                    "Locally installed services without User= run as root. Many need to, but "
                    "each should be reviewed.",
                    "Add User=/DynamicUser= and sandboxing (ProtectSystem=, NoNewPrivileges=) "
                    "where possible.",
                )
            )
        return checks

    def _executable(self, folder: str) -> tuple[str | None, str]:
        try:
            return os.readlink(f"{folder}/exe"), "exe link"
        except PermissionError:
            pass
        except OSError:
            return None, ""  # kernel thread or exited
        try:
            argv0 = Path(folder, "cmdline").read_bytes().split(b"\0")[0].decode(errors="replace")
        except OSError:
            return None, ""
        return (
            argv0 if argv0.startswith("/") else None
        ), "argv[0] (exe unreadable; can be spoofed)"

    def processes(self, coverage: Coverage) -> list[Check]:
        checks: list[Check] = []
        for entry in os.scandir(self.proc):
            if not entry.name.isdigit():
                continue
            exe, source = self._executable(entry.path)
            if not exe:
                continue
            coverage.checked += 1
            deleted = exe.endswith(" (deleted)")
            if not (deleted or exe.startswith(SUSPICIOUS_DIRS)):
                continue
            original = exe.removesuffix(" (deleted)")
            # A package update replaces the file while the old process keeps running.
            replaced = (
                deleted and not original.startswith(SUSPICIOUS_DIRS) and os.path.exists(original)
            )
            uid = None
            try:
                for line in Path(entry.path, "status").read_text().splitlines():
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
            except OSError:
                pass
            if replaced:
                severity = Severity.LOW
                weakness = "binary replaced on disk after start (likely an update; restart pending)"
            else:
                severity = Severity.CRITICAL if uid == 0 else Severity.HIGH
                weakness = (
                    "executable deleted after start"
                    if deleted
                    else "executable in a temporary directory"
                )
            checks.append(
                Check(
                    "EX007",
                    "Process running from a suspicious location",
                    severity,
                    f"PID {entry.name} {exe}",
                    weakness,
                    {"pid": int(entry.name), "executable": exe, "source": source, "uid": uid},
                    "Programs running from world-writable temporary directories, or whose file "
                    "was deleted after start, are a common sign of dropped payloads; legitimate "
                    "updaters and build tools also do this.",
                    "Identify the process (process --pid), check its parent and origin, and stop "
                    "it if it is not expected.",
                )
            )
        return checks

    def sudo(self, coverage: Coverage) -> list[Check]:
        checks: list[Check] = []
        files: list[str] = []
        for path in self.sudoers:
            if os.path.isdir(path):
                try:
                    files += sorted(str(p) for p in Path(path).iterdir() if p.is_file())
                except PermissionError:
                    coverage.deny(path)
            else:
                files.append(path)
        unreadable = 0
        for path in files:
            try:
                lines = Path(path).read_text(errors="replace").splitlines()
            except PermissionError:
                unreadable += 1
                coverage.deny(path)
                continue
            except OSError:
                continue
            coverage.checked += 1
            for number, line in enumerate(lines, 1):
                rule = line.split("#", 1)[0].strip()
                if not rule:
                    continue
                for pattern, severity, weakness in SUDO_PATTERNS:
                    if pattern == SHELL_ESCAPE_RULE and not re.search(r"\bALL\b|NOPASSWD", rule):
                        continue  # program names only matter inside a user privilege rule
                    if re.search(pattern, rule):
                        checks.append(
                            Check(
                                "EX008",
                                "Dangerous sudo configuration",
                                severity,
                                f"{path}:{number}",
                                weakness,
                                {"file": path, "line": number, "rule": rule[:200]},
                                "This sudoers rule lets the allowed users gain root more easily "
                                "than intended.",
                                "Restrict the rule to specific full command paths without "
                                "wildcards, require authentication, and avoid programs with "
                                "shell escapes.",
                            )
                        )
                        break
        if unreadable:
            coverage.unavailable.append(
                f"{unreadable} sudoers file(s) unreadable without root: sudo patterns not assessed"
            )
        return checks

    # ----- module interface -----

    def scan(self, full: bool = False) -> ScanReport:
        started = datetime.now(UTC)
        clock = time.perf_counter()
        coverage = Coverage()
        full = full or self.scans % self.settings.full_scan_every == 0
        self.scans += 1
        checks = self.privileged_files(coverage, full)
        if self.settings.scan_path_dirs:
            checks += self.path_dirs()
        if self.settings.scan_sensitive:
            checks += self.sensitive_files(coverage)
        if self.settings.scan_services:
            checks += self.services(coverage)
        if self.settings.scan_processes:
            checks += self.processes(coverage)
        if self.settings.scan_sudo:
            checks += self.sudo(coverage)
        weights = self.settings.weights
        raw = [
            Finding.create(
                MODULE,
                check.rule,
                check.resource,
                title=check.title,
                severity=check.severity,
                evidence=check.evidence
                | {
                    "weakness": check.weakness,
                    "summary": check.weakness,
                    "multiplier": check.multiplier,
                },
                explanation=check.explanation,
                remediation=check.remediation,
                attribution="not applicable: static posture check",
                detected_at=started,
            )
            for check in checks
        ]
        findings, suppressed = self.policy.apply(raw)
        for finding in findings:
            accepted = finding.finding_id in self.accepted
            finding.evidence["baseline_status"] = "accepted" if accepted else "new"
            if accepted:
                finding.promoted = False  # known posture is not re-alerted
            multiplier = float(finding.evidence.get("multiplier", 1.0))
            finding.risk_score = round(weights.get(finding.severity.value, 0) * multiplier, 2)
        new = [f for f in findings if f.evidence["baseline_status"] == "new"]
        score = sum(f.risk_score or 0 for f in new)
        critical = any(f.severity == Severity.CRITICAL for f in new)
        summary = {
            "scan_type": "full" if full else "incremental",
            "posture": grade(score, critical),
            "score": round(score, 2),
            "score_all_findings": round(sum(f.risk_score or 0 for f in findings), 2),
            "counts": {s.value: sum(1 for f in findings if f.severity == s) for s in Severity},
            "new": len(new),
            "accepted": len(findings) - len(new),
            "weights": weights,
            "by_rule": {
                rule: sum(1 for f in findings if f.rule_id == rule)
                for rule in sorted({f.rule_id for f in findings})
            },
        }
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
