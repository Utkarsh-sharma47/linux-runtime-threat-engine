"""Ransomware early warning from file behaviour in explicitly configured directories.

Telemetry: Linux inotify (via ctypes, no dependency) on the configured directories, with
a polling fallback. inotify reports WHAT happened to a path but never WHICH process did
it. Attribution is therefore a labelled heuristic: when a burst is detected, processes
whose open files or working directory are inside the monitored directory are listed as
candidates. Reliable per-process attribution needs audit or eBPF, which is not used.

Indicators over a sliding window (`window_seconds`), each normalized to 0..1:

  modifications   writes / modification_threshold                       weight 0.25
  renames         renames / rename_threshold                            weight 0.20
  files           distinct files / files_threshold                      weight 0.15
  directories     distinct directories / directories_threshold          weight 0.10
  entropy         fraction of sampled writes whose Shannon entropy rose
                  from <= low_entropy (or a new file) to >= high_entropy,
                  / entropy_ratio_threshold                             weight 0.20
  extensions      fraction of renames that change the extension, mostly
                  to one common new extension, / extension_ratio_threshold weight 0.10

Behavioural risk score = 100 x sum(weight x indicator). A finding needs the score >=
`alert_score` (50) AND at least `min_indicators` (2) indicators at full strength. High
entropy alone can contribute at most 20 points, so compressed or encrypted files that
are written without mass modification and renaming never alert.

Shannon entropy H(X) = -sum p(x) log2 p(x) over byte values, in bits per byte (0..8),
computed on at most `sample_bytes` from the start of the file and rate-limited.
"""

import ctypes
import ctypes.util
import errno
import fnmatch
import math
import os
import select
import struct
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtime_engine.config.settings import RansomwareSettings
from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import (
    Coverage,
    Finding,
    ScanReport,
    SeverityPolicy,
    revision_of,
)

MODULE = "ransomware"
IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x2, 0x8, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR = 0x100, 0x200, 0x4000, 0x8000, 0x40000000
WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_MODIFY
WEIGHTS = {"modifications": 0.25, "renames": 0.20, "files": 0.15, "directories": 0.10,
           "entropy": 0.20, "extensions": 0.10}  # fmt: skip
EVENT = struct.Struct("iIII")


def shannon_entropy(data: bytes) -> float:
    """H(X) = -sum p(x) log2 p(x) over byte values; 0 for empty input, at most 8."""
    if not data:
        return 0.0
    total = len(data)
    return abs(-sum((n / total) * math.log2(n / total) for n in Counter(data).values()))


@dataclass
class FileEvent:
    when: float
    kind: str  # write, create, delete, rename
    path: str
    old_path: str | None = None


class InotifyWatcher:
    """Recursive inotify watches (bounded); `read()` drains pending events without blocking."""

    def __init__(self, roots: list[str], exclude: list[str], max_watches: int) -> None:
        name = ctypes.util.find_library("c")
        self.libc = ctypes.CDLL(name, use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.exclude = exclude
        self.max_watches = max_watches
        self.watches: dict[int, str] = {}
        self.overflows = 0
        self.watch_errors: list[str] = []
        self.cookies: dict[int, str] = {}
        for root in roots:
            self._watch_tree(root)

    def _add(self, path: str) -> None:
        if len(self.watches) >= self.max_watches:
            if "watch limit" not in " ".join(self.watch_errors):
                self.watch_errors.append(f"watch limit {self.max_watches} reached")
            return
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), WATCH_MASK)
        if wd < 0:
            self.watch_errors.append(f"{path}: {errno.errorcode.get(ctypes.get_errno(), 'error')}")
            return
        self.watches[wd] = path

    def _watch_tree(self, root: str) -> None:
        self._add(root)
        for current, dirs, _ in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, p) for p in self.exclude)]
            for name in dirs:
                self._add(os.path.join(current, name))

    def read(self) -> list[FileEvent]:
        events: list[FileEvent] = []
        while True:
            ready, _, _ = select.select([self.fd], [], [], 0)
            if not ready:
                return events
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return events
            now = time.time()
            offset = 0
            while offset + EVENT.size <= len(data):
                wd, mask, cookie, length = EVENT.unpack_from(data, offset)
                raw = data[offset + EVENT.size : offset + EVENT.size + length].rstrip(b"\0")
                offset += EVENT.size + length
                if mask & IN_Q_OVERFLOW:
                    self.overflows += 1
                    continue
                if mask & IN_IGNORED:
                    self.watches.pop(wd, None)
                    continue
                base = self.watches.get(wd)
                if base is None:
                    continue
                path = os.path.join(base, os.fsdecode(raw)) if raw else base
                if any(fnmatch.fnmatch(os.path.basename(path), p) for p in self.exclude):
                    continue
                if mask & IN_ISDIR:
                    if mask & (IN_CREATE | IN_MOVED_TO):
                        self._watch_tree(path)  # new subdirectory: watch it too
                    continue
                if mask & IN_MOVED_FROM:
                    self.cookies[cookie] = path
                    if len(self.cookies) > 10_000:
                        self.cookies.pop(next(iter(self.cookies)))
                elif mask & IN_MOVED_TO:
                    events.append(FileEvent(now, "rename", path, self.cookies.pop(cookie, None)))
                elif mask & IN_CLOSE_WRITE:
                    events.append(FileEvent(now, "write", path))
                elif mask & IN_CREATE:
                    events.append(FileEvent(now, "create", path))
                elif mask & IN_DELETE:
                    events.append(FileEvent(now, "delete", path))

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class PollingWatcher:
    """Fallback: compare (inode, size, mtime) snapshots; renames are matched by inode."""

    def __init__(self, roots: list[str], exclude: list[str], max_files: int = 50_000) -> None:
        self.roots, self.exclude, self.max_files = roots, exclude, max_files
        self.overflows = 0
        self.watch_errors: list[str] = []
        self.state = self._snapshot()

    def _snapshot(self) -> dict[str, tuple[int, int, int]]:
        found: dict[str, tuple[int, int, int]] = {}
        self.watch_errors = [
            f"{root}: not a readable directory"
            for root in self.roots
            if not os.path.isdir(root) or not os.access(root, os.R_OK | os.X_OK)
        ]
        for root in self.roots:
            for current, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, p) for p in self.exclude)]
                for name in files:
                    if len(found) >= self.max_files or any(
                        fnmatch.fnmatch(name, p) for p in self.exclude
                    ):
                        continue
                    path = os.path.join(current, name)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    found[path] = (st.st_ino, st.st_size, st.st_mtime_ns)
        if len(found) >= self.max_files:
            self.watch_errors.append(f"file limit {self.max_files} reached; files beyond it unseen")
        return found

    def read(self) -> list[FileEvent]:
        now = time.time()
        current = self._snapshot()
        events: list[FileEvent] = []
        gone = {v[0]: p for p, v in self.state.items() if p not in current}
        for path, value in current.items():
            before = self.state.get(path)
            if before is None:
                old = gone.pop(value[0], None)
                events.append(
                    FileEvent(now, "rename", path, old) if old else FileEvent(now, "create", path)
                )
                if old is not None and value[1:] != self.state[old][1:]:
                    events.append(FileEvent(now, "write", path))
            elif before != value:
                events.append(FileEvent(now, "write", path))
        events += [FileEvent(now, "delete", path) for path in gone.values()]
        self.state = current
        return events

    def close(self) -> None:
        pass


@dataclass
class Window:
    events: deque[tuple[float, str, str, str | None, float | None, float | None]] = field(
        default_factory=deque
    )  # (time, kind, path, old_path, entropy_before, entropy_after)


class BehaviourAnalyzer:
    """Bounded sliding window and entropy sampling for one monitored root."""

    def __init__(
        self, settings: RansomwareSettings, clock: Callable[[], float] = time.time
    ) -> None:
        self.settings = settings
        self.clock = clock
        self.window = Window()
        self.entropy: OrderedDict[str, float] = OrderedDict()
        self.tokens = settings.entropy_reads_per_second
        self.last_refill = clock()
        self.sampled = 0
        self.skipped_samples = 0
        self.dropped_events = 0

    def _sample(self, path: str) -> float | None:
        now = self.clock()
        self.tokens = min(
            self.settings.entropy_reads_per_second,
            self.tokens + (now - self.last_refill) * self.settings.entropy_reads_per_second,
        )
        self.last_refill = now
        if self.tokens < 1:
            self.skipped_samples += 1
            return None
        self.tokens -= 1
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(self.settings.sample_bytes)
        except OSError:
            return None
        self.sampled += 1
        return shannon_entropy(data)

    def _remember(self, path: str, value: float) -> None:
        self.entropy[path] = value
        self.entropy.move_to_end(path)
        if len(self.entropy) > 20_000:
            self.entropy.popitem(last=False)

    def seed(self, path: str) -> None:
        """Record a file's starting entropy (initial directory walk, bounded by rate limit)."""
        value = self._sample(path)
        if value is not None:
            self._remember(path, value)

    def feed(self, event: FileEvent) -> None:
        before = after = None
        if event.kind in ("write", "rename"):
            before = self.entropy.pop(event.old_path, None) if event.old_path else None
            before = self.entropy.get(event.path, before)
            after = self._sample(event.path)
            if after is not None:
                self._remember(event.path, after)
        elif event.kind == "delete":
            self.entropy.pop(event.path, None)
        self.window.events.append(
            (event.when, event.kind, event.path, event.old_path, before, after)
        )
        if len(self.window.events) > self.settings.max_events_per_window:
            self.window.events.popleft()
            self.dropped_events += 1

    def evaluate(self, now: float | None = None) -> dict[str, Any]:
        s = self.settings
        now = self.clock() if now is None else now
        while self.window.events and now - self.window.events[0][0] > s.window_seconds:
            self.window.events.popleft()
        events = list(self.window.events)
        writes = [e for e in events if e[1] == "write"]
        renames = [e for e in events if e[1] == "rename"]
        files = {e[2] for e in events if e[1] != "delete"}
        dirs = {os.path.dirname(p) for p in files}
        sampled = [e for e in events if e[1] in ("write", "rename") and e[5] is not None]
        jumps = [
            e
            for e in sampled
            if (e[5] or 0.0) >= s.high_entropy and (e[4] is None or e[4] <= s.low_entropy)
        ]
        changed_ext = [e for e in renames if e[3] and Path(e[3]).suffix != Path(e[2]).suffix]
        common = Counter(Path(e[2]).suffix for e in changed_ext).most_common(1)
        ext_ratio = (common[0][1] / len(renames)) if renames and common else 0.0
        entropy_ratio = len(jumps) / len(sampled) if sampled else 0.0
        indicators = {
            "modifications": min(1.0, len(writes) / s.modification_threshold),
            "renames": min(1.0, len(renames) / s.rename_threshold),
            "files": min(1.0, len(files) / s.files_threshold),
            "directories": min(1.0, len(dirs) / s.directories_threshold) if len(files) > 1 else 0.0,
            "entropy": min(1.0, entropy_ratio / s.entropy_ratio_threshold)
            if len(sampled) >= 3
            else 0.0,
            "extensions": min(1.0, ext_ratio / s.extension_ratio_threshold),
        }
        score = 100 * sum(WEIGHTS[k] * v for k, v in indicators.items())
        triggered = sorted(k for k, v in indicators.items() if v >= 1.0)
        span = max(1.0, (events[-1][0] - events[0][0]) if events else 1.0)
        return {
            "score": round(score, 1),
            "indicators": {k: round(v, 3) for k, v in indicators.items()},
            "triggered": triggered,
            "alert": score >= s.alert_score and len(triggered) >= s.min_indicators,
            "window_seconds": s.window_seconds,
            "events": len(events),
            "modifications": len(writes),
            "renames": len(renames),
            "files": len(files),
            "directories": len(dirs),
            "modification_rate_per_min": round(len(writes) * 60 / span, 1),
            "rename_rate_per_min": round(len(renames) * 60 / span, 1),
            "entropy_samples": len(sampled),
            "entropy_increases": len(jumps),
            "entropy_examples": [
                {
                    "path": e[2],
                    "before": None if e[4] is None else round(e[4], 2),
                    "after": round(e[5] or 0.0, 2),
                }
                for e in jumps[:5]
            ],
            "extension_change": common[0][0] if common else None,
            "extension_change_ratio": round(ext_ratio, 3),
        }


def candidate_processes(
    root: str, proc: Path = Path("/proc"), limit: int = 20
) -> list[dict[str, Any]]:
    """Heuristic attribution: processes with open files or cwd inside `root` right now."""
    base = os.path.realpath(root).rstrip("/") + "/"
    found: list[dict[str, Any]] = []
    for entry in os.scandir(proc):
        if not entry.name.isdigit() or len(found) >= limit:
            continue
        reasons = []
        try:
            cwd = os.readlink(f"{entry.path}/cwd")
            if (cwd + "/").startswith(base):
                reasons.append("working directory inside")
        except OSError:
            continue
        try:
            for fd in os.listdir(f"{entry.path}/fd"):
                try:
                    if os.readlink(f"{entry.path}/fd/{fd}").startswith(base):
                        reasons.append("has a file open inside")
                        break
                except OSError:
                    continue
        except OSError:
            pass
        if reasons:
            try:
                stat = Path(entry.path, "stat").read_text()
                start = stat[stat.rindex(")") + 2 :].split()[19]
                name = stat[stat.index("(") + 1 : stat.rindex(")")]
            except (OSError, ValueError, IndexError):
                continue
            found.append({"pid": int(entry.name), "name": name, "start": start, "reasons": reasons})
    return found


class RansomwareMonitor:
    name = MODULE

    def __init__(
        self,
        settings: RansomwareSettings,
        policy: SeverityPolicy | None = None,
        *,
        directories: list[str] | None = None,
        use_inotify: bool = True,
        proc: Path = Path("/proc"),
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.interval = settings.interval_seconds
        self.policy = policy or SeverityPolicy(
            overrides=settings.severity_overrides, allow=settings.allow
        )
        self.directories = [
            os.path.realpath(os.path.expanduser(d)) for d in (directories or settings.directories)
        ]
        self.proc = proc
        self.clock = clock
        try:
            self.boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            self.boot = "local"
        self.mechanism = "inotify"
        self.watcher: InotifyWatcher | PollingWatcher
        try:
            if not use_inotify:
                raise OSError("inotify disabled")
            self.watcher = InotifyWatcher(self.directories, settings.exclude, settings.max_watches)
        except (OSError, AttributeError):
            self.mechanism = "polling (inotify unavailable)"
            self.watcher = PollingWatcher(self.directories, settings.exclude)
        self.analyzers = {d: BehaviourAnalyzer(settings, clock) for d in self.directories}
        for directory in self.directories:  # seed starting entropy, bounded by the rate limit
            for current, _, files in os.walk(directory, followlinks=False):
                for name in files[:200]:
                    self.analyzers[directory].seed(os.path.join(current, name))
        self.totals: Counter[str] = Counter()
        self.last_candidates: list[dict[str, Any]] = []

    def root_of(self, path: str) -> str | None:
        for directory in self.directories:
            if path == directory or path.startswith(directory.rstrip("/") + "/"):
                return directory
        return None

    def scan(self) -> ScanReport:
        started = datetime.now(UTC)
        clock = time.perf_counter()
        for event in self.watcher.read():
            root = self.root_of(event.path)
            if root is not None:
                self.totals[event.kind] += 1
                self.analyzers[root].feed(event)
        coverage = Coverage(checked=len(self.directories))
        coverage.unavailable.append(
            f"{self.mechanism}: file events carry no process identity; attribution is a "
            "heuristic (open files or working directory at detection time)"
        )
        if self.watcher.overflows:
            coverage.unavailable.append(
                f"inotify queue overflowed {self.watcher.overflows} time(s): events were lost"
            )
        coverage.unavailable += self.watcher.watch_errors[:5]
        raw: list[Finding] = []
        per_directory: dict[str, Any] = {}
        for directory, analyzer in self.analyzers.items():
            result = analyzer.evaluate()
            result["entropy_samples_skipped"] = analyzer.skipped_samples
            result["events_dropped"] = analyzer.dropped_events
            per_directory[directory] = result
            if not result["alert"]:
                continue
            candidates = candidate_processes(directory, self.proc)
            self.last_candidates = candidates
            unique = candidates[0] if len(candidates) == 1 else None
            key = (
                f'["{self.boot}",{unique["pid"]},"{unique["start"]}"]'
                if unique is not None
                else None
            )
            finding = Finding.create(
                MODULE,
                "RW001",
                directory,
                title="Ransomware-like file activity",
                severity=Severity.HIGH if result["score"] >= 75 else Severity.MEDIUM,
                risk_score=result["score"],
                evidence=result
                | {
                    "summary": f"score {result['score']}: {', '.join(result['triggered'])}",
                    "candidate_processes": candidates,
                },  # fmt: skip
                explanation=(
                    "Several behavioural indicators crossed their thresholds together in one "
                    f"{self.settings.window_seconds:g} s window: {', '.join(result['triggered'])}. "
                    "Mass rewriting and renaming with rising entropy is how encrypting "
                    "ransomware behaves, but backups, archivers, sync clients and build tools "
                    "can do the same. "
                    "This is an early warning to investigate, not a confirmed infection."
                ),
                remediation=(
                    "Identify the writing process (candidates listed are heuristic), suspend it if "
                    "it is not expected, protect backups and do not delete the changed files."
                ),
                attribution=(
                    "heuristic: only process with open files or cwd inside the directory"
                    if unique
                    else f"unavailable: inotify has no PIDs ({len(candidates)} candidate(s))"
                ),
                process_key=key,
                pid=unique["pid"] if unique else None,
                process_name=unique["name"] if unique else None,
                detected_at=started,
            )
            finding.revision = revision_of(
                {"bucket": int(result["score"] // 10), "triggered": result["triggered"]}
            )
            raw.append(finding)
        findings, suppressed = self.policy.apply(raw)
        summary = {
            "mechanism": self.mechanism,
            "directories": per_directory,
            "watches": len(getattr(self.watcher, "watches", {})),
            "totals": dict(self.totals),
            "candidates": self.last_candidates,
            "weights": WEIGHTS,
            "alert_score": self.settings.alert_score,
            "min_indicators": self.settings.min_indicators,
        }
        status = "degraded" if self.watcher.overflows or self.watcher.watch_errors else "ok"
        return ScanReport(MODULE, status, started, time.perf_counter() - clock, findings, coverage,
                          summary, suppressed)  # fmt: skip

    def close(self) -> None:
        self.watcher.close()
