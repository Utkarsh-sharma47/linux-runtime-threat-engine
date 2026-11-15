"""Stage C: evidence collected around one Atomic run, without the live monitor.

Two kinds of evidence are kept apart:

* captured DURING execution: the strace process tree (see trace.py), process feature
  samples for anomaly scoring, /proc polling as a fallback when tracing is unavailable,
  and file events from an inotify watch on explicitly configured directories;
* STATE DIFFERENCES: module scans before and after the run (persistence locations,
  Merkle integrity, exposure, listening sockets). They show what changed, not which
  process changed it, and cannot reconstruct anything that happened and was undone
  between the two scans.
"""

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtime_engine.collector.net_collector import NetCollector
from runtime_engine.collector.proc_collector import ProcCollector
from runtime_engine.config.settings import Settings
from runtime_engine.security.anomaly import ProcessSampler
from runtime_engine.security.exposure import ExposureAnalyzer
from runtime_engine.security.findings import ScanReport
from runtime_engine.security.integrity import (
    IntegrityMonitor,
    MerkleTree,
    baseline_body,
    collect,
    leaves_from_body,
    verify_proof,
)
from runtime_engine.security.persistence import (
    PersistenceMonitor,
    entries_from_body,
    entries_to_body,
)
from runtime_engine.security.ransomware import RansomwareMonitor
from runtime_engine.security.scheduler import safe_scan


def write_private(path: Path, data: Any) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, default=str, sort_keys=True)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def listeners(snapshot_sockets: list[Any]) -> dict[str, dict[str, Any]]:
    found = {}
    for sock in snapshot_sockets:
        if sock.state == "LISTEN" or (sock.protocol.startswith("udp") and sock.remote_port == 0):
            key = f"{sock.protocol} {sock.local_ip}:{sock.local_port}"
            found[key] = {
                "socket": key,
                "uid": sock.uid,
                "owners": [o.name for o in sock.owners],
                "attribution": sock.attribution,
            }
    return found


@dataclass
class StateCollector:
    """Before/after scans with the existing security modules; baselines stay in the run."""

    settings: Settings
    directory: Path
    integrity_paths: list[str]
    reports: dict[str, Any] = field(default_factory=dict)

    def _path(self, name: str) -> Path:
        self.directory.mkdir(mode=0o700, exist_ok=True)
        return self.directory / name

    def before(self) -> None:
        security = self.settings.security
        persistence = PersistenceMonitor(security.persistence)
        current, coverage = persistence.collect()
        write_private(self._path("persistence-baseline.json"), entries_to_body(current, coverage))
        leaves, cov = collect(self.integrity_paths, security.integrity, {}, full=True)
        write_private(
            self._path("integrity-baseline.json"), baseline_body(self.integrity_paths, leaves, cov)
        )
        exposure = safe_scan(ExposureAnalyzer(security.exposure))
        write_private(self._path("exposure-before.json"), exposure.as_dict())
        snapshot = NetCollector().snapshot()
        write_private(self._path("listeners-before.json"), listeners(snapshot.sockets))

    def after(self, label: str = "after") -> dict[str, Any]:
        """Compare the current state with the stored baselines; reusable after cleanup."""
        security = self.settings.security
        result: dict[str, Any] = {"label": label, "taken_at": datetime.now(UTC).isoformat()}
        body = read_json(self._path("persistence-baseline.json"))
        if body is not None:
            monitor = PersistenceMonitor(
                security.persistence, None, entries_from_body(body), "before the Atomic run"
            )
            result["persistence"] = safe_scan(monitor).as_dict()
        integrity = read_json(self._path("integrity-baseline.json"))
        if integrity is not None:
            result["integrity"] = integrity_after(security.integrity, integrity)
        before = read_json(self._path("exposure-before.json")) or {}
        known = {
            (f["finding_id"], f.get("revision")) for f in (before.get("findings") or [])
        }  # fmt: skip
        now = safe_scan(ExposureAnalyzer(security.exposure)).as_dict()
        now["new_findings"] = [
            f for f in now.get("findings", []) if (f["finding_id"], f.get("revision")) not in known
        ]
        now["preexisting_findings"] = len(now.get("findings", [])) - len(now["new_findings"])
        now.pop("findings", None)
        result["exposure"] = now
        old = read_json(self._path("listeners-before.json")) or {}
        current = listeners(NetCollector().snapshot().sockets)
        result["listeners"] = {
            "new": [v for k, v in current.items() if k not in old],
            "closed": [v for k, v in old.items() if k not in current],
        }
        write_private(self._path(f"state-{label}.json"), result)
        return result


def integrity_after(settings: Any, baseline: dict[str, Any]) -> dict[str, Any]:
    monitor = IntegrityMonitor(settings, baseline)
    report = monitor.scan(full=True)
    data = report.as_dict()
    result = monitor.last_result or {}
    proofs = []
    old_leaves = leaves_from_body(baseline)
    old_tree = MerkleTree(list(old_leaves.values()))
    new_tree = MerkleTree(list(monitor.previous.values()))
    for item in (result.get("modified") or [])[:5] + (result.get("metadata_changed") or [])[:5]:
        path = item.get("path")
        leaf = old_leaves.get(path)
        if leaf is None:
            continue
        steps = old_tree.proof(path)
        proofs.append(
            {
                "path": path,
                "baseline_leaf": leaf.hash().hex(),
                "proof_steps": len(steps),
                "verifies_against_baseline_root": verify_proof(
                    leaf.hash().hex(), steps, baseline["root"]
                ),
                "baseline_proof_verifies_against_current_root": verify_proof(
                    leaf.hash().hex(), steps, new_tree.root
                ),
            }
        )
        current = monitor.previous.get(path)
        if current is not None:
            proofs[-1]["current_leaf"] = current.hash().hex()
            proofs[-1]["current_proof_verifies_against_current_root"] = verify_proof(
                current.hash().hex(), new_tree.proof(path), new_tree.root
            )
    data["proofs"] = proofs
    data["changes"] = {
        k: [i.get("path") for i in result.get(k, [])]
        for k in ("added", "deleted", "modified", "metadata_changed")
    }
    return data


class DuringCollector:
    """Samples the test's process tree while it runs (a background thread, no monitor)."""

    def __init__(
        self,
        root_pid: int,
        *,
        interval: float = 0.25,
        poll_events: bool = False,
        ransomware: RansomwareMonitor | None = None,
    ) -> None:
        self.root_pid = root_pid
        self.interval = interval
        self.sampler = ProcessSampler()
        self.poll = ProcCollector() if poll_events else None
        self.ransomware = ransomware
        self.samples: dict[str, dict[str, Any]] = {}
        self.events: dict[str, Any] = {}
        self.ransomware_reports: list[ScanReport] = []
        self.passes = 0
        self.errors = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="atomic-evidence", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def finish(self) -> None:
        self.stop.set()
        self.thread.join(10)
        self._pass()  # one last pass after the test ended
        if self.ransomware is not None:
            self.ransomware_reports.append(safe_scan(self.ransomware))

    def _descendants(self, parents: dict[int, int]) -> set[int]:
        found = {self.root_pid}
        changed = True
        while changed:
            changed = False
            for pid, ppid in parents.items():
                if ppid in found and pid not in found:
                    found.add(pid)
                    changed = True
        found.discard(self.root_pid)
        return found

    def _pass(self) -> None:
        try:
            samples, _ = self.sampler.samples()
            mine = self._descendants({s.pid: s.ppid for s in samples})
            rows = self.sampler.features([s for s in samples if s.pid in mine], None)
            for sample in samples:
                if sample.pid in mine and sample.key in rows:
                    self.samples[sample.key] = {
                        "process_key": sample.key,
                        "pid": sample.pid,
                        "ppid": sample.ppid,
                        "process": sample.name,
                        "exe": sample.exe,
                        "sampled_at": time.time(),
                        "features": rows[sample.key],
                    }
            if self.poll is not None:
                events = list(self.poll.collect())
                parents = {e.pid: e.ppid for e in events if e.pid and e.ppid is not None}
                tree = self._descendants(parents)
                for event in events:
                    if event.pid in tree and event.process_key not in self.events:
                        self.events[str(event.process_key)] = event.model_dump(mode="json") | {
                            "metadata": event.metadata | {"collector": "atomic-proc-poll"}
                        }
            if self.ransomware is not None:
                self.ransomware_reports.append(safe_scan(self.ransomware))
            self.passes += 1
        except Exception:  # sampling must never abort the run
            self.errors += 1

    def _run(self) -> None:
        while not self.stop.wait(self.interval):
            self._pass()
