"""Network behaviour: connection telemetry, per-process statistics and beacon analysis.

Each scan takes a socket snapshot. Sockets not present in the previous snapshot are
"newly observed" and become NETWORK_CONNECTION events in the existing pipeline (so YAML
rules such as RT006 and ancestry correlation apply). The analyzer keeps a bounded
history of first-observed times per (process, destination) and computes:

* repeated destinations: new connections to one endpoint within a window;
* periodicity: inter-arrival times Δt_i of new connections, mean μ, population standard
  deviation σ and coefficient of variation CV = σ / μ. A low CV means regular timing.
  Regular timing is common for legitimate software (NTP, update checks, health probes,
  telemetry), so NB001 is an indicator to investigate, never proof of C2. Polling
  quantizes every Δt to the scan interval and misses connections shorter than it.
"""

import ipaddress
import statistics
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any

from runtime_engine.collector.net_collector import NetCollector, Snapshot, Socket
from runtime_engine.config.settings import NetworkSettings
from runtime_engine.events.schema import Event, EventType, Severity
from runtime_engine.security.findings import Coverage, Finding, ScanReport, SeverityPolicy

MODULE = "network"
UNATTRIBUTED = "unattributed"


def periodicity(times: list[float]) -> dict[str, Any] | None:
    """Inter-arrival statistics; None with fewer than three observations."""
    ordered = sorted(times)
    if len(ordered) < 3:
        return None
    intervals = [b - a for a, b in pairwise(ordered)]
    mean = statistics.fmean(intervals)
    stdev = statistics.pstdev(intervals)
    return {
        "connections": len(ordered),
        "mean_interval_seconds": round(mean, 3),
        "stdev_seconds": round(stdev, 3),
        "cv": round(stdev / mean, 4) if mean > 0 else None,
        "recent_intervals": [round(i, 2) for i in intervals[-10:]],
    }


@dataclass
class FlowHistory:
    process_key: str | None
    process_name: str | None
    pid: int | None
    destination: str
    times: deque[float]


class BeaconAnalyzer:
    """Bounded histories: `max_flows` (process, destination) pairs, LRU-evicted."""

    def __init__(self, settings: NetworkSettings) -> None:
        self.settings = settings
        self.flows: OrderedDict[tuple[str, str], FlowHistory] = OrderedDict()
        self.evicted = 0

    def observe(
        self,
        when: float,
        destination: str,
        process_key: str | None,
        process_name: str | None,
        pid: int | None,
    ) -> FlowHistory:
        key = (process_key or UNATTRIBUTED, destination)
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowHistory(
                process_key,
                process_name,
                pid,
                destination,
                deque(maxlen=self.settings.history_per_flow),
            )
            self.flows[key] = flow
            if len(self.flows) > self.settings.max_tracked_flows:
                self.flows.popitem(last=False)
                self.evicted += 1
        else:
            self.flows.move_to_end(key)
        flow.times.append(when)
        return flow

    def evaluate(self, flow: FlowHistory, now: float) -> list[tuple[str, Severity, dict[str, Any]]]:
        s = self.settings
        results: list[tuple[str, Severity, dict[str, Any]]] = []
        recent = [t for t in flow.times if now - t <= s.repeat_window_seconds]
        if len(recent) >= s.repeat_threshold:
            results.append(
                (
                    "NB002",
                    Severity.LOW,
                    {
                        "summary": (
                            f"{len(recent)} new connections in {s.repeat_window_seconds:g} s"
                        ),
                        "connections_in_window": len(recent),
                        "window_seconds": s.repeat_window_seconds,
                        "threshold": s.repeat_threshold,
                    },
                )
            )
        stats = periodicity(list(flow.times))
        if (
            stats is not None
            and stats["connections"] >= s.beacon_min_connections
            and stats["cv"] is not None
            and stats["cv"] <= s.beacon_cv_threshold
            and s.beacon_min_interval_seconds
            <= stats["mean_interval_seconds"]
            <= s.beacon_max_interval_seconds
        ):
            results.append(
                (
                    "NB001",
                    Severity.LOW,
                    stats
                    | {
                        "summary": (
                            f"{stats['connections']} connections, mean interval "
                            f"{stats['mean_interval_seconds']:.1f} s, CV {stats['cv']:.3f}"
                        ),
                        "cv_threshold": s.beacon_cv_threshold,
                        "poll_interval_seconds": s.interval_seconds,
                    },
                )
            )
        return results


RULES = {
    "NB001": (
        "Periodic outbound connections (possible beaconing)",
        "Connection start times to this destination are regular (low coefficient of "
        "variation of inter-arrival times). Beaconing malware is periodic, but so are NTP, "
        "update checks, health probes and telemetry; this is an indicator, not proof of "
        "command-and-control. Start times are first-observed snapshot times, quantized to "
        "the scan interval.",
        "https://attack.mitre.org/techniques/T1071/",
    ),
    "NB002": (
        "Many new connections to one destination",
        "The process opened many new connections to the same endpoint in a short window. "
        "Polling only counts connections that existed at a snapshot.",
        "https://attack.mitre.org/techniques/T1071/",
    ),
}


def analyze_series(
    records: list[dict[str, Any]], settings: NetworkSettings
) -> list[dict[str, Any]]:
    """Offline analysis of {"time", "destination", "process"?, "pid"?} records.

    Uses the same analyzer and thresholds as live monitoring, so recorded or synthetic
    connection timelines can be examined without generating real traffic.
    """
    analyzer = BeaconAnalyzer(settings)
    ordered = sorted(records, key=lambda r: float(r["time"]))
    for record in ordered:
        name = record.get("process")
        analyzer.observe(
            float(record["time"]), str(record["destination"]), name, name, record.get("pid")
        )
    now = float(ordered[-1]["time"]) if ordered else 0.0
    results = []
    for flow in analyzer.flows.values():
        flagged = analyzer.evaluate(flow, now)
        results.append(
            {
                "process": flow.process_name or UNATTRIBUTED,
                "destination": flow.destination,
                "periodicity": periodicity(list(flow.times)),
                "rules": [rule for rule, _, _ in flagged],
            }
        )
    return results


def demo_series(seed: int = 7) -> list[dict[str, Any]]:
    """Synthetic timelines only: no traffic is generated.

    * beacon-sim: every 60 s with ±1.5 s jitter (regular, like a simple beacon)
    * ntp-client: every 1024 s with ±0.5 s jitter (regular and legitimate)
    * browser: exponential gaps averaging 40 s (irregular human-driven traffic)
    """
    import random

    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    t = 0.0
    for _ in range(20):
        t += 60 + rng.uniform(-1.5, 1.5)
        records.append({"time": t, "destination": "198.51.100.7:443", "process": "beacon-sim"})
    t = 0.0
    for _ in range(8):
        t += 1024 + rng.uniform(-0.5, 0.5)
        records.append({"time": t, "destination": "192.0.2.123:123", "process": "ntp-client"})
    t = 0.0
    for _ in range(25):
        t += rng.expovariate(1 / 40)
        records.append({"time": t, "destination": "203.0.113.80:443", "process": "browser"})
    return records


def excluded(ip: str, settings: NetworkSettings) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if address.is_unspecified:
        return True
    if not settings.include_loopback and (address.is_loopback or address.is_link_local):
        return True
    return any(
        address in ipaddress.ip_network(cidr, strict=False) for cidr in settings.exclude_cidrs
    )


def analyze_records(
    records: list[dict[str, Any]], settings: NetworkSettings
) -> list[dict[str, Any]]:
    """Offline analysis of connection start records with the live analyzer and thresholds.

    Each record: {"time": seconds, "destination": "ip:port", "process": name, "pid": int}.
    """
    analyzer = BeaconAnalyzer(settings)
    flags: dict[tuple[str, str], set[str]] = {}
    for record in sorted(records, key=lambda r: float(r["time"])):
        name = str(record.get("process", UNATTRIBUTED))
        key = f"{name}:{record.get('pid')}"
        flow = analyzer.observe(
            float(record["time"]), str(record["destination"]), key, name, record.get("pid")
        )
        for rule, _, _ in analyzer.evaluate(flow, float(record["time"])):
            flags.setdefault((key, flow.destination), set()).add(rule)
    return [
        {
            "process": flow.process_name,
            "pid": flow.pid,
            "destination": flow.destination,
            "periodicity": periodicity(list(flow.times)),
            "indicators": sorted(
                flags.get((flow.process_key or UNATTRIBUTED, flow.destination), set())
            ),
        }
        for flow in analyzer.flows.values()
    ]


def demo_records(seed: int = 7) -> list[dict[str, Any]]:
    """Synthetic connection timelines (no network traffic): a beacon-like client, a
    legitimate NTP-like client that is also periodic, and irregular browsing."""
    import random

    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    t = 0.0
    for _ in range(20):  # 60 s period, ±2 s jitter
        t += 60 + rng.uniform(-2, 2)
        records.append(
            {"time": t, "destination": "198.51.100.23:443", "process": "beacon-sim", "pid": 4100}
        )
    t = 0.0
    for _ in range(8):  # NTP-like 1024 s poll: legitimate yet periodic
        t += 1024 + rng.uniform(-1, 1)
        records.append(
            {"time": t, "destination": "192.0.2.123:123", "process": "chronyd", "pid": 610}
        )
    t = 0.0
    for _ in range(25):  # human browsing: bursty, exponential gaps
        t += rng.expovariate(1 / 45)
        records.append(
            {"time": t, "destination": "203.0.113.80:443", "process": "browser", "pid": 2200}
        )
    return records


class NetworkMonitor:
    name = MODULE

    def __init__(
        self,
        settings: NetworkSettings,
        policy: SeverityPolicy | None = None,
        collector: NetCollector | None = None,
    ) -> None:
        self.settings = settings
        self.interval = settings.interval_seconds
        self.policy = policy or SeverityPolicy(
            overrides=settings.severity_overrides, allow=settings.allow
        )
        self.collector = collector or NetCollector()
        from runtime_engine.collector.iface_collector import IfaceCollector

        self.ifaces = IfaceCollector()
        self.analyzer = BeaconAnalyzer(settings)
        self.previous: set[tuple[Any, ...]] | None = None
        self.new_total = 0
        self.per_process: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def _event(self, snap: Snapshot, item: Socket) -> Event:
        owner = item.owners[0] if len(item.owners) == 1 else None
        return Event(
            timestamp=snap.taken_at,
            event_type=EventType.NETWORK_CONNECTION,
            pid=owner.pid if owner else None,
            ppid=owner.ppid if owner else None,
            process_name=owner.name if owner else None,
            uid=item.uid,
            process_start_time=owner.start if owner else None,
            parent_start_time=owner.parent_start if owner else None,
            host_id=snap.host,
            network_destination=item.remote_ip,
            source="proc_net",
            metadata={
                "protocol": item.protocol,
                "remote_port": item.remote_port,
                "local": f"{item.local_ip}:{item.local_port}",
                "state": item.state,
                "attribution": item.attribution,
                "observation": "snapshot: first observed, not connect time",
            },
        )

    def _track(
        self, key: str, name: str | None, pid: int | None, destination: str, now: float
    ) -> None:
        stats = self.per_process.get(key)
        if stats is None:
            stats = {
                "process": name,
                "pid": pid,
                "new": 0,
                "destinations": set(),
                "times": deque(maxlen=200),
            }
            self.per_process[key] = stats
            if len(self.per_process) > self.settings.max_tracked_flows:
                self.per_process.popitem(last=False)
        self.per_process.move_to_end(key)
        stats["new"] += 1
        if len(stats["destinations"]) < 500:
            stats["destinations"].add(destination)
        stats["times"].append(now)

    def scan(self) -> ScanReport:
        started = datetime.now(UTC)
        clock = time.perf_counter()
        snap = self.collector.snapshot()
        now = snap.taken_at.timestamp()
        coverage = Coverage(checked=len(snap.sockets))
        coverage.denied_count = snap.denied_processes
        if snap.denied_processes:
            coverage.unavailable.append(
                f"descriptors of {snap.denied_processes} processes (other users) are unreadable "
                "without root: their sockets are unattributed"
            )
        connected = [
            s for s in snap.sockets if s.connected and not excluded(s.remote_ip, self.settings)
        ]
        flows = {s.flow for s in connected}
        previous = self.previous
        first = previous is None
        new = [] if previous is None else [s for s in connected if s.flow not in previous]
        self.previous = flows
        events: list[Event] = []
        raw: list[Finding] = []
        for item in new:
            self.new_total += 1
            if self.settings.emit_events:
                events.append(self._event(snap, item))
            owner = item.owners[0] if len(item.owners) == 1 else None
            key = owner.key(snap.host) if owner else None
            name = owner.name if owner else None
            pid = owner.pid if owner else None
            self._track(key or UNATTRIBUTED, name, pid, item.remote, now)
            flow = self.analyzer.observe(now, item.remote, key, name, pid)
            for rule, severity, evidence in self.analyzer.evaluate(flow, now):
                title, explanation, reference = RULES[rule]
                raw.append(
                    Finding.create(
                        MODULE,
                        rule,
                        f"{name or UNATTRIBUTED}->{item.remote}",
                        title=title,
                        severity=severity,
                        evidence=evidence
                        | {
                            "remote": item.remote_ip,
                            "destination": item.remote,
                            "protocol": item.protocol,
                            "attribution": item.attribution,
                        },
                        explanation=explanation,
                        mitre_reference=reference,
                        attribution=item.attribution,
                        process_key=key,
                        pid=pid,
                        process_name=name,
                        detected_at=snap.taken_at,
                    )
                )
        findings, suppressed = self.policy.apply(raw)
        # The first snapshot only records existing connections; they are not "new".
        status = "baseline-created" if first else "degraded" if snap.denied_processes else "ok"
        summary = self._summary(snap, connected, len(new), now)
        return ScanReport(
            MODULE,
            status,
            started,
            time.perf_counter() - clock,
            findings,
            coverage,
            summary,
            suppressed,
            events=events,
        )

    def _summary(
        self, snap: Snapshot, connected: list[Socket], new: int, now: float
    ) -> dict[str, Any]:
        listening = [s for s in snap.sockets if s.state == "LISTEN" or s.state == "UNCONNECTED"]
        processes = []
        for key, stats in reversed(self.per_process.items()):
            recent = [t for t in stats["times"] if now - t <= 600]
            processes.append(
                {
                    "process_key": key,
                    "process": stats["process"],
                    "pid": stats["pid"],
                    "new_connections": stats["new"],
                    "per_minute_10m": round(len(recent) / 10, 2),
                    "destinations": len(stats["destinations"]),
                }
            )
        flows = sorted(
            (f for f in self.analyzer.flows.values() if len(f.times) >= 2),
            key=lambda f: len(f.times),
            reverse=True,
        )
        repeated: list[dict[str, Any]] = [
            {
                "process": f.process_name or UNATTRIBUTED,
                "pid": f.pid,
                "destination": f.destination,
                "connections": len(f.times),
                "periodicity": periodicity(list(f.times)),
            }
            for f in flows
        ]
        return {
            "taken_at": snap.taken_at.isoformat(),
            "sockets": len(snap.sockets),
            "connected": len(connected),
            "new_this_scan": new,
            "new_total": self.new_total,
            "listening": len(listening),
            "connections": [s.as_dict(snap.host) for s in connected[:300]],
            "listeners": [s.as_dict(snap.host) for s in listening[:100]],
            "processes": processes[:100],
            "repeated": repeated[:50],
            "tracked_flows": len(self.analyzer.flows),
            "evicted_flows": self.analyzer.evicted,
            "denied_processes": snap.denied_processes,
            "process_resources": {
                key: {"fds": snap.fd_counts[key], "sockets": snap.socket_counts.get(key, 0)}
                for key in snap.fd_counts
            },
            "interfaces": self.ifaces.snapshot().as_dict(),
        }
