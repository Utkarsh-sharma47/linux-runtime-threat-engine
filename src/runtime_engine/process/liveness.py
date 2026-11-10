"""Read-only check whether an observed identity is still the process visible under its PID.

A bare PID is never trusted: the boot ID and start ticks must both match, otherwise the
caller must present stored information as historical.
"""

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from runtime_engine.events.schema import Event


@dataclass(frozen=True)
class Liveness:
    running: bool
    label: str
    detail: str


def check(event: Event, root: Path = Path("/proc")) -> Liveness:
    if event.source != "proc" or event.pid is None or event.process_start_time is None:
        return Liveness(False, "HISTORICAL", "replayed or non-/proc telemetry; not checked live")
    try:
        boot_id = (root / "sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return Liveness(False, "UNKNOWN", "boot ID unreadable; cannot verify identity")
    if boot_id != event.host_id:
        return Liveness(False, "HISTORICAL", "observed during a different boot")
    try:
        stat = (root / str(event.pid) / "stat").read_text()
        start = stat[stat.rindex(")") + 2 :].split()[19]
    except (OSError, ValueError, IndexError):
        return Liveness(
            False, "HISTORICAL", "process no longer visible (exited or hidden); stored data"
        )
    if start != event.process_start_time:
        return Liveness(
            False,
            "HISTORICAL",
            "PID now belongs to a different process (start time differs); stored data",
        )
    return Liveness(True, "RUNNING", "identity verified by boot ID, PID and start ticks")


def start_time(event: Event, root: Path = Path("/proc")) -> datetime | None:
    """Wall-clock start derived from boot time + start ticks, only for this boot's /proc data."""
    if event.source != "proc" or event.process_start_time is None:
        return None
    try:
        if (root / "sys/kernel/random/boot_id").read_text().strip() != event.host_id:
            return None
        boot = next(
            int(line.split()[1])
            for line in (root / "stat").read_text().splitlines()
            if line.startswith("btime ")
        )
        ticks = int(event.process_start_time)
        hertz = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, StopIteration, IndexError):
        return None
    return datetime.fromtimestamp(boot + ticks / hertz, UTC)
