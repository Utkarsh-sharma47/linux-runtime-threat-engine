"""Read-only /proc snapshots. This is not a kernel event feed."""

import logging
import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from runtime_engine.events.schema import Event, EventType

logger = logging.getLogger(__name__)


class ProcCollector:
    """Discover identities newly visible since the last successful snapshot.

    A disappeared entry is not reported as PROCESS_EXIT: invisibility is not exit evidence.
    The first snapshot includes all visible processes. Command lines are opt-in.
    """

    def __init__(self, root: Path = Path("/proc"), *, include_cmdline: bool = False) -> None:
        self.root = root
        self.include_cmdline = include_cmdline
        self.seen: set[str] = set()
        self.errors = 0
        self.rejected = 0
        self.host_id = (root / "sys/kernel/random/boot_id").read_text().strip()
        if not self.host_id:
            raise ValueError("a boot ID is required for safe process identity")

    def _read(self, folder: Path, timestamp: datetime) -> Event:
        stat = (folder / "stat").read_text()
        left, right = stat.index("("), stat.rindex(")")
        pid = int(stat[:left].strip())
        if pid != int(folder.name):
            raise ValueError("PID changed during collection")
        tail = stat[right + 2 :].split()
        ppid, start = int(tail[1]), tail[19]  # fields 4 and 22 in proc_pid_stat(5)
        int(start)
        uid = None
        for line in (folder / "status").read_text().splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
                break
        exe = None
        try:
            exe = os.readlink(folder / "exe")
        except FileNotFoundError:
            pass  # kernel threads and racing exits may lack exe
        except PermissionError:
            self.errors += 1
            logger.debug("proc_exe_denied pid=%d", pid)
        cmdline = None
        if self.include_cmdline:
            try:
                cmdline = [
                    p.decode("utf-8", errors="replace")
                    for p in (folder / "cmdline").read_bytes().split(b"\0")
                    if p
                ]
            except (PermissionError, FileNotFoundError):
                self.errors += 1
                logger.debug("proc_cmdline_unavailable pid=%d", pid)
        # Recheck start ticks after reading other fields to avoid mixing a reused PID.
        check = (folder / "stat").read_text()
        if check[check.rindex(")") + 2 :].split()[19] != start:
            raise ValueError("PID reused while reading")
        return Event(
            timestamp=timestamp,
            event_type=EventType.PROCESS_START,
            pid=pid,
            ppid=ppid,
            process_name=stat[left + 1 : right],
            executable_path=exe,
            command_line=cmdline,
            uid=uid,
            process_start_time=start,
            host_id=self.host_id,
            source="proc",
            metadata={"observation": "poll_discovery", "start_time_unit": "boot_ticks"},
        )

    def collect(self) -> Iterator[Event]:
        """Take one snapshot, enriching parent identity from the same snapshot only."""
        snapshot: dict[int, Event] = {}
        timestamp = datetime.now(UTC)
        for folder in sorted(self.root.iterdir()):
            if not folder.name.isdigit():
                continue
            try:
                event = self._read(folder, timestamp)
                assert event.pid is not None
                snapshot[event.pid] = event
            except (OSError, ValueError, IndexError) as exc:
                self.errors += 1
                logger.debug(
                    "proc_read_failed pid=%s error_type=%s", folder.name, type(exc).__name__
                )
        current: set[str] = set()
        for event in snapshot.values():
            parent = snapshot.get(event.ppid or 0)
            # A parent must have begun no later than its child; guard against PID reuse.
            if (
                parent is not None
                and parent.process_start_time is not None
                and event.process_start_time is not None
                and int(parent.process_start_time) <= int(event.process_start_time)
            ):
                event.parent_start_time = parent.process_start_time
                event.parent_process_name = parent.process_name
            key = event.process_key
            assert key is not None
            current.add(key)
            if key not in self.seen:
                yield event
        # Keep failed/invisible entries in seen to avoid repeated detections after transient errors.
        self.seen.update(current)
