"""Socket snapshots from /proc/net with process attribution through /proc/PID/fd.

This is snapshot polling, not connection lifecycle capture:

* a connection that opens and closes between two snapshots is never seen;
* "first observed" is the first snapshot that contained the socket, not its connect time;
* a socket is attributed by finding `socket:[inode]` among a process's file descriptors.
  Other users' descriptors are unreadable without root, so their sockets stay
  unattributed; a socket shared by several processes (fork, fd passing) is ambiguous;
  TIME_WAIT sockets have no owner (inode 0).

The interface (snapshot -> list[Socket]) is deliberately small so an eBPF or audit source
can replace it later.
"""

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}
TABLES = (
    ("tcp", socket.AF_INET),
    ("tcp6", socket.AF_INET6),
    ("udp", socket.AF_INET),
    ("udp6", socket.AF_INET6),
)


@dataclass(frozen=True)
class Owner:
    pid: int
    start: str  # kernel start ticks: with the boot ID this is the process identity
    name: str
    ppid: int | None
    parent_start: str | None
    uid: int | None

    def key(self, host: str) -> str:
        import json

        return json.dumps([host, self.pid, self.start], separators=(",", ":"))


@dataclass
class Socket:
    protocol: str  # tcp, tcp6, udp, udp6
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int
    uid: int
    owners: list[Owner] = field(default_factory=list)
    attribution: str = "unattributed"

    @property
    def flow(self) -> tuple[str, str, int, str, int, int]:
        return (
            self.protocol,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.inode,
        )

    @property
    def remote(self) -> str:
        return (
            f"[{self.remote_ip}]:{self.remote_port}"
            if ":" in self.remote_ip
            else f"{self.remote_ip}:{self.remote_port}"
        )

    @property
    def connected(self) -> bool:
        return self.remote_port != 0 and self.state not in ("LISTEN", "TIME_WAIT", "CLOSE")

    def as_dict(self, host: str) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "local": f"{self.local_ip}:{self.local_port}",
            "remote": self.remote,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "state": self.state,
            "uid": self.uid,
            "inode": self.inode,
            "attribution": self.attribution,
            "processes": [
                {"pid": o.pid, "name": o.name, "process_key": o.key(host)} for o in self.owners
            ],
        }


def decode_address(text: str, family: int) -> tuple[str, int]:
    """/proc/net addresses are hex, in host byte order per 32-bit word."""
    address, port = text.split(":")
    raw = bytes.fromhex(address)
    if family == socket.AF_INET:
        packed = struct.pack("<I", struct.unpack(">I", raw)[0])
    else:
        packed = b"".join(
            struct.pack("<I", struct.unpack(">I", raw[i : i + 4])[0]) for i in range(0, 16, 4)
        )
    ip = ipaddress.ip_address(packed)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip), int(port, 16)


def parse_table(text: str, protocol: str, family: int) -> list[Socket]:
    sockets: list[Socket] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_ip, local_port = decode_address(parts[1], family)
            remote_ip, remote_port = decode_address(parts[2], family)
        except (ValueError, struct.error):
            continue
        state = TCP_STATES.get(parts[3], parts[3])
        if protocol.startswith("udp"):
            state = "CONNECTED" if remote_port else "UNCONNECTED"
        sockets.append(
            Socket(
                protocol,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state,
                int(parts[9]),
                int(parts[7]),
            )
        )
    return sockets


@dataclass
class Snapshot:
    taken_at: datetime
    sockets: list[Socket]
    fd_counts: dict[str, int]  # process key -> open descriptor count (readable processes)
    socket_counts: dict[str, int]  # process key -> sockets owned
    denied_processes: int
    host: str


class NetCollector:
    def __init__(self, root: Path = Path("/proc")) -> None:
        self.root = root
        try:
            self.host = (root / "sys/kernel/random/boot_id").read_text().strip() or "local"
        except OSError:
            self.host = "local"
        self.owner_cache: dict[int, Owner] = {}

    def _owner(self, pid: int) -> Owner | None:
        try:
            stat = (self.root / str(pid) / "stat").read_text()
        except OSError:
            return None
        left, right = stat.index("("), stat.rindex(")")
        tail = stat[right + 2 :].split()
        start = tail[19]
        cached = self.owner_cache.get(pid)
        if cached and cached.start == start:
            return cached
        ppid = int(tail[1])
        parent_start = None
        try:
            parent = (self.root / str(ppid) / "stat").read_text()
            candidate = parent[parent.rindex(")") + 2 :].split()[19]
            if int(candidate) <= int(start):  # parent cannot start after its child
                parent_start = candidate
        except (OSError, ValueError, IndexError):
            pass
        uid = None
        try:
            for line in (self.root / str(pid) / "status").read_text().splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
        except OSError:
            pass
        owner = Owner(pid, start, stat[left + 1 : right], ppid or None, parent_start, uid)
        self.owner_cache[pid] = owner
        return owner

    def snapshot(self) -> Snapshot:
        taken = datetime.now(UTC)
        sockets: list[Socket] = []
        for name, family in TABLES:
            try:
                sockets += parse_table((self.root / "net" / name).read_text(), name, family)
            except OSError:
                continue
        wanted = {s.inode for s in sockets if s.inode}
        holders: dict[int, list[int]] = {}
        fd_counts: dict[str, int] = {}
        socket_counts: dict[str, int] = {}
        denied = 0
        live: set[int] = set()
        for entry in os.scandir(self.root):
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                names = os.listdir(f"{entry.path}/fd")
            except PermissionError:
                denied += 1
                continue
            except OSError:
                continue
            live.add(pid)
            owned = 0
            for fd in names:
                try:
                    target = os.readlink(f"{entry.path}/fd/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    inode = int(target[8:-1])
                    if inode in wanted:
                        holders.setdefault(inode, []).append(pid)
                        owned += 1
            owner = self._owner(pid)
            if owner is not None:
                fd_counts[owner.key(self.host)] = len(names)
                socket_counts[owner.key(self.host)] = owned
        for pid in list(self.owner_cache):
            if pid not in live:
                del self.owner_cache[pid]
        for item in sockets:
            if not item.inode:
                item.attribution = "unattributed: no owning socket (inode 0, e.g. TIME_WAIT)"
                continue
            pids = sorted(set(holders.get(item.inode, [])))
            item.owners = [o for o in (self._owner(p) for p in pids) if o is not None]
            if not item.owners:
                item.attribution = "unattributed: owner's descriptors not readable (needs root)"
            elif len(item.owners) == 1:
                item.attribution = "unique"
            else:
                item.attribution = f"ambiguous: shared by {len(item.owners)} processes"
        return Snapshot(taken, sockets, fd_counts, socket_counts, denied, self.host)
