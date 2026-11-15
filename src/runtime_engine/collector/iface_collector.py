"""Host network interface discovery from /sys/class/net and /proc/net/dev.

Provides counters and throughput deltas. This is socket/interface statistics, not
packet capture. Permissions and virtual interfaces (docker, veth, VPN) are normal.
"""

from __future__ import annotations

import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class InterfaceStats:
    name: str
    state: str = "unknown"
    if_type: str = "unknown"
    mac: str | None = None
    mtu: int | None = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    rx_bps: float | None = None  # bytes/sec since previous sample
    tx_bps: float | None = None
    is_default: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RouteInfo:
    default_gateway: str | None = None
    default_interface: str | None = None
    source: str = "/proc/net/route"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InterfaceSnapshot:
    taken_at: float
    interfaces: list[InterfaceStats]
    route: RouteInfo
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "taken_at": self.taken_at,
            "interfaces": [i.as_dict() for i in self.interfaces],
            "route": self.route.as_dict(),
            "errors": list(self.errors),
            "limitation": (
                "Interface counters from /proc/net/dev and /sys/class/net. "
                "Throughput is a delta between samples, not instantaneous wire speed. "
                "Not packet-level monitoring."
            ),
        }


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _read_int(path: Path) -> int | None:
    text = _read_text(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def default_route(root: Path = Path("/proc")) -> RouteInfo:
    """Parse IPv4 default route from /proc/net/route (destination 00000000)."""
    path = root / "net" / "route"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return RouteInfo(source=str(path))
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gateway, flags = parts[0], parts[1], parts[2], parts[3]
        try:
            if int(dest, 16) != 0:
                continue
            if int(flags, 16) & 0x2 == 0:  # RTF_GATEWAY
                continue
            gw = socket.inet_ntoa(int(gateway, 16).to_bytes(4, "little"))
            return RouteInfo(default_gateway=gw, default_interface=iface, source=str(path))
        except (ValueError, OSError):
            continue
    return RouteInfo(source=str(path))


def parse_netdev(text: str) -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev into {iface: counters}."""
    result: dict[str, dict[str, int]] = {}
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        cols = rest.split()
        if len(cols) < 16:
            continue
        try:
            result[name] = {
                "rx_bytes": int(cols[0]),
                "rx_packets": int(cols[1]),
                "rx_errors": int(cols[2]),
                "rx_dropped": int(cols[3]),
                "tx_bytes": int(cols[8]),
                "tx_packets": int(cols[9]),
                "tx_errors": int(cols[10]),
                "tx_dropped": int(cols[11]),
            }
        except ValueError:
            continue
    return result


def _iface_addresses(name: str) -> tuple[list[str], list[str]]:
    """Best-effort address listing via getaddrinfo on interface hostname is unreliable;

    Prefer /sys and /proc/net/fib_trie is heavy — use `ip -j` only if available later.
    Here we read IPv4 from /proc/net/fib_trie is complex; use socket on Linux via
    netlink-free approach: parse `ip addr` is forbidden (subprocess). Use
    `/sys/class/net/<iface>/` only for L2; for IPs use getifaddrs via stdlib when
    available (Python 3.8+ has no getifaddrs). Fall back to empty and note gap.
    """
    # Prefer psutil-free: attempt reading from /proc/net/if_inet6 and ARP-less IPv4
    # via ioctl is platform-specific. Keep empty with a note if unavailable.
    ipv4: list[str] = []
    ipv6: list[str] = []
    try:
        import fcntl
        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # SIOCGIFADDR
            ifreq = struct.pack("256s", name[:15].encode("utf-8"))
            res = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)
            addr = socket.inet_ntoa(res[20:24])
            if addr and addr != "0.0.0.0":
                ipv4.append(addr)
        except OSError:
            pass
        finally:
            sock.close()
    except OSError:
        pass
    inet6 = Path("/proc/net/if_inet6")
    try:
        for line in inet6.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            if parts[5] != name:
                continue
            raw = parts[0]
            groups = [raw[i : i + 4] for i in range(0, 32, 4)]
            ipv6.append(":".join(groups))
    except OSError:
        pass
    return ipv4, ipv6


def _type_from_sys(sys_iface: Path) -> str:
    type_code = _read_int(sys_iface / "type")
    # ARP hardware identifiers (subset)
    mapping = {1: "ethernet", 772: "loopback", 778: "gre", 65534: "tunnel"}
    if type_code in mapping:
        return mapping[type_code]
    wireless = sys_iface / "wireless"
    if wireless.exists():
        return "wifi"
    return "other" if type_code is None else f"type-{type_code}"


class IfaceCollector:
    """Snapshot host interfaces; keep prior counters to compute throughput."""

    def __init__(
        self, proc: Path = Path("/proc"), sys_class: Path = Path("/sys/class/net")
    ) -> None:
        self.proc = proc
        self.sys_class = sys_class
        self._previous: dict[str, dict[str, int]] = {}
        self._previous_at: float | None = None
        self.errors = 0

    def snapshot(self) -> InterfaceSnapshot:
        now = time.monotonic()
        errors: list[str] = []
        route = default_route(self.proc)
        counters: dict[str, dict[str, int]] = {}
        try:
            counters = parse_netdev((self.proc / "net" / "dev").read_text(encoding="utf-8"))
        except OSError as exc:
            errors.append(f"/proc/net/dev unreadable: {exc}")
            self.errors += 1

        name_set = set(counters)
        if self.sys_class.is_dir():
            name_set |= {p.name for p in self.sys_class.iterdir() if p.is_dir()}
        names = sorted(name_set)
        elapsed = None if self._previous_at is None else max(now - self._previous_at, 1e-6)
        interfaces: list[InterfaceStats] = []
        for name in names:
            sys_iface = self.sys_class / name
            stats = InterfaceStats(name=name)
            if sys_iface.is_dir():
                stats.state = (_read_text(sys_iface / "operstate") or "unknown").lower()
                stats.mtu = _read_int(sys_iface / "mtu")
                stats.mac = _read_text(sys_iface / "address")
                stats.if_type = _type_from_sys(sys_iface)
            else:
                stats.notes.append("no /sys/class/net entry")
            c = counters.get(name, {})
            for key in (
                "rx_bytes",
                "tx_bytes",
                "rx_packets",
                "tx_packets",
                "rx_errors",
                "tx_errors",
                "rx_dropped",
                "tx_dropped",
            ):
                setattr(stats, key, c.get(key, 0))
            if elapsed is not None and name in self._previous:
                prev = self._previous[name]
                stats.rx_bps = (stats.rx_bytes - prev.get("rx_bytes", 0)) / elapsed
                stats.tx_bps = (stats.tx_bytes - prev.get("tx_bytes", 0)) / elapsed
            ipv4, ipv6 = _iface_addresses(name)
            stats.ipv4 = ipv4
            stats.ipv6 = ipv6
            if not ipv4 and not ipv6:
                stats.notes.append("addresses unavailable without extra privileges/API")
            if route.default_interface == name:
                stats.is_default = True
            interfaces.append(stats)

        self._previous = {n: dict(counters.get(n, {})) for n in names}
        self._previous_at = now
        return InterfaceSnapshot(now, interfaces, route, errors)


def format_bps(value: float | None) -> str:
    if value is None:
        return "n/a (need 2 samples)"
    if value < 1024:
        return f"{value:.0f} B/s"
    if value < 1024**2:
        return f"{value / 1024:.1f} KiB/s"
    return f"{value / 1024**2:.2f} MiB/s"


__all__ = [
    "IfaceCollector",
    "InterfaceSnapshot",
    "InterfaceStats",
    "RouteInfo",
    "default_route",
    "format_bps",
    "parse_netdev",
]
