"""Host network interface discovery and RX/TX throughput (delta-based)."""

from __future__ import annotations

from pathlib import Path

import pytest

from runtime_engine.collector.iface_collector import (
    IfaceCollector,
    default_route,
    format_bps,
    parse_netdev,
)

# Minimal /proc/net/dev lines (header ignored; 16 numeric columns after the colon).
_HDR = "Inter-| Receive | Transmit\n face |bytes packets ... |bytes packets ...\n"
_LO_1 = "    lo: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
_ETH = "  eth0: 5000 50 1 2 0 0 0 0 8000 80 3 4 0 0 0 0\n"
_LO_2 = "    lo: 3000 30 0 0 0 0 0 0 6000 60 0 0 0 0 0 0\n"


def test_parse_netdev_counters():
    parsed = parse_netdev(_HDR + _LO_1 + _ETH)
    assert parsed["lo"]["rx_bytes"] == 1000
    assert parsed["eth0"]["tx_bytes"] == 8000
    assert parsed["eth0"]["rx_errors"] == 1
    assert parsed["eth0"]["tx_dropped"] == 4


def test_default_route_from_fixture(tmp_path: Path):
    proc = tmp_path / "proc"
    net = proc / "net"
    net.mkdir(parents=True)
    # Destination 00000000, gateway 0100A8C0 = 192.168.0.1 little-endian, flags 0003
    (net / "route").write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
        encoding="utf-8",
    )
    route = default_route(proc)
    assert route.default_interface == "eth0"
    assert route.default_gateway == "192.168.0.1"


def test_throughput_is_delta_not_cumulative(tmp_path: Path, monkeypatch):
    proc = tmp_path / "proc"
    net = proc / "net"
    net.mkdir(parents=True)
    sys_class = tmp_path / "sys" / "class" / "net"
    lo = sys_class / "lo"
    lo.mkdir(parents=True)
    (lo / "operstate").write_text("up\n", encoding="utf-8")
    (lo / "mtu").write_text("65536\n", encoding="utf-8")
    (lo / "type").write_text("772\n", encoding="utf-8")
    (lo / "address").write_text("00:00:00:00:00:00\n", encoding="utf-8")
    (net / "route").write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
        encoding="utf-8",
    )
    (net / "dev").write_text(_HDR + _LO_1, encoding="utf-8")

    times = iter([100.0, 102.0])
    monkeypatch.setattr(
        "runtime_engine.collector.iface_collector.time.monotonic", lambda: next(times)
    )
    collector = IfaceCollector(proc=proc, sys_class=sys_class)
    first = collector.snapshot()
    assert first.interfaces[0].rx_bps is None  # need two samples
    assert first.interfaces[0].rx_bytes == 1000

    (net / "dev").write_text(_HDR + _LO_2, encoding="utf-8")
    second = collector.snapshot()
    iface = second.interfaces[0]
    assert iface.name == "lo"
    assert iface.if_type == "loopback"
    assert iface.rx_bps == pytest.approx(1000.0)  # +2000 bytes / 2s
    assert iface.tx_bps == pytest.approx(2000.0)
    assert iface.rx_bytes == 3000  # cumulative still available separately
    assert "n/a" in format_bps(None)
    assert "KiB/s" in format_bps(2048.0)
