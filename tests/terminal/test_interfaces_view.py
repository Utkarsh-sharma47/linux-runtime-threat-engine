"""Host interface panel rendering and numeric network navigation."""

from __future__ import annotations

from terminal_helpers import render

from runtime_engine.terminal.interactions import _NUMERIC, PAGES
from runtime_engine.terminal.views import interfaces_view


def test_interfaces_view_empty_and_populated():
    empty = render(interfaces_view.render_interfaces(None))
    assert "No interface snapshot" in empty
    summary = {
        "interfaces": {
            "route": {
                "default_interface": "wlan0",
                "default_gateway": "192.168.1.1",
                "source": "/proc/net/route",
            },
            "limitation": "socket/interface statistics, not packet capture",
            "errors": ["permission denied on ioctl"],
            "interfaces": [
                {
                    "name": "wlan0",
                    "state": "up",
                    "if_type": "wifi",
                    "ipv4": ["192.168.1.10"],
                    "rx_bps": 1024.0,
                    "tx_bps": 512.0,
                    "rx_bytes": 100000,
                    "tx_bytes": 50000,
                    "rx_errors": 0,
                    "tx_errors": 0,
                    "rx_dropped": 0,
                    "tx_dropped": 0,
                    "is_default": True,
                }
            ],
        }
    }
    text = render(interfaces_view.render_interfaces(summary))
    assert "wlan0" in text and "DEFAULT ROUTE" in text
    assert "KiB/s" in text or "B/s" in text
    assert "not packet" in text.lower() or "LIMITATION" in text


def test_numeric_aliases_map_to_pages():
    assert _NUMERIC["5"] == "n"
    assert _NUMERIC["6"] == "s"
    assert "5" in PAGES and "n" in PAGES


def test_network_view_connection_table_and_render():
    from datetime import UTC, datetime

    from runtime_engine.security.findings import Coverage, Finding, ScanReport, Severity
    from runtime_engine.terminal.views import network_view

    empty = render(network_view.connections_table([], "EMPTY"))
    assert "No connections" in empty
    rows = [
        {
            "protocol": "tcp",
            "local": "127.0.0.1:1",
            "remote": "127.0.0.1:2",
            "state": "ESTABLISHED",
            "attribution": "unique",
            "processes": [{"name": "curl", "pid": 9, "process_key": '["h",9,"1"]'}],
        },
        {
            "protocol": "udp",
            "local": "::1:3",
            "remote": "*:*",
            "state": "UNCONNECTED",
            "attribution": "none",
            "processes": [],
        },
    ]
    # force caption path with limit
    big = rows * 20
    text = render(
        network_view.connections_table(big, "CONNS", incidents={'["h",9,"1"]': ["INC-1"]}, limit=5)
    )
    assert "curl" in text and "INC-1" in text and "more not shown" in text
    finding = Finding.create(
        "network",
        "NB001",
        "127.0.0.1:80",
        title="beacon",
        severity=Severity.LOW,
        evidence={},
        explanation="x",
    )
    report = ScanReport(
        "network",
        "ok",
        datetime.now(UTC),
        0.01,
        [finding],
        Coverage(checked=1),
        {
            "sockets": 2,
            "connected": 1,
            "listening": 1,
            "taken_at": datetime.now(UTC).isoformat(),
            "new_total": 1,
            "new_this_scan": 1,
            "connections": rows,
            "processes": [
                {
                    "process": "curl",
                    "pid": 9,
                    "new_connections": 1,
                    "per_minute_10m": 0.1,
                    "destinations": 1,
                }
            ],
            "repeated": [
                {
                    "process": "curl",
                    "pid": 9,
                    "destination": "127.0.0.1:2",
                    "connections": 3,
                    "periodicity": {"mean_interval_seconds": 1.5, "cv": 0.1},
                }
            ],
        },
    )
    body = render(network_view.render_network(report, [finding], pid=9))
    assert "NETWORK MONITOR" in body and "curl" in body
