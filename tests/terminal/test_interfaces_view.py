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
            "errors": [],
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
