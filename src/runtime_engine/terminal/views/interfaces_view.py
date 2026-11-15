"""Host network interface overview: state, addresses, counters, RX/TX throughput."""

from __future__ import annotations

from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtime_engine.collector.iface_collector import format_bps
from runtime_engine.terminal.formatting import clean


def render_interfaces(summary: dict[str, Any] | None) -> RenderableType:
    data = (summary or {}).get("interfaces") if summary else None
    if not data:
        return Panel(
            Text(
                "No interface snapshot yet. Start the monitor with security modules enabled "
                "(default) so NetworkMonitor can sample /proc/net/dev.",
                style="dim",
            ),
            title="HOST NETWORK INTERFACES",
            title_align="left",
            border_style="cyan",
        )
    route = data.get("route") or {}
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold", no_wrap=True)
    header.add_column(overflow="fold")
    header.add_row(
        "DEFAULT ROUTE",
        f"iface={route.get('default_interface') or '?'}  "
        f"gateway={route.get('default_gateway') or '?'}  "
        f"({route.get('source') or '-'})",
    )
    header.add_row(
        "LIMITATION",
        Text(str(data.get("limitation") or ""), style="yellow"),
    )
    if data.get("errors"):
        header.add_row("ERRORS", Text("; ".join(data["errors"]), style="red"))

    table = Table(title="INTERFACES (/sys + /proc/net/dev)", title_justify="left", expand=True)
    for col in (
        "IFACE",
        "STATE",
        "TYPE",
        "IPv4",
        "RX B/s",
        "TX B/s",
        "RX bytes",
        "TX bytes",
        "ERR/DROP",
        "DEFAULT",
    ):
        table.add_column(col, no_wrap=True, overflow="ellipsis")
    for item in data.get("interfaces") or []:
        style = "bold green" if item.get("is_default") else None
        err = f"{item.get('rx_errors', 0)}/{item.get('tx_errors', 0)}"
        drop = f"{item.get('rx_dropped', 0)}/{item.get('tx_dropped', 0)}"
        table.add_row(
            clean(item.get("name") or "-", 12),
            clean(item.get("state") or "-", 10),
            clean(item.get("if_type") or "-", 10),
            clean(",".join(item.get("ipv4") or []) or "-", 18),
            format_bps(item.get("rx_bps")),
            format_bps(item.get("tx_bps")),
            f"{item.get('rx_bytes', 0):,}",
            f"{item.get('tx_bytes', 0):,}",
            f"{err} · {drop}",
            "yes" if item.get("is_default") else "-",
            style=style,
        )
    note = Text(
        "Throughput requires at least two NetworkMonitor samples. "
        "Loopback, docker/veth, and VPN interfaces appear when the kernel exposes them. "
        "This is not packet capture.",
        style="dim italic",
    )
    return Panel(
        Group(header, table, note),
        title="HOST NETWORK INTERFACES [5/n]",
        title_align="left",
        border_style="cyan",
    )


__all__ = ["render_interfaces"]
