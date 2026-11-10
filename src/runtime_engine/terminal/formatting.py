"""Shared terminal formatting. Every telemetry string passes through `clean`.

Rich passes ESC sequences inside `Text` straight to the terminal, so untrusted values
(process names, paths, arguments) are escaped here before any rendering.
"""

import pwd
from datetime import datetime

from rich.text import Text

from runtime_engine.events.schema import Severity

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
}
LEVEL_STYLES = {
    "INFO": "dim",
    "NOTICE": "cyan",
    "WARNING": "bold yellow",
    "ALERT": "bold red",
    "ERROR": "bold white on dark_red",
    "DEBUG": "dim magenta",
}
STATUS_STYLES = {
    "RUNNING": "bold green",
    "STARTING": "yellow",
    "STOPPING": "bold yellow",
    "STOPPED": "bold cyan",
    "FAILED": "bold white on dark_red",
}
NORMAL_STYLE = "green"
MISSING = "-"


def clean(value: object, limit: int | None = None, missing: str = MISSING) -> str:
    """Printable, single-line text: control and non-printable characters are escaped."""
    if value is None:
        return missing
    text = "".join(
        c if c.isprintable() else f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}"
        for c in str(value)
    )
    return truncate(text, limit) if limit is not None else text


def truncate(text: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..." if limit > 3 else text[:limit]


def command_line(argv: list[str] | None, limit: int | None = None) -> str:
    if not argv:
        return MISSING
    return clean(" ".join(argv), limit)


def severity_style(severity: Severity | str | None) -> str:
    if severity is None:
        return NORMAL_STYLE
    return SEVERITY_STYLES.get(str(severity), "")


def severity_text(severity: Severity | str | None, normal: str = "NORMAL") -> Text:
    """Text label always present, so colour is never the only indicator."""
    label = str(severity) if severity is not None else normal
    return Text(label, style=severity_style(severity))


def level_text(level: str, width: int = 8) -> Text:
    return Text(level.ljust(width), style=LEVEL_STYLES.get(level, ""))


def local(moment: datetime) -> datetime:
    return moment.astimezone()


def clock_ms(moment: datetime) -> str:
    value = local(moment)
    return value.strftime("%H:%M:%S.") + f"{value.microsecond // 1000:03d}"


def clock(moment: datetime | None) -> str:
    return local(moment).strftime("%H:%M:%S") if moment else "N/A"


def timestamp(moment: datetime | str | None) -> str:
    """Readable local timestamp with UTC offset; N/A when not recorded."""
    if moment is None:
        return "N/A"
    if isinstance(moment, str):
        moment = datetime.fromisoformat(moment)
    return local(moment).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + local(moment).strftime(" %z")


def duration(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    total = int(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def number(value: int | float | None) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:,.2f}"
    return f"{value:,}"


def milliseconds(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f} ms"


def memory(kilobytes: int | None) -> str:
    return "N/A" if kilobytes is None else f"{kilobytes / 1024:.1f} MiB (peak RSS)"


_USERS: dict[int, str | None] = {}


def user(uid: int | None, local_host: bool) -> str:
    """UID with the local account name only for live /proc data from this host."""
    if uid is None:
        return MISSING
    if not local_host:
        return str(uid)
    if uid not in _USERS:
        try:
            _USERS[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _USERS[uid] = None
    name = _USERS[uid]
    return f"{uid} ({clean(name)})" if name else str(uid)
