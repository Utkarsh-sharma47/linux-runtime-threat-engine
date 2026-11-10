"""Shared helpers for terminal tests (fakes for collector, keys and prompts)."""

import contextlib
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from io import StringIO

from rich.console import Console

from runtime_engine.events.schema import Event
from runtime_engine.monitor.state import SessionInfo, Verbosity

BOOT = "boot-test"


def make_info(**overrides: object) -> SessionInfo:
    values: dict[str, object] = dict(
        session_id="SES-TEST",
        mode="LIVE",
        hostname="test-host",
        kernel="6.0-test",
        engine_pid=4242,
        started_at=datetime.now(UTC) - timedelta(seconds=5),
        verbosity=Verbosity.NORMAL,
        poll_interval=0.05,
        queue_capacity=100,
        window_seconds=120,
        telemetry="/proc polling (test)",
        database_path=":memory:",
        reports_directory="reports/generated",
    )
    values.update(overrides)
    return SessionInfo(**values)  # type: ignore[arg-type]


def make_console(width: int = 140, height: int = 50) -> Console:
    return Console(
        file=StringIO(),
        width=width,
        height=height,
        force_terminal=False,
        color_system=None,
        legacy_windows=False,
    )


def text_of(console: Console) -> str:
    assert isinstance(console.file, StringIO)
    return console.file.getvalue()


def render(renderable: object, width: int = 140, height: int = 50) -> str:
    console = make_console(width, height)
    console.print(renderable)
    return text_of(console)


_counter = 0


def proc_event(
    pid: int,
    *,
    ppid: int | None = None,
    name: str = "worker",
    start: str | None = None,
    parent_start: str | None = None,
    exe: str | None = "/usr/bin/worker",
    **extra: object,
) -> Event:
    """A /proc-shaped event (real identity fields), never executed or observed live."""
    global _counter
    _counter += 1
    return Event.model_validate(
        dict(
            event_id=f"term-{_counter}",
            timestamp=datetime.now(UTC),
            event_type="PROCESS_START",
            pid=pid,
            ppid=ppid,
            process_name=name,
            executable_path=exe,
            uid=1000,
            process_start_time=start or str(pid * 10),
            parent_start_time=parent_start,
            host_id=BOOT,
            source="proc",
        )
        | extra
    )


class FakeCollector:
    """Scripted snapshots with the same counters as ProcCollector."""

    def __init__(self, batches: list[list[Event]], *, fail: bool = False) -> None:
        self.batches = list(batches)
        self.errors = 0
        self.rejected = 0
        self.missing_telemetry = 0
        self.read_failures = 0
        self.fail = fail
        self.polls = 0

    def collect(self) -> Iterator[Event]:
        self.polls += 1
        if self.fail:
            raise RuntimeError("collector broke")
        if self.batches:
            self.missing_telemetry += 1
            self.errors += 1
            yield from self.batches.pop(0)


class FakeKeys:
    """Scripted key presses; KeyboardInterrupt entries raise like Ctrl+C."""

    def __init__(self, keys: list[object]) -> None:
        self.keys = list(keys)
        self.suspended = 0

    def __enter__(self) -> "FakeKeys":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def read_key(self, timeout: float) -> str | None:
        if not self.keys:
            time.sleep(timeout)
            return None
        key = self.keys.pop(0)
        if key is KeyboardInterrupt:
            raise KeyboardInterrupt
        if callable(key):
            return key()  # type: ignore[no-any-return]
        if key is None:
            time.sleep(timeout)
        return key  # type: ignore[return-value]

    @contextlib.contextmanager
    def suspend(self) -> Iterator[None]:
        self.suspended += 1
        yield


def scripted(answers: list[str]) -> Callable[[str], str]:
    """Prompt replacement; running out of answers behaves like closed stdin."""
    queue = list(answers)

    def prompt(message: str) -> str:
        if not queue:
            raise EOFError
        return queue.pop(0)

    return prompt
