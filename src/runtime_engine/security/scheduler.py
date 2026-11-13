"""Run security modules on their own intervals, off the collector and pipeline threads.

Each enabled module scans in its own daemon thread. Reports are cached in
SecurityState for the dashboard (which never triggers a scan); findings are handed to
the session's bounded queue, so the single pipeline thread stays the only writer.
A scan that raises is reported as an `error` status, never as a clean result.
"""

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from runtime_engine.events.schema import Event
from runtime_engine.security.findings import Finding, ScanReport, SecurityState


class SecurityModule(Protocol):
    name: str
    interval: float

    def scan(self) -> ScanReport: ...


def safe_scan(module: SecurityModule) -> ScanReport:
    started = datetime.now(UTC)
    clock = time.perf_counter()
    try:
        return module.scan()
    except Exception as exc:  # a module failure must not stop monitoring
        return ScanReport(
            module.name,
            "error",
            started,
            time.perf_counter() - clock,
            error=f"{type(exc).__name__}: {exc}",
        )


class SecurityScheduler:
    def __init__(
        self,
        modules: list[SecurityModule],
        submit: Callable[[Finding], bool],
        security: SecurityState,
        stop: threading.Event,
        submit_event: Callable[[Event], bool] | None = None,
    ) -> None:
        self.modules = modules
        self.submit = submit
        self.submit_event = submit_event
        self.security = security
        self.stop = stop
        self.threads: list[threading.Thread] = []

    def start(self) -> None:
        for module in self.modules:
            self.security.set_enabled(module.name, "enabled")
            thread = threading.Thread(
                target=self._run, args=(module,), name=f"security-{module.name}", daemon=True
            )
            self.threads.append(thread)
            thread.start()

    def _run(self, module: SecurityModule) -> None:
        while not self.stop.is_set():
            report = safe_scan(module)
            self.security.record_report(report)
            submit_event = self.submit_event
            for event in report.events if submit_event is not None else []:
                if submit_event is not None and not submit_event(event):
                    return
            for finding in report.findings:
                if not self.submit(finding):
                    return  # session stopping: no new findings are accepted
            if self.stop.wait(module.interval):
                return

    def finished(self) -> bool:
        return not any(thread.is_alive() for thread in self.threads)

    def join(self, timeout: float = 5.0) -> list[str]:
        """Join module threads; returns modules still scanning after the timeout."""
        deadline = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        return [t.name.removeprefix("security-") for t in self.threads if t.is_alive()]
