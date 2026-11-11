"""Collector and pipeline threads joined by one bounded queue, with coordinated shutdown.

Queue policy: the collector blocks (backpressure) when the queue is full; it never drops an
observation it already read unless an abort was requested. Every wait on a full queue is
counted. Polling simply happens later, which is visible as `backpressure_waits`.

Shutdown: stop collecting, let the pipeline drain every accepted event, then report. An
abort (fatal pipeline error or a second interrupt during shutdown) stops draining; the
events still queued are counted as unprocessed instead of being silently discarded.
"""

import queue
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from time import perf_counter
from typing import Protocol

from runtime_engine.events.schema import Event
from runtime_engine.monitor.state import DashboardState
from runtime_engine.pipeline import Pipeline


class SnapshotCollector(Protocol):
    errors: int
    rejected: int

    def collect(self) -> Iterator[Event]: ...


@dataclass(frozen=True)
class ShutdownResult:
    status: str  # STOPPED_GRACEFULLY, FORCED_STOP or FAILED
    reason: str
    unprocessed: int


class MonitorSession:
    def __init__(
        self,
        pipeline: Pipeline,
        collector: SnapshotCollector,
        state: DashboardState,
        *,
        poll_interval: float,
        queue_capacity: int,
        duration: float | None = None,
        put_timeout: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if queue_capacity < 1:
            raise ValueError("queue capacity must be positive")
        self.pipeline = pipeline
        self.collector = collector
        self.state = state
        self.poll_interval = poll_interval
        self.duration = duration
        self.put_timeout = put_timeout
        self.clock = clock
        self.events: queue.Queue[tuple[bool, Event]] = queue.Queue(maxsize=queue_capacity)
        self.stop_requested = threading.Event()
        self.abort = threading.Event()
        self.collector_done = threading.Event()
        self.processor_done = threading.Event()
        self.reason: str | None = None
        self.failure: str | None = None
        self.forced = False
        self._reason_lock = threading.Lock()
        self._collector_thread = threading.Thread(
            target=self._collect, name="runtime-engine-collector", daemon=True
        )
        self._processor_thread = threading.Thread(
            target=self._process, name="runtime-engine-pipeline", daemon=True
        )
        self._result: ShutdownResult | None = None
        self._stop_logged = False

    @property
    def stopping(self) -> bool:
        return self.stop_requested.is_set()

    def start(self) -> None:
        self.state.set_status("RUNNING")
        self.state.record_lifecycle(
            "MONITORING_STARTED",
            [
                ("SESSION", self.state.info.session_id),
                ("TELEMETRY", self.state.info.telemetry),
                ("QUEUE_CAPACITY", self.events.maxsize),
            ],
        )
        self._processor_thread.start()
        self._collector_thread.start()

    def request_stop(self, reason: str) -> None:
        with self._reason_lock:
            if self.reason is None:
                self.reason = reason
                self.state.stop_reason = reason
        self.stop_requested.set()

    def wait(self, timeout: float) -> bool:
        """Sleep up to `timeout`; True once a stop was requested by anyone."""
        return self.stop_requested.wait(timeout)

    def _fail(self, message: str) -> None:
        self.failure = message
        self.state.record_error("MONITORING_FAILURE", [("ERROR", message)], fatal=True)
        self.abort.set()
        self.request_stop("error")

    def _sync_collector(self) -> None:
        self.state.update_collector(
            self.collector.errors,
            getattr(self.collector, "missing_telemetry", 0),
            getattr(self.collector, "read_failures", 0),
            self.collector.rejected,
        )

    def _enqueue(self, baseline: bool, event: Event) -> bool:
        """Block while the queue is full (counted once per wait); drop only on abort."""
        item = (baseline, event)
        try:
            self.events.put_nowait(item)
        except queue.Full:
            self.state.record_backpressure()
            while True:
                if self.abort.is_set():
                    self.state.record_dropped()
                    return False
                try:
                    self.events.put(item, timeout=self.put_timeout)
                    break
                except queue.Full:
                    continue
        self.state.record_accepted(self.events.qsize())
        return True

    def _collect(self) -> None:
        deadline = self.clock() + self.duration if self.duration else None
        poll = 0
        try:
            while not (self.stop_requested.is_set() or self.abort.is_set()):
                poll += 1
                started = perf_counter()
                missing = getattr(self.collector, "missing_telemetry", 0)
                failures = getattr(self.collector, "read_failures", 0)
                discovered = 0
                for event in self.collector.collect():
                    self.state.record_observed()
                    if not self._enqueue(poll == 1, event):
                        break
                    discovered += 1
                    if self.stop_requested.is_set():
                        break
                self._sync_collector()
                self.state.record_poll(
                    poll,
                    perf_counter() - started,
                    discovered,
                    getattr(self.collector, "missing_telemetry", 0) - missing,
                    getattr(self.collector, "read_failures", 0) - failures,
                )
                if deadline is not None and self.clock() >= deadline:
                    self.request_stop("duration_elapsed")
                    break
                delay = self.poll_interval
                if deadline is not None:
                    delay = min(delay, max(0.0, deadline - self.clock()))
                self.stop_requested.wait(delay)
        except Exception as exc:
            self._fail(f"collector failure: {type(exc).__name__}")
        finally:
            self.collector_done.set()

    def _process(self) -> None:
        try:
            while not self.abort.is_set():
                try:
                    baseline, event = self.events.get(timeout=0.1)
                except queue.Empty:
                    if self.collector_done.is_set() and self.events.empty():
                        break
                    continue
                result = self.pipeline.process(event)
                self.state.apply(result, baseline)
                self.state.record_queue_depth(self.events.qsize())
        except Exception as exc:
            # Storage errors abort the run: in-memory state may be ahead of the database.
            self._fail(f"pipeline failure: {type(exc).__name__}")
        finally:
            self.processor_done.set()

    def _join(self, thread: threading.Thread) -> None:
        while thread.is_alive():
            try:
                thread.join(0.1)
            except KeyboardInterrupt:
                self.force()

    def begin_stop(self, reason: str) -> None:
        """Stop collecting; the pipeline keeps draining accepted events."""
        self.request_stop(reason)
        if not self._stop_logged:
            self._stop_logged = True
            self.state.set_status("STOPPING")
            self.state.record_lifecycle(
                "STOPPING", [("REASON", self.reason), ("QUEUED", self.events.qsize())]
            )

    def force(self) -> None:
        """Stop draining (second interrupt). Queued events are reported as unprocessed."""
        self.forced = True
        self.abort.set()

    def shutdown(self, reason: str = "user_quit") -> ShutdownResult:
        """Idempotent coordinated stop. Safe to call from the terminal (main) thread."""
        if self._result is not None:
            return self._result
        self.begin_stop(reason)
        if self._collector_thread.ident is None:
            self.collector_done.set()
        self._join(self._collector_thread)
        self._join(self._processor_thread)
        self._sync_collector()
        unprocessed = self.events.qsize()
        self.state.record_unprocessed(unprocessed)
        metrics = self.pipeline.metrics
        metrics.events_rejected += self.collector.rejected
        metrics.collector_errors += self.collector.errors
        if self.failure:
            status = "FAILED"
        elif self.forced or unprocessed:
            status = "FORCED_STOP"
        else:
            status = "STOPPED_GRACEFULLY"
        self.state.set_status("FAILED" if self.failure else "STOPPED")
        self.state.record_lifecycle(
            "MONITORING_STOPPED", [("STATUS", status), ("UNPROCESSED", unprocessed)]
        )
        self._result = ShutdownResult(status, self.reason or reason, unprocessed)
        return self._result
