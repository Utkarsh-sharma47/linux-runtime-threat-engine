import threading
import time

import pytest
from terminal_helpers import FakeCollector, make_info, proc_event

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import Alert, Severity
from runtime_engine.monitor.notifications import NotificationCenter
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.monitor.state import DashboardState, Verbosity
from runtime_engine.pipeline import Pipeline


class SlowPipeline(Pipeline):
    """The real pipeline, slowed down to force a full queue."""

    def __init__(self, *args: object, delay: float = 0.002, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.delay = delay

    def process(self, event):  # type: ignore[no-untyped-def]
        time.sleep(self.delay)
        return super().process(event)


def session_for(database, batches, *, capacity=100, delay=0.0, duration=None, **kwargs):
    state = DashboardState(make_info(queue_capacity=capacity))
    pipeline = SlowPipeline(database, load_rules(), delay=delay)
    collector = FakeCollector(batches, **kwargs)
    session = MonitorSession(
        pipeline,
        collector,
        state,
        poll_interval=0.01,
        queue_capacity=capacity,
        duration=duration,
        put_timeout=0.01,
    )
    return session, state, pipeline, collector


def wait_for(predicate, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_queue_overflow_applies_backpressure_without_dropping(database):
    events = [proc_event(1000 + i) for i in range(60)]
    session, state, pipeline, _ = session_for(database, [events], capacity=2, delay=0.003)
    session.start()
    assert wait_for(lambda: state.counters.processed == 60)
    result = session.shutdown("user_quit")
    assert result.status == "STOPPED_GRACEFULLY" and result.unprocessed == 0
    counters = state.counters
    assert counters.backpressure_waits > 0
    assert counters.dropped == 0
    assert counters.queue_peak <= 2
    assert counters.observed == counters.accepted == counters.processed == 60
    assert pipeline.metrics.total_events_processed == 60


def test_abort_while_queue_is_full_counts_dropped_and_unprocessed(database):
    events = [proc_event(2000 + i) for i in range(50)]
    session, state, _, _ = session_for(database, [events], capacity=1, delay=0.2)
    session.start()
    assert wait_for(lambda: state.counters.backpressure_waits > 0)
    session.force()
    # With the pipeline aborted nothing drains the full queue, so the collector must drop.
    assert session.collector_done.wait(5)
    result = session.shutdown("keyboard_interrupt")
    assert result.status == "FORCED_STOP"
    summary = state.summary(status=result.status)
    events_stats = summary["events"]
    assert events_stats["dropped"] >= 1
    assert (
        events_stats["processed"] + events_stats["unprocessed_at_shutdown"]
        == events_stats["accepted"]
    )


def test_graceful_shutdown_keeps_every_accepted_event(database):
    events = [proc_event(3000 + i) for i in range(200)]
    session, state, _, _ = session_for(database, [events], capacity=500, delay=0.002)
    session.start()
    assert wait_for(lambda: state.counters.accepted == 200)
    assert state.counters.processed < 200  # still draining when the stop arrives
    result = session.shutdown("user_quit")
    assert result.status == "STOPPED_GRACEFULLY"
    assert state.counters.processed == 200 and result.unprocessed == 0
    stored = database.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert stored == 200
    assert state.status == "STOPPED"


def test_no_duplicate_incidents_after_shutdown(database):
    parent = proc_event(4000, name="dropper", exe="/tmp/dropper", start="40000")
    child = proc_event(
        4001, ppid=4000, name="curl", exe="/usr/bin/curl", start="40010", parent_start="40000"
    )
    bash = proc_event(
        4002, ppid=4000, name="bash", exe="/bin/bash", start="40020", parent_start="40000"
    )
    curl = proc_event(
        4003, ppid=4002, name="curl", exe="/usr/bin/curl", start="40030", parent_start="40020"
    )
    session, state, pipeline, _ = session_for(database, [[parent, child], [bash, curl]])
    session.start()
    assert wait_for(lambda: state.counters.processed == 4)
    first = session.shutdown("user_quit")
    second = session.shutdown("keyboard_interrupt")
    assert first is second
    ids = [i.incident_id for i in database.incidents()]
    assert ids == sorted(set(ids)) == sorted(state.incidents)
    assert len(ids) == len(pipeline.correlation.incidents) == 1
    summary = state.summary(status=first.status)
    assert summary["incident_ids"] == ids
    assert summary["security"]["rule_matches"] == pipeline.metrics.total_alerts_generated


def test_duration_elapsed_stops_session(database):
    session, state, _, collector = session_for(database, [[proc_event(5000)]], duration=0.1)
    session.start()
    assert session.wait(5)
    result = session.shutdown("ignored")
    assert result.reason == "duration_elapsed"
    assert collector.polls >= 1 and state.counters.polls >= 1
    assert state.counters.baseline_processes == 1


def test_collector_failure_is_reported_as_monitoring_error(database):
    session, state, _, _ = session_for(database, [], fail=True)
    session.start()
    assert session.wait(5)
    result = session.shutdown("user_quit")
    assert result.status == "FAILED" and result.reason == "error"
    assert "collector failure" in (state.error or "")
    errors = [e for e in state.visible_entries(Verbosity.QUIET) if e.title == "MONITORING_FAILURE"]
    assert errors and errors[0].level == "ERROR"


def test_storage_failure_aborts_pipeline(database):
    session, state, pipeline, _ = session_for(database, [[proc_event(5100)]])

    def broken(*args, **kwargs):
        raise OSError("disk full")

    pipeline.process = broken  # type: ignore[method-assign]
    session.start()
    assert session.wait(5)
    result = session.shutdown("user_quit")
    assert result.status == "FAILED"
    assert "pipeline failure: OSError" == state.error


def test_shutdown_before_start_is_safe(database):
    session, state, _, _ = session_for(database, [])
    result = session.shutdown("user_quit")
    assert result.status == "STOPPED_GRACEFULLY" and state.status == "STOPPED"
    with pytest.raises(ValueError):
        MonitorSession(
            session.pipeline, session.collector, state, poll_interval=1, queue_capacity=0
        )


def test_concurrent_updates_and_snapshots(database):
    state = DashboardState(make_info())
    pipeline = Pipeline(database, load_rules())
    errors: list[BaseException] = []
    done = threading.Event()

    def reader() -> None:
        try:
            while not done.is_set():
                snap = state.snapshot()
                state.event_records()
                state.alert_list()
                state.incident_list()
                state.suspicious_processes()
                state.summary()
                assert snap.counters.processed >= 0
        except BaseException as exc:  # pragma: no cover - only on failure
            errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(3)]
    for thread in readers:
        thread.start()
    for number in range(300):
        exe = "/tmp/tool" if number % 10 == 0 else "/usr/bin/tool"
        state.apply(pipeline.process(proc_event(6000 + number, exe=exe)))
    done.set()
    for thread in readers:
        thread.join()
    assert not errors
    assert state.counters.processed == 300
    assert state.counters.rule_matches == 30 == len(state.alerts)
    assert len(state.incidents) == 30


def make_alert(rule: str, severity: Severity, alert_id: str) -> Alert:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    return Alert(
        alert_id=alert_id,
        rule_id=rule,
        rule_name=f"rule {rule}",
        severity=severity,
        reason="x",
        event_ids=["e"],
        process_key=None,
        first_seen=now,
        last_seen=now,
    )


def test_notification_throttling_and_deduplication():
    clock = [0.0]
    center = NotificationCenter(
        display_seconds=10, coalesce_seconds=30, capacity=3, clock=lambda: clock[0]
    )
    center.push(make_alert("RT005", Severity.LOW, "a1"), "INC-0001", 1, "curl")
    center.push(make_alert("RT005", Severity.LOW, "a2"), "INC-0002", 2, "curl")
    center.push(make_alert("RT002", Severity.MEDIUM, "a3"), "INC-0001", 1, "curl")
    active = center.active()
    assert len(active) == 1 and active[0].matches == 3 and center.coalesced == 2
    assert active[0].incident_ids == ["INC-0001", "INC-0002"]
    assert active[0].severity == Severity.MEDIUM
    center.push(make_alert("RT001", Severity.HIGH, "h1"), "INC-0003", 3, "bash")
    clock[0] = 100
    pinned = center.active()
    assert [n.severity for n in pinned] == [Severity.HIGH]  # critical/high are never hidden
    center.acknowledge()
    assert center.active() == []
    for number in range(5):
        center.push(make_alert(f"R{number}", Severity.HIGH, f"x{number}"), f"I{number}", 1, "p")
    assert len(center.active()) == 3 and center.evicted == 2


def test_state_records_duplicate_and_rejected_results(database, make_event):
    from runtime_engine.pipeline import ProcessResult

    state = DashboardState(make_info(verbosity=Verbosity.DEBUG))
    event = make_event()
    state.apply(ProcessResult(event, "duplicate"))
    state.apply(ProcessResult(event, "rejected"))
    assert state.counters.duplicate_events == 1 and state.counters.rejected == 1
    titles = [e.title for e in state.visible_entries(Verbosity.DEBUG)]
    assert "DUPLICATE_EVENT_IGNORED" in titles and "EVENT_REJECTED" in titles


def test_repeated_matches_are_folded_and_shown_only_in_verbose(database, make_event):
    state = DashboardState(make_info(mode="REPLAY"))
    pipeline = Pipeline(database, load_rules())
    for _ in range(3):
        state.apply(pipeline.process(make_event(event_type="FILE_ACCESS", file_path="/etc/shadow")))
    assert state.counters.rule_matches == 3 and state.counters.duplicate_matches == 2
    assert len(state.alerts) == 1
    normal = [e.title for e in state.visible_entries(Verbosity.NORMAL)]
    verbose = [e.title for e in state.visible_entries(Verbosity.VERBOSE)]
    assert normal.count("RULE_MATCH") == 1 and "RULE_MATCH_REPEATED" not in normal
    assert verbose.count("RULE_MATCH_REPEATED") == 2
    quiet = state.visible_entries(Verbosity.QUIET)
    assert all(e.kind.value in ("RULE_MATCH", "INCIDENT", "ERROR", "LIFECYCLE") for e in quiet)
