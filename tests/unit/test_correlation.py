from datetime import timedelta

import pytest

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import Severity
from runtime_engine.incidents.generator import generate
from runtime_engine.pipeline import Pipeline


def sensitive(make_event, **kwargs):
    return make_event(event_type="FILE_ACCESS", file_path="/etc/shadow", **kwargs)


def test_duplicate_alerts_preserve_original_events(database, make_event):
    pipeline = Pipeline(database, load_rules())
    first, second = sensitive(make_event), sensitive(make_event)
    for event in [first, second, first]:
        pipeline.process(event)
    incident = database.incidents()[0]
    assert incident.event_count == 2
    assert len(incident.alert_ids) == 1
    assert len(database.evidence(incident.incident_id)) == 2
    assert database.alerts(incident.alert_ids)[0].event_ids == [first.event_id, second.event_id]
    assert pipeline.metrics.duplicate_alerts_suppressed == 1
    assert pipeline.metrics.duplicate_events_suppressed == 1


@pytest.mark.parametrize("seconds,expected", [(119, 1), (120, 1), (121, 2), (-119, 1), (-121, 2)])
def test_event_time_window_including_out_of_order(database, make_event, seconds, expected):
    pipeline = Pipeline(database, load_rules())
    first = sensitive(make_event)
    second = sensitive(make_event, timestamp=first.timestamp + timedelta(seconds=seconds))
    pipeline.process(first)
    pipeline.process(second)
    assert len(database.incidents()) == expected


def test_window_is_bounded_not_indefinitely_sliding(database, make_event):
    pipeline = Pipeline(database, load_rules(), 120)
    first = sensitive(make_event)
    for seconds in [0, 100, 200]:
        pipeline.process(
            sensitive(make_event, timestamp=first.timestamp + timedelta(seconds=seconds))
        )
    assert len(database.incidents()) == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"pid": 500},
        {"process_start_time": "2000"},
        {"host_id": "other"},
        {"process_start_time": None},
    ],
)
def test_unrelated_events_do_not_merge(database, make_event, changes):
    pipeline = Pipeline(database, load_rules())
    pipeline.process(sensitive(make_event))
    pipeline.process(sensitive(make_event, **changes))
    assert len(database.incidents()) == 2


def test_ancestor_and_child_merge_but_siblings_do_not(database, make_event):
    pipeline = Pipeline(database, load_rules())
    parent = make_event()
    child1 = sensitive(
        make_event, pid=110, process_start_time="1100", ppid=100, parent_start_time="1000"
    )
    child2 = sensitive(
        make_event, pid=120, process_start_time="1200", ppid=100, parent_start_time="1000"
    )
    for event in [parent, child1, child2]:
        pipeline.process(event)
    assert len(database.incidents()) == 2
    pipeline.process(sensitive(make_event))
    # Parent may join the earliest related incident; never rewrites two existing reports into one.
    assert len(database.incidents()) == 2
    assert database.incidents()[0].event_count == 2


def test_severity_resources_and_report(database, make_event):
    pipeline = Pipeline(database, load_rules())
    pipeline.process(make_event(executable_path="/tmp/tool"))
    pipeline.process(sensitive(make_event))
    pipeline.process(make_event(event_type="FILE_ACCESS", file_path="/etc/gshadow"))
    incident = database.incidents()[0]
    assert incident.severity == Severity.HIGH
    assert len(incident.alert_ids) == 3
    report = generate(database, incident.incident_id)
    assert report["event_count"] == 3
    assert len(report["supporting_events"]) == 3
    assert report["detections"][0]["reason"]
    assert report["evidence_timeline"][0]["source"] == "synthetic"


def test_conflicting_duplicate_id_is_rejected(database, make_event):
    pipeline = Pipeline(database, load_rules())
    first = sensitive(make_event)
    pipeline.process(first)
    pipeline.process(first.model_copy(update={"file_path": "/etc/gshadow"}))
    assert pipeline.metrics.events_rejected == 1
    assert database.event(first.event_id).file_path == "/etc/shadow"


def test_new_session_unique_incident_id_and_existing_duplicates(database, make_event):
    event = sensitive(make_event)
    Pipeline(database, load_rules()).process(event)
    later = Pipeline(database, load_rules())
    later.process(event)
    later.process(sensitive(make_event))
    assert [i.incident_id for i in database.incidents()] == ["INC-0001", "INC-0002"]


def test_atomic_database_failure_rolls_back(database, make_event):
    import sqlite3

    from runtime_engine.events.schema import Incident

    event = make_event()
    invalid = Incident(
        incident_id="INC-0001",
        severity=Severity.HIGH,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        event_ids=["absent"],
    )
    with pytest.raises(sqlite3.IntegrityError):
        database.save(event, [invalid], [])
    assert database.event(event.event_id) is None
    assert database.incidents() == []


def test_sql_parameters_and_missing_incident(database):
    assert database.incident("x' OR 1=1 --") is None
    with pytest.raises(KeyError):
        generate(database, "missing")


def test_multiple_rules_same_event_without_process_identity(database, make_event):
    pipeline = Pipeline(database, load_rules())
    pipeline.process(
        make_event(
            process_start_time=None,
            process_name="bash",
            parent_process_name="soffice",
            executable_path="/tmp/bash",
        )
    )
    incidents = database.incidents()
    assert len(incidents) == 1
    assert incidents[0].event_count == 1
    assert set(incidents[0].rule_ids) == {"RT001", "RT002"}
