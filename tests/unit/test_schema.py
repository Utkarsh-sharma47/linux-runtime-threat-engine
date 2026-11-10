from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from runtime_engine.events.normalizer import normalize


def test_timezone_normalization():
    event = normalize(
        dict(timestamp="2026-01-01T05:30:00+05:30", event_type="PROCESS_START", source="synthetic")
    )
    assert event.timestamp == datetime(2026, 1, 1, tzinfo=UTC)
    assert event.process_key is None
    assert event.command_line is None


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": "2026-01-01T00:00:00"},
        {"pid": -1},
        {"pid": True},
        {"pid": "2"},
        {"event_type": "UNKNOWN"},
        {"source": ""},
        {"unknown": 1},
        {"uid": -1},
        {"command_line": "bash -c anything"},
        {"process_start_time": ""},
    ],
)
def test_invalid_event(make_event, changes):
    with pytest.raises(ValidationError):
        make_event(**changes)


def test_pid_reuse_and_hosts_have_distinct_identities(make_event):
    old = make_event()
    assert old.process_key != make_event(process_start_time="2000").process_key
    assert old.process_key != make_event(host_id="another-host").process_key
