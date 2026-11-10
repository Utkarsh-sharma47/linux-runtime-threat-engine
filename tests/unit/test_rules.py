from pathlib import Path

import pytest
from pydantic import ValidationError

from runtime_engine.detection.engine import DetectionEngine
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.process.ancestry import AncestryTracker


@pytest.mark.parametrize(
    "rule_id,positive,negative",
    [
        (
            "RT001",
            {"process_name": "bash", "parent_process_name": "soffice"},
            {"process_name": "bash", "parent_process_name": "terminal"},
        ),
        ("RT002", {"executable_path": "/tmp/tool"}, {"executable_path": "/tmpish/tool"}),
        (
            "RT003",
            {"event_type": "FILE_ACCESS", "file_path": "/etc/shadow"},
            {"event_type": "FILE_ACCESS", "file_path": "/etc/passwd"},
        ),
        (
            "RT004",
            {"event_type": "PRIVILEGE_CHANGE", "previous_uid": 1000, "uid": 0},
            {"event_type": "PRIVILEGE_CHANGE", "uid": 0},
        ),
        (
            "RT005",
            {"process_name": "curl", "parent_process_name": "bash"},
            {"process_name": "curl", "parent_process_name": "cron"},
        ),
        (
            "RT006",
            {"event_type": "NETWORK_CONNECTION", "network_destination": "203.0.113.10"},
            {"event_type": "NETWORK_CONNECTION", "network_destination": "192.0.2.1"},
        ),
    ],
)
def test_each_rule(make_event, rule_id, positive, negative):
    rule = next(r for r in load_rules() if r.rule_id == rule_id)
    engine = DetectionEngine([rule])
    tracker = AncestryTracker()
    alerts = engine.evaluate(make_event(**positive), tracker)
    assert len(alerts) == 1 and alerts[0].rule_id == rule_id
    assert alerts[0].reason and alerts[0].event_ids
    assert not engine.evaluate(make_event(**negative), tracker)
    assert not engine.evaluate(make_event(), tracker)
    rule.enabled = False
    assert not engine.evaluate(make_event(**positive), tracker)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/tmp/../usr/bin/safe", False),
        ("/var/tmp/tool", True),
        ("tmp/tool", False),
        ("/dev/shm/tool", True),
    ],
)
def test_location_boundary(make_event, path, expected):
    engine = DetectionEngine([load_rules()[1]])
    assert bool(engine.evaluate(make_event(executable_path=path), AncestryTracker())) is expected


@pytest.mark.parametrize(
    "contents", ["{}", "- {rule_id: x}", "!!python/object/apply:os.system ['false']"]
)
def test_invalid_rule_yaml(tmp_path, contents):
    import yaml

    path = tmp_path / "rules.yaml"
    path.write_text(contents)
    with pytest.raises((ValueError, ValidationError, yaml.YAMLError)):
        load_rules(path)


def test_duplicate_ids(tmp_path):
    text = Path("rules/default_rules.yaml").read_text()
    path = tmp_path / "rules.yaml"
    path.write_text(text + "\n" + text)
    with pytest.raises(ValueError, match="duplicate"):
        load_rules(path)


def test_bundled_rules_match_editable_copy():
    assert load_rules() == load_rules(Path("rules/default_rules.yaml"))
