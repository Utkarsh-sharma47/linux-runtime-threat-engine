import pytest
from pydantic import ValidationError

from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import Condition
from runtime_engine.incidents.reporter import safe
from runtime_engine.metrics.collector import Metrics


@pytest.mark.parametrize(
    "field,op,value",
    [
        ("process_name", "path_under", ["/tmp"]),
        ("file_path", "path_under", ["tmp"]),
        ("uid", "in", 0),
    ],
)
def test_bad_rule_conditions_rejected(field, op, value):
    with pytest.raises(ValidationError):
        Condition(field=field, op=op, value=value)


@pytest.mark.parametrize(
    "settings", [{"correlation_window_seconds": 0}, {"poll_interval_seconds": 0}, {"unknown": True}]
)
def test_bad_settings_rejected(settings):
    with pytest.raises(ValidationError):
        Settings.model_validate(settings)


def test_metrics_empty_and_measured():
    metrics = Metrics()
    assert metrics.report()["event_throughput_per_second"] == 0
    metrics.total_events_processed = 2
    metrics.observe(0.1)
    metrics.observe(0.3)
    assert metrics.report()["average_processing_latency_ms"] == 200
    assert metrics.report()["maximum_processing_latency_ms"] == 300
    assert metrics.report()["event_throughput_per_second"] == 5


def test_terminal_control_escape():
    assert "\x1b" not in safe("\x1b[31mtest")
