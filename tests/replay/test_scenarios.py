from pathlib import Path

import pytest

from runtime_engine.collector.replay_collector import ReplayCollector
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.pipeline import Pipeline


@pytest.mark.parametrize(
    "name,incidents,events,alerts,dedup",
    [
        ("benign", 0, 2, 0, 0),
        ("shell", 1, 1, 1, 0),
        ("chain", 1, 6, 6, 0),
        ("sensitive", 1, 1, 1, 0),
        ("repeated", 1, 3, 3, 2),
        ("unrelated", 2, 2, 2, 0),
    ],
)
def test_scenarios(database, name, incidents, events, alerts, dedup):
    pipeline = Pipeline(database, load_rules())
    for event in ReplayCollector(Path(f"datasets/{name}.jsonl")).collect():
        assert event.metadata["synthetic"] is True
        pipeline.process(event)
    assert len(database.incidents()) == incidents
    assert pipeline.metrics.total_events_processed == events
    assert pipeline.metrics.total_alerts_generated == alerts
    assert pipeline.metrics.duplicate_alerts_suppressed == dedup
    if name == "chain":
        report = database.incidents()[0]
        assert report.event_count == 5  # initial benign parent is context, not a matched event
        assert any("soffice" in tree and "curl" in tree for tree in report.ancestry)


def test_invalid_records_are_counted_and_skipped(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        '\nnot-json\n[]\n{}\n{"timestamp":"2026-01-01","event_type":"FILE_ACCESS"}\n'
        + Path("datasets/shell.jsonl").read_text()
    )
    collector = ReplayCollector(path)
    assert len(list(collector.collect())) == 1
    assert collector.rejected == 4


def test_sort_is_explicit(tmp_path):
    import json

    rows = [json.loads(s) for s in Path("datasets/chain.jsonl").read_text().splitlines()]
    path = tmp_path / "reverse.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in reversed(rows)))
    ordered = list(ReplayCollector(path, sort=True).collect())
    assert ordered[0].timestamp < ordered[-1].timestamp
    original = list(ReplayCollector(path).collect())
    assert original[0].timestamp > original[-1].timestamp
