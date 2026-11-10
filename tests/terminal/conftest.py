from pathlib import Path

import pytest
from terminal_helpers import make_info

from runtime_engine.collector.replay_collector import ReplayCollector
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.monitor.state import DashboardState
from runtime_engine.pipeline import Pipeline


@pytest.fixture
def chain(database):
    """The synthetic chain replayed through the real pipeline into a dashboard state."""
    state = DashboardState(make_info(mode="REPLAY"))
    pipeline = Pipeline(database, load_rules())
    state.set_status("RUNNING")
    for event in ReplayCollector(Path("datasets/chain.jsonl")).collect():
        state.record_observed()
        state.apply(pipeline.process(event))
    return state, pipeline
