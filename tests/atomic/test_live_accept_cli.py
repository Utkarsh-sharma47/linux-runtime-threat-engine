"""Exercise the synthetic `atomic live-accept` CLI path (no real Atomic attacks)."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from runtime_engine.config.settings import Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.terminal import atomic_app


def test_atomic_live_accept_cli(tmp_path: Path):
    ns = argparse.Namespace(
        action="live-accept",
        json=True,
        engine_db=tmp_path / "live-accept.db",
        results_dir=tmp_path / "results",
        atomics=tmp_path,
        profiles=None,
    )
    code = atomic_app.live_accept(ns, Settings(), load_rules(), Console(record=True))
    assert code == 0
    assert (tmp_path / "live-accept.db").exists()
