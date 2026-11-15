"""Scenario F: report Isolation Forest state; train only with a safe fixture if supported."""

from __future__ import annotations

import json
from pathlib import Path

from runtime_engine.lab.paths import session_dirs
from runtime_engine.lab.status import LabStatus, ScenarioResult, now_iso


def run(session: Path, status: LabStatus, dry_run: bool) -> ScenarioResult:
    dirs = session_dirs(session)
    model_dir = dirs["models"]
    result = ScenarioResult(
        name="anomaly",
        status="dry-run" if dry_run else "running",
        started_at=now_iso(),
        provenance=["SYNTHETIC_LAB_FIXTURE"],
        behavior=[
            "Inspect whether an Isolation Forest / robust-z model exists under the lab models dir",
            "If untrained, record UNTRAINED honestly — do not invent anomaly scores",
            "Optionally write a training-fixture note for the operator",
        ],
        collectors=["AnomalyDetector"],
        expected_rules=[],
        expected_modules=["anomaly"],
        notes=[
            "Dashboard: s → anomaly (UNTRAINED / scores only when a real model exists).",
            "Train separately if desired: python -m runtime_engine.main anomaly train ...",
        ],
        evidence={"model_directory": str(model_dir)},
    )
    if dry_run:
        result.status = "dry-run"
        result.ended_at = now_iso()
        return result

    model_files = list(model_dir.glob("*")) if model_dir.is_dir() else []
    trained = any(p.suffix in {".joblib", ".pkl", ".json"} or p.name == "model.joblib"
                  for p in model_files)
    note = {
        "state": "TRAINED" if trained else "UNTRAINED",
        "files": [p.name for p in model_files],
        "instruction": (
            "Model present — anomaly scores come from AnomalyDetector scans."
            if trained
            else "No model yet. Dashboard must show UNTRAINED. "
            "Do not invent probabilities. Optional: train with collected samples via "
            "`python -m runtime_engine.main --config <lab-config> anomaly train`."
        ),
    }
    (dirs["anomaly"] / "state.json").write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")
    result.evidence["state"] = note
    result.grade_hint = "UNTRAINED" if not trained else "model will score live process features"
    if not trained:
        result.notes.append("Reported UNTRAINED — no fabricated anomaly probability.")
    result.status = "completed"
    result.ended_at = now_iso()
    return result
