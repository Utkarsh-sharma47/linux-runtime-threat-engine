"""Anomaly detection: features, scaling, training rules, persistence, fallback, CLI."""

import json
import os

import pytest

from runtime_engine.config.settings import AnomalySettings
from runtime_engine.events.schema import Severity
from runtime_engine.main import main
from runtime_engine.security import anomaly
from runtime_engine.security.anomaly import (
    AnomalyDetector,
    ProcessSampler,
    Scaler,
    exe_category,
    load_model,
    rank,
    save_model,
    synthetic_rows,
    train,
)

SETTINGS = AnomalySettings(min_training_rows=20)


def rows(n=60, **features):
    base = {name: 1.0 for name in anomaly.FEATURES}
    return [
        {"process": f"p{i}", "features": base | {"cpu_percent": 1 + (i % 5) * 0.1} | features}
        for i in range(n)
    ]


def test_exe_category():
    assert exe_category("/usr/bin/ls") == 0.0
    assert exe_category("/opt/app/bin") == 1.0 and exe_category("/usr/local/bin/x") == 1.0
    assert exe_category("/home/u/x") == 2.0
    assert exe_category("/tmp/x") == 3.0 and exe_category("/usr/bin/x (deleted)") == 3.0
    assert exe_category(None) is None


def test_scaler_handles_spread_constant_and_missing():
    data = [{"rss_mb": v, "exe_category": 0.0} for v in (1, 2, 3, 4, 100)]
    scaler = Scaler.fit(data, ["rss_mb", "exe_category"])
    assert scaler.scale["exe_category"] == 1.0  # constant feature: no division by zero
    z = scaler.z({"rss_mb": 100.0, "exe_category": None})
    assert z["exe_category"] is None and z["rss_mb"] > 2
    assert scaler.vector({"rss_mb": None, "exe_category": None}) == [0.0, 0.0]  # median imputed


def test_training_rules_exclusions_and_dropped_features():
    data = rows(40) + rows(5, cpu_percent=500.0)
    for row in data[-5:]:
        row["label"] = "anomaly"
    data[0]["process_key"] = "known-incident"
    for row in data[:30]:
        row["features"]["fd_count"] = None
    model = train(
        data,
        SETTINGS,
        dataset="t",
        excluded_keys={"known-incident"},
        algorithm="robust",
        assertion="test",
    )
    assert model.metadata["training_rows"] == 39 and model.metadata["excluded_rows"] == 6
    assert "fd_count" in model.metadata["dropped_features"]
    with pytest.raises(ValueError, match="at least 20"):
        train(rows(10), SETTINGS, dataset="t", assertion="test")
    override = AnomalySettings(min_training_rows=20, threshold_override=9.5)
    assert train(rows(), override, dataset="t", algorithm="robust", assertion="x").threshold == 9.5


@pytest.mark.parametrize("algorithm", ["robust", "iforest"])
def test_synthetic_outliers_found_without_flagging_normal_rows(algorithm):
    if algorithm == "iforest" and not anomaly.sklearn_available():
        pytest.skip("scikit-learn not installed")
    baseline, observed = synthetic_rows()
    model = train(
        baseline, AnomalySettings(), dataset="synthetic", algorithm=algorithm, assertion="synthetic"
    )
    features = {str(i): r["features"] for i, r in enumerate(observed)}
    names = {str(i): (r["pid"], r["process"]) for i, r in enumerate(observed)}
    ranking = rank(model, features, names, 3.0)
    flagged = {r["process"] for r in ranking if r["above_threshold"]}
    injected = {r["process"] for r in observed if r["label"] == "anomaly"}
    assert flagged == injected  # no normal row is a false positive in this dataset
    assert "unreadable-exe" not in flagged  # missing values are imputed, not suspicious
    top = next(r for r in ranking if r["process"] == "respawner")
    assert top["deviations"][0]["feature"] == "launch_rate_per_min"
    again = rank(
        train(
            baseline,
            AnomalySettings(),
            dataset="synthetic",
            algorithm=algorithm,
            assertion="synthetic",
        ),
        features,
        names,
        3.0,
    )
    assert [r["score"] for r in again] == [r["score"] for r in ranking]  # deterministic


def test_model_persistence_tampering_and_missing(tmp_path):
    assert load_model(tmp_path / "none") is None
    robust = train(rows(), SETTINGS, dataset="t", algorithm="robust", assertion="t")
    save_model(robust, tmp_path / "robust")
    loaded = load_model(tmp_path / "robust")
    assert loaded is not None and loaded.metadata["version"] == robust.metadata["version"]
    assert loaded.score_rows([rows(1)[0]["features"]]) == robust.score_rows(
        [rows(1)[0]["features"]]
    )
    if not anomaly.sklearn_available():
        pytest.skip("scikit-learn not installed")
    forest = train(rows(), SETTINGS, dataset="t", algorithm="iforest", assertion="t")
    path = save_model(forest, tmp_path / "forest")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert load_model(tmp_path / "forest") is not None
    artifact = next((tmp_path / "forest").glob("model-*.joblib"))
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(RuntimeError, match="does not match"):
        load_model(tmp_path / "forest")


def test_fallback_without_scikit_learn(tmp_path, monkeypatch):
    monkeypatch.setattr(anomaly, "sklearn_available", lambda: False)
    model = train(rows(), SETTINGS, dataset="t", assertion="t")
    assert model.metadata["algorithm"] == "robust-zscore"
    metadata = dict(model.metadata, algorithm="isolation-forest", artifact="x", artifact_sha256="y")
    (tmp_path / "metadata-v.json").write_text(json.dumps(metadata))
    (tmp_path / "current.json").write_text(json.dumps({"version": "v"}))
    with pytest.raises(RuntimeError, match="scikit-learn"):
        load_model(tmp_path)


def stat_line(pid, name, ppid, start, utime=0, stime=0):
    fields = ["S", str(ppid)] + ["0"] * 9 + [str(utime), str(stime)] + ["0"] * 6 + [str(start)]
    return f"{pid} ({name}) " + " ".join(fields) + " 0 0\n"


@pytest.fixture
def proc(tmp_path):
    root = tmp_path / "proc"
    (root / "sys/kernel/random").mkdir(parents=True)
    (root / "sys/kernel/random/boot_id").write_text("boot-a\n")
    (root / "uptime").write_text("1000.00 0.00\n")
    hz = os.sysconf("SC_CLK_TCK")
    for pid, name, ppid, start, cpu, exe in [
        (1, "init", 0, 0, 10 * hz, "/usr/lib/systemd/systemd"),
        (50, "shell", 1, 900 * hz, 0, "/usr/bin/bash"),
        (51, "dropper", 50, 990 * hz, 9 * hz, "/tmp/dropper"),
    ]:
        folder = root / str(pid)
        folder.mkdir()
        (folder / "stat").write_text(stat_line(pid, name, ppid, start, cpu))
        (folder / "status").write_text("VmRSS:\t   2048 kB\n")
        os.symlink(exe, folder / "exe")
    return root


def test_sampler_features(proc):
    sampler = ProcessSampler(proc)
    samples, coverage = sampler.samples()
    by_sample = {sample.name: sample for sample in samples}
    # Directory order is not stable; attach descriptor data to init explicitly.
    rows_ = sampler.features(samples, {by_sample["init"].key: {"fds": 7, "sockets": 2}})
    by_name = {sample.name: rows_[sample.key] for sample in samples}
    assert by_name["dropper"]["lifetime_seconds"] == pytest.approx(10)
    assert by_name["dropper"]["cpu_percent"] == pytest.approx(90)
    assert by_name["dropper"]["exe_category"] == 3.0 and by_name["dropper"]["rss_mb"] == 2.0
    assert by_name["shell"]["child_count"] == 1.0 and by_name["init"]["child_count"] == 1.0
    assert by_name["init"]["fd_count"] == 7.0
    assert by_name["dropper"]["fd_count"] is None  # missing, not zero
    assert by_name["shell"]["fd_count"] is None
    assert coverage.checked == 3


def test_detector_statuses_threshold_and_findings(proc, tmp_path):
    settings = AnomalySettings(model_directory=str(tmp_path / "m"), min_training_rows=20)
    detector = AnomalyDetector(settings, sampler=ProcessSampler(proc))
    report = detector.scan()
    assert report.status == "no-model" and not report.findings
    assert any("network module" in note for note in report.coverage.unavailable)
    normal = [
        {
            "features": {
                "cpu_percent": 0.5,
                "rss_mb": 2.0,
                "lifetime_seconds": 900.0 + i,
                "child_count": 1.0,
                "fd_count": None,
                "net_connections": None,
                "exe_category": 0.0,
                "launch_rate_per_min": 0.1,
            }
        }
        for i in range(30)
    ]
    save_model(
        train(normal, settings, dataset="t", algorithm="robust", assertion="t"), tmp_path / "m"
    )
    detector.reload()
    report = detector.scan()
    assert report.status == "degraded"  # fd/socket counts unavailable without the network module
    flagged = {f.process_name: f for f in report.findings}
    assert "dropper" in flagged and flagged["dropper"].severity == Severity.LOW
    evidence = flagged["dropper"].evidence
    assert evidence["algorithm"] == "robust-zscore" and evidence["score"] >= evidence["threshold"]
    assert {d["feature"] for d in evidence["deviations"]} >= {"cpu_percent", "exe_category"}
    assert flagged["dropper"].process_key.startswith('["boot-a",51,')
    assert detector.scan().findings[0].revision == flagged["dropper"].revision  # stable
    strict = AnomalySettings(model_directory=str(tmp_path / "m"), threshold_override=1e9)
    save_model(
        train(
            normal,
            strict.model_copy(update={"min_training_rows": 20}),
            dataset="t",
            algorithm="robust",
            assertion="t",
        ),
        tmp_path / "m",
    )
    detector.reload()
    assert detector.scan().findings == []
    (tmp_path / "m" / "current.json").write_text("{broken")
    detector.reload()
    assert detector.scan().status == "error"


def test_anomaly_cli(tmp_path, capsys):
    db = ["--db", str(tmp_path / "e.db")]
    model = ["--model-dir", str(tmp_path / "model")]
    assert main(db + ["anomaly", "status"] + model) == 0
    assert "No trained model" in capsys.readouterr().out
    assert main(db + ["anomaly", "score", "--dataset", "x"] + model) == 3
    capsys.readouterr()
    assert main(db + ["anomaly", "demo", "--json", "--output", str(tmp_path / "data")]) == 0
    demo = json.loads(capsys.readouterr().out)
    assert demo["normal_rows_flagged"] == [] and len(demo["injected_found"]) == 4
    host = tmp_path / "host.jsonl"
    host.write_text(
        "".join(
            json.dumps(r | {"source": "host-collected"}) + "\n" for r in synthetic_rows()[0][:80]
        )
    )
    assert main(db + ["anomaly", "train", "--dataset", str(host)] + model) == 2
    assert "not a verified clean baseline" in capsys.readouterr().err
    assert (
        main(
            db
            + [
                "anomaly",
                "train",
                "--dataset",
                str(host),
                "--i-reviewed-baseline",
                "--algorithm",
                "robust",
                "--json",
            ]
            + model
        )
        == 0
    )
    trained = json.loads(capsys.readouterr().out)
    assert trained["baseline_assertion"].startswith("host-collected; operator asserted")
    assert main(db + ["anomaly", "status", "--json"] + model) == 0
    assert json.loads(capsys.readouterr().out)["algorithm"] == "robust-zscore"
    observed = tmp_path / "data" / "observed.jsonl"
    assert main(db + ["anomaly", "score", "--dataset", str(observed), "--top", "3"] + model) == 0
    assert "PROCESS ANOMALY RANKING" in capsys.readouterr().out
    assert main(db + ["anomaly", "inspect", "--pid", str(os.getpid()), "--json"] + model) == 0
    assert json.loads(capsys.readouterr().out)["ranking"][0]["pid"] == os.getpid()
    assert main(db + ["anomaly", "inspect", "--pid", "999999999"] + model) == 3
    output = tmp_path / "collected.jsonl"
    assert (
        main(
            db
            + [
                "anomaly",
                "collect",
                "--duration",
                "0.1",
                "--interval",
                "0.1",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    first = json.loads(output.read_text().splitlines()[0])
    assert first["source"] == "host-collected" and oct(output.stat().st_mode & 0o777) == "0o600"
    assert main(db + ["anomaly", "collect", "--duration", "0.1", "--output", str(output)]) == 1
