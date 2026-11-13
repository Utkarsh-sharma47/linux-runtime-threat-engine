import json
import math
import os
import tempfile
from pathlib import Path

import pytest

from runtime_engine.config.settings import RansomwareSettings, Settings
from runtime_engine.main import main
from runtime_engine.security import ransomware_sim
from runtime_engine.security.modules import build_modules
from runtime_engine.security.ransomware import (
    BehaviourAnalyzer,
    FileEvent,
    PollingWatcher,
    RansomwareMonitor,
    candidate_processes,
    shannon_entropy,
)
from runtime_engine.storage.database import Database


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


TEXT = b"Quarterly report: revenue grew in every region. " * 100


def test_entropy_bounds_and_known_values() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert str(shannon_entropy(b"aaaa")) == "0.0"  # never "-0.0"
    assert shannon_entropy(b"ab" * 50) == pytest.approx(1.0)
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
    assert 3.5 < shannon_entropy(TEXT) < 4.5
    assert shannon_entropy(os.urandom(65536)) > 7.9
    four = bytes([0, 1, 2, 3]) * 10
    assert shannon_entropy(four) == pytest.approx(math.log2(4))


def test_sampling_reads_at_most_sample_bytes_and_is_rate_limited(tmp_path: Path) -> None:
    clock = Clock()
    settings = RansomwareSettings(sample_bytes=256, entropy_reads_per_second=2)
    analyzer = BehaviourAnalyzer(settings, clock)
    big = write(tmp_path / "big.bin", b"a" * 256 + os.urandom(100_000))
    analyzer.seed(str(big))
    assert analyzer.entropy[str(big)] == 0.0  # only the first 256 bytes were read
    for i in range(5):
        analyzer.seed(str(write(tmp_path / f"f{i}", TEXT)))
    assert analyzer.sampled == 2 and analyzer.skipped_samples == 4
    clock.now += 1  # tokens refill at entropy_reads_per_second
    analyzer.seed(str(big))
    assert analyzer.sampled == 3


def test_high_entropy_alone_never_alerts(tmp_path: Path) -> None:
    clock = Clock()
    settings = RansomwareSettings(entropy_reads_per_second=1000)
    analyzer = BehaviourAnalyzer(settings, clock)
    for i in range(5):  # e.g. a user saving a few compressed archives
        path = write(tmp_path / f"photo{i}.zip", os.urandom(8192))
        analyzer.feed(FileEvent(clock.now, "write", str(path)))
    result = analyzer.evaluate()
    assert result["indicators"]["entropy"] == 1.0
    assert result["triggered"] == ["entropy"]
    assert result["score"] < 50 and result["alert"] is False


def test_mass_modification_without_entropy_is_not_enough_alone(tmp_path: Path) -> None:
    clock = Clock()
    analyzer = BehaviourAnalyzer(RansomwareSettings(entropy_reads_per_second=1000), clock)
    path = write(tmp_path / "build.log", TEXT)
    for _ in range(100):  # one file rewritten many times: a log or build tool
        analyzer.feed(FileEvent(clock.now, "write", str(path)))
    result = analyzer.evaluate()
    assert result["triggered"] == ["modifications"]
    assert result["alert"] is False


def test_encryption_like_behaviour_alerts(tmp_path: Path) -> None:
    clock = Clock()
    settings = RansomwareSettings(entropy_reads_per_second=1000)
    analyzer = BehaviourAnalyzer(settings, clock)
    paths = [write(tmp_path / f"d{i % 4}" / f"doc{i}.txt", TEXT) for i in range(40)]
    for path in paths:
        analyzer.seed(str(path))
    for path in paths:
        path.write_bytes(os.urandom(len(TEXT)))
        analyzer.feed(FileEvent(clock.now, "write", str(path)))
        locked = path.with_name(path.name + ".locked")
        path.rename(locked)
        analyzer.feed(FileEvent(clock.now, "rename", str(locked), str(path)))
        clock.now += 0.05
    result = analyzer.evaluate()
    assert result["alert"] is True and result["score"] == pytest.approx(100.0)
    assert set(result["triggered"]) == {
        "modifications", "renames", "files", "directories", "entropy", "extensions",
    }  # fmt: skip
    assert result["extension_change"] == ".locked"
    assert (
        result["entropy_examples"][0]["before"] < 6.0 < 7.2 < result["entropy_examples"][0]["after"]
    )


def test_window_expires_old_events_and_is_bounded(tmp_path: Path) -> None:
    clock = Clock()
    settings = RansomwareSettings(window_seconds=10, max_events_per_window=100)
    analyzer = BehaviourAnalyzer(settings, clock)
    for i in range(150):
        analyzer.feed(FileEvent(clock.now, "create", str(tmp_path / f"f{i}")))
    assert len(analyzer.window.events) == 100 and analyzer.dropped_events == 50
    clock.now += 11
    assert analyzer.evaluate()["events"] == 0


def test_entropy_memory_is_bounded(tmp_path: Path) -> None:
    analyzer = BehaviourAnalyzer(RansomwareSettings(), Clock())
    for i in range(20_050):
        analyzer._remember(f"/x/{i}", 1.0)
    assert len(analyzer.entropy) == 20_000 and "/x/0" not in analyzer.entropy


def test_polling_watcher_detects_create_write_rename_delete(tmp_path: Path) -> None:
    keep = write(tmp_path / "a.txt", TEXT)
    gone = write(tmp_path / "b.txt", TEXT)
    moved = write(tmp_path / "c.txt", TEXT)
    write(tmp_path / ".git" / "objects" / "x", TEXT)
    watcher = PollingWatcher([str(tmp_path)], [".git", "*.swp"])
    write(tmp_path / "new.txt", TEXT)
    write(tmp_path / "ignored.swp", TEXT)
    keep.write_bytes(os.urandom(500))
    gone.unlink()
    moved.rename(tmp_path / "c.txt.locked")
    kinds = {(e.kind, Path(e.path).name, e.old_path and Path(e.old_path).name)
             for e in watcher.read()}  # fmt: skip
    assert kinds == {
        ("create", "new.txt", None),
        ("write", "a.txt", None),
        ("delete", "b.txt", None),
        ("rename", "c.txt.locked", "c.txt"),
    }
    assert watcher.read() == []


def test_monitor_polling_fallback_detects_in_place_encryption(tmp_path: Path) -> None:
    docs = [write(tmp_path / f"d{i % 3}" / f"doc{i}.txt", TEXT) for i in range(30)]
    settings = RansomwareSettings(entropy_reads_per_second=1000)
    monitor = RansomwareMonitor(settings, directories=[str(tmp_path)], use_inotify=False)
    try:
        assert monitor.mechanism.startswith("polling")
        for path in docs:
            path.write_bytes(os.urandom(len(TEXT) + 7))
            path.rename(path.with_name(path.name + ".locked"))
        report = monitor.scan()
    finally:
        monitor.close()
    assert report.status == "ok"
    [finding] = report.findings
    assert finding.rule_id == "RW001" and finding.severity.name == "HIGH"
    assert "polling" in report.summary["mechanism"]


def test_inotify_monitor_reports_quiet_directory_as_ok(tmp_path: Path) -> None:
    write(tmp_path / "notes.txt", TEXT)
    monitor = RansomwareMonitor(RansomwareSettings(), directories=[str(tmp_path)])
    try:
        report = monitor.scan()
    finally:
        monitor.close()
    assert report.status == "ok" and report.findings == []
    assert monitor.mechanism in ("inotify", "polling (inotify unavailable)")


@pytest.mark.parametrize("use_inotify", [True, False])
def test_missing_directory_is_reported_not_silently_clean(
    tmp_path: Path, use_inotify: bool
) -> None:
    absent = str(tmp_path / "absent")
    monitor = RansomwareMonitor(RansomwareSettings(), directories=[absent], use_inotify=use_inotify)
    try:
        report = monitor.scan()
    finally:
        monitor.close()
    assert report.findings == [] and report.status == "degraded"
    assert any(note.startswith(absent) for note in report.coverage.unavailable)


def test_polling_file_limit_is_reported(tmp_path: Path) -> None:
    for i in range(5):
        write(tmp_path / f"f{i}", TEXT)
    watcher = PollingWatcher([str(tmp_path)], [], max_files=3)
    assert len(watcher.state) == 3 and "file limit 3" in watcher.watch_errors[0]


def test_candidate_processes_finds_own_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    found = candidate_processes(str(tmp_path))
    mine = [c for c in found if c["pid"] == os.getpid()]
    assert mine and "working directory inside" in mine[0]["reasons"]


def test_simulator_refuses_paths_outside_its_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    home_like = tmp_path / "Documents"
    write(home_like / "thesis.docx", TEXT)
    for bad in (
        home_like,  # not under the temp directory
        tmp_path / "tmp" / "my-files",  # wrong prefix
        tmp_path / "tmp" / "rte-ransomware-lab-x" / "nested",  # not directly under temp
    ):
        with pytest.raises(ransomware_sim.UnsafeLabError):
            ransomware_sim.simulate(bad, files=1)
    occupied = tmp_path / "tmp" / "rte-ransomware-lab-occupied"
    write(occupied / "user.txt", TEXT)  # non-empty without the marker
    with pytest.raises(ransomware_sim.UnsafeLabError):
        ransomware_sim.create_lab(str(occupied))
    link = tmp_path / "tmp" / "rte-ransomware-lab-link"
    link.symlink_to(home_like)
    with pytest.raises(ransomware_sim.UnsafeLabError):
        ransomware_sim.cleanup(link)
    assert (home_like / "thesis.docx").read_bytes() == TEXT
    assert (occupied / "user.txt").read_bytes() == TEXT


def test_simulator_bounds_and_cleanup_only_removes_its_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    lab = ransomware_sim.create_lab()
    for files in (0, ransomware_sim.MAX_FILES + 1):
        with pytest.raises(ransomware_sim.UnsafeLabError):
            ransomware_sim.simulate(lab, files=files)
    result = ransomware_sim.simulate(lab, files=5, delay=0)
    assert sorted(os.listdir(lab)) == sorted(
        [ransomware_sim.MARKER, ransomware_sim.NOTE] + list(result["renamed"])  # type: ignore[arg-type]
    )
    assert shannon_entropy((lab / "lab-file-000.txt.locked").read_bytes()) > 7.0
    write(lab / "someone-elses.txt", TEXT)
    assert ransomware_sim.cleanup(lab) == 7
    assert os.listdir(lab) == ["someone-elses.txt"]  # foreign file kept, lab not removed
    (lab / "someone-elses.txt").unlink()
    ransomware_sim.create_lab(str(lab))
    ransomware_sim.cleanup(lab)
    assert not lab.exists()


def test_simulator_cli_refuses_with_exit_code_2(tmp_path: Path) -> None:
    assert ransomware_sim.main([str(tmp_path / "Documents"), "--files", "1"]) == 2


def test_module_registration_is_off_until_directories_configured(tmp_path: Path) -> None:
    database = Database(tmp_path / "db.sqlite")
    settings = Settings()
    _, off = build_modules(settings, database)
    assert "no directories configured" in off["ransomware"]
    settings.security.ransomware.directories = [str(tmp_path)]
    modules, off = build_modules(settings, database)
    try:
        assert "ransomware" not in off
        assert any(m.name == "ransomware" for m in modules)
    finally:
        for module in modules:
            close = getattr(module, "close", None)
            if close is not None:
                close()


def test_cli_demo_detects_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    db = str(tmp_path / "db.sqlite")
    assert main(["--db", db, "ransomware", "demo", "--files", "30", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in data["findings"]] == ["RW001"]
    assert data["promoted_to_incidents"] >= 1
    assert not list(tmp_path.glob("rte-ransomware-lab*"))
    assert main(["--db", db, "ransomware", "report", "--json"]) == 0
    stored = json.loads(capsys.readouterr().out)
    assert stored["findings"] and stored["last_report"]["module"] == "ransomware"
    assert main(["--db", db, "ransomware", "simulate", "--lab-dir", "/etc", "--files", "1"]) == 2
    assert "refused" in capsys.readouterr().err
