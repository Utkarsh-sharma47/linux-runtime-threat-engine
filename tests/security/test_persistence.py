"""Persistence and privilege monitoring, findings pipeline and scheduler integration.

Everything runs against synthetic directories under tmp_path; host configuration is
never modified.
"""

import json
import os
import queue
import stat
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from runtime_engine.config.settings import PersistenceSettings, Settings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import EventType, Severity
from runtime_engine.main import main
from runtime_engine.monitor.session import MonitorSession
from runtime_engine.monitor.state import DashboardState
from runtime_engine.pipeline import Pipeline
from runtime_engine.security import fsutil, persistence
from runtime_engine.security.findings import (
    Coverage,
    Finding,
    ScanReport,
    SecurityState,
    SeverityPolicy,
    stable_id,
)
from runtime_engine.security.persistence import PersistenceMonitor
from runtime_engine.security.scheduler import SecurityScheduler, safe_scan

ROOT = os.geteuid() == 0
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialNeverStored user@lab"


@pytest.fixture
def lab(tmp_path):
    """A fake host layout: systemd, cron, ssh, sudoers, privileged and sensitive dirs."""
    dirs = {name: tmp_path / name for name in ("systemd", "cron", "ssh", "priv", "local")}
    for path in dirs.values():
        path.mkdir()
    (dirs["systemd"] / "app.service").write_text("[Service]\nExecStart=/usr/bin/app\n")
    (dirs["cron"] / "backup").write_text("0 1 * * * root /usr/bin/backup\n")
    (dirs["cron"] / "backup").chmod(0o644)
    (dirs["ssh"] / "authorized_keys").write_text(KEY + "\n")
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL:ALL) ALL\n")
    tool = dirs["priv"] / "tool"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    settings = PersistenceSettings(
        systemd_paths=[str(dirs["systemd"])],
        cron_paths=[str(dirs["cron"])],
        ssh_paths=[str(dirs["ssh"] / "authorized_keys")],
        sudoers_paths=[str(sudoers)],
        privileged_dirs=[str(dirs["priv"])],
        sensitive_exec_dirs=[str(dirs["local"])],
    )
    return tmp_path, dirs, settings


def baseline_monitor(settings, **policy):
    monitor = PersistenceMonitor(settings, SeverityPolicy(**policy))
    first = monitor.scan()
    assert first.status == "baseline-created" and not first.findings
    return monitor


def by_rule(report):
    return {f.rule_id: f for f in report.findings}


def test_detects_persistence_and_privilege_changes(lab):
    tmp_path, dirs, settings = lab
    monitor = baseline_monitor(settings)
    (dirs["systemd"] / "evil.timer").write_text("[Timer]\nOnBootSec=1\n")
    (dirs["cron"] / "backup").write_text("* * * * * root /tmp/x\n")
    with open(dirs["ssh"] / "authorized_keys", "a") as stream:
        stream.write(KEY.replace("user@lab", "other@lab") + "\n")
    (tmp_path / "sudoers").write_text("root ALL=(ALL:ALL) ALL\nuser ALL=(ALL) NOPASSWD: ALL\n")
    (dirs["priv"] / "tool").chmod(0o4755)
    new_exec = dirs["local"] / "helper"
    new_exec.write_text("#!/bin/sh\n")
    new_exec.chmod(0o755)
    report = monitor.scan()
    rules = by_rule(report)
    assert {"PM001", "PM002", "PM003", "PM004", "PM005", "PM007"} <= set(rules)
    assert rules["PM001"].evidence["change"] == "new systemd item"
    assert rules["PM002"].evidence["change"].startswith("content changed")
    assert "key count 1 -> 2" in rules["PM003"].evidence["change"]
    # The baseline tracks privileged files only, so a newly SUID file is a new item.
    assert rules["PM005"].evidence["change"] == "new SUID executable"
    assert rules["PM005"].severity == Severity.HIGH
    assert rules["PM005"].evidence["current"]["meta"]["permissions"] == "-rwsr-xr-x"
    assert rules["PM001"].attribution.startswith("unavailable")
    # Key material and file contents never appear in evidence.
    dumped = json.dumps([f.model_dump(mode="json") for f in report.findings])
    assert "AAAAC3Nza" not in dumped and "NOPASSWD" not in dumped and "/tmp/x" not in dumped
    assert report.status == "ok"


def test_new_suid_weakened_permissions_and_removal(lab):
    tmp_path, dirs, settings = lab
    monitor = baseline_monitor(settings)
    suid = dirs["priv"] / "newsuid"
    suid.write_text("x")
    suid.chmod(0o2755)
    (dirs["cron"] / "backup").chmod(0o666)
    (dirs["systemd"] / "app.service").unlink()
    rules = by_rule(monitor.scan())
    assert rules["PM005"].evidence["change"] == "new SGID executable"
    assert rules["PM008"].evidence["change"] == "became world-writable; became group-writable"
    entries, _ = monitor.collect()
    monitor.set_baseline(entries, "rebaselined")  # newsuid is now a known SGID file
    suid.chmod(0o6755)  # an already privileged file gains another privilege bit
    added = by_rule(monitor.scan())["PM005"]
    assert added.evidence["change"] == "SUID/SGID bit added"
    assert added.evidence["previous"]["meta"]["permissions"] == "-rwxr-sr-x"
    assert rules["PM008"].severity == Severity.HIGH
    assert rules["PM009"].resource.endswith("app.service")
    assert rules["PM009"].evidence["current"] is None


def test_capabilities_are_detected(lab, monkeypatch):
    tmp_path, dirs, settings = lab
    monitor = baseline_monitor(settings)
    real = fsutil.file_capabilities

    def fake(path):
        return "cap_setuid=ep" if path.endswith("/tool") else real(path)

    monkeypatch.setattr(persistence, "file_capabilities", fake)
    rules = by_rule(monitor.scan())
    assert rules["PM006"].severity == Severity.HIGH
    assert "cap_setuid=ep" in rules["PM006"].evidence["change"]


def test_capability_xattr_decoding(monkeypatch):
    # vfs_cap_data revision 2: magic|effective, permitted lo, inheritable lo, hi words
    raw = (0x02000001).to_bytes(4, "little") + (1 << 13).to_bytes(4, "little")
    raw += (0).to_bytes(4, "little") * 3
    monkeypatch.setattr(os, "getxattr", lambda *a, **k: raw)
    assert fsutil.file_capabilities("/x") == "cap_net_raw=ep"
    assert fsutil.dangerous("cap_setuid,cap_net_raw=ep") == ["cap_setuid"]
    monkeypatch.setattr(os, "getxattr", lambda *a, **k: b"\x00")
    assert fsutil.file_capabilities("/x") == "unparsed"


def test_allowlist_severity_override_and_promotion(lab):
    tmp_path, dirs, settings = lab
    monitor = baseline_monitor(
        settings,
        promote_min=Severity.HIGH,
        overrides={"PM002": Severity.LOW},
        allow=[f"PM001:{dirs['systemd']}/*"],
    )
    (dirs["systemd"] / "allowed.service").write_text("x")
    (dirs["cron"] / "backup").write_text("changed\n")
    (dirs["priv"] / "tool").chmod(0o4755)
    report = monitor.scan()
    rules = by_rule(report)
    assert "PM001" not in rules and report.suppressed == 1
    assert rules["PM002"].severity == Severity.LOW and not rules["PM002"].promoted
    assert rules["PM005"].promoted


@pytest.mark.skipif(ROOT, reason="root bypasses permission checks")
def test_permission_denied_is_reported_not_hidden(lab):
    tmp_path, dirs, settings = lab
    secret = tmp_path / "sudoers"
    secret.chmod(0)
    locked = dirs["cron"] / "locked"
    locked.mkdir()
    (locked / "job").write_text("x")
    locked.chmod(0)
    try:
        monitor = PersistenceMonitor(settings)
        entries, coverage = monitor.collect()
        assert entries[str(secret)].hash_status == "denied"
        assert str(locked) in coverage.denied and str(secret) in coverage.denied
        assert any("sudoers" in note for note in coverage.unavailable)
        monitor.set_baseline(entries, "test")
        secret.chmod(0o200)
        secret.write_text("changed and longer\n")
        secret.chmod(0)
        report = monitor.scan()
        assert report.status == "degraded"
        change = by_rule(report)["PM004"].evidence["change"]
        assert "content unreadable" in change
    finally:
        locked.chmod(0o755)
        secret.chmod(0o644)


def test_walk_never_follows_symlinks_out_of_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("x")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)
    paths = [m.path for m in fsutil.walk(root, max_depth=5)]
    assert paths == [str(root / "link")]
    assert fsutil.lstat(root / "link").kind == "symlink"
    hasher = fsutil.FileHasher(max_bytes=3)
    big = tmp_path / "big"
    big.write_text("12345")
    assert hasher.digest(fsutil.lstat(big)) == (None, "too-large")
    small = tmp_path / "small"
    small.write_text("12")
    first = hasher.digest(fsutil.lstat(small))
    assert first[1] == "hashed" and hasher.digest(fsutil.lstat(small)) == (first[0], "cached")
    assert hasher.digest(fsutil.lstat(root / "link")) == (None, "not-a-file")


def finding(severity=Severity.HIGH, promoted=True, resource="/etc/x", process_key=None, **kw):
    item = Finding.create(
        "persistence",
        "PM004",
        resource,
        title="sudoers configuration changed",
        severity=severity,
        evidence={"change": kw.pop("change", "content changed")},
        explanation="test",
        process_key=process_key,
        **kw,
    )
    item.promoted = promoted
    return item


def test_pipeline_promotes_each_revision_once(database):
    pipeline = Pipeline(database, load_rules())
    first = pipeline.process_finding(finding())
    assert first is not None and first.created_incident_ids == ["INC-0001"]
    assert first.event.event_type == EventType.SECURITY_FINDING
    assert pipeline.process_finding(finding()) is None  # same revision: refresh only
    stored = database.finding(finding().finding_id)
    assert stored["occurrences"] == 2 and stored["promoted"]
    changed = pipeline.process_finding(finding(change="content changed again"))
    assert changed is not None and len(database.incidents()) == 2
    assert pipeline.process_finding(finding(Severity.LOW, False, "/etc/y")) is None
    assert database.findings(rule_id="PM004")[0]["resource"] in ("/etc/x", "/etc/y")
    assert len(database.findings("persistence")) == 2
    assert pipeline.metrics.security_findings_promoted == 2


def test_attributed_finding_joins_the_process_incident(database, make_event):
    pipeline = Pipeline(database, load_rules())
    process = make_event(executable_path="/tmp/dropper", process_name="dropper")
    pipeline.process(process)  # RT002 creates INC-0001 for this process identity
    result = pipeline.process_finding(
        finding(
            process_key=process.process_key,
            pid=process.pid,
            attribution="test",
            detected_at=process.timestamp + timedelta(seconds=5),  # inside the window
        )
    )
    assert result is not None
    assert result.created_incident_ids == []
    assert [i.incident_id for i in database.incidents()] == ["INC-0001"]
    assert set(database.incidents()[0].rule_ids) == {"RT002", "PM004"}


class FakeModule:
    def __init__(self, name, findings=None, fail=False, interval=0.05):
        self.name, self.interval, self.fail = name, interval, fail
        self.findings = findings or []
        self.scans = 0

    def scan(self):
        self.scans += 1
        if self.fail:
            raise RuntimeError("boom")
        return ScanReport(self.name, "ok", datetime.now(UTC), 0.0, list(self.findings))


def make_info():
    from runtime_engine.monitor.state import SessionInfo, Verbosity

    return SessionInfo(
        "SES-SEC",
        "LIVE",
        "host",
        "kernel",
        1,
        datetime.now(UTC),
        Verbosity.NORMAL,
        0.05,
        10,
        120,
        "test",
        ":memory:",
        "reports",
    )


class Idle:
    errors = rejected = 0

    def collect(self):
        return iter(())


def test_session_processes_findings_and_stops_cleanly(database):
    state = DashboardState(make_info())
    module = FakeModule("persistence", [finding()])
    broken = FakeModule("network", fail=True)
    session = MonitorSession(
        Pipeline(database, load_rules()),
        Idle(),
        state,
        poll_interval=0.05,
        queue_capacity=10,
        security_modules=[module, broken],
    )
    session.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not database.incidents():
        time.sleep(0.02)
    result = session.shutdown("user_quit")
    assert result.status == "STOPPED_GRACEFULLY" and result.unprocessed == 0
    assert [i.incident_id for i in database.incidents()] == ["INC-0001"]  # one revision
    assert module.scans >= 1 and database.finding(finding().finding_id)["occurrences"] >= 1
    assert state.security.report("network").status == "error"
    assert "boom" in state.security.report("network").error
    assert state.security.recent("persistence")[0].finding_id == finding().finding_id
    assert state.counters.observed == state.counters.accepted == 0
    assert session.submit_finding(finding()) is False  # stopped: nothing new accepted


def test_finding_submission_respects_queue_pressure(database):
    state = DashboardState(make_info())
    session = MonitorSession(
        Pipeline(database, load_rules()),
        Idle(),
        state,
        poll_interval=1,
        queue_capacity=1,
        put_timeout=0.01,
    )
    assert session.submit_finding(finding())
    blocked = threading.Thread(target=lambda: session.submit_finding(finding()))
    blocked.start()
    time.sleep(0.1)
    assert state.counters.backpressure_waits == 1
    session.force()
    blocked.join(2)
    assert not blocked.is_alive() and state.counters.dropped == 1
    with pytest.raises(queue.Full):
        session.events.put_nowait((False, finding()))


def test_scheduler_and_state_helpers():
    security = SecurityState(finding_capacity=3)
    stop = threading.Event()
    submitted = []

    def submit(item):
        submitted.append(item)
        stop.set()
        return True

    module = FakeModule("persistence", [finding()], interval=10)
    scheduler = SecurityScheduler([module], submit, security, stop)
    scheduler.start()
    assert scheduler.join(2) == []
    assert submitted and security.overview()["persistence"]["status"] == "ok"
    assert security.overview()["network"]["enabled"] == "not configured"
    assert safe_scan(FakeModule("x", fail=True)).status == "error"
    for index in range(5):
        security.record_finding(finding(resource=f"/r{index}"))
    assert len(security.recent()) == 3  # bounded
    cov = Coverage()
    for index in range(60):
        cov.deny(f"/d{index}")
    assert cov.denied_count == 60 and len(cov.denied) == 50
    report = ScanReport("persistence", "ok", datetime.now(UTC), 0.1, [finding()], cov)
    assert ScanReport.from_dict(report.as_dict()).findings[0].finding_id == finding().finding_id
    assert stable_id("a", "b", "c") == stable_id("a", "b", "c") != stable_id("a", "b", "d")
    policy = SeverityPolicy(allow=["*:443", "PM004:/etc/*"])
    assert policy.allowed(finding(resource="10.0.0.1:443"))
    assert policy.allowed(finding()) and not policy.allowed(finding(resource="/var/x"))


def write_config(tmp_path, settings):
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump({"security": {"persistence": settings.model_dump(mode="json")}})
    )
    return config


def test_persistence_cli(lab, capsys):
    tmp_path, dirs, settings = lab
    config = write_config(tmp_path, settings)
    prefix = ["--config", str(config), "--db", str(tmp_path / "engine.db")]
    assert main(prefix + ["persistence", "scan"]) == 3  # no baseline yet
    assert "no persistence baseline" in capsys.readouterr().err
    assert main(prefix + ["persistence", "baseline", "--json"]) == 0
    assert "warning" in json.loads(capsys.readouterr().out)
    (dirs["priv"] / "tool").chmod(0o4755)
    assert main(prefix + ["persistence", "scan", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in report["findings"]] == ["PM005"]
    assert report["promoted_to_incidents"] == 1
    assert main(prefix + ["persistence", "scan"]) == 0
    text = capsys.readouterr().out
    assert "PRIVILEGE-RELATED CHANGES" in text and "PM005" in text
    assert main(prefix + ["persistence", "show"]) == 0
    assert "PERSISTENCE MONITOR" in capsys.readouterr().out
    finding_id = report["findings"][0]["finding_id"]
    assert main(prefix + ["persistence", "show", "--id", finding_id]) == 0
    assert "new SUID executable" in capsys.readouterr().out
    assert main(prefix + ["persistence", "show", "--id", "nope"]) == 3
    assert main(prefix + ["incidents"]) == 0
    assert "PM005" in capsys.readouterr().out
    assert stat.S_IMODE((dirs["priv"] / "tool").stat().st_mode) == 0o4755  # untouched


def test_default_settings_parse():
    settings = Settings()
    assert settings.security.persistence.enabled
    assert "/etc/sudoers" in settings.security.persistence.sudoers_paths
