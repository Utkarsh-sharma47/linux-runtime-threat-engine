"""Attack surface analyzer on a synthetic host layout (no host configuration touched)."""

import json
import os

import pytest
import yaml

from runtime_engine.config.settings import ExposureSettings
from runtime_engine.events.schema import Severity
from runtime_engine.main import main
from runtime_engine.security import exposure
from runtime_engine.security.exposure import ExposureAnalyzer, grade

ROOT = os.geteuid() == 0
HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
)


def row(slot, local, remote, state, uid, inode):
    queues = "00000000:00000000 00:00000000 00000000"
    return f"   {slot}: {local} {remote} {state} {queues}  {uid}        0 {inode} 1 0\n"


@pytest.fixture
def host(tmp_path):
    bins = tmp_path / "bin"
    bins.mkdir()
    for name, mode in [
        ("passwd", 0o4755),
        ("custom-helper", 0o4755),
        ("find", 0o4755),
        ("plain", 0o755),
        ("group-tool", 0o2755),
    ]:
        path = bins / name
        path.write_text("#!/bin/sh\n")
        path.chmod(mode)
    writable = tmp_path / "wbin"
    writable.mkdir()
    writable.chmod(0o777)
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    secrets = tmp_path / "etc"
    secrets.mkdir()
    (secrets / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    (secrets / "passwd").chmod(0o666)
    (secrets / "key").write_text("PRIVATE")
    (secrets / "key").chmod(0o644)
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh").chmod(0o755)
    (home / ".ssh" / "id_ed25519").write_text("never read")
    (home / ".ssh" / "id_ed25519").chmod(0o640)
    (home / ".ssh" / "known_hosts").write_text("x")
    (home / ".ssh" / "known_hosts").chmod(0o644)
    sudoers = tmp_path / "sudoers"
    sudoers.write_text(
        "root ALL=(ALL:ALL) ALL\n"
        "# alice ALL=(ALL) NOPASSWD: ALL\n"
        "alice ALL=(ALL) NOPASSWD: ALL\n"
        "bob ALL=(root) /usr/bin/vim\n"
        'Defaults env_keep += "LD_PRELOAD"\n'
        "carol ALL=(root) /opt/scripts/*\n"
    )
    units = tmp_path / "units"
    units.mkdir()
    (units / "app.service").write_text("[Service]\nExecStart=/opt/app/run\n")
    (units / "safe.service").write_text("[Service]\nUser=app\nExecStart=/opt/app/run\n")
    proc = tmp_path / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("b\n")
    (proc / "net").mkdir()
    (proc / "net/tcp").write_text(
        HEADER
        + row(0, "00000000:1538", "00000000:0000", "0A", 0, 1)  # 0.0.0.0:5432 root
        + row(1, "0100007F:0BB9", "00000000:0000", "0A", 0, 2)  # 127.0.0.1:3001 root
        + row(2, "00000000:0016", "00000000:0000", "0A", 0, 3)  # :22 expected
        + row(3, "00000000:1F90", "00000000:0000", "0A", 1000, 4)  # user service
    )
    (proc / "net/tcp6").write_text(
        HEADER
        + row(
            0,
            "00000000000000000000000000000000:1538",
            "00000000000000000000000000000000:0000",
            "0A",
            0,
            5,
        )
    )
    for name in ("udp", "udp6"):
        (proc / "net" / name).write_text(HEADER)
    for pid, exe in [(10, "/tmp/dropper"), (11, "/usr/bin/ls"), (12, "/no/such/old (deleted)"),
                     (13, "/usr/bin/env (deleted)")]:  # replaced system binary  # fmt: skip
        (proc / str(pid)).mkdir()
        os.symlink(exe, proc / str(pid) / "exe")
        (proc / str(pid) / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    settings = ExposureSettings(suid_paths=[str(bins)], expected_suid=["passwd"],
                                expected_listen_ports=[22])  # fmt: skip
    analyzer = ExposureAnalyzer(
        settings,
        proc=proc,
        home=str(home),
        sudoers=[str(sudoers)],
        sensitive=[(str(secrets / "passwd"), "no-world-write"), (str(secrets / "key"), "private")],
        path_env=f"{bins}:{writable}:{sticky}:.:{tmp_path / 'missing'}",
        unit_dir=str(units),
    )
    return tmp_path, analyzer


def by_resource(report):
    return {f.resource: f for f in report.findings}


def test_suid_and_capability_classification(host, monkeypatch):
    tmp_path, analyzer = host
    real = exposure.file_capabilities
    monkeypatch.setattr(exposure, "file_capabilities", lambda p: (
        "cap_net_raw=ep" if p.endswith("plain") else real(p)))  # fmt: skip
    found = by_resource(analyzer.scan())
    bins = tmp_path / "bin"
    assert found[str(bins / "passwd")].severity == Severity.LOW  # expected helper
    # Test files are owned by the test user, not root: SUID to that user is MEDIUM.
    helper = found[str(bins / "custom-helper")]
    assert helper.severity == Severity.MEDIUM and "non-root uid" in helper.evidence["weakness"]
    assert found[str(bins / "find")].severity == Severity.CRITICAL  # shell escape
    assert found[str(bins / "group-tool")].evidence["weakness"] == "unexpected SGID executable"
    caps = [f for f in found.values() if f.rule_id == "EX002"]
    assert (
        caps[0].severity == Severity.LOW
        and "network capability only" in caps[0].evidence["weakness"]
    )
    assert found[str(bins / "passwd")].evidence["metadata"]["permissions"] == "-rwsr-xr-x"


def test_path_sensitive_files_and_private_keys(host):
    tmp_path, analyzer = host
    found = by_resource(analyzer.scan())
    assert found[str(tmp_path / "wbin")].severity == Severity.HIGH
    assert found[str(tmp_path / "sticky")].severity == Severity.MEDIUM
    assert found["."].rule_id == "EX003"
    assert found[str(tmp_path / "etc/passwd")].severity == Severity.CRITICAL
    key = found[str(tmp_path / "etc/key")]
    assert key.evidence["weakness"].startswith("world-readable, group-readable")
    assert "PRIVATE" not in json.dumps(key.model_dump(mode="json"))  # contents never read


def test_default_ssh_checks_use_names_only(host):
    tmp_path, analyzer = host
    analyzer.sensitive = None
    items = dict(analyzer._sensitive_items())
    ssh = tmp_path / "home/.ssh"
    assert items[str(ssh)] == "private-dir" and items[str(ssh / "id_ed25519")] == "private"
    assert str(ssh / "known_hosts") not in items


def test_services_processes_and_sudo(host):
    tmp_path, analyzer = host
    report = analyzer.scan()
    found = by_resource(report)
    exposed = found["tcp/5432 on 0.0.0.0, ::"]  # IPv4 and IPv6 merged into one finding
    assert exposed.severity == Severity.MEDIUM and exposed.risk_score == 7.5
    assert found["tcp/3001 on 127.0.0.1"].severity == Severity.LOW
    assert not any(":22" in r or "/22 " in r for r in found)  # expected port
    assert not any("/8080" in r for r in found)  # not root
    unit = found[str(tmp_path / "units/app.service")]
    assert unit.evidence["exec_start"] == "/opt/app/run"
    assert str(tmp_path / "units/safe.service") not in found
    assert found["PID 10 /tmp/dropper"].severity == Severity.HIGH
    assert found["PID 12 /no/such/old (deleted)"].severity == Severity.HIGH
    replaced = found["PID 13 /usr/bin/env (deleted)"]
    assert replaced.severity == Severity.LOW and "restart pending" in replaced.evidence["weakness"]
    sudo = {f.evidence["line"]: f for f in report.findings if f.rule_id == "EX008"}
    assert set(sudo) == {3, 4, 5, 6}  # comment on line 2 ignored, root line not flagged
    assert sudo[3].severity == Severity.HIGH and sudo[5].severity == Severity.CRITICAL
    assert sudo[6].severity == Severity.MEDIUM and sudo[4].evidence["weakness"].startswith("allows")


@pytest.mark.skipif(ROOT, reason="root can read everything")
def test_unreadable_sudoers_is_reported(host):
    tmp_path, analyzer = host
    (tmp_path / "sudoers").chmod(0)
    try:
        report = analyzer.scan()
        assert any("sudo patterns not assessed" in n for n in report.coverage.unavailable)
        assert report.status == "degraded"
    finally:
        (tmp_path / "sudoers").chmod(0o644)


def test_scoring_baseline_acceptance_and_incremental(host):
    tmp_path, analyzer = host
    first = analyzer.scan()
    assert first.summary["scan_type"] == "full"
    weights = ExposureSettings().weights
    assert first.summary["score"] == sum(f.risk_score for f in first.findings)
    assert all(f.risk_score == weights[f.severity.value] * float(f.evidence["multiplier"])
               for f in first.findings)  # fmt: skip
    assert first.summary["posture"] == "CRITICAL"
    analyzer.accepted = {f.finding_id for f in first.findings}
    second = analyzer.scan()
    assert second.summary["scan_type"] == "incremental" and second.summary["score"] == 0
    assert second.summary["posture"] == "GOOD" and not any(f.promoted for f in second.findings)
    newcomer = tmp_path / "bin/new-suid"
    newcomer.write_text("x")
    newcomer.chmod(0o4755)  # directory mtime changes, so the incremental scan sees it
    third = analyzer.scan()
    assert by_resource(third)[str(newcomer)].evidence["baseline_status"] == "new"
    (tmp_path / "bin/plain").chmod(0o4755)  # bit added in an unchanged directory
    assert str(tmp_path / "bin/plain") not in by_resource(analyzer.scan())  # incremental miss
    assert str(tmp_path / "bin/plain") in by_resource(analyzer.scan(full=True))
    assert grade(5, False) == "GOOD" and grade(5, True) == "POOR" and grade(80, False) == "CRITICAL"


def test_exposure_cli(host, tmp_path, capsys):
    _, analyzer = host
    config = tmp_path / "c.yaml"
    config.write_text(
        yaml.safe_dump({"security": {"exposure": analyzer.settings.model_dump(mode="json")}})
    )
    run = ["--config", str(config), "--db", str(tmp_path / "e.db"), "exposure"]
    assert main(run + ["report"]) == 3
    capsys.readouterr()
    assert main(run + ["scan", "--json"]) == 0
    scanned = json.loads(capsys.readouterr().out)
    assert scanned["summary"]["scan_type"] == "full" and scanned["promoted_to_incidents"] >= 1
    assert main(run + ["baseline"]) == 0
    assert "Accepted" in capsys.readouterr().out
    assert main(run + ["scan", "--incremental", "--json"]) == 0
    again = json.loads(capsys.readouterr().out)
    assert again["summary"]["scan_type"] == "incremental" and again["summary"]["new"] == 0
    assert main(run + ["report", "--severity", "high"]) == 0
    text = capsys.readouterr().out
    assert "ATTACK SURFACE ANALYZER" in text and "REMEDIATION GUIDANCE" in text
    finding = scanned["findings"][0]["finding_id"]
    assert main(run + ["show", "--id", finding]) == 0
    assert "REMEDIATION" in capsys.readouterr().out
    assert main(run + ["show"]) == 1
    assert main(run + ["report", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["module"] == "exposure"
