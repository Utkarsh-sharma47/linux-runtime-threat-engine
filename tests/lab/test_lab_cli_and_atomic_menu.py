"""Coverage for lab CLI entrypoints and the interactive Atomic menu (no real attacks)."""

from __future__ import annotations

from pathlib import Path

import pytest

from runtime_engine.lab import __main__ as lab_main
from runtime_engine.lab import atomic_menu


@pytest.fixture
def isolated_lab(tmp_path, monkeypatch):
    fake_tmp = tmp_path / "tmp"
    fake_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(fake_tmp))
    monkeypatch.setattr("runtime_engine.lab.paths.tempfile.gettempdir", lambda: str(fake_tmp))
    monkeypatch.setattr(
        "runtime_engine.security.ransomware_sim.tempfile.gettempdir", lambda: str(fake_tmp)
    )
    monkeypatch.delenv("RTE_LAB_STATUS", raising=False)
    return fake_tmp


def _inspect_dict(tmp_path: Path) -> dict:
    return {
        "environment": {
            "atomics": str(tmp_path),
            "atomics_commit": "deadbeef",
            "pwsh": "/usr/bin/pwsh",
            "module_version": "1.0",
            "tracing": False,
            "strace": None,
            "ptrace_scope": None,
            "virtualization": "none",
            "uid": 1000,
        },
        "test": {
            "technique": "T1059.004",
            "technique_name": "shell",
            "mitre_url": "https://example.test",
            "number": 8,
            "name": "test",
            "guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "description": "x",
            "executor": "sh",
            "elevation_required": False,
            "prerequisites": [],
            "input_arguments": {},
            "triage_risk": "A",
            "triage_reasons": [],
        },
        "overrides": {},
        "command": "echo hi",
        "cleanup": "",
        "risk": "A",
        "risk_label": "safe",
        "risk_source": "test",
        "profile": None,
        "refusals": [],
        "review_flags": [],
        "warnings": [],
        "setuid_programs": [],
        "approval_token": "abcd1234",
    }


class _FakeConsole:
    def __init__(self, answers: list[str]):
        self._answers = iter(answers)

    def print(self, *args, **kwargs):
        return None

    def input(self, prompt=""):
        return next(self._answers)


def test_lab_main_help_list_and_unknown(capsys, isolated_lab):
    assert lab_main.main([]) == 0
    assert "prepare" in capsys.readouterr().out
    assert lab_main.main(["--help"]) == 0
    assert lab_main.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "process" in out and "all" in out
    assert lab_main.main(["nope"]) == 2
    assert "unknown" in capsys.readouterr().err


def test_lab_main_prepare_run_cleanup(isolated_lab, capsys):
    assert lab_main.main(["prepare"]) == 0
    out = capsys.readouterr().out
    assert "session=" in out
    assert lab_main.main(["run", "--dry-run", "--skip-monitor-check", "--scenario", "all"]) == 0
    assert lab_main.main(["cleanup", "--yes"]) == 0


def test_atomic_menu_non_tty_refuses(monkeypatch, capsys):
    monkeypatch.setattr(atomic_menu.sys.stdin, "isatty", lambda: False)
    assert atomic_menu.main([]) == 2
    assert "TTY" in capsys.readouterr().err


def test_atomic_menu_abort_blank(monkeypatch):
    monkeypatch.setattr(atomic_menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(atomic_menu, "Console", lambda: _FakeConsole([""]))
    assert atomic_menu.main([]) == 0


def test_atomic_menu_invalid_selection(monkeypatch, capsys):
    monkeypatch.setattr(atomic_menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(atomic_menu, "Console", lambda: _FakeConsole(["99"]))
    assert atomic_menu.main([]) == 2
    assert "invalid" in capsys.readouterr().err


def test_atomic_menu_dry_run_and_refusal(monkeypatch, tmp_path):
    monkeypatch.setattr(atomic_menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(atomic_menu, "Console", lambda: _FakeConsole(["1"]))

    class FakeEnv:
        uid = 1000
        atomics_present = True
        atomics = str(tmp_path)
        pwsh = "/usr/bin/pwsh"
        module_version = "1.0"
        tracing = False
        strace = None
        ptrace_scope = None
        virtualization = "none"

    class FakePre:
        refusals: list[str] = []
        test = object()
        token = "abcd1234"

        def as_dict(self):
            return _inspect_dict(tmp_path)

    monkeypatch.setattr(atomic_menu.preflight, "environment", lambda *a, **k: FakeEnv())
    monkeypatch.setattr(atomic_menu.preflight, "check", lambda *a, **k: FakePre())
    monkeypatch.setattr(atomic_menu, "load_profiles", lambda: {})
    monkeypatch.setattr(atomic_menu.atomic_view, "render_inspect", lambda pre: "ok")
    assert atomic_menu.main(["--dry-run", "--atomics", str(tmp_path)]) == 0

    class Refused(FakePre):
        refusals = ["missing atomics"]
        test = None

    monkeypatch.setattr(atomic_menu, "Console", lambda: _FakeConsole(["2"]))
    monkeypatch.setattr(atomic_menu.preflight, "check", lambda *a, **k: Refused())
    assert atomic_menu.main(["--dry-run", "--atomics", str(tmp_path)]) == 4


def test_atomic_menu_live_accept(monkeypatch, tmp_path):
    called = {}

    def fake_live_accept(ns, settings, rules, console):
        called["ok"] = True
        return 0

    monkeypatch.setattr("runtime_engine.terminal.atomic_app.live_accept", fake_live_accept)
    assert atomic_menu.main(["--live-accept", "--results-dir", str(tmp_path)]) == 0
    assert called["ok"] is True


def test_atomic_menu_not_approved(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(atomic_menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(atomic_menu, "Console", lambda: _FakeConsole(["1", "wrong"]))

    class FakeEnv:
        uid = 1000
        atomics_present = True
        atomics = str(tmp_path)
        pwsh = "/bin/pwsh"
        module_version = "1"
        tracing = False
        strace = None
        ptrace_scope = None
        virtualization = "none"

    class FakePre:
        refusals: list[str] = []
        test = object()
        token = "abcd1234"

        def as_dict(self):
            return _inspect_dict(tmp_path)

    monkeypatch.setattr(atomic_menu.preflight, "environment", lambda *a, **k: FakeEnv())
    monkeypatch.setattr(atomic_menu.preflight, "check", lambda *a, **k: FakePre())
    monkeypatch.setattr(atomic_menu, "load_profiles", lambda: {})
    monkeypatch.setattr(atomic_menu.atomic_view, "render_inspect", lambda d: "inspect")
    assert atomic_menu.main(["--atomics", str(tmp_path)]) == 5
    assert "not approved" in capsys.readouterr().err


def test_atomic_menu_http_profile_override(monkeypatch, tmp_path):
    """Selecting T1071.001 sets domain override and allow_review_required."""
    monkeypatch.setattr(atomic_menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(atomic_menu, "Console", lambda: _FakeConsole(["4"]))
    seen: dict = {}

    class FakeEnv:
        uid = 1000
        atomics_present = True
        atomics = str(tmp_path)
        pwsh = "/bin/pwsh"
        module_version = "1"
        tracing = False
        strace = None
        ptrace_scope = None
        virtualization = "none"

    class FakePre:
        refusals = ["stop"]
        test = None
        token = ""

        def as_dict(self):
            return _inspect_dict(tmp_path)

    def fake_check(env, tech, num, profiles, overrides, **flags):
        seen["tech"] = tech
        seen["overrides"] = dict(overrides)
        seen["flags"] = flags
        return FakePre()

    monkeypatch.setattr(atomic_menu.preflight, "environment", lambda *a, **k: FakeEnv())
    monkeypatch.setattr(atomic_menu.preflight, "check", fake_check)
    monkeypatch.setattr(atomic_menu, "load_profiles", lambda: {})
    monkeypatch.setattr(atomic_menu.atomic_view, "render_inspect", lambda d: "inspect")
    assert atomic_menu.main(["--dry-run", "--atomics", str(tmp_path)]) == 4
    assert seen["tech"] == "T1071.001"
    assert seen["overrides"].get("domain") == "203.0.113.10"
    assert seen["flags"].get("allow_review_required") is True
