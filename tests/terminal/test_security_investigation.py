import json
from datetime import UTC, datetime

from terminal_helpers import make_console, make_info, render, scripted, text_of

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import Severity
from runtime_engine.monitor.investigation import DatabaseSource, LiveSource
from runtime_engine.monitor.state import DashboardState
from runtime_engine.security.findings import Coverage, Finding, ScanReport
from runtime_engine.terminal.dashboard import render_dashboard
from runtime_engine.terminal.interactions import DASHBOARD_COMMANDS, PAGES, Inspector
from runtime_engine.terminal.session_summary import render_session_report
from runtime_engine.terminal.views import security_view
from runtime_engine.terminal.views.metrics_view import render_help


def finding(module="persistence", rule="PM004", resource="/etc/sudoers", severity=Severity.HIGH):
    item = Finding.create(
        module,
        rule,
        resource,
        title=f"{rule} test finding",
        severity=severity,
        evidence={"change": f"{resource} changed"},
        explanation="test explanation",
    )
    item.promoted = severity.rank >= Severity.MEDIUM.rank
    return item


def report(module="persistence", findings=(), status="ok"):
    return ScanReport(
        module, status, datetime.now(UTC), 0.01, list(findings), Coverage(checked=3), {}
    )


def populated_state():
    state = DashboardState(make_info())
    security = state.security
    high, low = finding(), finding(rule="PM007", resource="/etc/cron.d/x", severity=Severity.LOW)
    for module in ("persistence", "network", "anomaly", "integrity", "exposure"):
        security.set_enabled(module, "enabled")
    security.set_enabled(
        "ransomware", "no directories configured (security.ransomware.directories)"
    )
    security.record_report(report("persistence", [high, low]))
    security.record_report(report("network"))
    security.record_report(report("integrity", status="degraded"))
    for item in (high, low, high):  # repeated revisions are deduplicated by ID
        security.record_finding(item)
    return state, high, low


def inspector(state, database, answers, tmp_path):
    console = make_console(170, 60)
    source = LiveSource(state, database) if state is not None else DatabaseSource(database)
    page = Inspector(
        console,
        scripted(answers),
        database=database,
        rules=load_rules(),
        source=source,
        reports_directory=tmp_path / "reports",
        state=state,
    )
    return page, console


def test_overview_counts_unique_findings_by_severity():
    state, high, _ = populated_state()
    overview = state.security.overview()
    persistence = overview["persistence"]
    assert persistence["findings"] == 2 and persistence["promoted"] == 1
    assert persistence["by_severity"] == {"HIGH": 1, "LOW": 1}
    assert persistence["worst"] == Severity.HIGH and persistence["scans"] == 1
    assert overview["anomaly"]["status"] is None  # enabled but not scanned yet
    assert overview["ransomware"]["enabled"].startswith("no directories configured")


def test_resolve_module_accepts_numbers_names_and_prefixes():
    assert security_view.resolve_module("1") == "persistence"
    assert security_view.resolve_module("6") == "ransomware"
    assert security_view.resolve_module("NET") == "network"
    assert security_view.resolve_module("i") == "integrity"
    assert security_view.resolve_module("7") is None
    assert security_view.resolve_module("") is None
    assert security_view.resolve_module("x") is None


def test_filter_and_find_findings():
    _, high, low = populated_state()
    both = [high, low]
    assert security_view.filter_findings(both, Severity.MEDIUM) == [high]
    assert security_view.filter_findings(both, rule="pm007") == [low]
    assert security_view.find_finding(both, high.finding_id[:12]) is high
    assert security_view.find_finding(both, "") is None
    assert security_view.find_finding(both, "nope") is None


def test_menu_lists_all_modules_with_status_and_honest_off_state():
    state, _, _ = populated_state()
    text = render(security_view.render_security_menu(state.security.overview()), 200, 40)
    for title in security_view.TITLES.values():
        assert title[0] in text
    assert "OFF: no directories" in text and "configured" in text
    assert "DEGRADED" in text and "PENDING" in text
    assert "0/1/0/1" in text  # persistence C/H/M/L
    assert "has not checked anything" in " ".join(text.split())


def test_security_page_navigation_filters_and_details(database, tmp_path):
    state, high, low = populated_state()
    database.save_finding(high)
    answers = [
        "bogus",  # unknown module or finding
        "persist",  # open the persistence module page
        "sev CRITICAL",
        "sev nonsense",
        "c",
        "rule PM007",
        low.finding_id[:10],  # details of the filtered finding
        "",  # back to the module page
        "unknown-id",
        "b",  # back to the menu
        high.finding_id,  # details straight from the menu
        "6",  # ransomware: off in this session
        "b",
        "",  # leave the security page
    ]
    page, console = inspector(state, database, answers, tmp_path)
    page.dispatch("s")
    text = text_of(console)
    assert "SECURITY INVESTIGATION" in text
    assert "No module or finding matches 'bogus'" in text
    assert "Filter: severity >= CRITICAL (0 of 2 findings shown)" in text
    assert "Severity must be LOW, MEDIUM, HIGH or CRITICAL." in text
    assert "Filter: rule PM007 (1 of 2 findings shown)" in text
    assert f"FINDING {low.finding_id}" in text
    assert "No persistence finding matches 'unknown-id'" in text
    assert f"FINDING {high.finding_id}" in text and "HISTORY" in text  # stored row has history
    assert "is not running in this session: no directories configured" in text


def test_security_page_from_stored_data_without_live_state(database, tmp_path):
    high = finding("exposure", "EX003", "/usr/local/bin/tool", Severity.HIGH)
    database.save_finding(high)
    database.save_baseline("exposure", "last-scan", report("exposure", [high]).as_dict())
    page, console = inspector(None, database, ["expo", high.finding_id[:8], "", "b", ""], tmp_path)
    page.security_page()
    text = text_of(console)
    assert "no stored scan" in text  # modules without a stored scan say so
    assert "ATTACK SURFACE" in text.upper()
    assert f"FINDING {high.finding_id}" in text and "HISTORY" in text


def test_dashboard_header_and_footer_show_security_modules():
    state, _, _ = populated_state()
    text = render(render_dashboard(state.snapshot(), 160, 45), 160, 45)
    assert "SECURITY MODULES [s]:" in text and "persistence OK 2" in text
    assert "ransomware off" in text and "[s] Security" in text
    assert "[n] Network" in text and "[a] Atomic" in text and "[q] Quit" in text
    compact = render(render_dashboard(state.snapshot(), 60, 15), 60, 15)
    assert "SECURITY MODULES [s]" in compact
    plain = DashboardState(make_info())  # no modules running: no status line
    assert "SECURITY MODULES [s]:" not in render(render_dashboard(plain.snapshot(), 160, 45))


def test_s_key_is_a_dashboard_page_and_documented_in_help():
    assert "s" in PAGES and ("s", "Security modules") in DASHBOARD_COMMANDS
    assert "n" in PAGES and ("n", "Network investigation") in DASHBOARD_COMMANDS
    assert "a" in PAGES and ("a", "Atomic sessions") in DASHBOARD_COMMANDS
    help_text = render(render_help("test"), 160, 60)
    assert "Security Investigation" in help_text
    assert "Network investigation" in help_text
    assert "Atomic execution sessions" in help_text


def test_session_summary_includes_security_modules():
    state, _, _ = populated_state()
    summary = state.summary()
    modules = json.loads(json.dumps(summary))["security_modules"]
    assert modules["persistence"]["worst"] == "HIGH"
    assert modules["persistence"]["last_scan"] is not None
    text = render(render_session_report(summary), 160, 200)
    assert "SECURITY MODULES" in text and "Persistence & privilege" in text
    assert "OFF: no directories configured" in text
    older = {k: v for k, v in summary.items() if k != "security_modules"}
    assert "SECURITY MODULES" not in render(render_session_report(older), 160, 200)
