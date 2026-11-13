"""Network collector, attribution, beacon analysis and CLI. Uses a fake /proc tree."""

import json
import os
import socket
import statistics

import pytest

from runtime_engine.collector.net_collector import NetCollector, decode_address, parse_table
from runtime_engine.config.settings import NetworkSettings
from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.events.schema import EventType
from runtime_engine.main import main
from runtime_engine.pipeline import Pipeline
from runtime_engine.security.network import (
    BeaconAnalyzer,
    NetworkMonitor,
    analyze_series,
    demo_series,
    excluded,
    periodicity,
)

ROOT = os.geteuid() == 0
HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
)


def row(slot, local, remote, state, uid, inode):
    queues = "00000000:00000000 00:00000000 00000000"
    return (
        f"   {slot}: {local} {remote} {state} {queues}  {uid}        0 {inode} 1 0 100 0 0 10 0\n"
    )


# 10.0.0.5:40000 -> 203.0.113.10:443 is "0500000A:9C40 0A7100CB:01BB" (little-endian words)
ESTABLISHED = row(0, "0500000A:9C40", "0A7100CB:01BB", "01", 1000, 111)
SHARED = row(1, "0500000A:9C41", "0A7100CB:01BB", "01", 1000, 222)
FOREIGN = row(2, "0500000A:9C42", "0A7100CB:01BB", "01", 0, 333)
TIME_WAIT = row(3, "0500000A:9C43", "0A7100CB:01BB", "06", 0, 0)
LISTEN = row(4, "0100007F:1F90", "00000000:0000", "0A", 1000, 444)
LOOPBACK = row(5, "0100007F:9C44", "0100007F:1F90", "01", 1000, 555)


def stat_line(pid, name, ppid, start):
    return f"{pid} ({name}) S {ppid} " + " ".join(["0"] * 17) + f" {start} 0 0\n"


def fake_proc(tmp_path, tcp_rows, processes):
    """processes: {pid: (name, ppid, start, [socket inodes], readable)}."""
    root = tmp_path / "proc"
    (root / "sys/kernel/random").mkdir(parents=True)
    (root / "sys/kernel/random/boot_id").write_text("boot-net\n")
    (root / "net").mkdir()
    (root / "net/tcp").write_text(HEADER + "".join(tcp_rows))
    for name in ("tcp6", "udp", "udp6"):
        (root / "net" / name).write_text(HEADER)
    for pid, (name, ppid, start, inodes, readable) in processes.items():
        folder = root / str(pid)
        (folder / "fd").mkdir(parents=True)
        (folder / "stat").write_text(stat_line(pid, name, ppid, start))
        (folder / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
        for index, inode in enumerate(inodes):
            os.symlink(f"socket:[{inode}]", folder / "fd" / str(index + 3))
        os.symlink("/dev/null", folder / "fd" / "0")
        if not readable:
            (folder / "fd").chmod(0)
    return root


@pytest.fixture
def proc(tmp_path):
    root = fake_proc(
        tmp_path,
        [ESTABLISHED, SHARED, FOREIGN, TIME_WAIT, LISTEN, LOOPBACK],
        {
            1: ("init", 0, "1", [], True),
            100: ("curl", 1, "500", [111], True),
            200: ("worker", 1, "600", [222, 444, 555], True),
            201: ("worker", 200, "700", [222], True),
            300: ("rootd", 1, "800", [333], False),
        },
    )
    yield root
    (root / "300/fd").chmod(0o755)


def test_address_decoding_and_table_parsing():
    assert decode_address("0100007F:1F90", socket.AF_INET) == ("127.0.0.1", 8080)
    v6 = "00000000000000000000000001000000:0016"
    assert decode_address(v6, socket.AF_INET6) == ("::1", 22)
    mapped = "0000000000000000FFFF00000100007F:0050"
    assert decode_address(mapped, socket.AF_INET6) == ("127.0.0.1", 80)
    sockets = parse_table(HEADER + ESTABLISHED + LISTEN + "garbage\n", "tcp", socket.AF_INET)
    assert [(s.remote_ip, s.remote_port, s.state) for s in sockets] == [
        ("203.0.113.10", 443, "ESTABLISHED"),
        ("0.0.0.0", 0, "LISTEN"),
    ]
    udp = parse_table(
        HEADER + row(0, "0500000A:0035", "00000000:0000", "07", 0, 9), "udp", socket.AF_INET
    )
    assert udp[0].state == "UNCONNECTED" and not udp[0].connected


def test_socket_attribution_unique_shared_denied_and_ownerless(proc):
    snap = NetCollector(proc).snapshot()
    by_inode = {s.inode: s for s in snap.sockets}
    assert by_inode[111].attribution == "unique"
    owner = by_inode[111].owners[0]
    assert (owner.pid, owner.name, owner.start, owner.ppid, owner.parent_start) == (
        100,
        "curl",
        "500",
        1,
        "1",
    )
    assert by_inode[222].attribution == "ambiguous: shared by 2 processes"
    if not ROOT:
        assert by_inode[333].attribution.startswith("unattributed: owner's descriptors")
        assert snap.denied_processes == 1
    assert by_inode[0].attribution.startswith("unattributed: no owning socket")
    assert (
        snap.fd_counts[owner.key("boot-net")] == 2
        and snap.socket_counts[owner.key("boot-net")] == 1
    )


def test_pid_reuse_refreshes_identity(proc):
    collector = NetCollector(proc)
    first = collector.snapshot()
    key = next(s for s in first.sockets if s.inode == 111).owners[0].key("boot-net")
    (proc / "100/stat").write_text(stat_line(100, "other", 1, "999"))
    second = collector.snapshot()
    reused = next(s for s in second.sockets if s.inode == 111).owners[0]
    assert reused.name == "other" and reused.key("boot-net") != key


def test_monitor_emits_new_connections_as_events(proc, database):
    monitor = NetworkMonitor(NetworkSettings(), collector=NetCollector(proc))
    first = monitor.scan()
    assert first.status == "baseline-created" and first.events == []
    assert first.summary["connected"] == 3  # loopback excluded, TIME_WAIT is not connected
    with open(proc / "net/tcp", "a") as stream:
        stream.write(row(6, "0500000A:9C50", "0A7100CB:01BB", "01", 1000, 666))
    os.symlink("socket:[666]", proc / "100/fd/9")
    second = monitor.scan()
    assert [e.network_destination for e in second.events] == ["203.0.113.10"]
    event = second.events[0]
    assert event.event_type == EventType.NETWORK_CONNECTION
    assert (event.pid, event.process_start_time, event.parent_start_time) == (100, "500", "1")
    assert (
        event.metadata["remote_port"] == 443 and "first observed" in event.metadata["observation"]
    )
    # The existing RT006 watchlist rule now fires on live connection telemetry.
    result = Pipeline(database, load_rules()).process(event)
    assert [d.alert.rule_id for d in result.detections] == ["RT006"]
    assert second.summary["processes"][0]["process"] == "curl"


def test_periodicity_math():
    stats = periodicity([0, 10, 20, 31, 40])
    intervals = [10, 10, 11, 9]
    assert stats["mean_interval_seconds"] == statistics.fmean(intervals)
    assert stats["cv"] == round(statistics.pstdev(intervals) / 10, 4)
    assert periodicity([1, 2]) is None
    assert periodicity([5, 5, 5])["cv"] is None


def test_beacon_and_repeat_rules_and_bounds():
    settings = NetworkSettings(repeat_threshold=5, repeat_window_seconds=100, max_tracked_flows=10)
    analyzer = BeaconAnalyzer(settings)
    flow = None
    for index in range(8):
        flow = analyzer.observe(index * 60.0, "198.51.100.7:443", "k", "beacon", 1)
    assert [rule for rule, _, _ in analyzer.evaluate(flow, 420)] == ["NB001"]
    burst = None
    for index in range(6):
        burst = analyzer.observe(1000 + index * 3.0, "203.0.113.5:80", "k2", "fetch", 2)
    rules = [rule for rule, _, _ in analyzer.evaluate(burst, 1015)]
    assert rules == ["NB002"]  # 3 s intervals are below the 10 s beacon minimum
    for index in range(20):
        analyzer.observe(float(index), f"192.0.2.{index}:1", None, None, None)
    assert len(analyzer.flows) == 10 and analyzer.evicted == 12
    irregular = [0, 5, 90, 100, 400, 405, 1000]
    results = analyze_series([{"time": t, "destination": "x:1"} for t in irregular], settings)
    assert results[0]["rules"] == []


def test_demo_flags_regular_timelines_including_legitimate_ones():
    results = {r["process"]: r for r in analyze_series(demo_series(), NetworkSettings())}
    assert results["beacon-sim"]["rules"] == ["NB001"]
    assert results["ntp-client"]["rules"] == ["NB001"]  # legitimate and periodic: indicator only
    assert results["browser"]["rules"] == []


def test_exclusions():
    settings = NetworkSettings(exclude_cidrs=["10.0.0.0/8"])
    assert excluded("127.0.0.1", settings) and excluded("fe80::1", settings)
    assert excluded("10.1.2.3", settings) and excluded("0.0.0.0", settings)
    assert excluded("not-an-ip", settings) and not excluded("8.8.8.8", settings)
    assert not excluded("127.0.0.1", NetworkSettings(include_loopback=True))


def test_network_cli(tmp_path, capsys):
    db = ["--db", str(tmp_path / "e.db")]
    assert main(db + ["network", "analyze", "--demo", "--json"]) == 0
    flagged = {r["process"]: r["rules"] for r in json.loads(capsys.readouterr().out)}
    assert flagged == {"beacon-sim": ["NB001"], "ntp-client": ["NB001"], "browser": []}
    timeline = tmp_path / "t.jsonl"
    timeline.write_text(
        "\n".join(json.dumps({"time": i * 30, "destination": "d:1"}) for i in range(8))
    )
    assert main(db + ["network", "analyze", "--input", str(timeline)]) == 0
    assert "NB001" in capsys.readouterr().out
    assert main(db + ["network", "analyze"]) == 1
    assert main(db + ["network", "process"]) == 1
    capsys.readouterr()
    assert main(db + ["network", "connections", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"taken_at", "connections", "coverage"}
    assert main(db + ["network", "process", "--pid", str(os.getpid()), "--json"]) == 0
    assert "stored_events" in json.loads(capsys.readouterr().out)
    assert main(db + ["network", "process", "--pid", str(os.getpid())]) == 0
    assert "STORED NETWORK_CONNECTION EVENTS" in capsys.readouterr().out
    assert main(db + ["network", "show"]) == 0
    assert "NETWORK MONITOR" in capsys.readouterr().out
    assert main(db + ["network", "show", "--id", "nope"]) == 3
