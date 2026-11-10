from pathlib import Path

from runtime_engine.collector.proc_collector import ProcCollector


def root(tmp_path):
    (tmp_path / "sys/kernel/random").mkdir(parents=True)
    (tmp_path / "sys/kernel/random/boot_id").write_text("test-boot")
    return tmp_path


def process(path, pid, ppid=1, start="100", name="odd ) name"):
    folder = path / str(pid)
    folder.mkdir(exist_ok=True)
    tail = ["S", str(ppid)] + ["0"] * 17 + [start]
    (folder / "stat").write_text(f"{pid} ({name}) " + " ".join(tail))
    (folder / "status").write_text("Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n")
    (folder / "cmdline").write_bytes(b"program\0--option\0")
    (folder / "exe").symlink_to("/usr/bin/program")


def test_snapshot_new_processes_parent_and_reuse(tmp_path):
    root(tmp_path)
    process(tmp_path, 1, ppid=0, start="50")
    process(tmp_path, 2, ppid=1)
    collector = ProcCollector(tmp_path, include_cmdline=True)
    events = list(collector.collect())
    assert len(events) == 2
    child = next(e for e in events if e.pid == 2)
    assert child.process_name == "odd ) name"
    assert child.parent_start_time == "50"
    assert child.command_line == ["program", "--option"]
    assert not list(collector.collect())
    stat = tmp_path / "2/stat"
    stat.write_text(stat.read_text().replace("100", "200"))
    assert len(list(collector.collect())) == 1


def test_malformed_disappearing_and_permission_entries(tmp_path, monkeypatch):
    root(tmp_path)
    process(tmp_path, 1)
    process(tmp_path, 2)
    (tmp_path / "3").mkdir()
    (tmp_path / "3/stat").write_text("malformed")
    (tmp_path / "4").mkdir()
    read_text = Path.read_text

    def restricted(path, *args, **kwargs):
        if path == tmp_path / "2/stat":
            raise PermissionError("test denied")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", restricted)
    collector = ProcCollector(tmp_path)
    events = list(collector.collect())
    assert len(events) == 1 and collector.errors == 3
    assert events[0].command_line is None


def test_parent_started_after_child_is_not_bound(tmp_path):
    root(tmp_path)
    process(tmp_path, 1, start="200")
    process(tmp_path, 2, ppid=1, start="100")
    child = next(e for e in ProcCollector(tmp_path).collect() if e.pid == 2)
    assert child.parent_start_time is None


def test_changed_identity_during_read_is_rejected(tmp_path, monkeypatch):
    root(tmp_path)
    process(tmp_path, 1)
    original = Path.read_text
    reads = 0

    def racing(path, *args, **kwargs):
        nonlocal reads
        data = original(path, *args, **kwargs)
        if path == tmp_path / "1/stat":
            reads += 1
            if reads == 2:
                return data.replace("100", "200")
        return data

    monkeypatch.setattr(Path, "read_text", racing)
    collector = ProcCollector(tmp_path)
    assert not list(collector.collect())
    assert collector.errors == 1


def test_process_collection_does_not_modify_fixture(tmp_path):
    import hashlib

    root(tmp_path)
    process(tmp_path, 1)

    def contents():
        return {
            str(p.relative_to(tmp_path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in tmp_path.rglob("*")
            if p.is_file() and not p.is_symlink()
        }

    before = contents()
    list(ProcCollector(tmp_path, include_cmdline=True).collect())
    assert contents() == before


def test_missing_uid_stays_missing(tmp_path):
    root(tmp_path)
    process(tmp_path, 1)
    (tmp_path / "1/status").write_text("Name:\tunknown\n")
    event = list(ProcCollector(tmp_path).collect())[0]
    assert event.uid is None
