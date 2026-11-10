from runtime_engine.process.ancestry import AncestryTracker


def test_reconstruction_exit_and_missing_parent(make_event):
    tracker = AncestryTracker()
    parent = make_event(process_name="parent")
    child = make_event(
        pid=110, process_start_time="1100", ppid=100, parent_start_time="1000", process_name="bash"
    )
    tracker.observe(child)
    assert "unobserved" in tracker.tree(child.process_key)
    tracker.observe(parent)
    assert tracker.related(parent.process_key, child.process_key)
    assert tracker.parent_name(child) == "parent"
    assert "parent" in tracker.tree(child.process_key)
    tracker.observe(make_event(event_type="PROCESS_EXIT", pid=110, process_start_time="1100"))
    assert "exit observed" in tracker.tree(child.process_key)


def test_cycle_is_finite(make_event):
    tracker = AncestryTracker()
    a = make_event(ppid=110, parent_start_time="1100")
    b = make_event(pid=110, process_start_time="1100", ppid=100, parent_start_time="1000")
    tracker.observe(a)
    tracker.observe(b)
    assert len(tracker.lineage(a.process_key)) == 2


def test_missing_start_time_does_not_bind_pid(make_event):
    tracker = AncestryTracker()
    parent = make_event()
    child = make_event(pid=110, process_start_time="1100", ppid=100)
    tracker.observe(parent)
    tracker.observe(child)
    assert not tracker.related(parent.process_key, child.process_key)
    tracker.observe(make_event(process_start_time=None))
    assert len(tracker.nodes) == 2


def test_pid_reuse_is_not_same_parent(make_event):
    tracker = AncestryTracker()
    old = make_event()
    child = make_event(pid=110, process_start_time="1100", ppid=100, parent_start_time="1000")
    new = make_event(process_start_time="2000")
    for event in [old, child, new]:
        tracker.observe(event)
    assert tracker.related(old.process_key, child.process_key)
    assert not tracker.related(new.process_key, child.process_key)
