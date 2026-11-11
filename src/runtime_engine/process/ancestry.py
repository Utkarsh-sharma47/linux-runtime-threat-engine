"""Start-time-qualified process graphs; PID alone never establishes a relationship."""

import json

from runtime_engine.events.schema import Event, EventType


def parent_key(event: Event) -> str | None:
    """The parent's identity key, only when the source reported the parent's start token."""
    if not event.ppid or not event.parent_start_time:
        return None
    key = json.dumps([event.host_id, event.ppid, event.parent_start_time], separators=(",", ":"))
    return None if key == event.process_key else key


class AncestryTracker:
    def __init__(self) -> None:
        self.nodes: dict[str, Event] = {}
        self.parents: dict[str, str] = {}
        self.terminated: set[str] = set()

    def observe(self, event: Event) -> None:
        """Record process identity and explicit parent identity without guessing from PID."""
        key = event.process_key
        if key is None:
            return
        existing = self.nodes.get(key)
        if existing is None or event.event_type == EventType.PROCESS_START:
            self.nodes[key] = event
        parent = parent_key(event)
        if parent is not None:
            self.parents[key] = parent
        if event.event_type == EventType.PROCESS_EXIT:
            self.terminated.add(key)

    def lineage(self, key: str) -> list[str]:
        """Return the child-to-root path; stop at missing nodes and cycles."""
        result: list[str] = []
        visited: set[str] = set()
        while key not in visited:
            visited.add(key)
            result.append(key)
            if key not in self.parents:
                break
            key = self.parents[key]
        return result

    def related(self, first: str, second: str) -> bool:
        """Only same process or direct ancestor/descendant, not shared init/systemd."""
        return first == second or first in self.lineage(second) or second in self.lineage(first)

    def tree(self, key: str) -> str:
        """Render one root-to-leaf path with explicit missing-parent markers."""
        lines: list[str] = []
        for depth, current in enumerate(reversed(self.lineage(key))):
            node = self.nodes.get(current)
            label = (
                f"{node.process_name or '?'} (PID {node.pid}, start={node.process_start_time})"
                if node
                else f"[unobserved {current}]"
            )
            if current in self.terminated:
                label += " [exit observed]"
            lines.append("  " * depth + ("+-- " if depth else "") + label)
        return "\n".join(lines)

    def parent_name(self, event: Event) -> str | None:
        """Use only the bound parent node or the collector's explicit parent observation."""
        parent = self.nodes.get(self.parents.get(event.process_key or "", ""))
        return parent.process_name if parent else event.parent_process_name
