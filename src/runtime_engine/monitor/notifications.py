"""Alert notification throttling. Every alert stays in state; only the pop-up is coalesced.

Notifications are keyed by incident, so new evidence updates one notification instead of
opening another. LOW/MEDIUM matches of the same rule in a short window are coalesced
across incidents. HIGH/CRITICAL notifications are pinned until the alert list is opened.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from runtime_engine.events.schema import Alert, Severity


@dataclass
class Notification:
    severity: Severity
    rule_ids: list[str]
    rule_names: list[str]
    incident_ids: list[str]
    pid: int | None
    process_name: str | None
    last_at: float
    matches: int = 1
    pinned: bool = False
    alert_ids: list[str] = field(default_factory=list)

    def copy(self) -> "Notification":
        return Notification(
            self.severity,
            list(self.rule_ids),
            list(self.rule_names),
            list(self.incident_ids),
            self.pid,
            self.process_name,
            self.last_at,
            self.matches,
            self.pinned,
            list(self.alert_ids),
        )


class NotificationCenter:
    """Not thread-safe by itself; `DashboardState` calls it under its lock."""

    def __init__(
        self,
        display_seconds: float = 12.0,
        coalesce_seconds: float = 30.0,
        capacity: int = 100,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.display_seconds = display_seconds
        self.coalesce_seconds = coalesce_seconds
        self.capacity = capacity
        self.clock = clock
        self.items: list[Notification] = []
        self.pushed = 0
        self.coalesced = 0
        self.evicted = 0

    def push(
        self, alert: Alert, incident_id: str, pid: int | None, process_name: str | None
    ) -> None:
        now = self.clock()
        self.pushed += 1
        self._expire(now)
        target = next((n for n in self.items if incident_id in n.incident_ids), None)
        if target is None and alert.severity.rank < Severity.HIGH.rank:
            target = next(
                (
                    n
                    for n in self.items
                    if not n.pinned
                    and alert.rule_id in n.rule_ids
                    and now - n.last_at <= self.coalesce_seconds
                ),
                None,
            )
        if target is None:
            self.items.append(
                Notification(
                    alert.severity,
                    [alert.rule_id],
                    [alert.rule_name],
                    [incident_id],
                    pid,
                    process_name,
                    now,
                    pinned=alert.severity.rank >= Severity.HIGH.rank,
                    alert_ids=[alert.alert_id],
                )
            )
            self._bound()
            return
        self.coalesced += 1
        target.matches += 1
        target.last_at = now
        target.pid, target.process_name = pid, process_name
        if alert.rule_id not in target.rule_ids:
            target.rule_ids.append(alert.rule_id)
            target.rule_names.append(alert.rule_name)
        if incident_id not in target.incident_ids:
            target.incident_ids.append(incident_id)
        if alert.alert_id not in target.alert_ids:
            target.alert_ids.append(alert.alert_id)
        if alert.severity.rank > target.severity.rank:
            target.severity = alert.severity
        target.pinned = target.pinned or alert.severity.rank >= Severity.HIGH.rank

    def _expire(self, now: float) -> None:
        self.items = [n for n in self.items if n.pinned or now - n.last_at <= self.display_seconds]

    def _bound(self) -> None:
        while len(self.items) > self.capacity:
            # Drop the least severe, oldest notification; the alert itself remains listed.
            victim = min(self.items, key=lambda n: (n.severity.rank, n.last_at))
            self.items.remove(victim)
            self.evicted += 1

    def active(self) -> list[Notification]:
        self._expire(self.clock())
        ordered = sorted(self.items, key=lambda n: (n.severity.rank, n.last_at), reverse=True)
        return [n.copy() for n in ordered]

    def acknowledge(self) -> None:
        """The user opened the full alert list, so the pop-ups have served their purpose."""
        self.items.clear()
