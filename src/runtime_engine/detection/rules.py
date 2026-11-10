"""Pure matching functions. Absent telemetry never satisfies a condition."""

import posixpath

from runtime_engine.detection.rule_loader import Condition


def matches(value: object, condition: Condition) -> bool:
    if value is None:
        return False
    expected = condition.value
    if condition.op == "equals":
        return value == expected
    if not isinstance(expected, list):
        return False
    if condition.op == "in":
        return value in expected
    if condition.op == "not_in":
        return value not in expected
    if condition.op == "path_under" and isinstance(value, str) and value.startswith("/"):
        path = posixpath.normpath(value)
        return any(
            isinstance(root, str)
            and (path == root.rstrip("/") or path.startswith(root.rstrip("/") + "/"))
            for root in expected
        )
    return False
