"""JSONL replay; sorting is explicit and buffers the input in memory."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from runtime_engine.events.normalizer import normalize
from runtime_engine.events.schema import Event

logger = logging.getLogger(__name__)


class ReplayCollector:
    def __init__(self, path: Path, *, sort: bool = False) -> None:
        self.path = path
        self.sort = sort
        self.errors = 0
        self.rejected = 0

    def _read(self) -> Iterator[Event]:
        with self.path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise ValueError("event must be an object")
                    yield normalize(raw)
                except (ValueError, ValidationError) as exc:
                    self.rejected += 1
                    # Do not log raw telemetry or validation values, which may contain secrets.
                    logger.warning(
                        "invalid_record line=%d error_type=%s", line_number, type(exc).__name__
                    )

    def collect(self) -> Iterator[Event]:
        """Yield valid events, preserving file order unless sorting was requested."""
        events = self._read()
        yield from sorted(events, key=lambda e: e.timestamp) if self.sort else events
