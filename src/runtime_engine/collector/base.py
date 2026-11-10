"""Collector interface."""

from collections.abc import Iterator
from typing import Protocol

from runtime_engine.events.schema import Event


class Collector(Protocol):
    """A finite stream per invocation, with explicit input/error counters."""

    errors: int
    rejected: int

    def collect(self) -> Iterator[Event]: ...
