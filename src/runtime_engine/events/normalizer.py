"""Single validation boundary shared by collectors and replay."""

from typing import Any

from runtime_engine.events.schema import Event


def normalize(raw: dict[str, Any]) -> Event:
    """Validate an event, rejecting unknown fields and naive timestamps."""
    return Event.model_validate(raw)
