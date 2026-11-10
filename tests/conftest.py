from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from runtime_engine.events.schema import Event
from runtime_engine.storage.database import Database


@pytest.fixture
def make_event() -> Callable[..., Event]:
    count = 0

    def make(**kwargs: object) -> Event:
        nonlocal count
        count += 1
        return Event.model_validate(
            dict(
                event_id=f"test-{count}",
                timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=count),
                event_type="PROCESS_START",
                source="synthetic",
                host_id="test-boot",
                pid=100,
                process_start_time="1000",
            )
            | kwargs
        )

    return make


@pytest.fixture
def database():
    db = Database(":memory:")
    yield db
    db.close()
