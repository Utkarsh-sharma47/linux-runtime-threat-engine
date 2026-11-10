"""Actual in-process counters; throughput covers pipeline calls, not collector sleep."""

from dataclasses import asdict, dataclass


@dataclass
class Metrics:
    total_events_processed: int = 0
    total_alerts_generated: int = 0
    total_incidents_created: int = 0
    duplicate_alerts_suppressed: int = 0
    duplicate_events_suppressed: int = 0
    events_rejected: int = 0
    collector_errors: int = 0
    processing_seconds: float = 0
    maximum_processing_latency_ms: float = 0

    def observe(self, seconds: float) -> None:
        self.processing_seconds += seconds
        self.maximum_processing_latency_ms = max(self.maximum_processing_latency_ms, seconds * 1000)

    def report(self) -> dict[str, int | float]:
        result = asdict(self)
        count = self.total_events_processed
        result["average_processing_latency_ms"] = (
            self.processing_seconds * 1000 / count if count else 0
        )
        result["event_throughput_per_second"] = (
            count / self.processing_seconds if self.processing_seconds else 0
        )
        return result
